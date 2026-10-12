// SPDX-License-Identifier: GPL-3.0-or-later
use crate::{
    archive::{self, Item},
    identity::Identity,
};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::{BodyExt, Full, StreamBody, combinators::UnsyncBoxBody};
use hyper::{
    Request, Response, StatusCode,
    body::{Frame, Incoming},
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use openssl::ssl::Ssl;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::{SocketAddr, SocketAddrV6},
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    sync::{Mutex, OwnedSemaphorePermit, Semaphore, oneshot},
};
use tokio_util::sync::CancellationToken;
type Error = Box<dyn std::error::Error + Send + Sync>;
type Body = UnsyncBoxBody<Bytes, Error>;
const METADATA_LIMIT: usize = 1024 * 1024;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_HEADER_TIMEOUT: Duration = Duration::from_secs(20);
const CONNECTION_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const TCP_LINGER_TIMEOUT: Duration = Duration::from_secs(10);
const RECEIVER_DRAIN_TIMEOUT: Duration = Duration::from_secs(20);
const UPLOAD_IDLE_POLL: Duration = Duration::from_secs(2);
const UPLOAD_IDLE_TIMEOUT: Duration = Duration::from_secs(20);
const UPLOAD_TOTAL_TIMEOUT: Duration = Duration::from_secs(600);
fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into())
        .map_err(|e| match e {})
        .boxed_unsync()
}
pub fn plist_bytes(value: &plist::Value) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    value.to_writer_binary(&mut bytes)?;
    Ok(bytes)
}
pub fn dict(fields: impl IntoIterator<Item = (String, plist::Value)>) -> plist::Value {
    plist::Value::Dictionary(fields.into_iter().collect())
}
fn response(code: StatusCode, body: Vec<u8>) -> Response<Body> {
    let mut builder = Response::builder().status(code);
    if !code.is_success() {
        builder = builder.header("Connection", "close");
    }
    builder.body(full(body)).expect("static response headers")
}
async fn metadata(body: Incoming) -> Result<plist::Value> {
    let mut body = body;
    let mut bytes = Vec::new();
    while let Some(frame) = tokio::time::timeout(Duration::from_secs(20), body.frame()).await? {
        if let Ok(data) = frame?.into_data() {
            ensure!(
                bytes.len() + data.len() <= METADATA_LIMIT,
                "metadata exceeds 1 MiB"
            );
            bytes.extend(data);
        }
    }
    Ok(plist::Value::from_reader(std::io::Cursor::new(bytes))?)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Offer {
    pub id: String,
    pub sender: String,
    pub items: Vec<Item>,
    pub urls: Vec<String>,
}
impl Offer {
    fn parse(value: plist::Value) -> Result<Self> {
        let d = value.as_dictionary().context("Ask must be a dictionary")?;
        let id = d
            .get("TransferID")
            .and_then(|v| {
                v.as_string()
                    .or_else(|| v.as_dictionary()?.get("id")?.as_string())
            })
            .context("missing TransferID")?;
        let id = uuid::Uuid::parse_str(id)?.to_string().to_uppercase();
        let sender = d
            .get("SenderComputerName")
            .and_then(plist::Value::as_string)
            .unwrap_or("Unknown")
            .to_owned();
        ensure!(sender.len() <= 256, "sender name is too long");
        let mut items = Vec::new();
        let mut urls = Vec::new();
        if let Some(files) = d.get("Files").and_then(plist::Value::as_array) {
            ensure!(files.len() <= 4096, "too many files");
            for file in files {
                let f = file.as_dictionary().context("invalid file metadata")?;
                let name = f
                    .get("FileName")
                    .and_then(plist::Value::as_string)
                    .context("missing FileName")?
                    .to_owned();
                ensure!(
                    archive::safe_path(&name)?.components().count() == 1,
                    "FileName must be a basename"
                );
                items.push(Item {
                    name,
                    size: f
                        .get("FileSize")
                        .and_then(plist::Value::as_unsigned_integer)
                        .unwrap_or(0),
                    directory: f
                        .get("FileIsDirectory")
                        .and_then(plist::Value::as_boolean)
                        .unwrap_or(false),
                });
            }
        }
        if let Some(links) = d.get("Items").and_then(plist::Value::as_array) {
            ensure!(links.len() <= 4096, "too many links");
            for link in links {
                if let Some(url) = link.as_string() {
                    ensure!(
                        url.len() <= 16384 && !url.contains(['\r', '\n', '\0']),
                        "invalid link"
                    );
                    urls.push(url.into());
                }
            }
        }
        ensure!(!items.is_empty() || !urls.is_empty(), "empty transfer");
        ensure!(
            items.is_empty() || urls.is_empty(),
            "mixed file and link transfer"
        );
        Ok(Self {
            id,
            sender,
            items,
            urls,
        })
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Transfer {
    pub offer: Offer,
    pub state: String,
    pub bytes: u64,
    pub output: Option<PathBuf>,
    pub error: Option<String>,
}
struct Entry {
    transfer: Transfer,
    decision: Option<oneshot::Sender<bool>>,
}
struct Approved {
    offer: Offer,
    _permit: Option<OwnedSemaphorePermit>,
}
#[derive(Clone)]
pub struct Receiver {
    pub name: String,
    pub identity: Identity,
    pub output: PathBuf,
    pub limit: u64,
    pub auto_accept: bool,
    pub owner: Option<(u32, u32)>,
    entries: Arc<Mutex<BTreeMap<String, Entry>>>,
    upload: Arc<Semaphore>,
    once: bool,
    single_offer: Arc<Semaphore>,
    completed: CancellationToken,
}
impl Receiver {
    pub fn new(
        name: String,
        identity: Identity,
        output: PathBuf,
        limit: u64,
        auto_accept: bool,
        owner: Option<(u32, u32)>,
    ) -> Self {
        Self {
            name,
            identity,
            output,
            limit,
            auto_accept,
            owner,
            entries: Arc::new(Mutex::new(BTreeMap::new())),
            upload: Arc::new(Semaphore::new(4)),
            once: false,
            single_offer: Arc::new(Semaphore::new(1)),
            completed: CancellationToken::new(),
        }
    }
    pub fn with_once(mut self, once: bool) -> Self {
        self.once = once;
        self
    }
    pub async fn transfers(&self) -> Vec<Transfer> {
        self.entries
            .lock()
            .await
            .values()
            .map(|e| e.transfer.clone())
            .collect()
    }
    pub async fn decide(&self, id: &str, accept: bool) -> Result<()> {
        let id = uuid::Uuid::parse_str(id)?.to_string().to_uppercase();
        let mut entries = self.entries.lock().await;
        let entry = entries.get_mut(&id).context("unknown transfer")?;
        entry
            .decision
            .take()
            .context("transfer is not pending approval")?
            .send(accept)
            .map_err(|_| anyhow::anyhow!("request expired"))?;
        Ok(())
    }
    async fn update(
        &self,
        id: &str,
        state: &str,
        bytes: u64,
        out: Option<PathBuf>,
        error: Option<String>,
    ) {
        if let Some(e) = self.entries.lock().await.get_mut(id) {
            e.transfer.state = state.into();
            e.transfer.bytes = bytes;
            e.transfer.output = out;
            e.transfer.error = error;
            if state == "completed" && self.once {
                self.completed.cancel();
            }
        }
    }
    fn discover(&self) -> Result<Vec<u8>> {
        let mut d = plist::Dictionary::new();
        d.insert("ReceiverComputerName".into(), self.name.clone().into());
        d.insert("ReceiverModelName".into(), "MacBookPro18,3".into());
        d.insert(
            "ReceiverMediaCapabilities".into(),
            plist::Value::Data(b"{\"Version\": 1}".to_vec()),
        );
        if let Some(record) = &self.identity.record {
            d.insert(
                "ReceiverRecordData".into(),
                plist::Value::Data(record.clone()),
            );
        }
        plist_bytes(&plist::Value::Dictionary(d))
    }
    pub async fn serve(&self, listener: TcpListener, cancel: CancellationToken) -> Result<()> {
        let acceptor = self.identity.acceptor()?;
        let connections = Arc::new(Semaphore::new(32));
        let mut tasks = tokio::task::JoinSet::new();
        let result = async {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = self.completed.cancelled(), if self.once => break,
                    done = tasks.join_next(), if !tasks.is_empty() => {
                        if let Some(Err(e)) = done {
                            tracing::warn!("HTTPS task: {e}");
                        }
                    }
                    accept = listener.accept() => {
                        let (socket, peer) = accept?;
                        if !peer.ip().is_loopback()
                            && !matches!(peer.ip(), std::net::IpAddr::V6(ip) if ip.is_unicast_link_local())
                        {
                            continue;
                        }
                        let Ok(permit) = connections.clone().try_acquire_owned() else {
                            continue;
                        };
                        let receiver = self.clone();
                        let ssl = Ssl::new(acceptor.context())?;
                        tasks.spawn(async move {
                            let _permit = permit;
                            let result = receiver.serve_connection(socket, ssl).await;
                            if let Err(e) = result {
                                tracing::debug!(%peer, "HTTPS: {e:#}");
                            }
                        });
                    }
                }
            }
            Ok::<_, anyhow::Error>(())
        }.await;
        if self.once && self.completed.is_cancelled() {
            let _ = tokio::time::timeout(RECEIVER_DRAIN_TIMEOUT, async {
                while tasks.join_next().await.is_some() {}
            })
            .await;
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        result
    }
    async fn serve_connection(&self, socket: tokio::net::TcpStream, ssl: Ssl) -> Result<()> {
        // A TAP write does not mean the phone acknowledged the reply. Retain a
        // final TCP descriptor after Hyper/TLS flushes, while AWDL stays active.
        let final_socket = self
            .once
            .then(|| socket2::SockRef::from(&socket).try_clone())
            .transpose()?;
        self.serve_https(socket, ssl).await?;
        if let Some(socket) = final_socket {
            tokio::task::spawn_blocking(move || {
                socket.set_nonblocking(false)?;
                socket.set_linger(Some(TCP_LINGER_TIMEOUT))?;
                // Only this descriptor remains: close waits for data/FIN ACKs.
                // Blocking linger must never occupy a Tokio network worker.
                drop(socket);
                Ok::<_, std::io::Error>(())
            })
            .await??;
        }
        Ok(())
    }
    async fn serve_https(&self, socket: tokio::net::TcpStream, ssl: Ssl) -> Result<()> {
        let mut stream = tokio_openssl::SslStream::new(ssl, socket)?;
        tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, Pin::new(&mut stream).accept()).await??;
        let session = Arc::new(Mutex::new(None::<Approved>));
        let receiver = self.clone();
        let service = service_fn(move |req| {
            let receiver = receiver.clone();
            let session = session.clone();
            async move { Ok::<_, std::convert::Infallible>(receiver.handle(req, session).await) }
        });
        let mut builder = hyper::server::conn::http1::Builder::new();
        builder
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout(HTTP_HEADER_TIMEOUT);
        let connection = builder.serve_connection(TokioIo::new(stream), service);
        tokio::pin!(connection);
        tokio::select! {
            result = &mut connection => result?,
            _ = self.completed.cancelled(), if self.once => {
                connection.as_mut().graceful_shutdown();
                tokio::time::timeout(CONNECTION_DRAIN_TIMEOUT, connection).await??;
            }
        }
        // Dropping Hyper here closes the original descriptor before TCP linger.
        Ok(())
    }
    async fn handle(
        &self,
        req: Request<Incoming>,
        session: Arc<Mutex<Option<Approved>>>,
    ) -> Response<Body> {
        match self.route(req, session).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("AirDrop request rejected: {e:#}");
                response(StatusCode::BAD_REQUEST, Vec::new())
            }
        }
    }
    async fn route(
        &self,
        req: Request<Incoming>,
        session: Arc<Mutex<Option<Approved>>>,
    ) -> Result<Response<Body>> {
        ensure!(req.method() == hyper::Method::POST, "only POST is accepted");
        match req.uri().path() {
            "/Discover" => {
                let _ = metadata(req.into_body()).await?;
                Ok(response(StatusCode::OK, self.discover()?))
            }
            "/Ask" => {
                *session.lock().await = None;
                let offer = Offer::parse(metadata(req.into_body()).await?)?;
                let permit = if self.once {
                    ensure!(
                        !self.completed.is_cancelled(),
                        "receive session is complete"
                    );
                    let permit = self
                        .single_offer
                        .clone()
                        .try_acquire_owned()
                        .context("receive --once already has an active offer")?;
                    ensure!(
                        !self.completed.is_cancelled(),
                        "receive session is complete"
                    );
                    Some(permit)
                } else {
                    None
                };
                let bytes = offer
                    .items
                    .iter()
                    .try_fold(0u64, |a, b| a.checked_add(b.size))
                    .context("size overflow")?;
                ensure!(bytes <= self.limit, "offered files exceed size limit");
                let (tx, rx) = oneshot::channel();
                {
                    let mut entries = self.entries.lock().await;
                    ensure!(!entries.contains_key(&offer.id), "duplicate transfer ID");
                    if entries.len() >= 256 {
                        let key = entries
                            .iter()
                            .find(|(_, e)| {
                                e.decision.is_none()
                                    && matches!(
                                        e.transfer.state.as_str(),
                                        "completed" | "failed" | "rejected"
                                    )
                            })
                            .map(|(k, _)| k.clone())
                            .context("too many transfers")?;
                        entries.remove(&key);
                    }
                    entries.insert(
                        offer.id.clone(),
                        Entry {
                            transfer: Transfer {
                                offer: offer.clone(),
                                state: "pending".into(),
                                bytes: 0,
                                output: None,
                                error: None,
                            },
                            decision: Some(tx),
                        },
                    );
                }
                tracing::info!(id=%offer.id,sender=%offer.sender,files=offer.items.len(),links=offer.urls.len(),"incoming AirDrop offer");
                let accepted = if self.auto_accept {
                    true
                } else {
                    tokio::time::timeout(Duration::from_secs(60), rx)
                        .await
                        .ok()
                        .and_then(Result::ok)
                        .unwrap_or(false)
                };
                if let Some(e) = self.entries.lock().await.get_mut(&offer.id) {
                    e.decision.take();
                }
                if !accepted {
                    self.update(&offer.id, "rejected", 0, None, None).await;
                    return Ok(response(StatusCode::FORBIDDEN, vec![]));
                }
                if !offer.urls.is_empty() {
                    let result = self.save_urls(&offer);
                    match result {
                        Ok(out) => {
                            self.update(&offer.id, "completed", 0, Some(out), None)
                                .await;
                        }
                        Err(e) => {
                            self.update(&offer.id, "failed", 0, None, Some(e.to_string()))
                                .await;
                            return Err(e);
                        }
                    }
                } else {
                    *session.lock().await = Some(Approved {
                        offer: offer.clone(),
                        _permit: permit,
                    });
                    self.update(&offer.id, "accepted", 0, None, None).await;
                }
                Ok(response(StatusCode::OK, self.discover()?))
            }
            "/Upload" => {
                let Some(approved) = session.lock().await.take() else {
                    return Ok(response(StatusCode::FORBIDDEN, vec![]));
                };
                let offer = &approved.offer;
                let result = tokio::time::timeout(UPLOAD_TOTAL_TIMEOUT, self.upload(req, offer))
                    .await
                    .context("incoming upload timed out")
                    .and_then(|r| r);
                match result {
                    Ok((bytes, out, incomplete_http)) => {
                        self.update(&offer.id, "completed", bytes, Some(out), None)
                            .await;
                        tracing::info!(id=%offer.id, bytes, http_complete=!incomplete_http,
                            "AirDrop upload committed");
                        // Finish the upload's TLS session with the empty HTTP reply.
                        // Keeping it alive makes some iOS transfers wait for the
                        // server's idle-header timeout before showing Sent.
                        let mut reply = response(StatusCode::OK, vec![]);
                        reply.headers_mut().insert(
                            "Connection",
                            hyper::header::HeaderValue::from_static("close"),
                        );
                        Ok(reply)
                    }
                    Err(e) => {
                        self.update(&offer.id, "failed", 0, None, Some(e.to_string()))
                            .await;
                        Err(e)
                    }
                }
            }
            _ => Ok(response(StatusCode::NOT_FOUND, vec![])),
        }
    }
    fn save_urls(&self, offer: &Offer) -> Result<PathBuf> {
        crate::identity::private_directory(&self.output, self.owner)?;
        let stage = tempfile::tempdir_in(&self.output)?;
        for (n, url) in offer.urls.iter().enumerate() {
            std::fs::write(
                stage.path().join(format!("link-{}.url", n + 1)),
                format!("[InternetShortcut]\nURL={url}\n"),
            )?;
        }
        let out = self.output.join(format!("airdrop-{}", offer.id));
        ensure!(!out.exists(), "output exists");
        self.ownership(stage.path())?;
        std::fs::rename(stage.path(), &out)?;
        Ok(out)
    }
    fn ownership(&self, path: &std::path::Path) -> Result<()> {
        if let Some((uid, gid)) = self.owner {
            for entry in walkdir::WalkDir::new(path) {
                let entry = entry?;
                nix::unistd::chown(
                    entry.path(),
                    Some(nix::unistd::Uid::from_raw(uid)),
                    Some(nix::unistd::Gid::from_raw(gid)),
                )?;
            }
        }
        Ok(())
    }
    async fn upload(&self, req: Request<Incoming>, offer: &Offer) -> Result<(u64, PathBuf, bool)> {
        let id = req
            .headers()
            .get("TransferID")
            .context("missing TransferID")?
            .to_str()?;
        ensure!(
            uuid::Uuid::parse_str(id)?.to_string().to_uppercase() == offer.id,
            "TransferID does not match this TLS connection"
        );
        let content = req
            .headers()
            .get("Content-Type")
            .context("missing Content-Type")?
            .to_str()?;
        ensure!(
            matches!(content, "application/x-dvzip" | "application/octet-stream"),
            "unsupported upload type"
        );
        let _permit = self
            .upload
            .clone()
            .try_acquire_owned()
            .context("too many concurrent uploads")?;
        crate::identity::private_directory(&self.output, self.owner)?;
        let disk = nix::sys::statvfs::statvfs(&self.output)?;
        // Four uploads may hold wire, decoded CPIO and extracted data at once.
        let budget = self
            .limit
            .min(disk.blocks_available().saturating_mul(disk.fragment_size()) / 12);
        ensure!(budget > 0, "insufficient receive disk space");
        let file = tempfile::NamedTempFile::new_in(&self.output)?;
        let mut writer = tokio::fs::File::from_std(file.reopen()?);
        let mut body = req.into_body();
        let mut bytes = 0u64;
        self.update(&offer.id, "receiving", 0, None, None).await;
        let mut last_data = tokio::time::Instant::now();
        let mut checked_bytes = None;
        loop {
            match tokio::time::timeout(UPLOAD_IDLE_POLL, body.frame()).await {
                Ok(Some(frame)) => {
                    if let Ok(data) = frame?.into_data() {
                        bytes = bytes
                            .checked_add(data.len() as u64)
                            .context("size overflow")?;
                        ensure!(bytes <= budget, "upload exceeds receive budget");
                        writer.write_all(&data).await?;
                        last_data = tokio::time::Instant::now();
                        self.update(&offer.id, "receiving", bytes, None, None).await;
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    // A stalled partial upload cannot become complete without new
                    // bytes. Decode at most once per quiet period, retaining the
                    // Hyper parser/body state so partial chunk lines survive waits.
                    if checked_bytes != Some(bytes) {
                        checked_bytes = Some(bytes);
                        writer.flush().await?;
                        let path = file.path().to_path_buf();
                        let output = self.output.clone();
                        let id = offer.id.clone();
                        let expected = offer.items.clone();
                        let limit = budget;
                        let check = tokio::task::spawn_blocking(move || {
                            archive::extract_checked(&path, &output, &id, limit, &expected)
                        })
                        .await?;
                        if let Ok(out) = check {
                            self.ownership(&out)?;
                            tracing::info!(id=%offer.id,bytes,"validated complete archive before HTTP terminator");
                            return Ok((bytes, out, true));
                        }
                    }
                    ensure!(
                        last_data.elapsed() < UPLOAD_IDLE_TIMEOUT,
                        "upload stalled before a complete archive arrived"
                    );
                }
            }
        }
        writer.flush().await?;
        drop(writer);
        let output = self.output.clone();
        let id = offer.id.clone();
        let limit = budget;
        let receiver = self.clone();
        let expected = offer.items.clone();
        let out = tokio::task::spawn_blocking(move || {
            let out = archive::extract_checked(file.path(), &output, &id, limit, &expected)?;
            receiver.ownership(&out)?;
            Ok::<_, anyhow::Error>(out)
        })
        .await??;
        Ok((bytes, out, false))
    }
}
#[derive(Clone)]
pub struct Sender {
    pub name: String,
    pub id: String,
    pub identity: Identity,
    pub tag: Option<[u8; 3]>,
    pub ask_timeout: Duration,
}
struct Connection {
    sender: hyper::client::conn::http1::SendRequest<Body>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Sender {
    async fn connect(&self, address: SocketAddrV6) -> Result<Connection> {
        let socket = tokio::net::TcpSocket::new_v6()?;
        if address.ip().is_unicast_link_local() {
            ensure!(
                address.scope_id() != 0,
                "link-local receiver needs an interface scope"
            );
            let interface = std::fs::read_dir("/sys/class/net")?
                .filter_map(Result::ok)
                .find(|entry| {
                    std::fs::read_to_string(entry.path().join("ifindex"))
                        .ok()
                        .and_then(|s| s.trim().parse::<u32>().ok())
                        == Some(address.scope_id())
                })
                .context("receiver interface no longer exists")?;
            let name = interface.file_name();
            use std::os::unix::ffi::OsStrExt;
            socket2::SockRef::from(&socket).bind_device(Some(name.as_bytes()))?;
            let mac: crate::protocol::Mac =
                std::fs::read_to_string(interface.path().join("address"))?
                    .trim()
                    .parse()?;
            socket.bind(SocketAddrV6::new(mac.ipv6(), 0, 0, address.scope_id()).into())?;
        }
        let tcp = tokio::time::timeout(Duration::from_secs(15), socket.connect(address.into()))
            .await
            .context("TCP connection timed out")?
            .with_context(|| format!("connect to {address}"))?;
        let config = self.identity.connector()?.configure()?;
        let mut ssl = config.into_ssl("AirDrop")?;
        ssl.set_verify(openssl::ssl::SslVerifyMode::NONE);
        let mut stream = tokio_openssl::SslStream::new(ssl, tcp)?;
        tokio::time::timeout(Duration::from_secs(15), Pin::new(&mut stream).connect())
            .await
            .context("TLS handshake timed out")?
            .context("AirDrop TLS handshake")?;
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        let task = tokio::spawn(async {
            if let Err(e) = conn.await {
                tracing::debug!("HTTPS client: {e}");
            }
        });
        Ok(Connection { sender, task })
    }
    fn request(&self, path: &str, value: plist::Value) -> Result<Request<Body>> {
        Ok(Request::builder()
            .method("POST")
            .uri(path)
            .header("Host", "AirDrop")
            .header("Content-Type", "application/octet-stream")
            .header("Connection", "keep-alive")
            .header("User-Agent", "AirDrop/1.0")
            .header("Accept", "*/*")
            .header("Accept-Language", "en-us")
            .body(full(plist_bytes(&value)?))?)
    }
    pub async fn discover(&self, address: SocketAddrV6) -> Result<String> {
        let mut c = self.connect(address).await?;
        let mut fields = vec![(
            "DeviceSupportFlags".into(),
            plist::Value::Integer(111611u64.into()),
        )];
        if let Some(record) = &self.identity.record {
            fields.push((
                "SenderRecordData".into(),
                plist::Value::Data(record.clone()),
            ));
        }
        let reply = tokio::time::timeout(
            Duration::from_secs(15),
            c.sender
                .send_request(self.request("/Discover", dict(fields))?),
        )
        .await??;
        ensure!(
            reply.status().is_success(),
            "Discover returned {}",
            reply.status()
        );
        let value = metadata(reply.into_body()).await?;
        Ok(value
            .as_dictionary()
            .and_then(|d| d.get("ReceiverComputerName"))
            .and_then(plist::Value::as_string)
            .context("receiver has no name")?
            .into())
    }
    pub async fn send(
        &self,
        address: SocketAddrV6,
        items: Vec<Item>,
        urls: Vec<String>,
        file: Option<PathBuf>,
        icon: Option<Vec<u8>>,
    ) -> Result<String> {
        let receiver = self.discover(address).await?;
        tracing::info!(%receiver,%address,"requesting AirDrop transfer");
        let id = uuid::Uuid::new_v4().to_string().to_uppercase();
        let links = !urls.is_empty();
        let files = items
            .iter()
            .map(|i| {
                dict([
                    ("FileName".into(), i.name.clone().into()),
                    ("FileBomPath".into(), format!("./{}", i.name).into()),
                    ("FileSize".into(), plist::Value::Integer(i.size.into())),
                    ("FileIsDirectory".into(), i.directory.into()),
                    ("FileType".into(), uti(&i.name, i.directory).into()),
                    ("ConvertMediaFormats".into(), false.into()),
                ])
            })
            .collect();
        let mut fields = vec![
            (
                "TransferID".into(),
                dict([("id".into(), id.clone().into())]),
            ),
            (
                "TransferType".into(),
                dict([(if links { "links" } else { "files" }.into(), dict([]))]),
            ),
            ("SenderID".into(), self.id.clone().into()),
            ("BundleID".into(), "com.apple.finder".into()),
            ("SenderComputerName".into(), self.name.clone().into()),
            ("SenderModelName".into(), "MacBookPro18,3".into()),
            ("Files".into(), plist::Value::Array(files)),
            (
                "Items".into(),
                plist::Value::Array(urls.into_iter().map(plist::Value::String).collect()),
            ),
            ("ConvertMediaFormats".into(), false.into()),
        ];
        if let Some(record) = &self.identity.record {
            fields.push((
                "SenderRecordData".into(),
                plist::Value::Data(record.clone()),
            ));
        }
        if let Some(tag) = self.tag {
            fields.push((
                "SenderIdentityAuthTag".into(),
                plist::Value::Data(tag.to_vec()),
            ));
        }
        if let Some(icon) = icon {
            ensure!(icon.len() <= 128 * 1024, "preview icon too large");
            fields.push(("FileIcon".into(), plist::Value::Data(icon)));
        }
        let mut c = self.connect(address).await?;
        let reply = tokio::time::timeout(
            self.ask_timeout,
            c.sender.send_request(self.request("/Ask", dict(fields))?),
        )
        .await
        .context("Ask approval timed out")?
        .context("send Ask")?;
        ensure!(
            reply.status().is_success(),
            "receiver declined transfer ({})",
            reply.status()
        );
        tracing::info!(%id,"AirDrop Ask accepted");
        let _ = metadata(reply.into_body())
            .await
            .context("read Ask response")?;
        if !links {
            let file = file.context("file transfer has no archive")?;
            let input = tokio::fs::File::open(file).await?;
            let wire_bytes = input.metadata().await?.len();
            tracing::info!(%id,wire_bytes,"uploading AirDrop archive");
            let stream = tokio_util::io::ReaderStream::new(input)
                .map(|data| data.map(Frame::data).map_err(|e| Box::new(e) as Error));
            let body = StreamBody::new(stream).boxed_unsync();
            let bytes = items
                .iter()
                .try_fold(0u64, |sum, i| sum.checked_add(i.size))
                .context("size overflow")?;
            let req = Request::builder()
                .method("POST")
                .uri("/Upload")
                .header("Host", "AirDrop")
                .header("Content-Type", "application/x-dvzip")
                .header("Connection", "keep-alive")
                .header("User-Agent", "AirDrop/1.0")
                .header("Accept", "*/*")
                .header("TransferID", &id)
                .header("TotalBytes", bytes.to_string())
                .body(body)?;
            let reply = tokio::time::timeout(Duration::from_secs(600), c.sender.send_request(req))
                .await
                .context("Upload timed out")?
                .context("send Upload")?;
            tracing::info!(%id,status=%reply.status(),"AirDrop upload response");
            ensure!(
                reply.status().is_success(),
                "Upload returned {}",
                reply.status()
            );
            let mut body = reply.into_body();
            let mut size = 0;
            while let Some(frame) =
                tokio::time::timeout(Duration::from_secs(20), body.frame()).await?
            {
                if let Ok(data) = frame?.into_data() {
                    size += data.len();
                    ensure!(size <= METADATA_LIMIT, "oversized upload reply");
                }
            }
        }
        Ok(id)
    }
}
fn uti(name: &str, dir: bool) -> &'static str {
    if dir {
        return "public.folder";
    }
    match name
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_lowercase()
        .as_str()
    {
        "jpg" | "jpeg" => "public.jpeg",
        "png" => "public.png",
        "heic" => "public.heic",
        "mp4" => "public.mpeg-4",
        "mov" => "com.apple.quicktime-movie",
        "pdf" => "com.adobe.pdf",
        "txt" => "public.plain-text",
        _ => "public.data",
    }
}
pub async fn listener(address: SocketAddr, interface: Option<&str>) -> Result<TcpListener> {
    let socket = socket2::Socket::new(
        if address.is_ipv6() {
            socket2::Domain::IPV6
        } else {
            socket2::Domain::IPV4
        },
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    if let Some(iface) = interface {
        socket.bind_device(Some(iface.as_bytes()))?;
    }
    socket.bind(&address.into())?;
    socket.listen(32)?;
    socket.set_nonblocking(true)?;
    Ok(TcpListener::from_std(socket.into())?)
}
