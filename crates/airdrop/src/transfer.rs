// SPDX-License-Identifier: GPL-3.0-or-later
use crate::{
    archive::{self, Item},
    contacts::{PeerCertificate, Verifier, record_data},
    identity::Identity,
    timeouts::Timeouts,
    visibility::{self, Policy, Visibility},
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
    net::TcpListener,
    sync::{Mutex, Semaphore, mpsc, oneshot, watch},
};
use tokio_util::sync::CancellationToken;
type Error = Box<dyn std::error::Error + Send + Sync>;
type Body = UnsyncBoxBody<Bytes, Error>;
const METADATA_LIMIT: usize = 1024 * 1024;
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
    let mut builder = Response::builder()
        .status(code)
        .header("Content-Length", body.len());
    if !code.is_success() {
        builder = builder.header("Connection", "close");
    }
    builder.body(full(body)).expect("static response headers")
}
async fn metadata(body: Incoming, timeout: Duration) -> Result<plist::Value> {
    let mut body = body;
    let mut bytes = Vec::new();
    while let Some(frame) = tokio::time::timeout(timeout, body.frame()).await? {
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
    /// Wire length, when provided by HTTP; offered sizes describe decoded files.
    pub total_bytes: Option<u64>,
    pub output: Option<PathBuf>,
    pub error: Option<String>,
}
struct Entry {
    created: tokio::time::Instant,
    transfer: Transfer,
    decision: Option<oneshot::Sender<bool>>,
    cancel: CancellationToken,
}
impl Entry {
    fn refresh_cancelled(&mut self) {
        if self.cancel.is_cancelled() {
            self.decision.take();
            if !crate::progress::terminal(&self.transfer.state) {
                self.transfer.state = "cancelled".into();
            }
        }
    }
}
#[derive(Clone)]
pub struct Receiver {
    pub name: String,
    pub identity: Identity,
    pub output: PathBuf,
    pub limit: u64,
    pub auto_accept: bool,
    entries: Arc<Mutex<BTreeMap<String, Entry>>>,
    upload: Arc<Semaphore>,
    activity: Option<Arc<crate::session::Activity>>,
    timeouts: Timeouts,
    policy: watch::Receiver<Policy>,
}
impl Receiver {
    pub fn new(
        name: String,
        identity: Identity,
        output: PathBuf,
        limit: u64,
        auto_accept: bool,
    ) -> Self {
        Self {
            name,
            identity,
            output,
            limit,
            auto_accept,
            entries: Arc::new(Mutex::new(BTreeMap::new())),
            upload: Arc::new(Semaphore::new(4)),
            activity: None,
            timeouts: Timeouts::default(),
            policy: watch::channel(Policy::everyone()).1,
        }
    }
    pub fn with_timeouts(mut self, timeouts: Timeouts) -> Self {
        self.timeouts = timeouts;
        self
    }
    pub(crate) fn with_policy(mut self, policy: watch::Receiver<Policy>) -> Self {
        self.policy = policy;
        self
    }
    pub(crate) fn with_activity(mut self, activity: Arc<crate::session::Activity>) -> Self {
        self.activity = Some(activity);
        self
    }
    pub(crate) fn visibility(&self) -> Visibility {
        self.policy.borrow().mode
    }
    pub(crate) async fn accept_next(&self) -> Result<Option<String>> {
        if !self.visibility().enabled() {
            return Ok(None);
        }
        let mut entries = self.entries.lock().await;
        loop {
            let next = entries
                .values_mut()
                .filter(|entry| {
                    entry.transfer.state == "pending"
                        && entry.decision.is_some()
                        && !entry.cancel.is_cancelled()
                })
                .min_by_key(|entry| entry.created);
            let Some(entry) = next else {
                return Ok(None);
            };
            let id = entry.transfer.offer.id.clone();
            if entry.decision.take().unwrap().send(true).is_ok() {
                return Ok(Some(id));
            }
        }
    }
    pub async fn transfers(&self) -> Vec<Transfer> {
        self.entries
            .lock()
            .await
            .values_mut()
            .map(|entry| {
                entry.refresh_cancelled();
                entry.transfer.clone()
            })
            .collect()
    }
    pub async fn decide(&self, id: &str, accept: bool) -> Result<()> {
        let id = uuid::Uuid::parse_str(id)?.to_string().to_uppercase();
        let mut entries = self.entries.lock().await;
        let entry = entries.get_mut(&id).context("unknown transfer")?;
        ensure!(!entry.cancel.is_cancelled(), "request expired");
        entry
            .decision
            .take()
            .context("transfer is not pending approval")?
            .send(accept)
            .map_err(|_| anyhow::anyhow!("request expired"))?;
        Ok(())
    }
    pub async fn cancel(&self, id: &str) -> Result<()> {
        let id = uuid::Uuid::parse_str(id)?.to_string().to_uppercase();
        let mut entries = self.entries.lock().await;
        let entry = entries.get_mut(&id).context("unknown transfer")?;
        ensure!(
            !crate::progress::terminal(&entry.transfer.state) && !entry.cancel.is_cancelled(),
            "transfer has already ended"
        );
        entry.cancel.cancel();
        entry.decision.take();
        entry.transfer.state = "cancelled".into();
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
            e.transfer.bytes = e.transfer.bytes.max(bytes);
            e.transfer.output = out;
            e.transfer.error = error;
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
        let certificates = Verifier::apple()?;
        let connections = Arc::new(Semaphore::new(32));
        let mut tasks = tokio::task::JoinSet::new();
        let result = async {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    done = tasks.join_next(), if !tasks.is_empty() => {
                        if let Some(Err(e)) = done {
                            tracing::warn!("HTTPS task: {e}");
                        }
                    }
                    accept = listener.accept() => {
                        let (socket, peer) = accept?;
                        tracing::debug!("incoming AirDrop TCP connection");
                        if !peer.ip().is_loopback()
                            && !matches!(peer.ip(), std::net::IpAddr::V6(ip) if ip.is_unicast_link_local())
                        {
                            continue;
                        }
                        let Ok(permit) = connections.clone().try_acquire_owned() else {
                            continue;
                        };
                        let lease = match self.activity.as_ref().map(|activity| activity.acquire()).transpose() {
                            Ok(lease) => lease,
                            Err(_) => continue,
                        };
                        let receiver = self.clone();
                        let mut ssl = Ssl::new(acceptor.context())?;
                        // Request optional identity from the first handshake so a live
                        // Everyone connection can later be checked in Contacts mode.
                        if let Some(contacts) = &self.policy.borrow().contacts { contacts.request_certificate(&mut ssl)?; }
                        else { certificates.request_certificate(&mut ssl)?; }
                        tasks.spawn(async move {
                            let _permit = permit;
                            let result = receiver.serve_connection(socket, ssl, lease).await;
                            if let Err(e) = result {
                                tracing::debug!(%peer, "HTTPS: {e:#}");
                            }
                        });
                    }
                }
            }
            Ok::<_, anyhow::Error>(())
        }.await;
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        result
    }
    async fn serve_connection(
        &self,
        socket: tokio::net::TcpStream,
        ssl: Ssl,
        lease: Option<crate::session::Lease>,
    ) -> Result<()> {
        // A TAP write does not mean the phone acknowledged the reply. Retain a
        // final TCP descriptor after Hyper/TLS flushes, while AWDL stays active.
        let final_socket = socket2::SockRef::from(&socket).try_clone()?;
        let lifetime = Arc::new(Mutex::new(lease));
        let completed = self.serve_https(socket, ssl, lifetime.clone()).await?;
        if completed && let Some(lease) = lifetime.lock().await.as_ref() {
            lease.complete();
        }
        if completed {
            let socket = final_socket;
            let linger = self.timeouts.tcp_linger;
            tokio::task::spawn_blocking(move || {
                socket.set_nonblocking(false)?;
                socket.set_linger(Some(linger))?;
                // Only this descriptor remains: close waits for data/FIN ACKs.
                // Blocking linger must never occupy a Tokio network worker.
                drop(socket);
                Ok::<_, std::io::Error>(())
            })
            .await??;
        }
        Ok(())
    }
    async fn serve_https(
        &self,
        socket: tokio::net::TcpStream,
        ssl: Ssl,
        lifetime: Arc<Mutex<Option<crate::session::Lease>>>,
    ) -> Result<bool> {
        let mut stream = tokio_openssl::SslStream::new(ssl, socket)?;
        let started = tokio::time::Instant::now();
        tokio::time::timeout(self.timeouts.tls_handshake, Pin::new(&mut stream).accept()).await??;
        tracing::debug!(
            elapsed_ms = started.elapsed().as_millis(),
            "incoming AirDrop TLS ready"
        );
        let peer = Arc::new(PeerCertificate::from_tls(stream.ssl()));
        let connection_cancel = CancellationToken::new();
        let _connection_guard = connection_cancel.clone().drop_guard();
        let session = Arc::new(Mutex::new(None::<Offer>));
        let receiver = self.clone();
        let refused = CancellationToken::new();
        let finished = CancellationToken::new();
        let refusal = refused.clone();
        let terminal = finished.clone();
        let request_cancel = connection_cancel.clone();
        let service = service_fn(move |req: Request<Incoming>| {
            let receiver = receiver.clone();
            let session = session.clone();
            let finished = terminal.clone();
            let peer = peer.clone();
            let refused = refusal.clone();
            let lifetime = lifetime.clone();
            let connection_cancel = request_cancel.clone();
            async move {
                if let Some(activity) = &receiver.activity {
                    let mut held = lifetime.lock().await;
                    if held.is_none() {
                        match activity.acquire() {
                            Ok(lease) => *held = Some(lease),
                            Err(_) => {
                                refused.cancel();
                                return Ok::<_, std::convert::Infallible>(response(
                                    StatusCode::FORBIDDEN,
                                    vec![],
                                ));
                            }
                        }
                    }
                }
                let discovery = req.uri().path() == "/Discover";
                let upload = req.uri().path() == "/Upload";
                let ask = req.uri().path() == "/Ask";
                let response = receiver
                    .handle(req, session.clone(), peer, connection_cancel)
                    .await;
                // A completed discovery reply needs no idle keep-alive lease.
                // Approved offers retain theirs across /Ask -> /Upload and
                // through the final connection drain and TCP linger.
                if discovery {
                    lifetime.lock().await.take();
                } else if ask
                    && response.status().is_success()
                    && session.lock().await.is_some()
                    && let Some(lease) = lifetime.lock().await.as_mut()
                {
                    // Only an approved file transfer changes the radio channel.
                    // TLS, Discover, and the approval wait stay on discovery.
                    lease.transmitting();
                }
                if !response.status().is_success() {
                    refused.cancel();
                } else if upload || (ask && session.lock().await.is_none()) {
                    finished.cancel();
                }
                Ok::<_, std::convert::Infallible>(response)
            }
        });
        let mut builder = hyper::server::conn::http1::Builder::new();
        builder
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout(self.timeouts.http_headers);
        let connection = builder.serve_connection(TokioIo::new(stream), service);
        tokio::pin!(connection);
        tokio::select! {
            _ = connection_cancel.cancelled() => return Ok(false),
            result = &mut connection => result?,
            _ = refused.cancelled() => {
                // Finish the refusal response, then close without waiting for
                // another request or retaining a success-only linger descriptor.
                connection.as_mut().graceful_shutdown();
                match tokio::time::timeout(self.timeouts.rejection_drain, connection).await {
                    Ok(result) => result?,
                    Err(_) => tracing::debug!("refusal close deadline reached"),
                }
            }
            _ = finished.cancelled() => {
                connection.as_mut().graceful_shutdown();
                tokio::time::timeout(self.timeouts.connection_drain, connection).await??;
            }
        }
        // Dropping Hyper here closes the original descriptor before TCP linger.
        Ok(finished.is_cancelled())
    }
    async fn handle(
        &self,
        req: Request<Incoming>,
        session: Arc<Mutex<Option<Offer>>>,
        peer: Arc<PeerCertificate>,
        connection_cancel: CancellationToken,
    ) -> Response<Body> {
        let endpoint = match req.uri().path() {
            "/Discover" => "Discover",
            "/Ask" => "Ask",
            "/Upload" => "Upload",
            _ => "unknown",
        };
        let started = tokio::time::Instant::now();
        let reply = match self.route(req, session, &peer, connection_cancel).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("AirDrop request rejected: {e:#}");
                response(StatusCode::BAD_REQUEST, Vec::new())
            }
        };
        tracing::debug!(
            endpoint,
            status = reply.status().as_u16(),
            elapsed_ms = started.elapsed().as_millis(),
            "incoming AirDrop response ready"
        );
        reply
    }

    async fn route(
        &self,
        req: Request<Incoming>,
        session: Arc<Mutex<Option<Offer>>>,
        peer: &PeerCertificate,
        connection_cancel: CancellationToken,
    ) -> Result<Response<Body>> {
        ensure!(req.method() == hyper::Method::POST, "only POST is accepted");
        match req.uri().path() {
            "/Discover" => {
                let value = metadata(req.into_body(), self.timeouts.metadata_idle).await?;
                let policy = self.policy.borrow().clone();
                if policy.mode == Visibility::Off {
                    return Ok(response(StatusCode::FORBIDDEN, vec![]));
                }
                if let Some(contacts) = &policy.contacts
                    && !contacts.discover(record_data(&value)).await
                {
                    return Ok(response(StatusCode::UNAUTHORIZED, vec![]));
                }
                if self.policy.borrow().revision != policy.revision {
                    return Ok(response(StatusCode::FORBIDDEN, vec![]));
                }
                Ok(response(StatusCode::OK, self.discover()?))
            }
            "/Ask" => {
                // A replacement offer on this connection invalidates its old
                // approval and controls before a new transfer can start.
                if let Some(previous) = session.lock().await.take() {
                    self.update(&previous.id, "cancelled", 0, None, None).await;
                }
                let value = metadata(req.into_body(), self.timeouts.metadata_idle).await?;
                let policy = self.policy.borrow().clone();
                if policy.mode == Visibility::Off {
                    return Ok(response(StatusCode::FORBIDDEN, vec![]));
                }
                if let Some(contacts) = &policy.contacts
                    && let Err(reason) = contacts.authorize(record_data(&value), peer).await
                {
                    tracing::info!(%reason, "Contacts Only offer refused");
                    return Ok(response(StatusCode::FORBIDDEN, vec![]));
                }
                if self.policy.borrow().revision != policy.revision {
                    return Ok(response(StatusCode::FORBIDDEN, vec![]));
                }
                let offer = Offer::parse(value)?;
                let bytes = offer
                    .items
                    .iter()
                    .try_fold(0u64, |a, b| a.checked_add(b.size))
                    .context("size overflow")?;
                ensure!(bytes <= self.limit, "offered files exceed size limit");
                let (tx, rx) = oneshot::channel();
                let cancel = connection_cancel.clone();
                {
                    let mut entries = self.entries.lock().await;
                    ensure!(!entries.contains_key(&offer.id), "duplicate transfer ID");
                    if entries.len() >= 256 {
                        // A dropped HTTP future cannot update its entry. Reconcile
                        // disconnected offers before reclaiming terminal history.
                        for entry in entries.values_mut() {
                            entry.refresh_cancelled();
                        }
                        let key = entries
                            .iter()
                            .find(|(_, e)| {
                                e.decision.is_none() && crate::progress::terminal(&e.transfer.state)
                            })
                            .map(|(k, _)| k.clone())
                            .context("too many transfers")?;
                        entries.remove(&key);
                    }
                    entries.insert(
                        offer.id.clone(),
                        Entry {
                            created: tokio::time::Instant::now(),
                            transfer: Transfer {
                                offer: offer.clone(),
                                state: "pending".into(),
                                bytes: 0,
                                total_bytes: None,
                                output: None,
                                error: None,
                            },
                            decision: Some(tx),
                            cancel: cancel.clone(),
                        },
                    );
                }
                tracing::info!(id=%offer.id,sender=%offer.sender,files=offer.items.len(),links=offer.urls.len(),"incoming AirDrop offer");
                let accepted = if self.auto_accept {
                    true
                } else {
                    let mut changes = self.policy.clone();
                    changes.borrow_and_update();
                    tokio::select! {
                        result = tokio::time::timeout(self.timeouts.approval, rx) => result.ok().and_then(Result::ok).unwrap_or(false),
                        _ = visibility::changed(&mut changes) => false,
                        _ = cancel.cancelled() => false,
                    }
                };
                if let Some(e) = self.entries.lock().await.get_mut(&offer.id) {
                    e.decision.take();
                }
                if !accepted
                    || cancel.is_cancelled()
                    || self.policy.borrow().revision != policy.revision
                {
                    self.update(
                        &offer.id,
                        if cancel.is_cancelled() {
                            "cancelled"
                        } else {
                            "rejected"
                        },
                        0,
                        None,
                        None,
                    )
                    .await;
                    return Ok(response(StatusCode::FORBIDDEN, vec![]));
                }
                if !offer.urls.is_empty() {
                    let mut entries = self.entries.lock().await;
                    let entry = entries.get_mut(&offer.id).context("unknown transfer")?;
                    ensure!(!cancel.is_cancelled(), "transfer cancelled");
                    let result = self.save_urls(&offer);
                    match result {
                        Ok(out) => {
                            entry.transfer.state = "completed".into();
                            entry.transfer.output = Some(out);
                        }
                        Err(e) => {
                            entry.transfer.state = "failed".into();
                            entry.transfer.error = Some(e.to_string());
                            return Err(e);
                        }
                    }
                } else {
                    *session.lock().await = Some(offer.clone());
                    self.update(&offer.id, "accepted", 0, None, None).await;
                }
                let mut reply = response(StatusCode::OK, self.discover()?);
                if !offer.urls.is_empty() {
                    reply.headers_mut().insert(
                        "Connection",
                        hyper::header::HeaderValue::from_static("close"),
                    );
                }
                Ok(reply)
            }
            "/Upload" => {
                let Some(offer) = session.lock().await.take() else {
                    return Ok(response(StatusCode::FORBIDDEN, vec![]));
                };
                let offer = &offer;
                let cancel = self
                    .entries
                    .lock()
                    .await
                    .get(&offer.id)
                    .context("unknown transfer")?
                    .cancel
                    .clone();
                let result = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => Err(anyhow::anyhow!("transfer cancelled")),
                    result =
                    tokio::time::timeout(self.timeouts.upload_total, self.upload(req, offer))
                        => result
                        .context("incoming upload timed out")
                        .and_then(|r| r),
                };
                match result {
                    Ok((bytes, incomplete_http)) => {
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
                        self.update(
                            &offer.id,
                            if cancel.is_cancelled() {
                                "cancelled"
                            } else {
                                "failed"
                            },
                            0,
                            None,
                            Some(e.to_string()),
                        )
                        .await;
                        Err(e)
                    }
                }
            }
            _ => Ok(response(StatusCode::NOT_FOUND, vec![])),
        }
    }
    fn save_urls(&self, offer: &Offer) -> Result<PathBuf> {
        crate::identity::private_directory(&self.output)?;
        let stage = tempfile::tempdir_in(&self.output)?;
        for (n, url) in offer.urls.iter().enumerate() {
            std::fs::write(
                stage.path().join(format!("link-{}.url", n + 1)),
                format!("[InternetShortcut]\nURL={url}\n"),
            )?;
        }
        let out = self.output.join(format!("airdrop-{}", offer.id));
        ensure!(!out.exists(), "output exists");
        std::fs::rename(stage.path(), &out)?;
        Ok(out)
    }
    async fn upload(&self, req: Request<Incoming>, offer: &Offer) -> Result<(u64, bool)> {
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
        let permit = self
            .upload
            .clone()
            .try_acquire_owned()
            .context("too many concurrent uploads")?;
        crate::identity::private_directory(&self.output)?;
        let disk = nix::sys::statvfs::statvfs(&self.output)?;
        // Four uploads each stage one decoded transfer; reserve additional free space.
        let budget = self
            .limit
            .min(disk.blocks_available().saturating_mul(disk.fragment_size()) / 8);
        ensure!(budget > 0, "insufficient receive disk space");
        let (chunks, reader) = mpsc::channel(4);
        let output = self.output.clone();
        let id = offer.id.clone();
        let cancel = CancellationToken::new();
        let _cancel_on_drop = cancel.clone().drop_guard();
        let mut decoded = tokio::task::spawn_blocking(move || {
            // A cancelled HTTP task must not free a slot while its decoder runs.
            let _permit = permit;
            archive::receive(
                UploadReader {
                    chunks: reader,
                    cancel,
                    current: std::io::Cursor::new(Bytes::new()),
                },
                &output,
                &id,
                budget,
            )
        });
        let mut chunks = Some(chunks);
        if let Some(entry) = self.entries.lock().await.get_mut(&offer.id) {
            entry.transfer.total_bytes = req
                .headers()
                .get(hyper::header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse().ok());
        }
        let mut body = req.into_body();
        let mut bytes = 0u64;
        self.update(&offer.id, "receiving", 0, None, None).await;
        let validated = loop {
            tokio::select! {
                result = &mut decoded => break result??,
                frame = tokio::time::timeout(self.timeouts.upload_idle, body.frame()), if chunks.is_some() => {
                    match frame.context("upload stalled before a complete archive arrived")? {
                        Some(frame) => if let Ok(data) = frame?.into_data() {
                            bytes = bytes.checked_add(data.len() as u64).context("size overflow")?;
                            ensure!(bytes <= budget, "upload exceeds receive budget");
                            self.update(&offer.id, "receiving", bytes, None, None).await;
                            if chunks.as_ref().expect("HTTP body still open").send(data).await.is_err() {
                                break decoded.await??;
                            }
                        },
                        None => { chunks.take(); }
                    }
                }
            }
        };
        // Serialize the publication boundary with cancellation: once the final
        // directory exists, cancellation must report that this transfer ended.
        let mut entries = self.entries.lock().await;
        let entry = entries.get_mut(&offer.id).context("unknown transfer")?;
        ensure!(!entry.cancel.is_cancelled(), "transfer cancelled");
        let out = validated.commit()?;
        entry.transfer.state = "completed".into();
        entry.transfer.bytes = bytes;
        entry.transfer.output = Some(out);
        drop(entries);
        tracing::info!(id=%offer.id, bytes, "validated complete archive while receiving");
        Ok((bytes, chunks.is_some()))
    }
}
// Bounded adapter between asynchronous HTTP input and the blocking archive
// decoder. Cancellation rejects buffered input; dropping the sender also
// unblocks a pending channel read so the worker can discard its staging.
struct UploadReader {
    chunks: mpsc::Receiver<Bytes>,
    cancel: CancellationToken,
    current: std::io::Cursor<Bytes>,
}
impl std::io::Read for UploadReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.cancel.is_cancelled() {
                return Err(std::io::Error::other("upload cancelled"));
            }
            let n = std::io::Read::read(&mut self.current, out)?;
            if n != 0 || out.is_empty() {
                return Ok(n);
            }
            match self.chunks.blocking_recv() {
                Some(data) => self.current = std::io::Cursor::new(data),
                None => return Ok(0),
            }
        }
    }
}
#[derive(Clone)]
pub struct Sender {
    pub name: String,
    pub id: String,
    pub identity: Identity,
    pub tag: Option<[u8; 3]>,
    pub timeouts: Timeouts,
}
#[derive(Default)]
pub(crate) struct SendContext<'a> {
    pub activity: Option<&'a Arc<crate::session::Activity>>,
    pub progress: Option<crate::progress::Progress>,
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
            let mac: owl_ipc::Mac = std::fs::read_to_string(interface.path().join("address"))?
                .trim()
                .parse()?;
            socket.bind(SocketAddrV6::new(mac.ipv6(), 0, 0, address.scope_id()).into())?;
        }
        let tcp = tokio::time::timeout(self.timeouts.tcp_connect, socket.connect(address.into()))
            .await
            .context("TCP connection timed out")?
            .with_context(|| format!("connect to {address}"))?;
        let config = self.identity.connector()?.configure()?;
        let mut ssl = config.into_ssl("AirDrop")?;
        ssl.set_verify(openssl::ssl::SslVerifyMode::NONE);
        let mut stream = tokio_openssl::SslStream::new(ssl, tcp)?;
        tokio::time::timeout(self.timeouts.tls_connect, Pin::new(&mut stream).connect())
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
        let fields = vec![(
            "DeviceSupportFlags".into(),
            plist::Value::Integer(111611u64.into()),
        )];
        let reply = tokio::time::timeout(
            self.timeouts.http_request,
            c.sender
                .send_request(self.request("/Discover", dict(fields))?),
        )
        .await??;
        ensure!(
            reply.status().is_success(),
            "Discover returned {}",
            reply.status()
        );
        let value = metadata(reply.into_body(), self.timeouts.metadata_idle).await?;
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
        self.send_with_context(address, items, urls, file, icon, SendContext::default())
            .await
    }
    pub(crate) async fn send_with_context(
        &self,
        address: SocketAddrV6,
        items: Vec<Item>,
        urls: Vec<String>,
        file: Option<PathBuf>,
        icon: Option<Vec<u8>>,
        context: SendContext<'_>,
    ) -> Result<String> {
        let receiver = self.discover(address).await?;
        if let Some(progress) = &context.progress {
            progress.update("pending", 0, None);
        }
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
            self.timeouts.approval,
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
        let _ = metadata(reply.into_body(), self.timeouts.metadata_idle)
            .await
            .context("read Ask response")?;
        if !links {
            let mut exchange = context.activity.map(|a| a.acquire()).transpose()?;
            if let Some(lease) = &mut exchange {
                let started = tokio::time::Instant::now();
                lease.channel_ready().await?;
                tracing::debug!(
                    elapsed_ms = started.elapsed().as_millis(),
                    "transfer channel ready"
                );
            }
            let file = file.context("file transfer has no archive")?;
            let input = tokio::fs::File::open(file).await?;
            let wire_bytes = input.metadata().await?.len();
            if let Some(progress) = &context.progress {
                progress.update("sending", 0, Some(wire_bytes));
            }
            tracing::info!(%id,wire_bytes,"uploading AirDrop archive");
            let mut sent = 0u64;
            let stream = tokio_util::io::ReaderStream::new(input).map(move |data| {
                if let Ok(data) = &data {
                    sent += data.len() as u64;
                    if let Some(progress) = &context.progress {
                        progress.update("sending", sent, Some(wire_bytes));
                    }
                }
                data.map(Frame::data).map_err(|e| Box::new(e) as Error)
            });
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
            let reply =
                tokio::time::timeout(self.timeouts.upload_total, c.sender.send_request(req))
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
                tokio::time::timeout(self.timeouts.metadata_idle, body.frame()).await?
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

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn next_accept_selects_oldest_live_offer_without_reusing_consent() {
        let dir = tempfile::tempdir().unwrap();
        let identity = Identity {
            dir: dir.path().join("keys"),
            record: None,
            hashes: [0; 8],
        };
        let receiver = Receiver::new(
            "fixture".into(),
            identity,
            dir.path().join("output"),
            1024,
            false,
        );
        let older = uuid::Uuid::new_v4().to_string().to_uppercase();
        let newer = uuid::Uuid::new_v4().to_string().to_uppercase();
        let expired = uuid::Uuid::new_v4().to_string().to_uppercase();
        let mut decisions = Vec::new();
        for (index, id) in [&expired, &older, &newer].into_iter().enumerate() {
            let (tx, rx) = oneshot::channel();
            decisions.push(rx);
            receiver.entries.lock().await.insert(
                id.clone(),
                Entry {
                    created: tokio::time::Instant::now() + Duration::from_millis(index as u64),
                    transfer: Transfer {
                        offer: Offer {
                            id: id.clone(),
                            sender: "fixture".into(),
                            items: vec![],
                            urls: vec![],
                        },
                        state: "pending".into(),
                        bytes: 0,
                        total_bytes: None,
                        output: None,
                        error: None,
                    },
                    decision: Some(tx),
                    cancel: CancellationToken::new(),
                },
            );
        }
        drop(decisions.remove(0)); // Stale pending entry must not consume the next acceptance.
        assert_eq!(receiver.accept_next().await.unwrap(), Some(older));
        assert!(decisions.remove(0).await.unwrap());
        assert_eq!(receiver.accept_next().await.unwrap(), Some(newer));
        assert!(decisions.remove(0).await.unwrap());
        assert_eq!(receiver.accept_next().await.unwrap(), None);
        receiver
            .entries
            .lock()
            .await
            .get(&expired)
            .unwrap()
            .cancel
            .cancel();
        assert_eq!(
            receiver
                .transfers()
                .await
                .into_iter()
                .find(|t| t.offer.id == expired)
                .unwrap()
                .state,
            "cancelled"
        );
        let entries = receiver.entries.lock().await;
        let entry = entries.get(&expired).unwrap();
        assert_eq!(entry.transfer.state, "cancelled");
        assert!(entry.decision.is_none()); // Disconnected offers can be evicted.
        drop(entries);

        assert!(!dir.path().join("output").exists());
    }
}
