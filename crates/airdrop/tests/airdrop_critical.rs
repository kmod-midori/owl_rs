// SPDX-License-Identifier: GPL-3.0-or-later
use airdrop::{
    archive,
    identity::Identity,
    transfer::{Receiver, Sender},
};
use std::{
    io::{Read, Write},
    time::Duration,
};
// Independent, test-only decoding of known-valid outgoing fixtures. Production
// reception has one streaming parser and never writes a decoded archive file.
fn cpio_bytes(wire: &archive::Prepared) -> Vec<u8> {
    let mut input = wire.file.reopen().unwrap();
    let mut out = Vec::new();
    loop {
        let mut header = [0; 4];
        if input.read(&mut header[..1]).unwrap() == 0 {
            break;
        }
        input.read_exact(&mut header[1..]).unwrap();
        let block = u32::from_be_bytes(header);
        let mut section = (&mut input).take((block & 0x7fffffff) as u64);
        if block & 0x80000000 != 0 {
            std::io::copy(&mut section, &mut out).unwrap();
        } else {
            std::io::copy(&mut flate2::read::ZlibDecoder::new(&mut section), &mut out).unwrap();
        }
    }
    out
}
fn stored(bytes: &[u8]) -> Vec<u8> {
    let mut wire = ((bytes.len() as u32) | 0x80000000).to_be_bytes().to_vec();
    wire.extend(bytes);
    wire
}
fn staging_exists(path: &std::path::Path) -> bool {
    std::fs::read_dir(path).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".owl-rs-")
    })
}
#[test]
fn archive_roundtrip_bounds_traversal_and_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("folder");
    std::fs::create_dir_all(tree.join("nested")).unwrap();
    std::fs::write(tree.join("nested/data.txt"), vec![b'a'; 180000]).unwrap();
    let mut random = vec![0; 90000];
    openssl::rand::rand_bytes(&mut random).unwrap();
    std::fs::write(tree.join("random.bin"), &random).unwrap();
    let standalone = dir.path().join("data.txt");
    std::fs::write(&standalone, b"standalone").unwrap();
    let wire = archive::prepare(&[tree, standalone], 1024 * 1024).unwrap();
    let destination = dir.path().join("received");
    let original = std::fs::read(wire.file.path()).unwrap();
    let bytes = cpio_bytes(&wire);
    // Apple's compressed blocks may expand beyond a decoder output buffer.
    let mut zip = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    zip.write_all(&bytes).unwrap();
    let compressed = zip.finish().unwrap();
    let mut large = (compressed.len() as u32).to_be_bytes().to_vec();
    large.extend(compressed);
    struct Fragmented(std::io::Cursor<Vec<u8>>);
    impl Read for Fragmented {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let len = out.len().min(3);
            let n = self.0.read(&mut out[..len])?;
            if n == 0 && !out.is_empty() {
                return Err(std::io::Error::other("unexpected transport EOF read"));
            }
            Ok(n)
        }
    }
    let split: Vec<_> = bytes.chunks(17).flat_map(stored).collect();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&bytes).unwrap();
    let mut gzip = gz.finish().unwrap();
    for (id, data) in [
        ("original", original.clone()),
        ("split", split),
        ("zlib", large.clone()),
        ("gzip", gzip.clone()),
    ] {
        let pending = archive::receive(
            Fragmented(std::io::Cursor::new(data)),
            &destination,
            id,
            1024 * 1024,
        )
        .unwrap();
        assert!(!destination.join(format!("airdrop-{id}")).exists());
        let out = pending.commit().unwrap();
        assert_eq!(std::fs::read(out.join("data.txt")).unwrap(), b"standalone");
        assert_eq!(
            std::fs::read(out.join("folder/random.bin")).unwrap(),
            random
        );
        assert_eq!(
            std::fs::read(out.join("folder/nested/data.txt")).unwrap(),
            vec![b'a'; 180000]
        );
    }
    let pending = archive::receive(
        std::io::Cursor::new(original.clone()),
        &destination,
        "cancelled",
        1024 * 1024,
    )
    .unwrap();
    drop(pending);
    assert!(!destination.join("airdrop-cancelled").exists());
    let next_member = bytes
        .windows(6)
        .enumerate()
        .find(|(n, b)| *n > 0 && *b == b"070707")
        .unwrap()
        .0;
    let trailer = bytes.windows(6).rposition(|b| b == b"070707").unwrap();
    *gzip.last_mut().unwrap() ^= 1;
    large.pop();
    let mut truncated = original.clone();
    truncated.pop();
    let mut forged = vec![b'0'; 110];
    forged[..6].copy_from_slice(b"070701");
    forged[94..102].copy_from_slice(b"ffffffff");
    for (id, data, limit) in [
        ("partial", stored(&bytes[..next_member]), 1024 * 1024),
        ("empty", stored(&bytes[trailer..]), 1024 * 1024),
        ("gzip-corrupt", gzip, 1024 * 1024),
        ("missing-checksum", large, 1024 * 1024),
        ("truncated", truncated, 1024 * 1024),
        ("forged-name", stored(&forged), 1024 * 1024),
        ("size-limit", original, 100),
    ] {
        assert!(
            archive::receive(std::io::Cursor::new(data), &destination, id, limit,).is_err(),
            "{id}"
        );
        assert!(!destination.join(format!("airdrop-{id}")).exists());
        assert!(!staging_exists(&destination), "{id}");
    }
    for name in ["../escape", "/absolute", "x/../../escape", "x\\escape", ""] {
        assert!(archive::safe_path(name).is_err());
    }
}
#[test]
fn extraction_streams_before_eof_and_removes_failed_staging() {
    use std::{cell::Cell, io::Cursor, path::Path};
    struct Observed<'a> {
        input: Cursor<Vec<u8>>,
        destination: &'a Path,
        observed: &'a Cell<bool>,
        fail: bool,
    }
    impl Read for Observed<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if self.input.position() >= 128 * 1024 && !self.observed.get() {
                let entries: Vec<_> =
                    std::fs::read_dir(self.destination)?.collect::<Result<_, _>>()?;
                assert_eq!(entries.len(), 1);
                assert!(
                    entries[0]
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".owl-rs-")
                );
                let len = std::fs::metadata(entries[0].path().join("payload.bin"))?.len();
                assert!(len > 0 && len < 256 * 1024);
                self.observed.set(true);
                if self.fail {
                    return Err(std::io::Error::other("connection failed"));
                }
            }
            let n = out.len().min(8192);
            self.input.read(&mut out[..n])
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("payload.bin");
    std::fs::write(&source, vec![0x5a; 256 * 1024]).unwrap();
    let prepared = archive::prepare(&[source], 1024 * 1024).unwrap();
    let wire = stored(&cpio_bytes(&prepared));
    for fail in [false, true] {
        let destination = dir.path().join(if fail { "failure" } else { "success" });
        let observed = Cell::new(false);
        let result = archive::receive(
            Observed {
                input: Cursor::new(wire.clone()),
                destination: &destination,
                observed: &observed,
                fail,
            },
            &destination,
            "fixture",
            1024 * 1024,
        );
        assert!(
            observed.get(),
            "file must be written before the final block arrives"
        );
        if fail {
            assert!(result.is_err());
        } else {
            let pending = result.unwrap();
            assert!(!destination.join("airdrop-fixture").exists());
            let out = pending.commit().unwrap();
            assert_eq!(
                std::fs::metadata(out.join("payload.bin")).unwrap().len(),
                256 * 1024
            );
        }
        assert!(!staging_exists(&destination));
    }
    // New ASCII CPIO aligns both names and file payloads to four bytes.
    fn member(out: &mut Vec<u8>, name: &str, mode: u32, data: &[u8]) {
        out.extend(b"070701");
        for value in [
            1,
            mode,
            0,
            0,
            1,
            0,
            data.len() as u32,
            0,
            0,
            0,
            0,
            name.len() as u32 + 1,
            0,
        ] {
            out.extend(format!("{value:08x}").bytes());
        }
        out.extend(name.bytes());
        out.push(0);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        out.extend(data);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
    }
    let destination = dir.path().join("newc");
    let mut cpio = Vec::new();
    member(&mut cpio, "file.txt", 0o100644, b"abc");
    member(&mut cpio, "TRAILER!!!", 0, b"");
    let wire_newc = stored(&cpio);
    let out = archive::receive(Cursor::new(wire_newc), &destination, "fixture", 1024)
        .unwrap()
        .commit()
        .unwrap();
    assert_eq!(std::fs::read(out.join("file.txt")).unwrap(), b"abc");
    // Failed publication preserves the existing transfer and removes staging.
    let pending =
        archive::receive(Cursor::new(wire), &destination, "fixture", 1024 * 1024).unwrap();
    assert!(pending.commit().is_err());
    assert_eq!(std::fs::read(out.join("file.txt")).unwrap(), b"abc");
    assert_eq!(std::fs::read_dir(destination).unwrap().count(), 1);
}

#[tokio::test]
async fn native_https_transfer_and_connection_bound_upload() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::load(&dir.path().join("keys"), "test").unwrap();
    let receiver = Receiver::new(
        "test receiver".into(),
        identity.clone(),
        dir.path().join("received"),
        16 * 1024 * 1024,
        true,
    );
    let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
    let std::net::SocketAddr::V6(address) = listener.local_addr().unwrap() else {
        panic!()
    };
    let cancel = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn({
        let receiver = receiver.clone();
        let cancel = cancel.clone();
        async move { receiver.serve(listener, cancel).await }
    });
    let sender = Sender {
        name: "test sender".into(),
        id: "020000000001".into(),
        identity: identity.clone(),
        tag: None,
        timeouts: airdrop::timeouts::Timeouts {
            approval: Duration::from_secs(2),
            ..Default::default()
        },
    };
    let path = dir.path().join("payload.txt");
    // Multiple incompressible megabytes exercise sustained HTTPS streaming and
    // many DVZip blocks, rather than only a small single-block transfer.
    let mut payload = vec![0; 8 * 1024 * 1024];
    openssl::rand::rand_bytes(&mut payload).unwrap();
    std::fs::write(&path, &payload).unwrap();
    let wrapper = dir.path().join("NSIRD_AirDrop_fixture");
    std::fs::create_dir(&wrapper).unwrap();
    std::fs::write(wrapper.join("second.txt"), b"second file").unwrap();
    let mut prepared = archive::prepare(&[path, wrapper], 16 * 1024 * 1024).unwrap();
    // Apple can put an offered file inside an archive-only temporary directory.
    prepared.items[1].name = "second.txt".into();
    prepared.items[1].directory = false;
    let mut reader = cpio_archive::reader(std::io::Cursor::new(cpio_bytes(&prepared))).unwrap();
    let header = reader.read_next().unwrap().unwrap();
    // A trailing slash makes Apple's extractor treat a regular file as a directory.
    assert_eq!(header.name(), "./payload.txt");
    let id = sender
        .send(
            address,
            prepared.items,
            vec![],
            Some(prepared.file.path().into()),
            prepared.icon,
        )
        .await
        .unwrap();
    let records = receiver.transfers().await;
    assert_eq!(records[0].state, "completed");
    assert_eq!(
        std::fs::read(records[0].output.as_ref().unwrap().join("payload.txt")).unwrap(),
        payload
    );
    assert_eq!(
        std::fs::read(
            records[0]
                .output
                .as_ref()
                .unwrap()
                .join("NSIRD_AirDrop_fixture/second.txt")
        )
        .unwrap(),
        b"second file"
    );
    // Even a known ID cannot authorize another TLS connection to upload.
    let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
    let ssl = identity
        .connector()
        .unwrap()
        .configure()
        .unwrap()
        .into_ssl("AirDrop")
        .unwrap();
    let mut stream = tokio_openssl::SslStream::new(ssl, tcp).unwrap();
    std::pin::Pin::new(&mut stream).connect().await.unwrap();
    let (mut client, conn) = hyper::client::conn::http1::handshake::<
        _,
        http_body_util::Full<bytes::Bytes>,
    >(hyper_util::rt::TokioIo::new(stream))
    .await
    .unwrap();
    let conn = tokio::spawn(conn);
    let req = hyper::Request::builder()
        .method("POST")
        .uri("/Upload")
        .header("TransferID", id)
        .header("Content-Type", "application/x-dvzip")
        .body(http_body_util::Full::new(bytes::Bytes::new()))
        .unwrap();
    assert_eq!(
        client.send_request(req).await.unwrap().status(),
        hyper::StatusCode::FORBIDDEN
    );
    drop(client);
    conn.abort();
    cancel.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn complete_archive_without_http_terminator_is_acknowledged_and_closed() {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufStream};
    async fn reply(
        stream: &mut BufStream<tokio_openssl::SslStream<tokio::net::TcpStream>>,
    ) -> String {
        let mut headers = String::new();
        let mut length = 0;
        loop {
            let mut line = String::new();
            assert!(stream.read_line(&mut line).await.unwrap() > 0);
            if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                length = value.trim().parse().unwrap();
            }
            headers.push_str(&line);
            assert!(headers.len() < 8192);
            if line == "\r\n" {
                break;
            }
        }
        stream.read_exact(&mut vec![0; length]).await.unwrap();
        headers
    }
    async fn ask(
        stream: &mut BufStream<tokio_openssl::SslStream<tokio::net::TcpStream>>,
        metadata: &[u8],
    ) {
        stream
            .write_all(
                format!(
                    "POST /Ask HTTP/1.1\r\nHost: AirDrop\r\nContent-Length: {}\r\n\r\n",
                    metadata.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        stream.write_all(metadata).await.unwrap();
        stream.flush().await.unwrap();
        assert!(reply(stream).await.starts_with("HTTP/1.1 200"));
    }
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::load(&dir.path().join("keys"), "test").unwrap();
    let receiver = Receiver::new(
        "test".into(),
        identity.clone(),
        dir.path().join("received"),
        1024 * 1024,
        true,
    )
    .with_timeouts(airdrop::timeouts::Timeouts {
        upload_idle: Duration::from_secs(1),
        upload_total: Duration::from_secs(3),
        ..Default::default()
    });
    let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let cancel = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn({
        let receiver = receiver.clone();
        let cancel = cancel.clone();
        async move { receiver.serve(listener, cancel).await }
    });
    async fn connect(
        identity: &Identity,
        address: std::net::SocketAddr,
    ) -> BufStream<tokio_openssl::SslStream<tokio::net::TcpStream>> {
        let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
        let ssl = identity
            .connector()
            .unwrap()
            .configure()
            .unwrap()
            .into_ssl("AirDrop")
            .unwrap();
        let mut tls = tokio_openssl::SslStream::new(ssl, tcp).unwrap();
        std::pin::Pin::new(&mut tls).connect().await.unwrap();
        BufStream::new(tls)
    }
    let mut stream = connect(&identity, address).await;
    let path = dir.path().join("photo.txt");
    let mut payload = vec![0; 90000];
    openssl::rand::rand_bytes(&mut payload).unwrap();
    payload[..10].copy_from_slice(b"TRAILER!!!");
    std::fs::write(&path, &payload).unwrap();
    let prepared = archive::prepare(&[path], 1024 * 1024).unwrap();
    let id = uuid::Uuid::new_v4().to_string().to_uppercase();
    let offer = airdrop::transfer::dict([
        ("TransferID".into(), id.clone().into()),
        (
            "Files".into(),
            plist::Value::Array(vec![airdrop::transfer::dict([
                ("FileName".into(), "photo.txt".into()),
                (
                    "FileSize".into(),
                    plist::Value::Integer((payload.len() as u64).into()),
                ),
            ])]),
        ),
    ]);
    let metadata = airdrop::transfer::plist_bytes(&offer).unwrap();
    let previous_id = uuid::Uuid::new_v4().to_string().to_uppercase();
    let mut previous_offer = offer.clone();
    previous_offer
        .as_dictionary_mut()
        .unwrap()
        .insert("TransferID".into(), previous_id.clone().into());
    ask(
        &mut stream,
        &airdrop::transfer::plist_bytes(&previous_offer).unwrap(),
    )
    .await;
    ask(&mut stream, &metadata).await;
    assert!(receiver.cancel(&previous_id).await.is_err());
    let data = std::fs::read(prepared.file.path()).unwrap();
    stream.write_all(format!("POST /Upload HTTP/1.1\r\nHost: AirDrop\r\nTransferID: {id}\r\nContent-Type: application/x-dvzip\r\nTransfer-Encoding: chunked\r\n\r\n").as_bytes()).await.unwrap();
    let chunk_size = format!("{:x}\r\n", data.len());
    stream.write_all(&chunk_size.as_bytes()[..1]).await.unwrap();
    stream.flush().await.unwrap();
    // Fragmented chunk headers and bodies must not complete a partial archive.
    tokio::time::sleep(Duration::from_millis(100)).await;
    stream.write_all(&chunk_size.as_bytes()[1..]).await.unwrap();
    stream.write_all(&data[..data.len() / 2]).await.unwrap();
    stream.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_ne!(
        receiver
            .transfers()
            .await
            .into_iter()
            .find(|transfer| transfer.offer.id == id)
            .unwrap()
            .state,
        "completed"
    );
    assert!(!dir.path().join(format!("received/airdrop-{id}")).exists());
    stream.write_all(&data[data.len() / 2..]).await.unwrap();
    stream.write_all(b"\r\n").await.unwrap();
    stream.flush().await.unwrap();
    // Never send the final zero HTTP chunk. Only the validated archive is complete.
    let response = tokio::time::timeout(Duration::from_millis(700), reply(&mut stream))
        .await
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.to_ascii_lowercase().contains("connection: close"));
    assert_eq!(
        std::fs::read(
            receiver
                .transfers()
                .await
                .into_iter()
                .find(|transfer| transfer.offer.id == id)
                .unwrap()
                .output
                .as_ref()
                .unwrap()
                .join("photo.txt")
        )
        .unwrap(),
        payload
    );
    drop(stream);
    assert!(receiver.cancel(&id).await.is_err()); // Published files cannot be cancelled.
    for failure in ["disconnect", "timeout", "cancel"] {
        let mut stream = connect(&identity, address).await;
        let failed_id = uuid::Uuid::new_v4().to_string().to_uppercase();
        let mut failed_offer = offer.clone();
        failed_offer
            .as_dictionary_mut()
            .unwrap()
            .insert("TransferID".into(), failed_id.clone().into());
        let metadata = airdrop::transfer::plist_bytes(&failed_offer).unwrap();
        ask(&mut stream, &metadata).await;
        stream.write_all(format!("POST /Upload HTTP/1.1\r\nHost: AirDrop\r\nTransferID: {failed_id}\r\nContent-Type: application/x-dvzip\r\nContent-Length: {}\r\n\r\n", data.len()).as_bytes()).await.unwrap();
        stream.write_all(&data[..data.len() / 2]).await.unwrap();
        stream.flush().await.unwrap();
        let staged = || staging_exists(&dir.path().join("received"));
        tokio::time::timeout(Duration::from_secs(2), async {
            while !staged() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let progress = receiver
            .transfers()
            .await
            .into_iter()
            .find(|t| t.offer.id == failed_id)
            .unwrap();
        assert!(progress.bytes > 0 && progress.bytes < data.len() as u64);
        assert_eq!(progress.total_bytes, Some(data.len() as u64));
        if failure == "cancel" {
            receiver.cancel(&failed_id).await.unwrap();
            assert!(receiver.decide(&failed_id, true).await.is_err());
            let mut response = Vec::new();
            let _closed =
                tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut response))
                    .await
                    .unwrap();
            assert!(!response.starts_with(b"HTTP/1.1 200"));
            assert_eq!(
                receiver
                    .transfers()
                    .await
                    .into_iter()
                    .find(|t| t.offer.id == failed_id)
                    .unwrap()
                    .state,
                "cancelled"
            );
        } else if failure == "timeout" {
            let response = tokio::time::timeout(Duration::from_secs(4), reply(&mut stream))
                .await
                .unwrap();
            assert!(!response.starts_with("HTTP/1.1 200"));
        }
        drop(stream);
        tokio::time::timeout(Duration::from_secs(2), async {
            while staged() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(
            !dir.path()
                .join(format!("received/airdrop-{failed_id}"))
                .exists()
        );
        assert!(dir.path().join(format!("received/airdrop-{id}")).exists());
    }
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
