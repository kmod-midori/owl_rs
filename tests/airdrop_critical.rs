// SPDX-License-Identifier: GPL-3.0-or-later
use owl_rs::{
    archive,
    identity::Identity,
    transfer::{Receiver, Sender},
};
use std::{
    io::{Read, Write},
    time::Duration,
};
#[test]
fn archive_roundtrip_bounds_traversal_and_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("folder");
    std::fs::create_dir_all(tree.join("nested")).unwrap();
    std::fs::write(tree.join("nested/data.txt"), vec![b'a'; 180000]).unwrap();
    let mut random = vec![0; 90000];
    openssl::rand::rand_bytes(&mut random).unwrap();
    std::fs::write(tree.join("random.bin"), &random).unwrap();
    let wire = archive::prepare(&[tree], 1024 * 1024).unwrap();
    let out = archive::extract_checked(
        wire.file.path(),
        &dir.path().join("received"),
        "fixture",
        1024 * 1024,
        &wire.items,
    )
    .unwrap();
    assert_eq!(
        std::fs::read(out.join("folder/random.bin")).unwrap(),
        random
    );
    assert_eq!(
        std::fs::read(out.join("folder/nested/data.txt")).unwrap(),
        vec![b'a'; 180000]
    );
    assert!(
        archive::extract_checked(
            wire.file.path(),
            &dir.path().join("received"),
            "unapproved",
            1024 * 1024,
            &[archive::Item {
                name: "other".into(),
                size: 0,
                directory: true
            }]
        )
        .is_err()
    );
    assert!(!dir.path().join("received/airdrop-unapproved").exists());
    // Apple's compressed blocks can expand beyond the streaming output buffer.
    let decoded = archive::decode(wire.file.path(), 1024 * 1024).unwrap();
    let bytes = std::fs::read(decoded.path()).unwrap();
    let mut zip = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    zip.write_all(&bytes).unwrap();
    let compressed = zip.finish().unwrap();
    let mut large = tempfile::NamedTempFile::new().unwrap();
    large
        .write_all(&(compressed.len() as u32).to_be_bytes())
        .unwrap();
    large.write_all(&compressed).unwrap();
    assert_eq!(
        std::fs::read(archive::decode(large.path(), 1024 * 1024).unwrap().path()).unwrap(),
        bytes
    );
    // A complete DVZip block ending between CPIO members is not a complete
    // archive; an empty archive must also be rejected.
    let partial = tempfile::NamedTempFile::new().unwrap();
    let next_member = bytes
        .windows(6)
        .enumerate()
        .find(|(n, b)| *n > 0 && *b == b"070707")
        .unwrap()
        .0;
    for raw in [&bytes[..next_member], &b""[..]] {
        let mut stored = ((raw.len() as u32) | 0x80000000).to_be_bytes().to_vec();
        stored.extend(raw);
        std::fs::write(partial.path(), stored).unwrap();
        assert!(archive::decode(partial.path(), 1024 * 1024).is_err());
    }
    let trailer_start = bytes
        .windows(6)
        .enumerate()
        .rfind(|(_, b)| *b == b"070707")
        .unwrap()
        .0;
    std::fs::write(partial.path(), &bytes[trailer_start..]).unwrap();
    assert!(archive::preflight(partial.path(), 1024 * 1024).is_err());
    assert!(archive::decode(wire.file.path(), 100).is_err());
    for name in ["../escape", "/absolute", "x/../../escape", "x\\escape", ""] {
        assert!(archive::safe_path(name).is_err());
    }
    let mut bytes = Vec::new();
    wire.file.reopen().unwrap().read_to_end(&mut bytes).unwrap();
    bytes.pop();
    let mut bad = tempfile::NamedTempFile::new().unwrap();
    bad.write_all(&bytes).unwrap();
    assert!(archive::decode(bad.path(), 1024 * 1024).is_err());
    let mut forged = vec![b'0'; 110];
    forged[..6].copy_from_slice(b"070701");
    forged[94..102].copy_from_slice(b"ffffffff");
    std::fs::write(bad.path(), forged).unwrap();
    assert!(archive::preflight(bad.path(), 1024 * 1024).is_err());
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
        None,
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
        timeouts: owl_rs::timeouts::Timeouts {
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
    let prepared = archive::prepare(&[path], 16 * 1024 * 1024).unwrap();
    let cpio = archive::decode(prepared.file.path(), 16 * 1024 * 1024).unwrap();
    let mut reader = cpio_archive::reader(cpio.reopen().unwrap()).unwrap();
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
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::load(&dir.path().join("keys"), "test").unwrap();
    let receiver = Receiver::new(
        "test".into(),
        identity.clone(),
        dir.path().join("received"),
        1024 * 1024,
        true,
        None,
    );
    let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let cancel = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn({
        let receiver = receiver.clone();
        let cancel = cancel.clone();
        async move { receiver.serve(listener, cancel).await }
    });
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
    let mut stream = BufStream::new(tls);
    let path = dir.path().join("photo.txt");
    let mut payload = vec![0; 90000];
    openssl::rand::rand_bytes(&mut payload).unwrap();
    payload[..10].copy_from_slice(b"TRAILER!!!");
    std::fs::write(&path, &payload).unwrap();
    let prepared = archive::prepare(&[path], 1024 * 1024).unwrap();
    let id = uuid::Uuid::new_v4().to_string().to_uppercase();
    let offer = owl_rs::transfer::dict([
        ("TransferID".into(), id.clone().into()),
        (
            "Files".into(),
            plist::Value::Array(vec![owl_rs::transfer::dict([
                ("FileName".into(), "photo.txt".into()),
                (
                    "FileSize".into(),
                    plist::Value::Integer((payload.len() as u64).into()),
                ),
            ])]),
        ),
    ]);
    let metadata = owl_rs::transfer::plist_bytes(&offer).unwrap();
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
    stream.write_all(&metadata).await.unwrap();
    stream.flush().await.unwrap();
    assert!(reply(&mut stream).await.starts_with("HTTP/1.1 200"));
    let data = std::fs::read(prepared.file.path()).unwrap();
    stream.write_all(format!("POST /Upload HTTP/1.1\r\nHost: AirDrop\r\nTransferID: {id}\r\nContent-Type: application/x-dvzip\r\nTransfer-Encoding: chunked\r\n\r\n").as_bytes()).await.unwrap();
    let chunk_size = format!("{:x}\r\n", data.len());
    stream.write_all(&chunk_size.as_bytes()[..1]).await.unwrap();
    stream.flush().await.unwrap();
    // Cancelled body waits must retain partially parsed chunk headers/data.
    tokio::time::sleep(Duration::from_millis(2200)).await;
    stream.write_all(&chunk_size.as_bytes()[1..]).await.unwrap();
    stream.write_all(&data[..data.len() / 2]).await.unwrap();
    stream.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(2200)).await;
    assert_ne!(receiver.transfers().await[0].state, "completed");
    assert!(!dir.path().join(format!("received/airdrop-{id}")).exists());
    stream.write_all(&data[data.len() / 2..]).await.unwrap();
    stream.write_all(b"\r\n").await.unwrap();
    stream.flush().await.unwrap();
    // Never send the final zero HTTP chunk. Only the validated archive is complete.
    let response = tokio::time::timeout(Duration::from_secs(5), reply(&mut stream))
        .await
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.to_ascii_lowercase().contains("connection: close"));
    assert_eq!(
        std::fs::read(
            receiver.transfers().await[0]
                .output
                .as_ref()
                .unwrap()
                .join("photo.txt")
        )
        .unwrap(),
        payload
    );
    drop(stream);
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
