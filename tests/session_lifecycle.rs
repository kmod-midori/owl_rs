// SPDX-License-Identifier: GPL-3.0-or-later
use owl_rs::{
    archive,
    identity::Identity,
    service::{self, Command},
    transfer::{Receiver, Sender},
};
use std::{net::SocketAddrV6, path::Path, time::Duration};
use tokio::process::{Child, Command as Process};

fn cli() -> Process {
    let mut command = Process::new(env!("CARGO_BIN_EXE_owl_rs"));
    command
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    command
}
async fn status(dir: &Path) -> serde_json::Value {
    service::client(dir, Command::Status, None).await.unwrap()
}
async fn ready(dir: &Path) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(value) = service::client(dir, Command::Status, None).await
                && value["session"]["phase"] == "active"
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
}
async fn finished(child: Child, success: bool) {
    let output = tokio::time::timeout(Duration::from_secs(10), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        output.status.success(),
        success,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
async fn idle(dir: &Path, address: SocketAddrV6) {
    assert!(status(dir).await["session"].is_null());
    assert!(
        tokio::net::TcpStream::connect(address).await.is_err(),
        "HTTPS must be torn down before the CLI returns"
    );
}
fn receive(dir: &Path, once: bool) -> Child {
    let mut command = cli();
    command
        .args(["receive", "--no-radio", "--auto-accept", "--run-dir"])
        .arg(dir);
    if once {
        command.arg("--once");
    }
    command.spawn().unwrap()
}

// Exercises the CLI/IPC boundary, final HTTP replies, and teardown rather than
// duplicating internal implementation choices. No radio or root is required.
#[tokio::test]
async fn idle_daemon_and_operation_scoped_services() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("run");
    let keys = temp.path().join("daemon-keys");
    let output = temp.path().join("received");
    let reserve = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
    let std::net::SocketAddr::V6(address) = reserve.local_addr().unwrap() else {
        panic!()
    };
    drop(reserve);
    // This interface cannot work; merely starting the daemon must not touch it.
    let daemon = cli()
        .args([
            "daemon",
            "--interface",
            "nonexistent-wifi",
            "--no-bluetooth",
            "--name",
            "inherited name",
            "--listen",
        ])
        .arg(address.to_string())
        .arg("--run-dir")
        .arg(&dir)
        .arg("--keys")
        .arg(&keys)
        .arg("--output")
        .arg(&output)
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !dir.join("control.sock").exists() {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    idle(&dir, address).await;
    assert!(
        !keys.exists(),
        "idle daemon must not create session identity"
    );
    assert!(!dir.join("radio.json").exists());
    let identity = Identity::load(&temp.path().join("sender-keys"), "fixture").unwrap();
    let sender = Sender {
        name: "fixture sender".into(),
        id: "020000000001".into(),
        identity: identity.clone(),
        tag: None,
        ask_timeout: Duration::from_secs(2),
    };

    let receiver = receive(&dir, true);
    ready(&dir).await;
    assert_eq!(sender.discover(address).await.unwrap(), "inherited name");
    let busy = cli()
        .args(["receive", "--no-radio", "--duration", "1", "--run-dir"])
        .arg(&dir)
        .output()
        .await
        .unwrap();
    assert!(!busy.status.success());
    assert!(String::from_utf8_lossy(&busy.stderr).contains("already active"));
    let path = temp.path().join("payload.txt");
    std::fs::write(&path, b"operation-scoped AirDrop").unwrap();
    let prepared = archive::prepare(std::slice::from_ref(&path), 1024 * 1024).unwrap();
    let corrupt = temp.path().join("corrupt.dvzip");
    std::fs::write(&corrupt, b"bad archive").unwrap();
    assert!(
        sender
            .send(address, prepared.items.clone(), vec![], Some(corrupt), None)
            .await
            .is_err()
    );
    assert_eq!(
        status(&dir).await["session"]["kind"],
        "receive",
        "failed upload must not consume --once"
    );
    let transfer_started = tokio::time::Instant::now();
    sender
        .send(
            address,
            prepared.items,
            vec![],
            Some(prepared.file.path().into()),
            prepared.icon,
        )
        .await
        .unwrap();
    assert_eq!(
        status(&dir).await["session"]["kind"],
        "receive",
        "successful receive must remain active during the completion grace period"
    );
    finished(receiver, true).await;
    assert!(transfer_started.elapsed() >= Duration::from_secs(5));
    idle(&dir, address).await;
    let records = service::client(&dir, Command::Transfers, None)
        .await
        .unwrap();
    let completed = records
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["state"] == "completed")
        .unwrap();
    assert_eq!(
        std::fs::read(Path::new(completed["output"].as_str().unwrap()).join("payload.txt"))
            .unwrap(),
        b"operation-scoped AirDrop"
    );

    let receiver = receive(&dir, false);
    ready(&dir).await;
    for n in 0..2 {
        sender
            .send(
                address,
                vec![],
                vec![format!("https://example.com/{n}")],
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(status(&dir).await["session"]["kind"], "receive");
    }
    // Foreground interruption must close IPC, wait for cleanup, and leave the
    // independent daemon alive.
    assert!(
        Process::new("kill")
            .args(["-INT", &receiver.id().unwrap().to_string()])
            .status()
            .await
            .unwrap()
            .success()
    );
    finished(receiver, false).await;
    idle(&dir, address).await;

    let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let remote = Receiver::new(
        "remote".into(),
        identity,
        temp.path().join("sent-back"),
        1024 * 1024,
        true,
        None,
    );
    let cancel = tokio_util::sync::CancellationToken::new();
    let server = tokio::spawn({
        let remote = remote.clone();
        let cancel = cancel.clone();
        async move { remote.serve(listener, cancel).await }
    });
    let sending = cli()
        .args(["send", "remote", "--no-radio", "--direct"])
        .arg(target.to_string())
        .arg("--run-dir")
        .arg(&dir)
        .arg(&path)
        .spawn()
        .unwrap();
    finished(sending, true).await;
    idle(&dir, address).await;
    assert_eq!(remote.transfers().await[0].offer.sender, "inherited name");
    cancel.cancel();
    server.await.unwrap().unwrap();

    let receiver = receive(&dir, false);
    ready(&dir).await;
    service::client(&dir, Command::Stop, None).await.unwrap();
    finished(daemon, true).await;
    finished(receiver, false).await;
    assert!(!dir.join("control.sock").exists());
    assert!(tokio::net::TcpStream::connect(address).await.is_err());
}

// A hard kill leaves the socket inode behind. A foreground session must
// replace it under the daemon lock and remove its control service on exit.
#[tokio::test]
async fn foreground_receive_restarts_after_daemon_kill() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("run");
    let mut daemon = cli()
        .args(["daemon", "--no-radio", "--no-bluetooth", "--run-dir"])
        .arg(&dir)
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while service::client(&dir, Command::Status, None).await.is_err() {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    daemon.kill().await.unwrap();
    assert!(dir.join("control.sock").exists());
    let receiver = cli()
        .args([
            "receive",
            "--auto-accept",
            "--duration",
            "1",
            "--no-radio",
            "--no-bluetooth",
            "--listen",
            "[::1]:0",
            "--run-dir",
        ])
        .arg(&dir)
        .arg("--keys")
        .arg(temp.path().join("keys"))
        .arg("--output")
        .arg(temp.path().join("received"))
        .spawn()
        .unwrap();
    ready(&dir).await;
    finished(receiver, true).await;
    assert!(!dir.join("control.sock").exists());
}
