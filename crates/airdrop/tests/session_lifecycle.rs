// SPDX-License-Identifier: GPL-3.0-or-later
use airdrop::{
    service::{self, Command},
    visibility::Visibility,
};
use std::{path::Path, process::Stdio, time::Duration};
use tokio::process::{Child, Command as Process};
async fn ready(dir: &Path) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if service::client(dir, Command::Status, None).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}
async fn finished(child: Child) {
    let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
#[tokio::test]
async fn runtime_visibility_idle_control_and_killed_daemon_restart() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("run");
    let keys = temp.path().join("keys");
    let start = || {
        Process::new(env!("CARGO_BIN_EXE_airdropd"))
            .env_remove("DISPLAY")
            .env_remove("WAYLAND_DISPLAY")
            .env("GDK_BACKEND", "x11")
            .kill_on_drop(true)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .args([
                "--no-radio",
                "--no-bluetooth",
                "--ble-idle-timeout",
                "0.25",
                "--approval-timeout",
                "3",
                "--run-dir",
            ])
            .arg(&dir)
            .arg("--keys")
            .arg(&keys)
            .spawn()
            .unwrap()
    };
    // Startup must preserve unrelated files and links at the socket path.
    std::fs::create_dir(&dir).unwrap();
    let socket = dir.join("control.sock");
    let target = temp.path().join("unrelated");
    std::fs::write(&target, b"keep me").unwrap();
    for symlink in [false, true] {
        if symlink {
            std::os::unix::fs::symlink(&target, &socket).unwrap();
        } else {
            std::fs::write(&socket, b"keep me").unwrap();
        }
        let output = tokio::time::timeout(Duration::from_secs(5), start().wait_with_output())
            .await
            .unwrap()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("refusing to remove non-socket"));
        assert_eq!(std::fs::read(&socket).unwrap(), b"keep me");
        assert_eq!(socket.is_symlink(), symlink);
        std::fs::remove_file(&socket).unwrap();
    }
    let mut daemon = start();
    ready(&dir).await;
    assert_eq!(
        service::client(&dir, Command::Status, None).await.unwrap()["timeouts"]["ble_idle"],
        0.25
    );
    for mode in [
        Visibility::Off,
        Visibility::Everyone,
        Visibility::Contacts,
        Visibility::Off,
    ] {
        service::client(
            &dir,
            Command::Discoverable {
                mode,
                contacts_file: (mode == Visibility::Contacts).then(|| temp.path().join("contacts")),
            },
            None,
        )
        .await
        .unwrap();
        let status = service::client(&dir, Command::Status, None).await.unwrap();
        assert_eq!(status["visibility"], serde_json::to_value(mode).unwrap());
        assert!(status["session"].is_null());
        assert_eq!(status["ble"]["listening"], false);
        assert!(!keys.exists());
        assert!(!dir.join("radio.json").exists());
    }
    let waiting = tokio::spawn({
        let dir = dir.clone();
        async move { service::client(&dir, Command::Accept { id: None }, None).await }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(service::client(&dir, Command::Status, None).await.unwrap()["session"].is_null());
    daemon.kill().await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert!(dir.join("control.sock").exists());
    let daemon = start();
    ready(&dir).await;
    assert_eq!(
        service::client(&dir, Command::Status, None).await.unwrap()["visibility"],
        "off"
    );
    service::client(&dir, Command::Stop, None).await.unwrap();
    finished(daemon).await;
    assert!(!dir.join("control.sock").exists());
    assert!(!keys.exists());
}
