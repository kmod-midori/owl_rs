// SPDX-License-Identifier: GPL-3.0-or-later
use owl_rs::service::{self, Command};
use std::{path::Path, time::Duration};
use tokio::process::{Child, Command as Process};
fn cli() -> Process {
    let mut command = Process::new(env!("CARGO_BIN_EXE_owl_rs"));
    command
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    command
}
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
async fn finished(child: Child, success: bool) {
    let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
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
#[tokio::test]
async fn runtime_visibility_idle_control_and_killed_daemon_restart() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("run");
    let keys = temp.path().join("keys");
    let start = || {
        cli()
            .args([
                "daemon",
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
    let mut daemon = start();
    ready(&dir).await;
    assert_eq!(
        service::client(&dir, Command::Status, None).await.unwrap()["timeouts"]["ble_idle"],
        0.25
    );
    for mode in ["off", "everyone", "contacts", "off"] {
        let mut command = cli();
        command.args(["discoverable", mode, "--run-dir"]).arg(&dir);
        if mode == "contacts" {
            command
                .arg("--contacts-file")
                .arg(temp.path().join("contacts"));
        }
        let output = command.output().await.unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let status = service::client(&dir, Command::Status, None).await.unwrap();
        assert_eq!(status["visibility"], mode);
        assert!(status["session"].is_null());
        assert_eq!(status["ble"]["listening"], false);
        assert!(!keys.exists());
        assert!(!dir.join("radio.json").exists());
    }
    let waiting = cli()
        .args(["accept", "--run-dir"])
        .arg(&dir)
        .spawn()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(service::client(&dir, Command::Status, None).await.unwrap()["session"].is_null());
    daemon.kill().await.unwrap();
    finished(waiting, false).await;
    assert!(dir.join("control.sock").exists());
    let daemon = start();
    ready(&dir).await;
    assert_eq!(
        service::client(&dir, Command::Status, None).await.unwrap()["visibility"],
        "off"
    );
    service::client(&dir, Command::Stop, None).await.unwrap();
    finished(daemon, true).await;
    assert!(!dir.join("control.sock").exists());
    assert!(!keys.exists());
}
