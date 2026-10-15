// SPDX-License-Identifier: GPL-3.0-or-later
use std::{os::unix::net::UnixListener, process::Command};

#[test]
fn sending_without_a_daemon_never_creates_identity_or_service_state() {
    let temp = tempfile::tempdir().unwrap();
    let run = temp.path().join("run");
    let keys = temp.path().join("keys");
    for stale_socket in [false, true] {
        if stale_socket {
            std::fs::create_dir(&run).unwrap();
            drop(UnixListener::bind(run.join("control.sock")).unwrap());
        }
        let output = Command::new(env!("CARGO_BIN_EXE_catdrop"))
            .args([
                "send",
                "fixture",
                "--url",
                "https://example.com",
                "--no-radio",
                "--no-bluetooth",
                "--direct",
                "[::1]:9",
                "--duration",
                "1",
                "--run-dir",
            ])
            .arg(&run)
            .arg("--keys")
            .arg(&keys)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("start `just daemon` first"));
        assert!(!keys.exists());
        assert!(!run.join("daemon.lock").exists());
        assert_eq!(run.exists(), stale_socket);
        assert_eq!(run.join("control.sock").exists(), stale_socket);
    }
}
