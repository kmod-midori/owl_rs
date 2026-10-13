set positional-arguments

[private]
default:
    @just --list

build:
    cargo build --release --locked

check:
    cargo fmt --check
    cargo clippy --all-targets --locked -- -D warnings
    cargo test --locked

probe *ARGS:
    cargo run --locked -- probe "$@"

# Foreground daemon: receiving starts on BLE after discoverable is enabled.
daemon *ARGS: build
    sudo target/release/owl_rs daemon "$@"

discoverable MODE *ARGS:
    target/release/owl_rs discoverable "$@"

send TO *FILES: build
    sudo target/release/owl_rs send "$@"

# Local contact management needs neither root nor an active daemon.
contact *ARGS: build
    target/release/owl_rs contact "$@"

peers *ARGS:
    target/release/owl_rs peers "$@"

status *ARGS:
    target/release/owl_rs status "$@"

transfers *ARGS:
    target/release/owl_rs transfers "$@"

accept *ARGS:
    target/release/owl_rs accept "$@"

reject ID *ARGS:
    target/release/owl_rs reject "$@"

stop *ARGS:
    target/release/owl_rs stop "$@"

recover *ARGS: build
    sudo target/release/owl_rs recover "$@"

replay CAPTURE:
    cargo run --locked -- awdl --read {{quote(CAPTURE)}} --no-rssi-filter --fixed-radio --metric-first

# Low-level observation on an already prepared monitor interface.
listen IFACE="owlmon0" SECONDS="30": build
    sudo target/release/owl_rs awdl --interface {{quote(IFACE)}} --no-rssi-filter --fixed-radio --metric-first --listen-only --duration {{quote(SECONDS)}}

# Optional machine-specific commands belong in ignored dev/.
import? 'dev/justfile.local'
