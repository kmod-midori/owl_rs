set positional-arguments

[private]
default:
    @just --list

build:
    cargo build --workspace --release --locked

check:
    cargo fmt --all --check
    cargo clippy --workspace --all-targets --locked -- -D warnings
    cargo test --workspace --locked

probe *ARGS:
    cargo run --locked -p owl --bin owld -- probe "$@"

# Privileged radio service: WLAN stays inactive until a user obtains a lease.
owld *ARGS: build
    sudo target/release/owld "$@"

# AirDrop runs as the current user and connects to owld as needed.
daemon *ARGS: build
    target/release/airdropd "$@"

discoverable MODE *ARGS:
    target/release/catdrop discoverable "$@"

send TO *FILES: build
    target/release/catdrop send "$@"

contact *ARGS: build
    target/release/catdrop contact "$@"

peers *ARGS:
    target/release/catdrop peers "$@"

status *ARGS:
    target/release/catdrop status "$@"

transfers *ARGS:
    target/release/catdrop transfers "$@"

accept *ARGS:
    target/release/catdrop accept "$@"

reject ID *ARGS:
    target/release/catdrop reject "$@"

stop *ARGS:
    target/release/catdrop stop "$@"

recover *ARGS: build
    sudo target/release/owld "$@" recover

replay CAPTURE:
    cargo run --locked -p owl --bin owld -- awdl --read {{quote(CAPTURE)}} --no-rssi-filter --fixed-radio --metric-first

listen IFACE="owlmon0" SECONDS="30": build
    sudo target/release/owld awdl --interface {{quote(IFACE)}} --no-rssi-filter --fixed-radio --metric-first --listen-only --duration {{quote(SECONDS)}}

import? 'dev/justfile.local'
