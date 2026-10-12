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

# Idle foreground control service. send/receive activate session services.
daemon *ARGS: build
    sudo target/release/owl_rs daemon "$@"

receive *ARGS: build
    sudo target/release/owl_rs receive "$@"

send TO *FILES: build
    sudo target/release/owl_rs send "$@"

peers *ARGS:
    target/release/owl_rs peers "$@"

status *ARGS:
    target/release/owl_rs status "$@"

transfers *ARGS:
    target/release/owl_rs transfers "$@"

accept ID *ARGS:
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
