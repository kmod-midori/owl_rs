# Development

[README](../README.md) · [Usage](usage.md) · [Protocol](protocol.md)

## Build and checks

Requires Rust 1.88+, Cargo, `just`, and libpcap, OpenSSL and D-Bus development
libraries. Run from the project directory:

```sh
just build
just check
```

`build` creates `target/release/owl_rs` without installing a package. `check`
runs formatting, all-target Clippy and the automated test suite. The suite uses
synthetic frames, temporary files, loopback HTTPS and local control sockets;
it does not require a phone, Wi-Fi setup or root.

Tests focus on critical or error-prone behavior: malformed radio frames,
encapsulation/MTU bounds, clock rollover, election/channel overlap, retry
deduplication, injection backpressure, profile validation, archive bounds and
traversal, connection-bound consent, interrupted HTTP framing, large uploads and
session teardown. Avoid tests that duplicate other scenarios or library behavior.

Builds and captures belong in ignored `build/` and `target/`. Machine-specific
helpers belong in ignored `dev/`; the justfile optionally imports
`dev/justfile.local`. Personal device information and captures stay in those
local directories.

## Local HTTPS testing

Loopback sessions require neither radio nor root. `--no-radio` accepts only an
IPv6 loopback listener; with radio setup, `--listen` supplies the HTTPS port.

```sh
cargo run --locked -- receive --no-radio --no-bluetooth \
  --run-dir build/local/run --keys build/local/identity \
  --output build/local/received --listen '[::1]:18771' --auto-accept
```

In another terminal, start a sender with its own control directory:

```sh
cargo run --locked -- send local /path/to/file \
  --run-dir build/local-send/run --no-radio --no-bluetooth \
  --keys build/local-send/identity --listen '[::1]:18772' \
  --direct '[::1]:18771'
```

## AWDL diagnostics

`awdl` shares the main CLI's Tokio runtime and logging. Choose exactly one input:
`--read PCAP` for offline radiotap replay, or `--interface IFACE` for an already
prepared monitor. Diagnostics do not convert managed interfaces or apply profiles;
managed setup and recovery belong to `send`/`receive`.

```sh
just replay /path/to/full-radiotap.pcap
just listen owlmon0 30
sudo target/release/owl_rs awdl --interface owlmon0 --channel 6 \
  --fixed-radio --metric-first --strategy pin --verbose
```

`--listen-only` observes the existing channel without retuning, TAP creation or
transmission. Active diagnostics can tune and inject; use an interface prepared
for that purpose. `--fixed-radio` holds the physical channel, relaxes multicast
gates and disables unicast retries. `--metric-first` ranks metric before counter.
`--strategy verbatim|rotate|pin|widen|intersect` controls the advertised schedule.
Other options include `--rate`, `--mac`, `--no-rssi-filter`, `--duration`,
`--save`, `--save-invalid PCAP` and `--summary`. Use `awdl --help` for details.

`--verbose` is global and repeatable; `RUST_LOG` overrides its logging level.

## Implementation and validation

Project code forbids `unsafe` and delegates native interaction to library
wrappers. Tokio owns networking and task lifetimes; clap parses arguments.
`wl-nl80211` and `rtnetlink` perform bounded radio/link requests, await kernel
acknowledgments and close their connection tasks during cleanup. `ip` and `iw`
executables are not required. NetworkManager ownership and saved-AP restoration
still use `nmcli`.

`pcap` and `tun-rs` handle capture and TAP I/O; `etherparse` and `hickory-proto`
handle packets and DNS; `bluer` owns BlueZ advertising. AirDrop uses `hyper`,
`tokio-openssl`, `openssl` and `plist`; archives and previews use `cpio-archive`,
`flate2`, `tempfile` and `image`. The [source map](protocol.md#source-map) links
each subsystem to its implementation.

Hardware setup checks have covered active-monitor creation and tuning, TAP
MTU/link-local readiness, permanent neighbor add/replace/delete, normal cleanup,
startup-error rollback, passive observation, SIGKILL recovery and stale-socket
restart. These checks restored managed Wi-Fi and preserved Ethernet configuration.
They are separate from transfer validation; see
[observed interoperability](protocol.md#observed-interoperability-and-remaining-scope)
for live transfer evidence, timings and remaining limits. The optional
[systemd unit](../examples/owl_rs.service) runs the idle foreground daemon.

## Origins

This project ports the patched OWL backend from `omdrop-owl`, based on
`jedbillyb/owl` commit `832d70f815c3d4a06a02117bf0fc5e868daa1ff0`. The original
Open Wireless Link / Milan Stute attribution and GPL-3.0-or-later license are
retained; see [COPYING](../COPYING).

The port includes TX-rate selection, MAC override, fixed radio, metric-first
election, fixed-radio unicast NOACK and fixed-channel pinning. It also adapts
[omdrop-owl PR #11](https://github.com/t4t5/omdrop-owl/pull/11) for nonblocking
injection backpressure, data-refreshed peer liveness and DAD-free TAP setup, and
[omdrop-plugin PR #41](https://github.com/brentkearney/omdrop-plugin/pull/41)
for fully validated archive completion when HTTP termination is missing.
The Apple public root certificate in `assets/` verifies optional identity records.
