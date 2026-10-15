# Development

[README](../README.md) · [Usage](usage.md) · [Protocol](protocol.md)

## Build and checks

Requires Rust 1.88+, Cargo, `just`, and libpcap, OpenSSL and D-Bus development
libraries. Run from the project directory:

```sh
just build
just check
```

`build` creates `target/release/owld`, `airdropd` and `catdrop` without
installing a package. `check` runs formatting, all-target Clippy and the
automated test suite. The suite uses
synthetic frames, temporary files, loopback HTTPS and local control sockets;
it does not require a phone, Wi-Fi setup or root.

Tests focus on critical or error-prone behavior: malformed radio frames,
encapsulation/MTU bounds, clock rollover, election/channel overlap, retry
deduplication, injection backpressure, profile validation, archive bounds and
traversal, connection-bound consent, interrupted HTTP framing, large uploads and
session teardown. Two contact-policy regressions use a synthetic root and
intermediate, real CMS signatures and TLS metadata requests to test trust,
signer role, replay, expiry and consent without sending files. Contact-list tests cover normalized matching, batch rejection,
private file permissions and concurrent updates. Avoid tests that duplicate other scenarios or library behavior.
Identity tests cover concurrent first-time creation, private permissions and
preservation of existing keys. Daemon startup tests ensure stale sockets can be
replaced without removing ordinary files or symlinks at the socket path.

Builds and captures belong in ignored `build/` and `target/`. Machine-specific
helpers belong in ignored `dev/`; the justfile optionally imports
`dev/justfile.local`. Personal device information and captures stay in those
local directories.

## Local lifecycle testing

Automated tests exercise runtime visibility, optional client certificates,
contact verification and consent over loopback TLS. A simulated BLE callback
starts a no-radio shared session, overlaps incoming and outgoing work, and checks
independent cancellation and ordered cleanup. The daemon
regression uses local control sockets to verify idle toggles, waiting acceptance
and restart after SIGKILL. None of these checks requires a phone or Bluetooth
adapter. BLE parser cases reject truncated, ambiguous and unrelated manufacturer
data; the session regression checks current Contacts/Everyone admission. A paused-clock test covers repeated
BLE wake resets, active-user protection and refresh during completion grace. CLI
checks cover fractional values and explicit override inheritance. Real BLE scanning is disabled for `--no-radio` sessions.

```sh
cargo test --workspace --locked --lib
cargo test --workspace --locked --test session_lifecycle
```

`airdropd --no-radio --no-bluetooth` exercises idle control commands. Tests create
direct loopback HTTPS receivers through the library API.

The UDP regression checks source address, interface and hop-limit metadata as
a normal user. Link regressions cover peer credentials, generation validation,
publication readiness, heartbeats, bounded framing and disconnect cleanup.
The daemon lifecycle test belongs to the AirDrop crate and uses Cargo's binary
path, so it runs without a previous build of the CLI.

## AWDL diagnostics

`owld awdl` shares the radio daemon's Tokio runtime and logging. Choose exactly one input:
`--read PCAP` for offline radiotap replay, or `--interface IFACE` for an already
prepared monitor. Diagnostics do not convert managed interfaces or apply profiles;
managed setup and recovery belong to `owld`.

```sh
just replay /path/to/full-radiotap.pcap
just listen owlmon0 30
sudo target/release/owld awdl --interface owlmon0 --channel 6 \
  --fixed-radio --metric-first --strategy pin --verbose
```

`--listen-only` observes the existing channel without retuning, TAP creation or
transmission. Active diagnostics can tune and inject; use an interface prepared
for that purpose. `--fixed-radio` holds the physical channel and relaxes multicast gates.
`--tx-ack profile|normal|noack` controls hardware ACK waiting independently.
`--metric-first` ranks metric before counter.
`--strategy verbatim|rotate|pin|widen|intersect` controls the advertised schedule.
Other options include `--rate`, `--mac`, `--no-rssi-filter`, `--duration`,
`--save`, `--save-invalid PCAP` and `--summary`. Use `awdl --help` for details.

`--verbose` is global and repeatable; `RUST_LOG` overrides its logging level.

## ACK timing diagnostics

For receive-performance investigations, start `owld` with
`RUST_LOG=owl=info,owl::tx=debug` and save its stderr alongside the radio capture.
Use the existing `--save` prefix to preserve each radio session, and capture the
TAP concurrently with `tcpdump -i awdl0 -p -n -s 0 -U -w tcp.pcap ip6 and tcp`.
Start the TAP capture as soon as the interface appears, before the transfer.
Keep local captures and test helpers under ignored `build/` and `dev/`.

Each `AWDL TCP ACK injection` record identifies a payload-free TCP ACK by a
session-local `ack_id`, peer, ports, sequence/acknowledgment, raw receive window
and optional TCP timestamp. An `options_crc` fingerprints the complete TCP
options, including SACK blocks, for matching against TAP packets. SYN, FIN, RST
and packets with payload are excluded. Aggregation and retries preserve the ACK
ID; `injection_id` identifies each backend call independently. Outcomes are
`accepted`, `backpressure`, `too_large` and `failed`; a rejected attempt is not counted as
an injected ACK. `AWDL TCP ACK dropped` records explicit queue drops.

`queued_us` is when the radio runtime reads the packet from TAP.
`injection_started_us` and `injection_finished_us` bracket the libpcap call.
`queue_wait_us` ends at the start of that call, and `injection_us` measures its
duration. These timestamps use the runtime's monotonic microsecond clock;
`AWDL runtime clock` supplies `clock_epoch_us` to approximately align them with
PCAP wall-clock timestamps. System-clock adjustments can affect that alignment.
Compare TAP timestamps with `queued_us` to detect delays before the TX queue.

`schedule_blocked` and `airtime_blocked` indicate that the ACK was deferred
directly or behind an earlier frame for that peer. `backpressured` records an
injection retry. These flags identify encountered causes, not durations spent
in each cause. Rate, channel, slot and aggregate member count describe the
attempt; `coding` records the selected injection FEC. An accepted call means
backend submission, not on-air transmission or receipt of the Wi-Fi hardware
ACK; the receive PCAP cannot prove TX delivery.

`status.awdl.stats.tx_ack` exposes bounded summary counters without detailed
logging. Queue wait totals/maxima cover successfully injected ACK packets;
injection totals/maxima and attempt counts cover backend calls containing ACKs,
including failed attempts, once per aggregate. Cause counts cover completed
or explicitly dropped ACK packets once each. Summaries are also logged every
ten seconds and at shutdown; the final queue record counts pending packets and
ACKs left when the session ends.

For a comparison, use the same file, discovery/transmission channels and phone
position. First measure automatic rate selection; a later separate run can
override `--rate` to investigate the return ACK path. Record upload throughput,
incoming PHY rates/retry flags, peer availability, ACK queue wait and TCP
sequence holes. Detailed logging adds overhead, so enable it consistently in
both comparison runs.

## Implementation and validation

Project code forbids `unsafe` and delegates native interaction to library
wrappers. Tokio owns networking and task lifetimes; clap parses arguments.
`wl-nl80211` and `rtnetlink` perform bounded radio/link requests, await kernel
acknowledgments and close their connection tasks during cleanup. `ip` and `iw`
executables are not required. NetworkManager ownership and saved-AP restoration
still use `nmcli`.

`pcap` and `tun-rs` handle capture and TAP I/O; `etherparse` and `hickory-proto`
handle radio packets and DNS; `socket2`/`nix` provide IPv6 UDP metadata without
raw sockets in the user process. `bluer` owns BlueZ LE scanning and advertising. AirDrop uses `hyper`,
`tokio-openssl`, `openssl` and `plist`; archives and previews use `cpio-archive`,
`flate2`, `tempfile` and `image`. `cms` and `x509-cert` inspect signed identity
records and certificate-role markers without unsafe code. The [source map](protocol.md#source-map) links
each subsystem to its implementation.

Hardware setup checks have covered active-monitor creation, 80/40/20 MHz tuning
on channels 149 and 44, return to channel 6 at 20 MHz, and TAP
MTU/link-local readiness, permanent neighbor add/replace/delete, normal cleanup,
startup-error rollback, passive observation, SIGKILL recovery and stale-socket
restart. These checks restored managed Wi-Fi and preserved Ethernet configuration.
The split also verified root owld with a user TCP/UDP listener on the AWDL
TAP, mDNS multicast membership and UDP submission, normal release and disconnect
cleanup. Those checks restored managed Wi-Fi and preserved Ethernet settings.
They are separate from transfer validation; see
[observed interoperability](protocol.md#observed-interoperability-and-remaining-scope)
for live transfer evidence, timings and remaining limits. The optional
[radio service](../examples/owld.service) runs as root, while the
[AirDrop user service](../examples/airdropd.service) runs in the user manager.
The [workspace architecture](architecture.md) documents their IPC boundary.

## Origins

This project ports the patched OWL backend from `omdrop-owl`, based on
`jedbillyb/owl` commit `832d70f815c3d4a06a02117bf0fc5e868daa1ff0`. The original
Open Wireless Link / Milan Stute attribution and GPL-3.0-or-later license are
retained; see [COPYING](../COPYING).

The port includes TX-rate selection, MAC override, fixed radio, metric-first
election and fixed-channel pinning. Unicast ACK policy follows the driver
profile; Intel and MT76x2U use NOACK workarounds. It also adapts
[omdrop-owl PR #11](https://github.com/t4t5/omdrop-owl/pull/11) for nonblocking
injection backpressure, data-refreshed peer liveness and DAD-free TAP setup, and
[omdrop-plugin PR #41](https://github.com/brentkearney/omdrop-plugin/pull/41)
for fully validated archive completion when HTTP termination is missing.
The Apple public root certificate in `assets/` verifies optional identity records.

Contacts Only reception follows omdrop-plugin's policy at commit
`b2f9a537b150c26402c5daad8125fb7e61c214ec`, with dedicated certificate-role
checks from Apple's published Security policies. Public Apple Application
Integration CA certificates are vendored from that reference; see
[their provenance and license](../assets/apple-ca/README.md).

`owld --save PATH` uses PATH as a capture prefix. Each radio lease writes
`PATH.<session-id>.pcap`, preserving earlier captures when BLE starts another
session. The `owld awdl --save PATH` diagnostic command still writes the exact
path supplied. Captures belong in ignored local directories.
