# Using catdrop and the daemons

[README](../README.md) · [Radio configuration](radio.md) · [Development](development.md)

## Transfers

Start `just owld` in a dedicated terminal first. This is the privileged radio
service; it stays idle until a user session acquires the link. All following
AirDrop commands run as your regular user. Start the user daemon in another
terminal before sending or receiving:

```sh
just daemon --name 'Example Computer'
```

Keep the phone unlocked with AirDrop set to Everyone for 10 Minutes. To send:

```sh
just send 'Example Phone' /path/to/photo.png
just send 'Example Phone' /path/to/folder /path/to/another-file
just send 'Example Phone' --url https://example.com
```

Files and recursive folders are supported; symlinks and special files are refused.
Received links are saved as inert `.url` files and never opened automatically.
Incoming files stream into a private temporary directory inside the destination;
the completed directory is renamed to `airdrop-TRANSFER_ID`. Failed or cancelled
uploads discard their temporary files; partial transfers are never published.

To receive, keep both daemons running. In another terminal, enable receiving
and accept the next incoming offer:

```sh
just discoverable everyone
just accept
```

On the phone, open Share → AirDrop and select the receiver when it appears.
The daemon listens for AirDrop BLE advertisements and automatically starts the
shared session. `accept` without an ID waits for the oldest pending offer and
returns after approving it. Ctrl+C cancels the wait without cancelling the
shared session. For a specific offer:

```sh
just transfers
just accept TRANSFER_ID
just reject TRANSFER_ID
```

Run `airdropd --auto-accept` to approve offers automatically after the receiving
policy passes. There is no separate `receive` command or receive visibility flag.

## Runtime discoverability

```sh
just discoverable everyone
just discoverable contacts
just discoverable off
```

| Mode | Receiving behavior |
| --- | --- |
| `everyone` | Listen for AirDrop BLE wake requests and allow incoming offers. |
| `contacts` | Wake on matching BLE hash prefixes; require signed, certificate-bound contact identity before approval. |
| `off` | Stop receive-side BLE scanning/advertising, withdraw mDNS and AWDL service announcements, refuse discovery and new offers. |

The setting applies immediately to active services and later sessions in the
same daemon. It resets to `off` when the daemon restarts. Changing modes does
not restart the daemon or retune Wi-Fi. An idle toggle only configures the BLE
listener; Wi-Fi and HTTPS start on a wake request or an outgoing `send`.
Already approved uploads retain their consent when switched off; pending offers
are rejected when their policy changes. `off` leaves outgoing sends available.

`status` reports `visibility`, `ble.listening`, the active session phase and
outgoing operation IDs. `--no-bluetooth` disables automatic receiving; `--no-radio` also
disables real BLE scanning for local tests. A Bluetooth adapter supporting LE
scanning is required for automatic receiving; failed listeners retry with a
warning. Scanner activation and advertisement withdrawal are asynchronous.

## Contacts Only receiving

Manage allowed Apple ID email addresses and international phone numbers locally:

```sh
just contact add friend@example.com '+1 (555) 010-1234'
just contact list
just contact remove friend@example.com '+1-555-010-1234'
```

`add` and `remove` accept multiple identifiers. Emails are trimmed and
lowercased; phone numbers are compared using ASCII digits only. Include the
country code: no region or dialing prefix is inferred. Equivalent spellings
are treated as one contact; removing an identifier removes every matching line.
An invalid argument rejects the entire batch before any list change.
`list --json` prints a JSON array; a missing or empty list prints no entries.

The default file is `~/.config/owl_rs/known-senders`, also used by the receiver.
Use `contact --contacts-file /path/to/known-senders add|list|remove` for a custom
list, and select it with
`discoverable contacts --contacts-file /path/to/known-senders`. The
default belongs to the current user. Run contact commands without sudo.
These commands do not start the daemon or touch Wi-Fi.

You can also edit the file with one identifier per line. Blank lines and lines
beginning with `#` are ignored. Updates preserve comments and unrelated entries,
use a lock to serialize concurrent commands, and replace the file atomically
with mode 0600. Keep this plaintext list private; identifiers and hashes are
never logged (`contact list` displays identifiers explicitly).

```sh
just discoverable contacts
just discoverable contacts --contacts-file /path/to/known-senders
```

The selected file is reused on subsequent contacts-mode toggles until the daemon
restarts. An invalid list rejects the toggle and retains the previous mode.

Only a sender with an Apple-signed validation record, a matching Apple-issued
sharing certificate on the TLS connection, and a listed identifier can propose
a transfer. This works with the receiver's default self-signed identity; no
local Apple-issued identity is needed. Missing/empty lists refuse all offers.
Unreadable or invalid lists fail closed. List changes apply to the next offer,
including on an existing connection; an already approved upload keeps its
connection-bound authorization.

`airdropd --auto-accept` skips manual approval only after these checks pass.
Discovery hiding is best-effort: a verifiable non-contact is not given receiver
metadata, but a device without a verifiable record can still see the receiver.
It cannot transfer without passing the separate certificate-bound offer check.
See [the protocol policy](protocol.md#contacts-only-receiving) for details.

Contacts Only sending is not implemented; set the target device to Everyone.
The runtime setting filters incoming offers during a send session without
enabling contact authentication by the sender.

## Sessions and the daemon

`send` uses a running daemon or starts a temporary control service. The idle
daemon exposes its control socket and scans BLE when receiving is enabled;
Wi-Fi and HTTPS remain inactive. BLE wake-up and CLI sends activate or reuse
one bidirectional session.

`owld` owns capture, scheduling, TAP addressing and WLAN restoration. The
user-owned `airdropd` owns HTTPS, UDP mDNS, identities, contact policy and BLE.
It acquires a connection-owned link lease through authenticated Unix IPC.
Sending and receiving share these resources.
Each send, peer browse and active incoming request holds the session alive.
Idle discovery connections do not delay cleanup.
Canceling a CLI send releases only that operation; `cancel SESSION_ID` stops
all work in the session. Visibility controls incoming offers, independently of
outgoing sends.

A BLE-activated session waits up to `--ble-idle-timeout` idle seconds (120 by
default) for a transfer. Every eligible live AirDrop BLE wake resets this deadline.
In `everyone`, any valid AirDrop wake qualifies; in `contacts`, only a current
known-sender hash-prefix match qualifies. Unmatched and Off-mode wakes neither
activate Wi-Fi nor extend an existing session. Once work
completes successfully, the session waits until every user has finished its
reply/TCP drain, then retains the radio for `--completion-grace` seconds (5 by
default). New transfers can join during that grace period; an eligible BLE wake
starts a fresh idle wait, including during completion grace.
The transport stops and sends discovery goodbyes before the link drains queued
frames, removes its interfaces and restores WLAN settings. A temporary control
service waits for cleanup and exits; an independent daemon returns to idle.

Omitted send flags inherit the active session's settings, or daemon defaults
when idle. Explicit settings must match an existing session; cancel that session
before changing its identity or transport configuration. Radio settings are
configured separately when starting `owld`. `send --duration SECONDS` limits that operation, while `airdropd --duration SECONDS` limits the
control service's lifetime.

```sh
just status
just peers
target/release/catdrop cancel SESSION_ID
just stop
```

`status` reports the session ID, radio state and transfer progress. `peers`
browses AirDrop services and resolves names over HTTPS during any active session. It does not activate an idle radio. `cancel` ends the
specified session; `stop` ends both the session and the daemon. Ctrl+C on a
CLI send cancels that operation; other transfers can keep the shared session active.

## Timeouts

Timeouts are command-line options; no timeout configuration file is used.
Set daemon defaults at startup, or override them when `send` starts a session.
Configure radio timeouts on `owld`; they also apply to its `probe`, `recover`
and `awdl` subcommands. AirDrop and link-client timeouts belong to `airdropd`
with per-session overrides from `catdrop send`. An existing active
session retains its settings: explicit conflicting overrides are rejected.
Control-only commands use the running daemon's settings; they cannot change
these flags. `status.timeouts` shows effective user-session values in seconds;
active `status.awdl.timeouts` reports radio service deadlines.

```sh
just daemon --ble-idle-timeout 180 --completion-grace 5 \
    --approval-timeout 90 --upload-idle-timeout 30 --upload-timeout 1800
```

The new flags accept fractional seconds, such as `--ble-idle-timeout 0.5`.
Values must be positive and at most 86400 seconds; `--completion-grace 0` disables
only that grace period. The radio quiet period must not exceed its drain timeout.
`--timeout` separately sets send discovery (default 60 s) or `peers` waiting
(default 10 s); `--duration` bounds a daemon or outgoing operation to
1–86400 whole seconds. These two
existing options take integer seconds. AWDL slot timing and advertised DNS TTLs
are protocol parameters, rather than application timeout options.

| Flag | Default (s) | Applies to |
| --- | ---: | --- |
| `--completion-grace` | 5 | Quiet grace after successful work and TCP drain. |
| `--retry-cache-timeout` | 0.5 | 802.11 retry duplicate-cache lifetime. |
| `--capture-read-timeout` | 0.001 | Packet capture read timeout (minimum resolution: one millisecond). |
| `--peer-idle-timeout` | 5 | AWDL neighbor inactivity deadline. |
| `--queued-packet-timeout` | 2 | Queued AWDL packet and early SYN expiry; quiet tail before returning to discovery. |
| `--link-startup-timeout` | 120 | User-side wait for owld link readiness. |
| `--channel-ready-timeout` | 15 | Sender wait for owld to commit the transfer channel before upload. |
| `--link-shutdown-timeout` | 180 | User-side wait for owld restoration. |
| `--discovery-cache-timeout` | 120 | Local mDNS cache lifetime cap. |
| `--discovery-fallback-timeout` | 2 | Transient AWDL fallback discovery candidate lifetime. |
| `--ble-idle-timeout` | 120 | Idle session lifetime after an eligible BLE wake. |
| `--tcp-connect-timeout` | 15 | Outgoing TCP connection deadline. |
| `--tls-handshake-timeout` | 10 | Incoming TLS handshake deadline. |
| `--tls-connect-timeout` | 15 | Outgoing TLS handshake deadline. |
| `--http-header-timeout` | 20 | Incoming HTTP header deadline. |
| `--http-request-timeout` | 15 | Outgoing Discover response deadline. |
| `--metadata-timeout` | 20 | Plist/response body stall deadline. |
| `--approval-timeout` | 60 | Incoming manual approval and outgoing Ask deadline. |
| `--upload-idle-timeout` | 20 | Incoming upload stall deadline. |
| `--upload-timeout` | 600 | Incoming and outgoing upload deadline. |
| `--connection-drain-timeout` | 5 | Successful HTTP/TLS close deadline. |
| `--rejection-drain-timeout` | 2 | Refusal response close deadline. |
| `--tcp-linger-timeout` | 10 | Successful final TCP acknowledgment drain bound. |
| `--control-request-timeout` | 10 | User control request deadline; on owld, link request/heartbeat deadline. |
| `--control-archive-timeout` | 600 | Control socket archive receive deadline. |
| `--transport-shutdown-timeout` | 2 | Transport task shutdown deadline. |
| `--name-probe-timeout` | 8 | Per-peer HTTPS name resolution deadline. |
| `--netlink-timeout` | 5 | Kernel netlink request deadline. |
| `--network-manager-timeout` | 15 | NetworkManager setup and restoration command deadline. |
| `--reconnect-timeout` | 10 | NetworkManager saved-AP reconnection wait. |
| `--ibss-ready-timeout` | 10 | Ad-hoc cell readiness deadline. |
| `--ibss-tune-timeout` | 15 | Ad-hoc channel retuning deadline. |
| `--radio-startup-timeout` | 15 | AWDL runtime startup deadline. |
| `--address-ready-timeout` | 5 | AWDL IPv6 address readiness deadline. |
| `--radio-drain-timeout` | 2 | AWDL transmit queue shutdown deadline. |
| `--radio-quiet-period` | 0.1 | Quiet period before ending AWDL queue drain. |
| `--ble-retry-interval` | 30 | BLE scan/advertisement retry interval. |
| `--ble-power-restore-timeout` | 5 | BLE adapter power restoration deadline. |

Radio flags (`retry-cache`, `capture-read`, `peer-idle`, `queued-packet`,
`netlink`, `network-manager`, `reconnect`, `ibss-ready`, `ibss-tune`,
`radio-startup`, `address-ready`, `radio-drain`, `radio-quiet`) are accepted only
by `owld`. The other timeout flags are accepted by `airdropd`/`catdrop send`;
`control-request-timeout` configures the corresponding IPC endpoint in each.

## Paths and ownership

| Data | Default | Override |
| --- | --- | --- |
| Identity | `~/.local/share/owl_rs/identity` | `--keys DIR` |
| Received transfers | `~/Downloads/AirDrop/airdrop-TRANSFER_ID/` | `--output DIR` |
| User control socket | `$XDG_RUNTIME_DIR/owl_rs/control.sock` | `--run-dir DIR` |
| Radio socket and recovery journal | `/run/owld/` | `owld --run-dir DIR` |
| Radio socket used by AirDrop | `/run/owld/control.sock` | `airdropd`/`send --owl-socket PATH` |

Run `airdropd` and `catdrop` as the account that owns identities, contacts and
received files. The user daemon rejects root execution. `owld --user USER`
authorizes that account; under sudo it defaults to the invoking user.
The user control socket accepts its owner or root; the radio socket accepts only
the configured UID, and the AirDrop client verifies that owld runs as root.
The root service never receives identity/contact/output/source file paths.
If XDG_RUNTIME_DIR is unset, the user control directory defaults to
`/run/user/UID/owl_rs`.

Every command addressing a custom control directory needs the same `--run-dir`:

```sh
just daemon --run-dir "$XDG_RUNTIME_DIR/owl_rs-example"
just discoverable everyone --run-dir "$XDG_RUNTIME_DIR/owl_rs-example"
just status --run-dir "$XDG_RUNTIME_DIR/owl_rs-example"
just stop --run-dir "$XDG_RUNTIME_DIR/owl_rs-example"
```

A stale socket left by a killed daemon is replaced under the daemon lock when
`airdropd` restarts. Interrupted radio state can require
[journal recovery](radio.md#recovery).

## Other options

Use `target/release/catdrop --help`, `airdropd --help` and `owld --help`
for their respective command-line options.

- `--max-bytes N` limits transfer size.
- `--no-bluetooth` disables BLE scanning and wake-up advertising; `--bluetooth-adapter hci0`
  selects an adapter.
- `--direct '[fe80::200:ff:fe00:1%3]:8770'` bypasses receiver-name discovery;
  substitute the receiver's address, interface scope and port.
- `--interface`, `--profiles`, `--backend`, `--channel` and `--discovery-channel`
  belong to `owld` and are covered in [Radio configuration](radio.md).

The identity directory contains a generated RSA private key and self-signed
certificate (`key.pem` and `cert.pem`). An optional `validation_record.cms` must
verify against Apple's root and match the certificate's account CN. Obtaining
that record is outside this CLI. It can identify the receiver, but outgoing
sends do not publish it. See
[TLS and HTTP](protocol.md#tls-and-http) for identity and authorization details,
and [DVZip and CPIO](protocol.md#dvzip-and-cpio) for archive validation.
