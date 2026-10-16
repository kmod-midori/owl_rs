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

Both tray backends enable desktop notifications through a separate D-Bus client.
The desktop notification service displays them and delivers action clicks;
notifications work independently of the tray host. See [Build](../README.md#build)
for backend selection.

Notifications offer **Accept** and **Decline**, then show transfer progress and
**Cancel**. These use the same approval state as the CLI: acting in either place
resolves the offer once.
Dismissing a notification does not accept, decline or cancel a transfer.
`--auto-accept` skips approval, and CLI commands work when desktop notifications
are unavailable.

Progress notifications update in place. Sending counts compressed archive bytes
passed to HTTP and waits for the receiver's response before reporting completion.
Receiving shows wire bytes and, when HTTP supplies a length, a percentage. Offered
file sizes describe decoded data and are not used as a compressed-stream total.
Desktops that support the `value` hint can show a progress bar; others show text.

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

Contact commands use the daemon’s selected receiving list, initially
`~/.config/owl_rs/known-senders`. Use
`contact --contacts-file /path/to/known-senders add|list|remove` to edit another
list, and select it for receiving with
`discoverable contacts --contacts-file /path/to/known-senders`.
Contact commands require a running user daemon; use `--run-dir DIR` for a
custom instance. Run them without sudo.
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
metadata, but a device without a verifiable record can see the receiver.
It cannot transfer without passing the separate certificate-bound offer check.
See [the protocol policy](protocol.md#contacts-only-receiving) for details.

Contacts Only sending is not implemented; set the target device to Everyone.
The runtime setting filters incoming offers during a send session without
enabling contact authentication by the sender.

## Sessions and the daemon

BLE wakes and CLI sends activate or reuse one bidirectional session. When idle,
the user daemon serves control commands and scans BLE if receiving is enabled;
Wi-Fi and HTTPS are inactive. Active sends, browsing and incoming requests hold
the session alive; idle discovery connections do not.

Eligible BLE wakes reset `--ble-idle-timeout` (default 120 seconds), including
during completion grace. Everyone accepts valid AirDrop wakes; Contacts requires
a current known-sender hash-prefix match. Unmatched and Off-mode wakes do not
activate or extend a session. After successful work and all reply/TCP drains,
`--completion-grace` holds the link for five seconds by default so new work can
join. Teardown sends discovery goodbyes, drains the radio, restores WLAN and
returns the daemon to idle; see [Architecture](architecture.md#networking-and-cleanup).

Send settings inherit the active session or daemon defaults. Conflicting overrides
require ending the active session first; radio settings belong to `owld`.
`send --duration SECONDS` limits that operation; `airdropd --duration SECONDS`
limits the daemon's lifetime.

```sh
just status
just peers
target/release/catdrop cancel SESSION_ID
target/release/catdrop cancel TRANSFER_ID
just stop
```

| Command | Behavior |
| --- | --- |
| `status` | Session ID, radio state and progress; incoming IDs in `transfers[].offer.id`, outgoing details in `status.outgoing`, active outgoing IDs in `status.sending`. |
| `peers` | Browse and resolve AirDrop services during an active session; does not wake an idle radio. |
| `cancel SESSION_ID` | Stop all session work. |
| `cancel TRANSFER_ID` | Cancel one transfer; other sends/receives continue. Ctrl+C on a CLI send has the same scope. |
| `stop` | End the session and daemon. |

## Timeouts

Configure radio deadlines on `owld` (also used by `probe`, `recover` and `awdl`),
and user/link-client deadlines on `airdropd`. `catdrop send` can override user
settings when starting a session; conflicts with an active session are rejected.
Control commands cannot change deadlines. Effective values, in seconds, appear
in `status.timeouts` and active `status.awdl.timeouts`. No timeout file is used.

```sh
just daemon --ble-idle-timeout 180 --completion-grace 5 \
    --approval-timeout 90 --upload-idle-timeout 30 --upload-timeout 1800
```

The timeout flags below accept fractional seconds, such as `--ble-idle-timeout 0.5`.
Values must be positive and at most 86400 seconds; `--completion-grace 0` disables
only that grace period. The radio quiet period must not exceed its drain timeout.
`--timeout` separately sets send discovery (default 60 s) or `peers` waiting
(default 10 s); `--duration` bounds a daemon or outgoing operation to
1–86400 whole seconds. These two options take integer seconds. AWDL slot timing and advertised DNS TTLs
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
| `--control-archive-timeout` | 600 | Daemon archive preparation and control archive receive deadline. |
| `--transport-shutdown-timeout` | 2 | Transport task shutdown deadline. |
| `--name-probe-timeout` | 8 | Per-peer HTTPS name resolution deadline. |
| `--netlink-timeout` | 5 | Kernel netlink request deadline. |
| `--network-manager-timeout` | 15 | NetworkManager D-Bus operation deadline. |
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
- `--interface`, `--profiles`, `--backend`, `--primary-channel`,
  `--max-bandwidth`, and `--reg-region`
  belong to `owld` and are covered in [Radio configuration](radio.md).

The identity directory contains a generated RSA private key and self-signed
certificate (`key.pem` and `cert.pem`). An optional `validation_record.cms` must
verify against Apple's root and match the certificate's account CN. Obtaining
that record is outside this CLI. It can identify the receiver, but outgoing
sends do not publish it. See
[TLS and HTTP](protocol.md#tls-and-http) for identity and authorization details,
and [DVZip and CPIO](protocol.md#dvzip-and-cpio) for archive validation.
