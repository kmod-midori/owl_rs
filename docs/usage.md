# Using owl_rs

[README](../README.md) · [Radio configuration](radio.md) · [Development](development.md)

## Transfers

Keep the phone unlocked with AirDrop set to Everyone for 10 Minutes. To send:

```sh
just send 'Example Phone' /path/to/photo.png
just send 'Example Phone' /path/to/folder /path/to/another-file
just send 'Example Phone' --url https://example.com
```

Files and recursive folders are supported; symlinks and special files are refused.
Received links are saved as inert `.url` files and never opened automatically.

`receive` is a foreground, receive-only session. Select its advertised name from
the phone's Share → AirDrop list:

```sh
just receive --name 'Example Computer'
```

By default, offers wait up to 60 seconds for approval. In another terminal:

```sh
just transfers
just accept TRANSFER_ID
just reject TRANSFER_ID
```

`--auto-accept` accepts offers without prompting. `--once` exits after one
successful file, folder or link transfer; rejections and failed uploads do not
consume the session:

```sh
just receive --once --auto-accept
```

## Sessions and the daemon

Both transfer commands use a running daemon or start a temporary control service
that exits after the operation. To keep the control service running:

```sh
just daemon --name 'Example Computer'
```

The daemon stays in the foreground and idle between operations. A session starts
AWDL, Bluetooth advertising, discovery and HTTPS, then stops those services and
restores saved WLAN settings on completion or cancellation. Successful
`receive --once` sessions retain the radio briefly after the final reply; the
drain sequence is described in [the protocol](protocol.md#layers-and-transfer-lifecycle).
Only one send or receive session can be active at a time.

Explicit session flags override the daemon's defaults; omitted flags inherit its
name, profile and paths. `--duration SECONDS` limits the active session, or the
control service's lifetime when supplied to `daemon`.

```sh
just status
just peers
target/release/owl_rs cancel SESSION_ID
just stop
```

`status` reports the session ID, radio state and transfer progress. `peers`
browses outgoing receivers only during an active send session. `cancel` ends the
specified session; `stop` ends both the session and the daemon. Ctrl+C on a
foreground transfer waits for cleanup and leaves an independent daemon idle.

## Paths and ownership

| Data | Default | Override |
| --- | --- | --- |
| Identity | `~/.local/share/owl_rs/identity` | `--keys DIR` |
| Received transfers | `~/Downloads/AirDrop/airdrop-TRANSFER_ID/` | `--output DIR` |
| Control socket and recovery journal | `/run/owl_rs` | `--run-dir DIR` |

Under sudo, ownership and home-directory defaults use the invoking user. Root
services can select `--owner USER`. The private control socket accepts only its
owner or root. Send clients build archives themselves; the privileged daemon
does not open source paths supplied through IPC.

Every command addressing a custom control directory needs the same `--run-dir`:

```sh
just daemon --run-dir /run/owl_rs-example
just receive --run-dir /run/owl_rs-example
just status --run-dir /run/owl_rs-example
just stop --run-dir /run/owl_rs-example
```

A stale socket left by a killed daemon is replaced under the daemon lock when
a standalone transfer starts. Interrupted radio state can require
[journal recovery](radio.md#recovery).

## Other options

Use `target/release/owl_rs send --help` or `receive --help` for the full CLI.

- `--max-bytes N` limits transfer size.
- `--no-bluetooth` disables wake-up advertising; `--bluetooth-adapter hci0`
  selects an adapter.
- `--direct '[fe80::200:ff:fe00:1%3]:8770'` bypasses receiver-name discovery;
  substitute the receiver's address, interface scope and port.
- `--interface`, `--profiles`, `--backend`, `--channel` and `--discovery-channel`
  are covered in [Radio configuration](radio.md).

The identity directory contains a generated RSA private key and self-signed
certificate (`key.pem` and `cert.pem`). An optional `validation_record.cms` must
verify against Apple's root and match the certificate's account CN. Obtaining
that record and enforcing Contacts Only are outside this CLI. See
[TLS and HTTP](protocol.md#tls-and-http) for identity and authorization details,
and [DVZip and CPIO](protocol.md#dvzip-and-cpio) for archive validation.
