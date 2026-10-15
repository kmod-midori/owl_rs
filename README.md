# owl_rs

A Linux AirDrop workspace with a safe Rust AWDL implementation. Send and
receive files, folders and links. Receive from everyone or verified contacts;
sending to Contacts Only recipients is not implemented.

## Build

Requires Rust 1.88+, Cargo, `just`, and libpcap, OpenSSL and D-Bus development
libraries. The default `tray` feature also requires GTK 3 development libraries
and libayatana-appindicator (or libappindicator) at runtime. Build without the
tray and its GUI dependencies with:

```sh
cargo build --workspace --release --locked --no-default-features
```

The radio service requires `/dev/net/tun`, root and a supported Wi-Fi
adapter. AirDrop transport and the CLI run as your regular user. NetworkManager
integration uses `nmcli`; Bluetooth wake-up uses BlueZ with LE advertising.

```sh
just build
just probe
```

Commands run the development build without installing a package. Use
`just check` for formatting, Clippy and automated tests.

## Send and receive

Start the radio service in its own terminal:

```sh
just owld
```

Start the user daemon in another terminal:

```sh
just daemon --name 'Example Computer'
```

The user daemon shows a tray icon with receiving-mode controls and a Quit action.
Changes made with `catdrop discoverable` also appear in the tray. Receiving starts
off; enabling it in the tray uses the same policy as the CLI. Quitting shuts down
the user daemon and releases its radio session. Without a graphical display, the
daemon continues without a tray icon. Your desktop needs AppIndicator support to
display the icon.

The default `tray` feature also enables desktop notifications: accept or decline
incoming offers, follow sending/receiving progress, and cancel one transfer.
The CLI controls remain available alongside notifications. Progress bars depend
on desktop support; byte counts are shown when the incoming stream has no known
total. Notifications are optional and do not block transfers if unavailable.

Only `owld` runs with sudo. Unlock the iPhone and set AirDrop to
**Everyone for 10 Minutes**, then send as your regular user:

```sh
just send 'Example Phone' /path/to/photo.png
```

To receive, keep both daemons running. In another terminal, enable receiving
and wait to accept the next offer:

```sh
just discoverable everyone
just accept
# Or restrict receiving to your contact list:
just contact add friend@example.com
just discoverable contacts
# Disable incoming discovery and BLE wake-up:
just discoverable off
```

Opening Share → AirDrop on the phone sends a BLE wake request. The daemon starts
a shared Wi-Fi/HTTPS session, then restores Wi-Fi after its transfers finish or
inactivity. `accept TRANSFER_ID` and `reject TRANSFER_ID` select specific offers;
`airdropd --auto-accept` skips manual approval. Received files go to
`~/Downloads/AirDrop/` by default.

Discoverability starts **off** and applies until the daemon stops. `send` requires
both `airdropd` and `owld`. Incoming and outgoing
transfers share one active session. See [Usage](docs/usage.md) for runtime controls
and Contacts Only receiving.

The development build produces `owld`, `airdropd` and the user-facing `catdrop`
CLI. `just send`, `just accept` and the other control helpers invoke `catdrop`.
mDNS uses scoped IPv6 UDP sockets in the user daemon.

## Documentation

- [Architecture](docs/architecture.md): privilege separation and link leases.
- [Usage](docs/usage.md): sessions, approvals, paths and control commands.
- [Radio configuration](docs/radio.md): profiles, backends, channels and recovery.
- [Development](docs/development.md): local testing, diagnostics and implementation.
- [Protocol](docs/protocol.md): AWDL synchronization, discovery and AirDrop transfers.

## License

GPL-3.0-or-later; see [COPYING](COPYING). Based on Open Wireless Link by Milan
Stute; upstream provenance is recorded in [Development](docs/development.md#origins).
