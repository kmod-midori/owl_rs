# owl_rs

A Linux AirDrop CLI and daemon with a safe Rust AWDL implementation. Send and
receive files, folders and links. Receive from everyone or verified contacts;
sending to Contacts Only recipients is not implemented.

## Build

Requires Rust 1.88+, Cargo, `just`, and libpcap, OpenSSL and D-Bus development
libraries. Live transfers require `/dev/net/tun`, root and a supported Wi-Fi
adapter. NetworkManager integration uses `nmcli`; Bluetooth wake-up uses BlueZ
with LE advertising.

```sh
just build
just probe
```

Commands run the development build without installing a package. Use
`just check` for formatting, Clippy and automated tests.

## Send and receive

Unlock the iPhone and set AirDrop to **Everyone for 10 Minutes**.

```sh
just send 'Example Phone' /path/to/photo.png
```

To receive, run the daemon in one terminal:

```sh
just daemon --name 'Example Computer'
```

In another terminal, enable receiving and wait to accept the next offer:

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
`daemon --auto-accept` skips manual approval. Received files go to
`~/Downloads/AirDrop/` by default.

Discoverability starts **off** and applies until the daemon stops. `send` works
standalone or through the daemon. Incoming and outgoing transfers share one
active session. See [Usage](docs/usage.md) for runtime controls and Contacts Only receiving.

## Documentation

- [Usage](docs/usage.md): sessions, approvals, paths and control commands.
- [Radio configuration](docs/radio.md): profiles, backends, channels and recovery.
- [Development](docs/development.md): local testing, diagnostics and implementation.
- [Protocol](docs/protocol.md): AWDL synchronization, discovery and AirDrop transfers.

## License

GPL-3.0-or-later; see [COPYING](COPYING). Based on Open Wireless Link by Milan
Stute; upstream provenance is recorded in [Development](docs/development.md#origins).
