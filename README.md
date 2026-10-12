# owl_rs

A Linux AirDrop CLI and daemon with a safe Rust AWDL implementation. Send and
receive files, folders and links. Supports AirDrop's Everyone mode; Contacts Only
is not implemented.

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
just receive --name 'Example Computer'
```

To send from the phone, select **Example Computer** in Share → AirDrop. Incoming
offers require approval; in another terminal:

```sh
just transfers
just accept TRANSFER_ID
# Or decline:
just reject TRANSFER_ID
```

For a single transfer with automatic acceptance:

```sh
just receive --once --auto-accept
```

Received files go to `~/Downloads/AirDrop/` by default. Each operation sets up
the radio and services, then tears them down and restores Wi-Fi. Ctrl+C ends a
session and waits for cleanup. Only one session can run at a time.

`send` and `receive` work standalone. An optional `just daemon` keeps an idle
control service running; the radio and HTTPS activate only for an operation.

## Documentation

- [Usage](docs/usage.md): sessions, approvals, paths and control commands.
- [Radio configuration](docs/radio.md): profiles, backends, channels and recovery.
- [Development](docs/development.md): local testing, diagnostics and implementation.
- [Protocol](docs/protocol.md): AWDL synchronization, discovery and AirDrop transfers.

## License

GPL-3.0-or-later; see [COPYING](COPYING). Based on Open Wireless Link by Milan
Stute; upstream provenance is recorded in [Development](docs/development.md#origins).
