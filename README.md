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
integration uses the system D-Bus API; Bluetooth wake-up uses BlueZ with LE advertising.

```sh
just build
just probe
```

Commands run the development build without installing a package. Use
`just check` for formatting, Clippy and automated tests.

## Arch Linux package

The `PKGBUILD` builds `owl_rs-git` from the GitHub repository with tray support:

```sh
makepkg -si
sudo systemctl enable --now "owld@$(id -un).service"
systemctl --user enable --now airdropd.service
```

Enable the radio service for one user only. Configure daemon arguments with
`systemctl edit` / `systemctl --user edit`. The package installs `owld`,
`airdropd`, and `catdrop`; use `catdrop` for the transfer commands below instead
of the development `just` helpers. Receiving starts off; enable it with
`catdrop discoverable everyone` or `catdrop discoverable contacts`.

## Send and receive

Start the radio service in its own terminal:

```sh
just owld
```

Start the user daemon in another terminal:

```sh
just daemon --name 'Example Computer'
```

The default `tray` feature provides receiving-mode controls, Quit, and transfer
notifications with accept, decline, cancel and progress actions. Receiving starts
**off**. CLI commands use the same state and work without desktop integration;
see [Usage](docs/usage.md#transfers). The tray requires AppIndicator support.

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

Incoming and outgoing transfers share one session. `just send`, `just accept`
and other control helpers invoke `catdrop`; both daemons must be running.
See [Usage](docs/usage.md) for Contacts Only reception and runtime controls.

## Documentation

- [Architecture](docs/architecture.md): privilege separation and link leases.
- [Usage](docs/usage.md): sessions, approvals, paths and control commands.
- [Radio configuration](docs/radio.md): profiles, backends, channels and recovery.
- [Development](docs/development.md): local testing, diagnostics and implementation.
- [Protocol](docs/protocol.md): AWDL synchronization, discovery and AirDrop transfers.

## License

GPL-3.0-or-later; see [COPYING](COPYING). Based on Open Wireless Link by Milan
Stute; upstream provenance is recorded in [Development](docs/development.md#origins).
