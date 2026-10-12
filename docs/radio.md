# Radio configuration

[README](../README.md) · [Usage](usage.md) · [Protocol](protocol.md)

## Adapter profiles

```sh
just probe
just probe --interface IFACE
```

The default interface selection uses the first managed Wi-Fi interface.
[profiles.toml](../profiles.toml) is compiled into the binary; `--profiles PATH`
loads a custom file. Its comments document the fields and hardware observations.
Profiles match the kernel driver name, falling back to `profiles.default`.
Untested profiles require `--allow-untested` for live setup. Unknown fields and
enum values are rejected.

`--mode shared|exclusive` and `--backend ibss|active-monitor` override profile
selections. There is no automatic fallback between backends.

## Modes and backends

Shared mode preserves AP association and requires its primary channel to be
6, 44 or 149. Discovery and transmission stay on that channel.

Exclusive mode saves NetworkManager ownership, the station's MAC/up state and
any connected AP's connection UUID. It disconnects Wi-Fi for the session and
restores saved state afterward. With no connected AP, disassociation and
reassociation are skipped. The backend supplies the radio's channel context:

- **IBSS:** `owlibss0` joins AWDL BSSID `00:25:00:ff:94:73` on the selected
  channel, supplying context and hardware ACKs. Passive `owlmon0` captures and
  injects frames.
- **Active monitor:** active `owlmon0` captures, injects and supplies hardware
  ACKs. The existing station becomes a passive monitor with the same MAC for
  tuning. This requires hardware support and `mon_mac = "station"`, and avoids
  an additional tuning interface on MT7612U.

`reconnect` addresses drivers that need reconnection after shared-mode monitor
removal. `mt76_pm` saves, disables and restores supported mt76 power-management
settings. Existing monitor/TAP names are rejected rather than adopted.

## Channels

Exclusive mode separates discovery/negotiation from transmission:

```sh
just receive --discovery-channel 6 --channel 149 --auto-accept
```

These flags also apply to `send` and to daemon session defaults.
`--transmit-channel` aliases `--channel`. Discovery defaults to 6; the transmit
preference defaults to 6 for active monitor and 44 for IBSS, subject to regulatory
availability. Disabled, radar and no-IR channels are excluded.

The local master uses its transmit preference. A follower chooses the usable
channel with the greatest overlap with the elected parent's schedule; failed
tunes fall back to other candidates. Advertised slots remain on the committed
transmit channel during temporary discovery visits, and data waits until the
radio returns to that channel. `status` exposes `channel_plan` and
`physical_channel`. Timing, overlap ranking and tuning acknowledgments are
described in [Radio context and IPv6](protocol.md#radio-context-and-ipv6).

`--rate 12` or `--rate mcs7-sgi` selects the data injection rate. Experimental
`--election-metric N` and `--election-counter N` change local election preference
(defaults 60 and 0). The fixed election counter is separate from availability
window timing and does not implement Apple's election-counter aging. Peers
decide whether to follow and how many slots to spend on each channel.

## Recovery

Normal completion, Ctrl+C, SIGTERM and bounded-duration exits remove owned
interfaces and restore WLAN settings. A locked journal records setup intent
before kernel mutations. After an abrupt process death, recover using the
original session's run directory:

```sh
just recover
# For a custom directory:
just recover --run-dir /run/owl_rs-example
```

Recovery refuses to interrupt a live owner. If auto-selection reports no managed
Wi-Fi interface after a killed session, recover before starting another session.
Rapid radio restart can also encounter a kernel tuning rejection; the underlying
netlink error is reported and saved WLAN state is restored.

The application does not configure firewall or VPN routing. mDNS and keepalives
use Ethernet frames on the AWDL TAP; HTTPS binds to its scoped link-local
interface. See [observed interoperability](protocol.md#observed-interoperability-and-remaining-scope)
for tested hardware and remaining limits.
