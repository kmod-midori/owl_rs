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
6, 44 or 149. Discovery and transmission stay on that channel, reusing the
current station address.

Exclusive mode saves NetworkManager ownership, the station's MAC/up state and
any connected AP's connection UUID. It disconnects Wi-Fi for the session and
restores saved state afterward. A cryptographically random, locally administered
unicast MAC is generated at each daemon start and reused for exclusive sessions
until the daemon exits. A restart generates a new MAC. The original station MAC
is retained in the recovery journal and restored during cleanup. With no
connected AP, disassociation and reassociation are skipped. The backend supplies the radio's channel context:

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
just daemon --discovery-channel 6 --channel 149 --auto-accept
# In another terminal:
just discoverable everyone
```

These flags also apply to `send` and to daemon session defaults.
`--transmit-channel` aliases `--channel`. Discovery defaults to 6; the transmit
preference defaults to 6 for active monitor and 44 for IBSS, subject to regulatory
availability. Disabled, radar and no-IR channels are excluded.

The local master uses its transmit preference. A follower chooses the usable
channel with the greatest overlap with the elected parent's schedule; failed
tunes fall back to other candidates. Idle sessions stay on the discovery
channel. TLS, `/Discover` and `/Ask` approval stay on discovery while no transfer
is active. Approved file transfers select and hold a transfer channel through
upload and TCP shutdown, then return to discovery after queued/recent TCP
traffic clears. There are no discovery detours during a transfer.
Advertised slots follow the successfully tuned channel. `status` exposes `channel_plan` and
`physical_channel` and `physical_channel_definition` (primary, width and center
frequency). Active-monitor transfers use the widest permitted 5 GHz context,
trying 80, 40 and 20 MHz in order; channel 6 and idle discovery use 20 MHz.
Rejected widths fall back on the same primary before trying another channel.
Every width change waits for kernel ACK before advertising it, and checks
readback when the kernel exposes it. Active/passive monitor setups may omit
readback; see the protocol notes.
Shared mode preserves the AP's width. `probe` lists permitted tuning candidates.
Timing, overlap ranking and tuning acknowledgments are
described in [Radio context and IPv6](protocol.md#radio-context-and-ipv6).

## Transmit rates

`send`, `daemon` and `awdl` default to `--rate auto`, selecting the fastest
mutually supported VHT or HT20 rate for each peer and the current channel.
Selection uses advertised capabilities and does not adapt to packet loss.

| Override | Selection |
| --- | --- |
| `--rate auto` | Automatic selection (default) |
| `--rate 12` | Legacy Mbps: 6, 9, 12, 18, 24, 36, 48 or 54 |
| `--rate mcs7-sgi` | HT20 MCS 0–31, optional `-sgi` |
| `--rate vht4-nss2-bw40-sgi` | VHT MCS 0–9, NSS 1–8, width 20/40/80 MHz, optional `-sgi` |

VHT requests are upper limits, constrained by both peers and the tuned channel.
Invalid PHY combinations are rejected. VHT requires 5 GHz; multicast discovery
and unavailable capabilities use 12 Mbps. Effective peer rates appear in
`status` and rate-change logs. See [Transmit rates](protocol.md#transmit-rates)
for capability and encoding details. HT/VHT unicast packets already in the
link queue are aggregated into A-MSDUs within peer, interface and slot limits;
`status` exposes the aggregation counters. See
[Transmit aggregation](protocol.md#transmit-aggregation) for retry and fallback behavior.

## Election experiments

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
