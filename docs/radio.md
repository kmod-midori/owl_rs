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

Shared mode preserves AP association, stays on the AP's current channel and
advertises all 16 slots on that channel with the AP's width. It ignores the
exclusive-mode primary-channel preference and does not retune the radio.

Exclusive mode disconnects Wi-Fi and journals NetworkManager ownership, station
MAC/up state and any connected AP's UUID for restoration. It acquires exclusive
control of the PHY before setup and restores the saved state on failure.
With no AP, disconnect/reconnect is skipped.
Each `owld` start generates a random locally administered unicast MAC reused by
its exclusive sessions. The backend supplies channel context:

- **IBSS:** `owlibss0` joins AWDL BSSID `00:25:00:ff:94:73` on the selected
  channel, supplying context and hardware ACKs. Passive `owlmon0` captures and
  injects frames.
- **Active monitor:** active `owlmon0` captures, injects and supplies hardware
  ACKs. The existing station becomes a passive monitor with the same MAC for
  tuning. Setup establishes the primary channel before bringing up the active
  monitor. This requires hardware support and `mon_mac = "station"`, and avoids
  an additional tuning interface on MT7612U.

`reconnect` addresses drivers that need reconnection after shared-mode monitor
removal. `mt76_pm` saves, disables and restores supported mt76 power-management
settings. Existing monitor/TAP names are rejected rather than adopted.

## Channels

In exclusive mode, `--primary-channel 6|44|149` selects a fixed channel, defaulting
to 149. The daemon stays on it and advertises it in all 16 slots during discovery,
approval, transfers, and idle periods. Peer schedules do not change this selection.

```sh
just owld --primary-channel 149
# Or: just owld --primary-channel 44
# In other terminals:
just daemon --auto-accept
just discoverable everyone
```

`--reg-region US` selects the global kernel regulatory region in exclusive mode
(default `US`). Shared mode uses the AP's regulatory context.
Use a two-letter country code for the operating region, or `00` for the world
domain. Each exclusive radio session requests it through nl80211 and waits for confirmation
before checking channel availability. The setting persists after the session;
`probe` only reads the current kernel state. Driver and regulatory restrictions
still determine which channels and widths are usable.

Radio flags configure `owld`; `catdrop send` and `airdropd` do not change them.
`--channel` and `--transmit-channel` alias `--primary-channel`.
`--discovery-channel 6` is accepted as an ignored compatibility option; other values
are rejected. The selected channel must permit transmission. Disabled, radar and no-IR
channels are excluded; an unavailable primary is an error, not a fallback.

`--max-bandwidth 20|40|80` caps exclusive-mode tuning (default 40 MHz).
Active monitor tries permitted widths from that cap downward on the primary.
Shared mode uses the AP width regardless of this option.
Channel 6 and IBSS use 20 MHz. Injection pauses during tuning; unicast also waits
for the peer's matching slot. The advertised width reflects successful tuning.
`probe` lists hardware candidates.
`status` exposes `channel_plan.primary_channel`, `physical_channel`, and
`physical_channel_definition` (channel, width, center frequency).
See [Radio context and IPv6](protocol.md#radio-context-and-ipv6).

## Transmit rates

`--rate auto` starts at the fastest mutually supported VHT or HT20 rate and
adapts using correlated hardware TX failures/retries. Without completion reports
it uses capability-based selection. Explicit rates do not adapt.
VHT TX is capped at **MCS8**; hardware-supported
MCS9 reception and advertisements are allowed.

| Override | Selection |
| --- | --- |
| `--rate auto` | Automatic selection (default) |
| `--rate 12` | Legacy Mbps: 6, 9, 12, 18, 24, 36, 48 or 54 |
| `--rate mcs15-40-sgi` | HT MCS 0–31, optional `-20`/`-40` and `-lgi`/`-sgi`; defaults to HT20 long GI |
| `--rate vht4-nss2-bw40-sgi` | VHT MCS 0–9 request, capped at 8; NSS 1–8, width 20/40/80 MHz, optional `-sgi` |

HT40 and VHT requests are upper limits constrained by local TX, peer RX, SMPS,
guard interval and channel width. Invalid PHY combinations are rejected; VHT
requires 5 GHz. These rates fall back to 12 Mbps for missing capabilities or
multicast destinations.
`status` and selection logs report effective peer parameters; see
[Transmit rates](protocol.md#transmit-rates) for encoding details.

Queued HT/VHT unicast packets can form A-MSDUs within peer, interface and slot
limits. See [Transmit aggregation](protocol.md#transmit-aggregation) for counters,
retries and fallback behavior.

## Unicast acknowledgments

Channel pinning and hardware ACK policy are independent. The daemon defaults to
`--tx-ack noack`. `--tx-ack auto` follows `tx_noack` in the driver profile, which
defaults to false.
The MT76x2U profile uses NOACK to avoid a driver TX-status cleanup stall after
channel changes. The Intel profile uses NOACK as a firmware workaround.
`--tx-ack normal` or `--tx-ack noack` overrides it.
NOACK suppresses hardware acknowledgment waiting and may suppress delivery
reports; it also disables feedback-based rate adaptation.

`status` exposes `tx_status_acked`, `tx_status_failed`, `tx_status_retries` and
`tx_status_ignored`. Debug logs record requested/reported rates and completion
latency. These are driver reports, distinct from successful libpcap submission.
The driver controls hardware retry limits; radiotap DATA_RETRIES does not bound
per-packet retries on mt76x02. Queue airtime is an estimate, so slot-edge
behavior needs on-air verification with ACK waiting enabled.

## Transmit coding

`--fec` controls adapter coding independently of `--rate`:

| Override | Selection |
| --- | --- |
| `--fec bcc` | BCC for every frame. |
| `--fec auto` | LDPC for HT/VHT unicast when the driver and the peer's corresponding RX capability support it; otherwise BCC. |
| `--fec ldpc` | Daemon default. Request LDPC for HT/VHT unicast; require driver TX support and the peer's corresponding RX capability. |

The `owld awdl` diagnostic command defaults to `--fec bcc --tx-ack auto`.

The profile's `supports_tx_ldpc` defaults to false; bundled `mt76x2u` enables it
based on the driver TX descriptor. Local RX bits do not establish TX support.
Explicit LDPC with a legacy rate is rejected; discovery/multicast and legacy
fallbacks use BCC. `tx_parameters` and logs report requested coding, not proof of
on-air encoding. The VHT injection workaround needs hardware validation; see
[Transmit coding](protocol.md#transmit-coding).

## Receive Block Ack

The MT76x2U profile enables `rx_ampdu`; other bundled profiles disable it.
Custom profiles can enable it in shared mode or exclusive active-monitor mode
with `mon_mac = "station"`. Hardware generates Block Ack replies; userspace
handles negotiation and reordering. See
[Block Ack negotiation](protocol.md#block-ack-negotiation) for limits and counters.

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
just recover --run-dir /run/owld-example
```

Recovery refuses to interrupt a live owner. If auto-selection reports no managed
Wi-Fi interface after a killed session, recover before starting another session.

The application does not configure firewall or VPN routing. The user daemon
uses interface-scoped UDP for mDNS and TCP for HTTPS; host routing and filtering
apply. `owld` generates Ethernet neighbor-learning probes on its owned
link. See [compatibility and limitations](protocol.md#compatibility-and-limitations)
for tested hardware and remaining limits.
