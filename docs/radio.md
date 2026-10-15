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

Exclusive mode disconnects Wi-Fi and journals NetworkManager ownership, station
MAC/up state and any connected AP's UUID for restoration. Setup waits for
NetworkManager to release the station. With no AP, disconnect/reconnect is skipped.
Each `owld` start generates a random locally administered unicast MAC reused by
its exclusive sessions. The backend supplies channel context:

- **IBSS:** `owlibss0` joins AWDL BSSID `00:25:00:ff:94:73` on the selected
  channel, supplying context and hardware ACKs. Passive `owlmon0` captures and
  injects frames.
- **Active monitor:** active `owlmon0` captures, injects and supplies hardware
  ACKs. The existing station becomes a passive monitor with the same MAC for
  tuning. Setup establishes the discovery channel before bringing up the active
  monitor. This requires hardware support and `mon_mac = "station"`, and avoids
  an additional tuning interface on MT7612U.

`reconnect` addresses drivers that need reconnection after shared-mode monitor
removal. `mt76_pm` saves, disables and restores supported mt76 power-management
settings. Existing monitor/TAP names are rejected rather than adopted.

## Channels

Exclusive mode separates discovery/negotiation from transmission:

```sh
just owld --discovery-channel 6 --channel 149
# In other terminals:
just daemon --auto-accept
just discoverable everyone
```

Radio flags configure `owld`; `catdrop send` and `airdropd` do not change them.
`--transmit-channel` aliases `--channel`. Discovery defaults to 6; the transmit
preference defaults to 6 for active monitor and 44 for IBSS, subject to regulatory
availability. Disabled, radar and no-IR channels are excluded.

A local master uses its transmit preference; a follower favors overlap with the
elected parent's schedule. Failed tunes try other candidates. Idle discovery,
TLS and offer approval use the discovery channel. Approved file transfers hold
their selected channel through upload and TCP shutdown, then return to discovery
after queued/recent TCP traffic clears, without discovery detours.

Active-monitor transfers try permitted 80, 40, then 20 MHz widths on each 5 GHz
primary before trying another channel. Channel 6 and idle discovery use 20 MHz;
shared mode uses the AP's width. `probe` lists candidates. Advertisements follow
kernel-acknowledged tuning, with readback checks when available.
`status` exposes `channel_plan`, `physical_channel` and
`physical_channel_definition` (primary, width, center frequency).
See [Radio context and IPv6](protocol.md#radio-context-and-ipv6) for overlap,
slot gating and tuning details.

## Transmit rates

`--rate auto` starts at the fastest mutually supported VHT or HT20 rate and
adapts using correlated hardware TX failures/retries. Without completion reports
it uses capability-based selection. Explicit rates do not adapt.
VHT TX is capped at **MCS8** after MCS9 stalled test uploads; hardware-supported
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

Channel pinning and hardware ACK policy are independent. `--tx-ack auto`
(default) follows `tx_noack` in the driver profile, which defaults to false.
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
| `--fec bcc` | BCC for every frame (default). |
| `--fec auto` | LDPC for HT/VHT unicast when the driver and the peer's corresponding RX capability support it; otherwise BCC. |
| `--fec ldpc` | Request LDPC for HT/VHT unicast; require driver TX support and the peer's corresponding RX capability. |

The profile's `supports_tx_ldpc` defaults to false; bundled `mt76x2u` enables it
based on the driver TX descriptor. Local RX bits do not establish TX support.
Explicit LDPC with a legacy rate is rejected; discovery/multicast and legacy
fallbacks use BCC. `tx_parameters` and logs report requested coding, not proof of
on-air encoding. The VHT injection workaround needs hardware validation; see
[Transmit coding](protocol.md#transmit-coding).

## Receive Block Ack

Copy `profiles.toml`, set `rx_ampdu = true` for an exclusive active-monitor
profile, and pass `--profiles PATH`. Built-in profiles disable it. Hardware must
generate Block Ack replies; the option installs no driver patches. See
[Block Ack negotiation](protocol.md#block-ack-negotiation) for limits and counters.

Upstream PRs [#58](https://github.com/t4t5/omdrop-owl/pull/58) and
[#59](https://github.com/t4t5/omdrop-owl/pull/59) report MT7612U support;
[#62](https://github.com/t4t5/omdrop-owl/pull/62) reports faster patched-MT7921
transfers with Block Ack and wide channels combined. Local tests validate
synthetic negotiation/reordering, not those hardware or throughput claims.

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
Rapid radio restart can also encounter a kernel tuning rejection; the underlying
netlink error is reported and saved WLAN state is restored.

The application does not configure firewall or VPN routing. The user daemon
uses interface-scoped UDP for mDNS and TCP for HTTPS; host routing and filtering
apply. `owld` generates Ethernet neighbor-learning probes on its owned
link. See [observed interoperability](protocol.md#observed-interoperability-and-remaining-scope)
for tested hardware and remaining limits.
