# AWDL and AirDrop protocol implemented by owl_rs

This document describes the wire formats and behavior implemented in this
repository. It is based on the patched C OWL implementation, the original
omdrop Python application, and live Apple traffic. It is a reverse-engineered
implementation contract, not an Apple specification. Constants and workarounds
below describe this implementation; they are not requirements for every Apple
release.

The application sends to Everyone-mode recipients and receives in Everyone or
Contacts Only mode. A receiver may publish an existing verified Apple identity
record; obtaining that record and Contacts Only sending are not implemented.

## Layers and transfer lifecycle

```mermaid
sequenceDiagram
    participant S as Sender
    participant R as Receiver
    S->>R: Apple BLE manufacturer advertisement
    S->>R: AWDL action frames: timing, election, channel schedule
    R->>S: AWDL action frames and service records
    S->>R: IPv6 mDNS query: _airdrop._tcp.local.
    R->>S: PTR, SRV, TXT, AAAA, NSEC
    S->>R: TLS connection A, POST /Discover
    R->>S: 200, receiver name and capabilities
    S->>R: TLS connection B, POST /Ask with offer
    Note over R: Wait for accept or reject
    R->>S: 200, receiver metadata
    S->>R: Same connection B, POST /Upload, chunked DVZip
    Note over R: Validate, extract, commit files
    R->>S: 200, empty body
```

For a link offer, acceptance of `/Ask` completes the transfer; there is no
`/Upload`. CLI sends and BLE wake requests activate or reuse one bidirectional
session. Idle daemons expose a local control socket and, when receiving is
enabled, an LE advertisement listener. Runtime
`discoverable everyone|contacts|off` controls incoming advertising and
authorization; it starts
as `off` and is not persisted across daemon restarts.

The Cargo workspace runs two distinct layers in separate processes:

- **`owld` (root):** transactional Wi-Fi setup, radiotap capture/injection,
  scheduling, TAP addressing, queue drain and WLAN restoration.
- **`airdropd` (user):** HTTPS, mDNS service discovery and receiver BLE advertising,
  using the leased link's address and interface without owning radio configuration.

`catdrop` controls the user daemon. Authenticated Unix IPC acquires the radio,
reports service visibility and revisioned transfer activity, acknowledges the
committed transfer channel, streams link snapshots,
and releases the lease. TCP file data travels through the kernel TAP/IPv6 stack.
The outgoing sender waits for its activity revision's channel-ready acknowledgment
before starting `/Upload`, bounded by `--channel-ready-timeout` (15 seconds).
`owld` chooses the channel; the acknowledgment confirms local tuning, not peer
availability in the current slot. Disconnect or heartbeat expiry makes `owld`
drain and restore the link. See
[Architecture](architecture.md) for the process boundary.

An outgoing operation, peer browse or active incoming HTTPS request holds a
shared lifetime lease. A CLI disconnect cancels only its outgoing operation. Incoming
transfer connections hold their leases through approval, upload, the final reply and
bounded TCP linger. Idle discovery keep-alive sockets release their leases after answering and do
not delay cleanup. The session cannot normally tear down while any user remains;
`cancel`, `stop` and signals explicitly interrupt all work.

An eligible live BLE wake starts or resets the configured idle wait (default
120 seconds). Everyone accepts any structurally valid AirDrop wake; Contacts
requires a current known-sender hash-prefix match. Repeated eligible advertisements
also reset the timer. Fresh wakes during completion grace start a new idle wait.
After successful work, all users finish, then the shared session retains the link
and advertising for the configured grace period (default five seconds). A new
operation can join during that grace period. Session acquisition waits for an
already-closing session to finish restoration before creating another link.

Successful file and link connections flush their HTTP/TLS reply and retain a
final TCP descriptor in a blocking worker with a ten-second linger bound, allowing
data/FIN acknowledgments while AWDL remains active. Failures and refusals do not
use that success-only linger. Session leases are released after this drain, so
the five-second grace follows TCP completion rather than a local TAP write.

At teardown the coordinator stops the transport first, sending mDNS goodbyes and
unregistering BLE advertising. It then stops the AWDL link. Link shutdown drains
queued replies, FINs and goodbyes until injection/TAP traffic has been quiet for
100 ms, bounded to two seconds if a peer becomes unavailable, then removes owned
interfaces and restores WLAN settings. An independent daemon returns to idle;
a temporary send service waits for cleanup before exiting.

## Radio context and IPv6

AWDL uses 802.11 frames with BSSID `00:25:00:ff:94:73`. The backend captures and
injects frames on a monitor interface and translates AWDL data to Ethernet on a
TAP interface. AirDrop runs over link-local IPv6 on that TAP. The link-local
address derives from the AWDL MAC using modified EUI-64: flip the universal/local
bit of the first byte and insert `ff:fe` between the MAC halves. The owned TAP is
created down, assigned this address with `nodad`, and then brought up. DAD is
disabled only on this temporary interface; no global setting is changed. Session
startup still verifies that the expected address is usable before binding HTTPS.
IBSS readiness and address readiness are polled at 50 ms intervals.

All link-local socket addresses need an interface scope. For example,
`[fe80::200:ff:fe00:1%3]:8770` uses an example link-local address and
interface index 3. Indices can change when a TAP is recreated. HTTPS sockets bind to that interface and the local
link-local address. mDNS uses ordinary IPv6 UDP sockets bound to the TAP,
with outgoing source/interface selection and received interface/hop-limit
metadata. The kernel handles Ethernet encapsulation. Neighbor-learning ICMP
probes are generated by the radio layer. Host IP routing and filtering apply
to UDP and TCP; the application does not add firewall or VPN exceptions.

The TAP MTU remains **1450** with packet offloads disabled. Session-owned
monitors request MTU 8192 through rtnetlink so packet sockets can accept larger
A-MSDUs. If that request is rejected, batching respects the reported monitor
MTU; raw diagnostics use the prepared interface's current MTU. The owned
monitor is deleted during teardown, so no persistent interface MTU changes.
The previous TAP limit is retained; the monitor MTU bounds the full injected
frame, including radiotap and 802.11 headers.

Radio operations use `wl-nl80211` and `rtnetlink` directly, with bounded
requests and kernel acknowledgments. Capability and regulatory checks decode
nl80211 attributes; AP association is read from cached BSS status without
triggering a scan. Monitor flags use the kernel's nested nl80211 attribute,
including the active-monitor flag for hardware ACKs. Interface state/MAC,
link-local IPv6 address scope and `NODAD`, address readiness, and permanent
neighbors use routing netlink. Operation-scoped connection tasks close during
cleanup. NetworkManager ownership and saved connection restoration still use
`nmcli`; `ip` and `iw` executables are not required.

The physical radio context is selected by the TOML profile:

| Backend | Channel context and ACKs | Capture/injection |
| --- | --- | --- |
| IBSS | `owlibss0`, fixed AWDL BSSID | Passive `owlmon0` |
| Active monitor | Active `owlmon0`; existing station supplies tuning context | Active `owlmon0` |

In active-monitor mode the existing station becomes a passive monitor with the
same MAC. Type and passive flags are set in one netlink request; a separate
flags update can be rejected by the driver. This is adapter setup, not an
additional AirDrop wire protocol.
Exclusive mode works without a connected AP. Discovery/negotiation and
transmission use separate channel settings; discovery defaults to 6.
An idle session stays on its discovery channel and advertises all 16 slots
there, so mDNS and HTTPS discovery can reach the receiver. TLS handshakes,
`/Discover`, and `/Ask` approval waits keep the discovery channel when no file
transfer is active. Once a file transfer is approved, it selects a fixed transfer
channel. A local master uses its configured preference; a follower ranks
channels by the number of slots in its elected sync parent's sequence. Only
permitted AWDL social channels (6, 44, 149) are considered; ties favor the
configured preference and then the lower channel number. Failed tunes exclude
a candidate for the session and select the next one.

The selected transfer channel stays fixed across uploads and final TCP shutdown,
even if the sync parent changes or disappears.
There are no periodic discovery visits during an exchange. Once all exchanges
finish and queued/recent TCP traffic clears, the radio returns to discovery.
The recent-traffic interval uses `--queued-packet-timeout` (default two seconds).
Discovery TCP, multicast mDNS and ICMP neighbor-learning keepalives do not
select the transfer channel. During a concurrent transfer, all traffic shares
that transfer's selected radio channel. A later exchange ranks the available channels again.

The channel-sequence TLV and synchronization channel fields describe the
successfully tuned channel, both while idle and during transfers. The schedule
changes only after successful kernel tuning; injection pauses throughout an
outstanding tune, then action frames immediately announce the new schedule.
Ethernet frames are gated on that channel and the destination peer's matching
slot. No usable transfer candidate, or an unavailable idle discovery channel,
is an operation error that triggers normal cleanup. IBSS retunes its channel context by
leaving/rejoining the fixed-BSSID network and polling readiness. Active monitor
uses an acknowledged kernel channel-setting operation. Shared mode requires a
connected AP on channel 6, 44 or 149 and advertises the intersection with that
channel; it does not use separate-channel discovery or adaptive retuning. Driver/regulatory limits
still apply. See [radio profiles](../profiles.toml) and [usage](../README.md).

## AWDL action frames

Radiotap precedes the captured or injected 802.11 frame. Action frames use frame
control `0x00d0`; ordinary injected data uses `0x0008`. Addresses are destination,
source and the AWDL BSSID, followed by the 12-bit 802.11 sequence number shifted
left by four. Fragmented, protected and DS frames are ignored by this backend.

An AWDL action body begins with:

| Field | Bytes / encoding |
| --- | --- |
| Vendor category | `7f` |
| Apple OUI | `00 17 f2` |
| Type / version | `08 10` |
| Subtype | `00` periodic synchronization frame; `03` master indication frame |
| Reserved | `00` |
| Two timestamps | Two little-endian 32-bit microsecond values |
| TLVs | Repeated type `u8`, length little-endian `u16`, value |

The implemented TLVs include:

| Type | Purpose | Relevant behavior |
| --- | --- | --- |
| 2 | Service response | AirDrop PTR/SRV/TXT records appended to outgoing MIFs |
| 4 | Synchronization parameters | Next-slot timing, availability counter, channel and master |
| 5 | Election parameters | Legacy height, master and metrics |
| 18 | Channel sequence | Sixteen slots; simple, legacy or operating-class encoding |
| 24 | Election parameters v2 | Master/sync MACs, counter, height, metrics and self counter; preferred over v1 |
| 16 | ARPA name | Bounded hostname, advertised in MIFs |
| 21 | Version/device class | Needed with a MIF to mark a peer valid |
| 7 | HT capabilities | Hardware HT flags, A-MPDU parameters and RX MCS mask, emitted in MIFs |
| 17 | IEEE 802.11 container | Hardware VHT Capability IE, emitted in MIFs when supported by the current band |
| 6, 12 | Compatibility fields | Emitted using the inherited OWL shapes; not fully interpreted |

Before live operation, nl80211 supplies separate 2.4 and 5 GHz capabilities from
the selected PHY. Split wiphy dump messages are merged by band. Each MIF uses
the capabilities of its physical channel; absent or incomplete capabilities are
omitted rather than replaced with a fixed device profile. Offline replay does
not query hardware.

HT type 7 contains two reserved bytes, the little-endian HT capability word,
one A-MPDU parameter byte, a variable RX MCS mask, and two reserved trailing
bytes. The receiver retains the first four mask bytes (MCS 0–31) and ignores
higher bits in extended masks. Local advertisements emit one to four mask
bytes. VHT type 17 wraps standard IE 191: length 12, little-endian capability
word and the eight-byte RX/TX MCS/NSS set. These layouts
follow the [Wireshark AWDL dissector](https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-awdl.c).
Capability flags describe hardware support. Active-monitor transfer tuning tries
80, 40, then 20 MHz on 5 GHz, constrained by the PHY's HT/VHT capabilities and
regulatory flags on every constituent 20 MHz channel. Kernel rejection falls
back to narrower definitions on the same primary before the channel plan tries
another primary. Channel 6 and idle discovery remain at 20 MHz; shared mode
preserves the AP's width and center frequency, and IBSS retains HT20.

SetWiphy supplies primary frequency, width and center frequency together. After
its ACK, GetInterface checks the requested definition when the kernel reports
one. mac80211 can omit this readback when active and passive monitors coexist
without a per-interface channel context; in that case the ACK establishes the
applied definition. A reported mismatch is rejected. Both synchronization and
channel-sequence TLVs then describe that confirmed context. AWDL's operating-class encoding retains the primary channel
number: class 128 for 80 MHz, 116/126 for HT40+ on 44/149, and 115/124 for HT20
on 44/149. Channel 6 uses class 81. Width changes preserve unavailable slots.
`status` exposes the confirmed `physical_channel_definition`; it is null while
tuning is in flight. These netlink channel definitions follow
[Linux cfg80211](https://github.com/torvalds/linux/blob/master/net/wireless/chan.c).

Unknown TLVs are skipped using their checked lengths. Zero-filled suffix
padding is accepted at action TLV boundaries, including one or two bytes left
after zero-length tag-0 records. A nonzero incomplete header or a truncated
declared value remains invalid. Unsupported optional VHT IE layouts and ARPA
label encodings are skipped without discarding timing and availability; a
compressed ARPA label without a preceding literal does not supply a hostname.
The whole action frame is parsed before peer state changes, so a malformed
trailing TLV cannot partially update timing or election state. Incoming
service-response TLVs are currently not used to resolve peers; IP mDNS and
scoped HTTPS probing perform resolution.

One time unit (TU) is 1024 microseconds. This backend uses 16-TU availability
windows, four windows per 64-TU slot, and 16 slots per schedule. Channel 0 means
unavailable. Sequence encoding has prefix `0f <encoding> 00 03 ff ff`, followed
by 16 one- or two-byte entries. Encoding 0 stores a channel byte; encoding 1
uses the second byte for the channel; encoding 3 stores channel then operating
class. Local fixed sequences use `51` for channel 6 and `80` for 44/149.

Counters wrap at 16 bits. Clock calculations use signed phase and wrapping
arithmetic to handle rollover and peers whose epoch precedes the local epoch.
Election normally ranks counter before metric; exclusive mode ranks metric
before counter, matching the patched C helper. Eligible parents must have tree
height below 10 and must not point back to this device as their sync parent.

Local election metric and counter default to 60 and 0. Experimental
`--election-metric` and `--election-counter` overrides set both the candidate's
self fields and its initial advertised master fields. They remain available
when a peer expires or the node returns to being its own master. The configured
election counter is fixed and separate from the wrapping availability-window
counter; Apple-style election-counter aging is not implemented. A larger local
rank does not prove that a peer has adopted this master or expanded its channel
availability. Check the peer's incoming election and channel-sequence TLVs.

The service uses `pin` plus an adaptive fixed transmit channel in exclusive mode, and
`intersect` in shared mode. Raw mode also exposes `verbatim`, `rotate` and
`widen`. A fixed physical channel does not remove unicast scheduling: unicast
still waits for a valid peer's matching channel slot, with boundary guards.
Fixed mode relaxes multicast scheduling. Runtime scheduling requests ticks every
500 microseconds (Tokio/OS timer resolution applies);
periodic synchronization frames are spaced 110 TU apart and MIFs are scheduled
around slot midpoints.

## AWDL data encapsulation

A phone's initial TCP SYN can arrive before its validating MIF. Up to 128 bare
SYN/SYN-ACK packets addressed to the local AWDL MAC and IPv6 address are staged,
without creating or validating a peer. Retransmissions with the same peer,
ports and TCP sequence share one entry. Staged packets expire after
`--queued-packet-timeout` (default two seconds) and are released only when that
peer passes normal AWDL validation. Other early data remains ignored; Contacts
Only authorization still occurs independently at HTTPS. The `rx_syn_buffered`,
`rx_syn_released` and `rx_syn_expired` statistics expose these transitions.

After the 802.11 header, a single data payload is:

```text
LLC/SNAP: aa aa 03 00 17 f2 08 00
AWDL marker: 03 04                  # little-endian 0x0403
AWDL sequence: <u16 little-endian>
Reserved: 00 00
EtherType: 86 dd                    # big-endian IPv6
IPv6 packet: ...
```

The decoder also accepts a zero SNAP OUI with the AWDL protocol ID. For QoS
A-MSDU, each subframe has destination MAC, source MAC, big-endian payload length,
and this LLC/AWDL payload; subframes align to four bytes. The decoder limits an
aggregate to 64 subframes and checks every length before copying.

The backend only forwards multicast or locally addressed data from valid peers.
802.11 retry duplicates are tracked for 500 ms by default with 128 sequence entries per
peer. Peer state is bounded to 512 entries and by default expires after five seconds without
valid action or data traffic. Fully parsed data from an already valid peer,
including a suppressed retry, refreshes its lifetime. Data cannot discover a new
peer or make an invalid peer valid, and malformed frames cannot refresh one.
Outgoing packets wait in a bounded queue with expiry instead of
accumulating indefinitely when no matching radio slot exists.

For nonblocking radio injection, `EAGAIN` and `ENOBUFS` mean temporary driver
backpressure. The runtime preserves the queued Ethernet frame, encoded AWDL
bytes and sequence numbers, yields to its event loop, and retries on a later
scheduler tick after rechecking the peer's channel slot. It does not block or
place frames in a separate driver queue that could transmit off-channel. The
original two-second packet expiry and 128-packet queue bound still apply.
Transmit counters increase only on success; `tx_backpressure` counts deferred
data injection attempts. Other injection errors remain failures with normal
session cleanup. These changes adapt
[omdrop-owl PR #11](https://github.com/t4t5/omdrop-owl/pull/11).

### Transmit rates

[Rate selection](../crates/owl/src/rate.rs) resolves `auto` against local TX and peer RX
capabilities before frame encoding. The radiotap library's rate tables rank
candidates by PHY Mbps. HT20 requires a defined local TX set matching RX;
VHT also uses the peer's operating classes and acknowledged local channel
width. Static/dynamic SMPS peers are limited to one stream because injection
does not arrange RTS/CTS wake-up. Unsupported short GI becomes long GI.
VHT requests bound MCS, streams and width. A transmit-policy ceiling of MCS8
applies to automatic and explicit requests after MCS9 stalled injected
uploads. Hardware capability maps remain unchanged for advertisement and
reception. Missing capabilities fall back to 12 Mbps. Actions and automatic/VHT multicast discovery also use 12 Mbps.
CLI syntax and overrides are documented in [Radio configuration](radio.md#transmit-rates).

The codec rejects unresolved `auto` and invalid PHY rates. VHT radiotap field
21 has two-byte alignment, known GI/bandwidth, bandwidth code 0/1/4, and a
single user's MCS/NSS nibble pair with selected coding. Encoding follows the
[radiotap VHT specification](https://www.radiotap.org/fields/VHT.html) and
[mac80211 injection format](https://docs.kernel.org/networking/mac80211-injection.html).
Queued packets keep their 802.11/AWDL sequence numbers across backpressure;
retuning or capability changes refresh only the radiotap transmission header. The
encoder can combine queued packets in A-MSDUs as described below.

Unicast hardware ACK handling is independent of fixed-channel scheduling.
The driver profile's `tx_noack` workaround defaults to false and is overridden
with `--tx-ack normal|noack`. Injection also requests NOSEQNO so a matching
shared station cannot rewrite sequence numbers used for completion correlation.
The MT76x2U profile uses NOACK to avoid a driver TX-status cleanup stall after
channel changes; the Intel profile retains the original NOACK workaround.
Incoming hardware reception ACKs are configured by the radio backend separately.

Radiotap TX_FLAGS plus DATA_RETRIES identify local driver completion reports.
They never enter TAP or refresh incoming peers. A bounded ledger correlates
successful unicast submissions using destination, 802.11 sequence and body
fingerprint; reports without a known PHY rate (including mt76 synthetic ACKs
after lost status), stale, duplicate, foreign and uncorrelated reports do not affect
rate selection. The existing queued-packet timeout bounds ledger age. Debug
logs include hardware outcome, retry count, requested/reported rate and latency.
USB completion padding is excluded using checked IPv6/A-MSDU lengths, preserving
zeros within application data. Radio cleanup also waits for pending completion
reports, bounded by the existing radio-drain and queued-packet timeouts.

`auto` starts at the shared capability ceiling. Four failures within a 32-frame
window, or at least two retries per frame after 16 reports, lower the target
PHY rate by at least 15% when a slower candidate exists. After 128 consecutive
successes without retries, it probes the next faster candidate. Late reports
from an older rate or channel cannot change the new selection. Explicit rates
remain fixed. Capability/channel changes reset the candidate ladder. No feedback
is synthesized from capture gaps or successful packet injection. Missing driver
reports leave capability-based selection in place.
FCS presence and radiotap padding are handled explicitly.

### Block Ack negotiation

`owld` declines IEEE 802.11 ADDBA requests addressed to its MAC by validated AWDL
peers. It echoes the dialog token, TID and policy with status 37 (Request declined),
without establishing an RX Block Ack window. Responses use the management rate
and the configured unicast ACK policy. They stay in a bounded MAC management
queue, share airtime/slot gating with data, and retain their sequence across
injection backpressure. The existing queued-packet timeout expires stale replies.
Listen-only diagnostics never respond. No management frame enters TAP or AirDrop.

`rx_addba_requests` and `tx_addba_rejections` report received requests and responses
successfully submitted to the driver; submission does not prove on-air delivery.
A-MSDU aggregation remains available. Accepting ADDBA would additionally require
working RX Block Ack support in the driver/hardware.

### Transmit coding

BCC remains the default; `--fec auto|ldpc` explicitly opts in. Coding is resolved
per peer after the concrete rate is selected. HT checks RX LDPC capability bit
0; VHT checks RX LDPC bit 4. Local TX support is supplied by the selected driver profile
(`supports_tx_ldpc`, false when omitted), independently of local advertised RX
capabilities. Declaring support does not enable LDPC; the default remains BCC.

HT LDPC sets radiotap MCS HAVE_FEC and FEC_LDPC. VHT sets the user-0 coding bit.
The upstream [Linux 7.2.9 injection parser](https://github.com/gregkh/linux/blob/v7.2.9/net/mac80211/tx.c)
ignores that VHT coding byte, so VHT LDPC additionally includes a preceding
MCS field `[0x12, 0x10, 0]`: HAVE_MCS|HAVE_FEC, LDPC, MCS0. HAVE_MCS is required
for Linux to process FEC. The later VHT field replaces the temporary HT rate
while retaining `IEEE80211_TX_CTL_LDPC`. This field is injection metadata and
is removed before transmission; the resulting requested PHY remains VHT.
The [MT76x2 driver](https://github.com/openwrt/mt76/blob/master/mt76x02_mac.c)
then sets its hardware LDPC descriptor bit. This path needs on-air validation
on the installed kernel before enabling it by default.

The codec leaves VHT's separate LDPC extra-OFDM-symbol field unknown; symbol
padding is a hardware decision. Cached frames include both rate and coding in
their key. A coding change refreshes only radiotap, preserving the 802.11/AWDL
sequence numbers and payload. Aggregation budgets use the actual header length,
including the VHT compatibility field and alignment padding.

### Transmit aggregation

[TX batching](../crates/owl/src/tx.rs) belongs to the AWDL link layer, between the Ethernet
TAP queue and the 802.11 codec. HTTP, TLS and archive code remain unaware of it.
Already queued packets with the same source/destination are combined into one
QoS TID-0 A-MSDU; sparse traffic is sent immediately without a coalescing timer.
Only validated HT/VHT unicast peers with known capabilities are eligible.

The body is bounded by both peers' HT maximum A-MSDU size (3839/7935), VHT
maximum MPDU size when applicable, the current monitor MTU, and the remaining
common-channel window. The local receive-size capability is also used as a
conservative hardware bound; backend size rejection still triggers fallback.
The scheduler subtracts its boundary guard and budgets each submitted burst
using the selected PHY rate and a preamble/ACK allowance. Reservations carry
across scheduler ticks and keep the radio on its transfer channel while
submitted frames have estimated airtime remaining. Cleanup waits for that reservation and the configured quiet interval.
Driver queue latency remains outside this estimate. Each subframe contains
DA/SA, a big-endian length and its own LLC/AWDL payload and sequence number;
padding aligns subsequent subframes to four bytes. No trailing padding is added.

The queue limit counts Ethernet packets, including members of cached aggregates.
Per-peer ordering and original expiry times survive batching and backpressure.
The encoded frame and sequences are retained until successful submission;
Rate or coding changes replace its radiotap header. If new capabilities no longer permit
that aggregate, its unsent members are repacked. An aggregate rejected with
`EMSGSIZE` disables aggregation for that link session and retries the members
individually. Other permanent injection errors remain fatal.

`tx_data` counts submitted Wi-Fi data frames, `tx_packets` counts their Ethernet
packets, and `tx_amsdu`/`tx_aggregated_packets` describe batching.
`tx_aggregation_rejected` counts driver size rejections. A-MPDU aggregation and
Block ACK session management require kernel support. The current monitor path
has no kernel peer records or BA sessions and cannot enable A-MPDU through
radiotap alone.

## Bluetooth wake-up

BlueZ advertising is owned by `bluer`. The Apple manufacturer ID is `0x004c`;
its 20-byte manufacturer payload is:

```text
05 12 40 <tag:3> 00 00 00 00 03 <hash-prefixes:8> 00
```

`05` is the AirDrop TLV type and `12` its 18-byte body length. The three-byte tag
is generated per advertising session and also sent as `SenderIdentityAuthTag`
in outgoing `/Ask`. A 100 ms advertising interval is requested. The precise
meaning of all reserved bytes is not established here; the shape matches the
existing helper. Zero hash prefixes are used for a self-signed Everyone identity.

With an optional verified Apple record, the current implementation fills up to
four two-byte slots from validated email hashes followed by validated phone
hashes. It does not implement every slot convention observed on Apple devices.
Advertising is unregistered on shutdown, and an adapter powered on by the session
is restored to its previous power state.

The idle daemon uses [bluer LE discovery and device property events](https://docs.rs/bluer/latest/bluer/struct.Adapter.html)
to listen for fresh Apple manufacturer (`0x004c`) data. The scanner parses
length-delimited Apple TLVs and accepts a single complete AirDrop (`05`, length
18) element. Cached device snapshots, unrelated properties and malformed or
ambiguous TLVs do not wake Wi-Fi. Duplicate-data events are requested so repeated
live advertisements can still be observed. Identical live payloads remain eligible
to refresh the idle deadline; there is no per-tag deduplication or global wake
cooldown. A bounded queue coalesces bursts while the daemon reuses one session.
Addresses and hash hints are never logged.

In Contacts mode, the four two-byte hash slots are compared against prefixes of
current known-sender SHA-256 hashes before waking or refreshing the timer. Missing, unreadable or invalid
lists produce no contact wake matches. These short, unauthenticated values are
only hints and may collide or be spoofed; full record and TLS verification at
Ask remains mandatory. The daemon checks the current policy and list again at
admission, including after waiting for an older session to finish cleanup. A
queued Everyone hint cannot bypass a later Contacts-only setting. Everyone mode
accepts a structurally valid wake hint;
Off mode releases the discovery stream and suppresses BLE session activation.

A wake callback uses the ordinary shared session setup/cleanup path and refuses
a second session while busy. The receiver advertises its own wake payload while
enabled; Off unregisters it. Adapter power is restored when an owned scanner or
advertiser releases an adapter it had powered on. Scanning and advertising share
power leases so switching receiving Off cannot power down an outgoing sender.
BlueZ errors are logged and retried. This path has synthetic/parser and
loopback lifecycle coverage. Live iPhone testing also verified BLE wake-up,
automatic exclusive-mode setup and Contacts Only reception.

## Service discovery

The local service identifier is the AWDL MAC as 12 lowercase hexadecimal digits.
Exclusive sessions reuse a random locally administered unicast MAC for the
`owld` instance's lifetime, then choose a new one after its restart. Shared sessions reuse
the current station address. Service-response TLVs,
mDNS, sender IDs, TAP addressing and IPv6 all use the session's actual MAC.
Apple devices may retain cached entries from an earlier daemon instance.
An active session publishes:

| DNS record | Value | Advertised TTL |
| --- | --- | --- |
| PTR `_airdrop._tcp.local.` | `<id>._airdrop._tcp.local.` | 4500 s |
| SRV `<id>._airdrop._tcp.local.` | Priority/weight 0, HTTPS port, `<id>.local.` | 120 s |
| TXT service instance | `flags=137` | 4500 s |
| AAAA `<id>.local.` | Local link-local IPv6 | 120 s |
| NSEC hostname | AAAA and NSEC bitmap | 120 s |

`137` is `0x89`; bit `0x80` indicates Discover support and bit `0x01` supports
links in the inherited implementation. The remaining bit is preserved without
assigning an undocumented meaning. NSEC tells Apple's resolver that an IPv4 A
record is absent; omitting it delayed or prevented visibility in live testing.
Unique records use the mDNS cache-flush bit.

mDNS uses UDP port 5353, multicast IPv6 `ff02::fb`, Ethernet destination
`33:33:00:00:00:fb`, and hop limit 255. Received messages must have a link-local
source and hop limit 255. Replies are rate-limited. The current helper-compatible
cadence sends an approximately one-second announcement burst every three
seconds, with discovery queries during each burst. TTL-zero records are sent on
graceful shutdown. DNS address, service and TXT caches are bounded and retained
up to the configured local cache cap (120 seconds by default), even when the
advertised TTL is longer.

AWDL service-response TLVs use Apple's fixed DNS compression dictionary rather
than packet-relative mDNS compression. The outgoing implementation uses `c0 07`
for the AirDrop service, `c0 0c` for `.local`, and `c0 00` as the PTR terminator.
Each type-2 TLV contains little-endian owner-name length, encoded owner, DNS type
byte, little-endian RDATA length, two reserved bytes and RDATA. SRV priority,
weight and port remain big-endian DNS fields. These records complement mDNS;
publishing only IPv6 mDNS was insufficient for receiver visibility in testing.

The radio runtime also sends a scoped unicast ICMPv6 echo to each valid AWDL neighbor
roughly every three seconds. This stimulates neighbor learning on Apple peers.
It is a compatibility mechanism, not a new AirDrop application message.

For name selection, the sender resolves `/Discover` concurrently, bounded to
eight probes. A valid AWDL neighbor that has not published mDNS is also tried at
its EUI-64 link-local address on port 8770. This is an Apple-port assumption,
not proof that every AWDL neighbor offers AirDrop; only a successful Discover
response makes such a fallback candidate visible as an AirDrop peer. A direct
scoped address can override discovery.

## TLS and HTTP

AirDrop uses HTTP/1.1 over TLS. The Rust implementation supports TLS 1.2 or newer
and handles TLS through Tokio/OpenSSL. It generates a private RSA-2048 key and
self-signed certificate when no identity exists. Everyone-mode TLS certificates
are not checked against public Web PKI; this supplies transport encryption, not
Apple-account authentication or protection against an active impostor.

An optional local `validation_record.cms` must verify to Apple Root CA, use the
dedicated record-signing certificate role, remain within its declared validity,
and match the local Apple-issued sharing certificate's account CN
`com.apple.idms.appleid.prd.<altDsID>`. It is published only as receiver identity.
Outgoing sends omit `SenderRecordData` and advertise zero Apple ID hash prefixes;
Contacts Only sending is not implemented.

Requests are POSTs. Metadata is a binary plist; current outgoing metadata uses
`Content-Type: application/octet-stream`. Content-Length and chunked incoming
metadata are both accepted. Apple uses chunked framing in observed replies and
requests, so metadata is read to the HTTP body end, not a presumed length.
Metadata is limited to 1 MiB with a configurable frame idle timeout (default
20 seconds).

### Discover

The sender opens a connection and posts `/Discover` with:

```text
DeviceSupportFlags = 111611
```

A successful response supplies `ReceiverComputerName`. The local receiver emits:

```text
ReceiverComputerName = <configured name>
ReceiverModelName = "MacBookPro18,3"
ReceiverMediaCapabilities = <JSON bytes: {"Version": 1}>
ReceiverRecordData = <CMS bytes>           # optional
```

Apple senders may also include `SenderRecordData` in incoming Discover requests.
That record affects Contacts Only discovery filtering, without granting consent.

The minimal media-capability value follows the original helper and asks Apple
to choose legacy-compatible media; it is not a claim of HEIF/HEVC codec support.

### Ask and approval

The sender opens a fresh TLS connection for `/Ask`, retaining that connection
for `/Upload`. The offer includes:

| Key | Current outgoing value |
| --- | --- |
| `TransferID` | Dictionary containing `id`: uppercase UUID |
| `TransferType` | `{"files": {}}` or `{"links": {}}` |
| `SenderID` | Local 12-hex service ID |
| `BundleID` | `com.apple.finder` |
| `SenderComputerName`, `SenderModelName` | Configured name, `MacBookPro18,3` |
| `Files` | Per-file dictionaries, or empty for links |
| `Items` | URL strings for links; otherwise empty |
| `ConvertMediaFormats` | false |
| `SenderIdentityAuthTag` | Three-byte current BLE tag, when advertising |
| `FileIcon` | Optional JPEG thumbnail |

Each file dictionary contains `FileName`, `FileBomPath` (`./<basename>`),
`FileSize`, `FileIsDirectory`, `FileType` and `ConvertMediaFormats=false`.
UTIs cover JPEG, PNG, HEIC, MP4, MOV, PDF, text and folders; unknown extensions use
`public.data`. A PNG/JPEG preview is bounded, resized to at most 240×240, and
JPEG-encoded at quality 80.

The receiver also accepts a string UUID in `TransferID`. File names must be
basenames; absent FileSize is treated as unspecified. Offers are bounded to
4096 files or links; mixed or empty offers are rejected. URL strings are bounded
and cannot contain newline, carriage return or NUL.

Apple senders may include `SenderRecordData` in incoming Ask requests. In
Contacts Only mode the record must pass the policy below before an offer can
become pending or automatically accepted.

By default the offer becomes `pending` for at most 60 seconds. Local
`accept TRANSFER_ID` authorizes it; rejection/expiry returns HTTP 403.
`--auto-accept` bypasses this decision explicitly. Acceptance returns HTTP 200
with the receiver metadata used by Discover. Authorization is stored on this
TLS connection; knowing the UUID on another connection does not authorize an
upload. Links are written as inert `.url` files when Ask is accepted.

### Upload and completion

The file sender posts `/Upload` on the accepted Ask connection:

```http
POST /Upload HTTP/1.1
Content-Type: application/x-dvzip
TransferID: <same uppercase UUID>
TotalBytes: <sum of offered file sizes>
Transfer-Encoding: chunked
```

The receiver checks the transfer ID against the connection's accepted offer and
consumes that authorization once. It accepts DVZip and octet-stream uploads,
with gzip-wrapped CPIO supported by the decoder. `TotalBytes` is informational;
actual wire and expanded bytes are bounded independently. The whole upload has
a ten-minute deadline, with a 20-second stall limit.

A successful upload returns **HTTP 200 with an empty body**, without a plist
Content-Type, and with `Connection: close`. Completing this upload's connection
lets the sender finish without waiting for the server's idle-header timeout;
the shared transport continues on other connections. The completed connection
holds its session lease through the final reply and TCP drain.

An earlier keep-alive reply left the connection open for 20 seconds after a
2,041,711-byte JPEG had been committed. The phone showed a finishing delay.
Closing the completed connection while retaining the empty, untyped reply was
then tested with an 8,727,870-byte MOV, which the phone reported as Sent. Earlier
Content-Type and keep-alive changes were tested together; this comparison
preserves the body and Content-Type behavior while changing connection closure.

Some captured iPhone transfers deliver a complete archive without finishing
its HTTP chunk terminator. The receiver now feeds incoming bytes through a
bounded queue to a blocking archive decoder, independent of HTTP completion.
DVZip decoding uses a 64 KiB input buffer and incremental zlib state. Bounded
CPIO headers are parsed as they arrive and each regular file is streamed directly
into a private `.owl-rs-*` directory inside the destination. No complete wire
archive, compressed block or decoded CPIO archive is buffered in RAM; reception
also avoids the former intermediate decoded-archive disk file. File contents
are consumed by their declared lengths, rather than searched for trailer text.
Gzip reception verifies its CRC/footer before completing.

A structurally parsed, zero-size `TRAILER!!!` entry after at least one member
marks archive completion. The enclosing DVZip block must also be complete.
Extraction checks safe member types and duplicate names before writing, then
verifies AppleDouble companions and all approved files and sizes. Validated files
remain in destination-local staging until the receive task renames the entire
directory to `airdrop-TRANSFER_ID` with an atomic no-replace rename and sends
HTTP 200. Decode, validation, I/O
and rename failures remove staging. Timeout or cancellation stops the worker;
its temporary directory is removed when it exits, even if the HTTP task has
already ended. An existing completed transfer is preserved. No quiet-period timer
or repeated whole-archive decoding is needed;
`--upload-idle-timeout` still rejects stalled incomplete uploads. Hyper retains
partial chunk headers and body data while the decoder runs.

The earlier disk-backed incremental validator was tested with a live 14.76 MiB
image receive without an HTTP terminator:
HTTP 200 was ready 89 ms after the final upload TCP packet, and the phone sent
FIN after 265 ms. The phone reported Sent and the extracted file matched its
source hash. A preceding quiet-period receive took 4.06 seconds from the final
upload packet to the phone's FIN; the radio environments were not controlled.

This is the same recovery principle as
[omdrop-plugin PR #41](https://github.com/brentkearney/omdrop-plugin/pull/41).
The missing HTTP zero chunk is framing, rather than file data: no missing file
bytes are invented or accepted. The focused HTTPS regression pauses inside a
chunk-size line and inside a chunk body, then sends a complete archive without
the closing zero chunk and requires an empty 200 reply and session teardown.

A saved file alone is not sufficient evidence of protocol success. Verification
requires the sender to receive its final HTTP success and the phone to finish
without changing to Failed.

## Contacts Only receiving

The policy follows [omdrop-plugin's contact gate](https://github.com/brentkearney/omdrop-plugin/blob/b2f9a537b150c26402c5daad8125fb7e61c214ec/bin/contacts.py):
verify a sender's record, bind it to its live TLS identity and match a known
identifier. `discoverable contacts` enables it; its `--contacts-file` selects
the plaintext list, defaulting to the invoking user's
`~/.config/owl_rs/known-senders`. Missing/empty lists authorize nobody. Files are
bounded to 1 MiB and 4096 distinct identifiers, read again for each offer, and
hashed with full SHA-256 after trimming/lowercasing emails or removing non-ASCII
digits from phone numbers. Phone numbers need an explicit country code.

Contacts Only TLS requests an optional client certificate. Certificate absence
does not abort discovery; certificate-chain acceptance at the handshake is
deferred to the application policy. OpenSSL still verifies possession of the
client private key. The certificate used at Ask is taken from that connection,
never from request metadata. Every mode requests an optional client certificate
so an existing Everyone TLS connection can later be checked in Contacts mode.
Handshake acceptance never authorizes an offer by itself. A shared watch carries
the current mode and a revision; discovery and offer admission recheck that
revision after verification and pending approval. A policy change rejects a
pending offer. Already approved uploads keep their connection-bound consent.
Off mode returns empty HTTP 403 responses to Discover and Ask, sends an mDNS
goodbye, suppresses further mDNS and AWDL service advertisements, and disables
receive-side BLE advertising/scanning. Outgoing sender wake advertising remains
available in Off mode.

Before approval, file extraction, link saving or upload authorization, Ask requires:

1. A CMS SignedData record (DER or BER) with a valid signature and certificate chain
   anchored only to the bundled Apple Root CA. Record size and decoded payload
   are limited to 128 KiB. OpenSSL canonicalizes BER envelopes before DER
   signer inspection; signature verification still uses the original CMS.
   If validity fields are present, `ValidAsOf` plus a
   finite positive `SuggestValidDuration` must not have expired; incomplete
   validity fields are rejected.
2. The actual CMS signer certificate must carry Apple's validation-record
   signing marker `1.2.840.113635.100.6.25`. `cms` and `x509-cert` parse the signer
   identifier and certificate role; OpenSSL verifies signature, chain and time.
   Issuer/serial and subject-key-identifier signer forms are supported. Merely
   including a record-signing certificate in the certificate bag is insufficient.
   An Apple-issued sharing key cannot mint accepted contact claims.
3. The TLS peer certificate must verify to the same trusted root, carry the
   sharing marker `1.2.840.113635.100.4.7`, and have a single account CN matching
   the signed `altDsID`. Bundled Application Integration intermediates supplement
   a bare peer leaf as untrusted chain material, never as trust anchors. Peer
   chains are limited to 16 certificates.
4. At least one full `ValidatedEmailHashes` or `ValidatedPhoneHashes` digest must
   match the current list. Names, BLE prefixes and sender-supplied certificate
   fields cannot authorize a transfer.

The certificate roles follow
[Apple's published Security policies](https://github.com/apple-oss-distributions/Security/blob/main/OSX/sec/Security/SecPolicy.c)
for validation-record signing and Apple ID sharing. The verification purpose is
`ANY` because the record signer is not an S/MIME identity; chain, signature,
validity and role checks remain mandatory. This is not a full implementation of
Apple's trust service: online OCSP/CRL revocation fetching is not implemented.

Ask refusal returns HTTP 403 with an explicit zero Content-Length and closes
within a two-second response-drain bound. Rejected connections do not use the
success-only TCP linger. No transfer
entry is created and `--auto-accept` cannot bypass this policy. Successful Ask
retains upload consent only on that TLS connection and for its transfer ID;
Upload without it is refused before file data is processed. List revocation
affects the next Ask, not an already approved upload.

Discover uses weaker, best-effort hiding. A valid signed record belonging to a
non-contact receives an empty HTTP 401, without receiver metadata. Missing,
malformed or expired records are still answered for compatibility with devices
that omit discovery identity. A replayed contact record can obtain discovery
metadata, but cannot pass Ask without the matching Apple-issued private key.
Discovery results are never cached as transfer authorization. Identifiers,
accounts and their hashes are omitted from contact-policy logs.

The receiver needs no local Apple-issued identity to enforce this policy.
Contacts Only receiving has synthetic CA/CMS and TLS-metadata regression
coverage. A live iPhone transfer also verified a BER-encoded Apple-signed record,
certificate-bound authorization and successful reception of a 1,868,495-byte
image after BLE wake-up.

## DVZip and CPIO

DVZip is a sequence of length-prefixed blocks:

```text
<u32 big-endian block header> <block bytes>
```

The high bit means a stored, uncompressed block. The lower 31 bits give the
following byte count. Without the high bit, the block is a complete zlib stream,
including checksum. Rust emits blocks from 64 KiB of CPIO input, using zlib
level 6 when compressed data is smaller, otherwise a stored block. There is no
separate DVZip end marker in this implementation; HTTP body completion and the
CPIO trailer delimit the transfer.

Apple's compressed blocks may expand to more than the decoder's 64 KiB output
buffer. Decompression must continue until zlib StreamEnd, verify all compressed
bytes were consumed, and reject truncated streams or trailing compressed data.
Using FlushDecompress::Finish with a limited output buffer rejected valid Apple
blocks; streaming with FlushDecompress::None fixed the captured archive.

Outgoing archives use portable ASCII/ODC CPIO (`070707`). Each member has a
76-byte ASCII header, a NUL-terminated name, and file data. Names are
`./<basename>` or `./<folder>/<relative path>`. **Regular file names must not have
a trailing slash.** A live iPhone reset Rust's upload when the file was encoded
as `./photo.png/`; correcting that path made the same transfer succeed.
Directories use mode `040755`, files `100644`, and members end with
`TRAILER!!!`. No symlinks, special files or hard-link entries are sent.

Receiving supports ODC and new ASCII CPIO (`070701`, four-byte alignment).
Each incoming header is bounded before the archive library allocates its name;
member sizes and count are checked incrementally. Extraction rejects
absolute/traversing paths, backslashes, NULs,
duplicate members, symlinks, special files and hard links. It stages privately
and atomically renames the completed transfer directory. Approved top-level
files must be present with matching types and specified sizes.

Apple may add `._<filename>` AppleDouble metadata. Such companions are allowed
only for an approved file, with size 26 bytes to 1 MiB and header
`00 05 16 07 00 02 00 00`. This checks the magic/version, not every AppleDouble
entry's semantics. Companions are retained as received rather than applied as
extended attributes.

The default receive limit is 4 GiB. At upload start, the effective budget is the
smaller of that limit and one eighth of available output-disk bytes, reserving
space for four concurrent extracted transfers with additional headroom. There
are at most 32 HTTPS connections, four uploads and 256 transfer records. These
are implementation limits configurable or revisable independently of the wire
protocol.

## Local daemon control protocol

This is the user daemon's local control protocol, separate from the owld link
lease protocol and Apple's wire protocol. A Unix socket at
`<run-dir>/control.sock` has mode 0600; peer credentials restrict clients to the
daemon owner or root. A connection sends one newline-terminated JSON command,
limited to 1 MiB, then receives one newline-terminated result:

```json
{"command":"transfers"}
{"ok":[{"offer":{"id":"...","sender":"Example Phone","items":[],"urls":[]},"state":"pending","bytes":0,"output":null,"error":null}]}
```

Commands are `status`, `peers`, `transfers`, `discoverable`, `accept`, `reject`,
`cancel`, `stop` and `send`. There is no public receive control request; the
internal BLE callback starts receiving. For example:

```json
{"command":"discoverable","mode":"contacts","contacts_file":null}
{"ok":{"visibility":"contacts"}}
{"command":"accept","id":null}
```

`accept` with a UUID selects that offer. An omitted/null ID waits for the oldest
pending offer and returns after approving it; closing this connection cancels
only the waiting acceptance. `reject` requires a transfer UUID. `cancel` uses
the active `session.id`. Idle status has `session: null`, runtime `visibility`
and `ble.listening`; active status adds the session ID and `phase` (`starting`,
`active` or `closing`). `timeouts` reports the effective deadline values in
seconds. `sending` contains independent outgoing operation IDs.
Transfer history remains after teardown. `peers` requires an active session,
holds it alive while resolving names over HTTPS, and does not activate an idle
radio. Raw AWDL neighbors remain available in `status.awdl.peers`, independently
of AirDrop service discovery. Errors use `{"error":"message"}`.

Before starting an outgoing operation, the CLI probes the control socket.
A missing socket or connection refusal asks the user to start `airdropd`;
the CLI never runs the service or loads identity keys. Other connection errors
are reported. Startup takes an exclusive daemon lock
before replacing an orphaned user socket. Radio recovery belongs to owld and
uses its separate root-owned run directory, not the user control directory.

Send `options` contain explicit user-session CLI overrides. Unknown fields,
including radio settings, are rejected. The user run directory and owld socket
must match the control service. An idle activation
inherits daemon defaults, excluding its lifetime `duration`. A send joining an
active session inherits that session's settings; explicit conflicting settings
are rejected until the session is canceled or finishes. `duration` bounds only
the outgoing operation and can differ between users of the same session.
`timeouts` holds explicit nested command-line deadline overrides; omitted values
inherit the active session or daemon defaults. Unknown, non-finite, zero deadline
and incompatible interval values are rejected before setup. Completion grace
alone accepts zero. See the [timeout flags](usage.md#timeouts) for all settings.

Additional sends reuse the session instead of competing for radio ownership.
Closing a send client's connection or pressing Ctrl+C cancels only that send.
Successful IPC replies indicate transfer completion; the session can remain
active for other work or completion grace. A temporary CLI service waits for
session cleanup before exiting. `cancel SESSION_ID` stops the entire session;
`stop` also ends the daemon.

For `send`, the JSON declares `to`, optional scoped `direct`, `items`, `urls`,
`bytes`, optional thumbnail `icon`, and discovery `timeout`. Exactly `bytes` raw
archive bytes follow the newline for a file transfer. The client builds the
archive; airdropd receives its bytes, while owld only handles the link lease.
`stop` acknowledges before triggering shutdown so the client does not see an
unexpected EOF; the daemon waits for any active session's restoration before
exiting.

## Observed interoperability and remaining scope

The split has completed name-based large-image sends and Contacts Only
receiving through user-owned UDP mDNS and HTTPS with root-owned radio leases.
A contact BLE wake activated the receiver in 1.19 seconds. A 14.76 MiB image
upload completed in 46.1 seconds with normal HTTP termination and HTTP 200;
the phone reported Sent, and the received image matched its source SHA-256.
Turning visibility off released the radio lease and restored managed Wi-Fi.
Initial attempts failed during monitor channel setup with `EBUSY`; a retry
succeeded. That intermittent setup failure remains unresolved. The earlier
receive measurements below predate the process split.

MT7612U/mt76x2u active-monitor tests completed native Rust image transfers in
both directions, including name-based sending. Large image and approximately
8 MiB video receives completed with matching offered sizes and valid media.
The original Python sender/receiver and Rust also interoperated in local HTTPS
tests for files, folders and links. Focused tests cover malformed frames,
timing rollover, encapsulation, archive bounds and connection-bound consent.
The HTTPS regression uses an 8 MiB incompressible synthetic file.

Early channel-6 video uploads took roughly 83–114 seconds from offer to file
commit. Separating discovery on 6 from transmission on 149 at HT20 reduced
bulk upload of a 7.44 MiB video to 29.3 seconds, averaging 0.25 MiB/s.

After hardware-derived HT/VHT advertising and wider tuning, a Contacts Only
receive of a comparable-size video completed with a 12.1-second bulk upload at
0.61 MiB/s. The receiver was tuned to 149 at 80 MHz; the phone predominantly
transmitted two-stream VHT at 40 MHz. The complete saved media passed a full
decode check and the phone reported Sent. This attempt omitted HTTP termination,
so validated archive completion added approximately two seconds after the final
large payload. BLE wake to radio readiness was 1.69 seconds, versus 1.09 seconds
in the earlier HT20 receive; this evidence does not establish faster discovery.

A 14.76 MiB synthetic PNG sent through name-based discovery completed in
45.9 seconds at 0.32 MiB/s, using the then-default 12 Mbps data injection rate.
The phone returned HTTP 200 and opened the image correctly. Both latest tests
reported no transmit queue drops or backpressure, and normal teardown restored
managed Wi-Fi. These observations are not controlled benchmarks; throughput
also depends on the radio environment and advertised peer schedule.

Post-split tests sent the same 14.76 MiB synthetic image with discovery on
channel 6 and the radio tuned to channel 149 at 80 MHz. Payload PHY widths
are listed separately; each successful image opened correctly on the phone.

| Transmit mode | A-MSDU aggregation | Upload result |
| --- | --- | --- |
| Legacy 54 Mbps | Disabled | 41.5 s |
| HT MCS15, 20 MHz, short GI | Enabled | 25.3 s |
| VHT MCS7, two streams, 20 MHz, short GI | Enabled | 14.4 s |
| VHT MCS7, two streams, 80 MHz, short GI | Enabled | 21.5 s |
| VHT MCS8, two streams, 80 MHz, short GI | Enabled | 24.9 s |
| VHT MCS9, two streams, 80 MHz, either GI | Enabled | Long stalls; cancelled |

These comparisons preceded the MCS8 transmit ceiling. The phone remained
unlocked during the fixed-rate MCS9 failures. They narrow the problem to
MCS9 in this setup, but do not distinguish radio margin from a driver or
firmware issue. Advertised capability alone does not establish a reliable
injection rate; the selector currently has no delivery-based rate adaptation.
Captures, device identifiers and test filenames remain in ignored local directories.

The bounded TCP drain and five-second grace period allowed final success-reply
and FIN acknowledgments before teardown. Sessions then removed owned
AWDL/monitor interfaces, restored managed WLAN and unregistered BLE advertising.
Normal HTTP termination and recovery from missing termination are separately
verified; incomplete archives remain rejected.

Native Rust IBSS/shared-mode AirDrop, Contacts Only sending, Apple identity acquisition, broad OS-version compatibility and all media conversions are not
validated or implemented by this evidence. A different phone failing to see a
receiver is not automatically an identity problem: the exclusive schedule,
service TLVs, NSEC, BLE presence and neighbor learning all affect visibility.

## Source map

| Area | Source |
| --- | --- |
| Frame encoding/decoding, service TLVs | [protocol.rs](../crates/owl/src/protocol.rs) |
| Outgoing A-MSDU batching and injection retries | [tx.rs](../crates/owl/src/tx.rs) |
| PHY rate parsing and selection | [rate.rs](../crates/owl/src/rate.rs) |
| Clock and channel sequence | [channel.rs](../crates/owl/src/channel.rs) |
| Election, peer validity, traffic scheduling | [engine.rs](../crates/owl/src/engine.rs) |
| Capture, TAP, neighbor and radio workers | [runtime.rs](../crates/owl/src/runtime.rs) |
| Adapter profiles and restoration | [radio.rs](../crates/owl/src/radio.rs) |
| BLE wake scanning and advertising | [ble.rs](../crates/airdrop/src/ble.rs) |
| mDNS and scoped discovery candidates | [discovery.rs](../crates/airdrop/src/discovery.rs) |
| Certificates and optional Apple record | [identity.rs](../crates/airdrop/src/identity.rs) |
| Contacts Only identity policy | [contacts.rs](../crates/airdrop/src/contacts.rs) |
| Contact list management | [contact_book.rs](../crates/airdrop/src/contact_book.rs) |
| Runtime receiving visibility | [visibility.rs](../crates/airdrop/src/visibility.rs) |
| HTTPS Discover/Ask/Upload | [transfer.rs](../crates/airdrop/src/transfer.rs) |
| Archive encoding, validation and extraction | [archive.rs](../crates/airdrop/src/archive.rs) |
| Radio/AWDL link lifecycle | [link.rs](../crates/owl/src/link.rs) |
| Privileged lease server | [daemon.rs](../crates/owl/src/daemon.rs) |
| User link lease client | [link.rs](../crates/airdrop/src/link.rs) |
| Shared bounded link messages | [owl-ipc](../crates/owl-ipc/src/lib.rs) |
| UDP mDNS socket and receive metadata | [mdns.rs](../crates/airdrop/src/mdns.rs) |
| User-facing CLI | [main.rs](../crates/catdrop/src/main.rs) |
| AirDrop transport lifecycle | [transport.rs](../crates/airdrop/src/transport.rs) |
| CLI deadline parsing and defaults | [timeouts.rs](../crates/owl-ipc/src/timeouts.rs) |
| Shared lifetime leases and idle policy | [session.rs](../crates/airdrop/src/session.rs) |
| Coordinator and local control socket | [service.rs](../crates/airdrop/src/service.rs) |
