// SPDX-License-Identifier: GPL-3.0-or-later
use crate::visibility::{self, Policy};
use anyhow::{Context, Result};
use futures_util::StreamExt;
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use hickory_proto::{
    op::{Message, MessageType, Query},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{AAAA, NULL, PTR, SRV, TXT},
    },
};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    net::{Ipv6Addr, SocketAddrV6},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
#[derive(Clone, Debug, Serialize)]
pub struct Peer {
    pub id: String,
    pub address: SocketAddrV6,
    pub flags: u32,
    #[serde(skip)]
    seen: Option<Instant>,
}
impl Peer {
    /// A live AWDL neighbor may answer HTTPS before publishing mDNS records.
    pub fn from_awdl(mac: crate::protocol::Mac, scope: u32, expiry: Duration) -> Self {
        Self {
            id: mac.0.iter().map(|b| format!("{b:02x}")).collect(),
            address: SocketAddrV6::new(mac.ipv6(), 8770, 0, scope),
            flags: 128,
            seen: Some(Instant::now() + expiry),
        }
    }
}
#[derive(Clone, Default)]
pub struct Discovery {
    policy: Option<tokio::sync::watch::Receiver<Policy>>,
    timeouts: crate::timeouts::Timeouts,
    pub peers: Arc<RwLock<BTreeMap<String, Peer>>>,
}
pub fn scope(interface: &str) -> Result<u32> {
    Ok(
        std::fs::read_to_string(format!("/sys/class/net/{interface}/ifindex"))?
            .trim()
            .parse()?,
    )
}
impl Discovery {
    pub(crate) fn with_timeouts(mut self, timeouts: crate::timeouts::Timeouts) -> Self {
        self.timeouts = timeouts;
        self
    }
    pub(crate) fn with_policy(mut self, policy: tokio::sync::watch::Receiver<Policy>) -> Self {
        self.policy = Some(policy);
        self
    }
    pub async fn list(&self) -> Vec<Peer> {
        self.peers
            .read()
            .await
            .values()
            .filter(|p| p.seen.is_some_and(|t| t > Instant::now()))
            .cloned()
            .collect()
    }
    pub(crate) async fn run(
        &self,
        interface: &str,
        id: &str,
        address: Ipv6Addr,
        port: u16,
        cancel: CancellationToken,
        snapshot: tokio::sync::watch::Receiver<serde_json::Value>,
    ) -> Result<()> {
        let mut policy = self
            .policy
            .clone()
            .unwrap_or_else(|| tokio::sync::watch::channel(Policy::everyone()).1);
        let index = scope(interface)?;
        // Match the proven helper: multicast mDNS uses Ethernet directly on the
        // AWDL TAP, independent of host VPN policy routing. pcap owns the native I/O.
        let mac: crate::protocol::Mac =
            std::fs::read_to_string(format!("/sys/class/net/{interface}/address"))?
                .trim()
                .parse()?;
        let mut capture = pcap::Capture::from_device(interface)?
            .snaplen(65535)
            .immediate_mode(true)
            .timeout(self.timeouts.capture_read.as_millis().max(1) as i32)
            .open()?
            .setnonblock()?;
        anyhow::ensure!(
            capture.get_datalink() == pcap::Linktype::ETHERNET,
            "mDNS needs an Ethernet TAP"
        );
        capture.direction(pcap::Direction::In)?;
        capture.filter("ip6 and udp port 5353", true)?;
        let mut stream = capture.stream(DnsCodec)?;
        let group: Ipv6Addr = "ff02::fb".parse()?;
        let service = Name::from_ascii("_airdrop._tcp.local.")?;
        let instance = Name::from_ascii(format!("{id}._airdrop._tcp.local."))?;
        let host = Name::from_ascii(format!("{id}.local."))?;
        let mut query = Message::new();
        query.add_query(Query::query(service.clone(), RecordType::PTR));
        let query = query.to_vec()?;
        let mut answer = Message::new();
        answer
            .set_message_type(MessageType::Response)
            .set_authoritative(true);
        answer.add_answer(Record::from_rdata(
            service.clone(),
            4500,
            RData::PTR(PTR(instance.clone())),
        ));
        for (name, ttl, data) in [
            (
                instance.clone(),
                120,
                RData::SRV(SRV::new(0, 0, port, host.clone())),
            ),
            (
                instance,
                4500,
                RData::TXT(TXT::new(vec!["flags=137".into()])),
            ),
            (host.clone(), 120, RData::AAAA(AAAA(address))),
        ] {
            let mut record = Record::from_rdata(name, ttl, data);
            record.set_mdns_cache_flush(true);
            answer.add_answer(record);
        }
        // IPv4-negative answers let Apple's hostname resolver finish immediately.
        let mut nsec = Vec::new();
        {
            let mut encoder = BinEncoder::new(&mut nsec);
            encoder.set_canonical_names(true);
            host.emit(&mut encoder)?;
        }
        nsec.extend([0, 6, 0, 0, 0, 8, 0, 1]);
        let mut record = Record::from_rdata(
            host,
            120,
            RData::Unknown {
                code: RecordType::NSEC,
                rdata: NULL::with(nsec),
            },
        );
        record.set_mdns_cache_flush(true);
        answer.add_answer(record);
        let mut wire = Vec::new();
        {
            let mut encoder = BinEncoder::new(&mut wire);
            encoder.set_canonical_names(true);
            answer.emit(&mut encoder)?;
        }
        let answer = wire;
        let mut goodbye = Message::from_vec(&answer)?;
        for record in goodbye.answers_mut() {
            record.set_ttl(0);
        }
        let goodbye = goodbye.to_vec()?;
        let mut advertised = false;
        let started = Instant::now();
        let mut tick = tokio::time::interval(Duration::from_millis(17));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut step = 0u32;
        let mut last_reply = Instant::now() - Duration::from_secs(1);
        let mut addresses = BTreeMap::<String, (Ipv6Addr, Instant)>::new();
        let mut services = BTreeMap::<String, (String, u16, Instant)>::new();
        let mut flags = BTreeMap::<String, (u32, Instant)>::new();
        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    if advertised { let _ = stream.capture_mut().sendpacket(ethernet_dns(mac.0, address, group, &goodbye)?); }
                    return Ok(());
                }
                _ = visibility::changed(&mut policy) => {
                    if !policy.borrow().mode.enabled() && advertised {
                        stream.capture_mut().sendpacket(ethernet_dns(mac.0, address, group, &goodbye)?)?;
                        advertised = false;
                    }
                    step = 0;
                }
                _ = tick.tick() => {
                    if step == 0 {
                        let peers = snapshot.borrow().get("peers")
                            .and_then(serde_json::Value::as_array).cloned().unwrap_or_default();
                        for peer in peers.iter().take(512) {
                            if let Some(value) = peer.get("mac").and_then(serde_json::Value::as_str)
                                && let Ok(peer) = value.parse::<crate::protocol::Mac>()
                            {
                                let builder = etherparse::PacketBuilder::ethernet2(mac.0, peer.0)
                                    .ipv6(address.octets(), peer.ipv6().octets(), 255)
                                    .icmpv6_echo_request(0x4157, 0);
                                let mut packet = Vec::new();
                                builder.write(&mut packet, b"owl_rs")?;
                                stream.capture_mut().sendpacket(packet)?;
                            }
                        }
                    }
                    if step < 64 {
                        if policy.borrow().mode.enabled() {
                            stream.capture_mut().sendpacket(ethernet_dns(mac.0, address, group, &answer)?)?;
                            if !advertised {
                                tracing::debug!(elapsed_ms=started.elapsed().as_millis(), "first mDNS advertisement submitted to AWDL");
                            }
                            advertised = true;
                        }
                        if step.is_multiple_of(8) {
                            stream.capture_mut().sendpacket(ethernet_dns(mac.0, address, group, &query)?)?;
                        }
                    }
                    step = (step + 1) % 176;
                }
                packet = stream.next() => {
                    let packet = packet.context("mDNS capture ended")??;
                    let Ok(parsed) = etherparse::SlicedPacket::from_ethernet(&packet) else { continue; };
                    let Some(etherparse::NetSlice::Ipv6(ip)) = parsed.net else { continue; };
                    if !ip.header().source_addr().is_unicast_link_local()
                        || ip.header().source_addr() == address || ip.header().hop_limit() != 255
                    {
                        continue;
                    }
                    let Some(etherparse::TransportSlice::Udp(udp)) = parsed.transport else { continue; };
                    if udp.source_port() != 5353 || udp.destination_port() != 5353 { continue; }
                    let Ok(msg) = Message::from_vec(udp.payload()) else { continue; };
                    if policy.borrow().mode.enabled() && last_reply.elapsed() >= Duration::from_millis(100)
                        && msg.queries().iter().any(|q| q.name() == &service || q.name().to_ascii().starts_with(id))
                    {
                        stream.capture_mut().sendpacket(ethernet_dns(mac.0, address, group, &answer)?)?;
                        last_reply = Instant::now();
                        advertised = true;
                        tracing::debug!(elapsed_ms=started.elapsed().as_millis(), "answered incoming AirDrop mDNS query");
                    }
                    for record in msg.answers().iter().chain(msg.additionals()).chain(msg.name_servers()) {
                        let name = record.name().to_ascii().to_lowercase();
                        if record.ttl() == 0 {
                            addresses.remove(&name);
                            services.remove(&name);
                            flags.remove(&name);
                            continue;
                        }
                        let expiry = Instant::now() + Duration::from_secs(u64::from(record.ttl())).min(self.timeouts.discovery_cache);
                        match record.data() {
                            RData::AAAA(AAAA(ip)) if ip.is_unicast_link_local() => {
                                if addresses.len() < 512 || addresses.contains_key(&name) {
                                    addresses.insert(name, (*ip, expiry));
                                }
                            }
                            RData::SRV(srv) if name.ends_with("._airdrop._tcp.local.") => {
                                if services.len() < 512 || services.contains_key(&name) {
                                    services.insert(name, (srv.target().to_ascii().to_lowercase(), srv.port(), expiry));
                                }
                            }
                            RData::TXT(txt) if name.ends_with("._airdrop._tcp.local.") => {
                                if (flags.len() < 512 || flags.contains_key(&name))
                                    && let Some(value) = txt.txt_data().iter().find_map(|v| {
                                        std::str::from_utf8(v).ok()?.strip_prefix("flags=")?.parse().ok()
                                    })
                                {
                                    flags.insert(name, (value, expiry));
                                }
                            }
                            _ => (),
                        }
                    }
                    let now = Instant::now();
                    addresses.retain(|_, (_, expiry)| *expiry > now);
                    services.retain(|_, (_, _, expiry)| *expiry > now);
                    flags.retain(|_, (_, expiry)| *expiry > now);
                    let mut peers = self.peers.write().await;
                    peers.clear();
                    for (name, (target, port, service_expiry)) in &services {
                        if let Some((ip, address_expiry)) = addresses.get(target) {
                            let peer_id = name.trim_end_matches("._airdrop._tcp.local.");
                            if peer_id != id {
                                peers.insert(peer_id.into(), Peer {
                                    id: peer_id.into(), address: SocketAddrV6::new(*ip, *port, 0, index),
                                    flags: flags.get(name).map(|(value, _)| *value).unwrap_or(137),
                                    seen: Some(*service_expiry.min(address_expiry)),
                                });
                            }
                        }
                    }
                }
            }
        }
    }
}

struct DnsCodec;
impl pcap::PacketCodec for DnsCodec {
    type Item = Vec<u8>;
    fn decode(&mut self, packet: pcap::Packet<'_>) -> Vec<u8> {
        packet.data.to_vec()
    }
}
fn ethernet_dns(
    mac: [u8; 6],
    source: Ipv6Addr,
    destination: Ipv6Addr,
    dns: &[u8],
) -> Result<Vec<u8>> {
    let builder = etherparse::PacketBuilder::ethernet2(mac, [0x33, 0x33, 0, 0, 0, 0xfb])
        .ipv6(source.octets(), destination.octets(), 255)
        .udp(5353, 5353);
    let mut frame = Vec::with_capacity(builder.size(dns.len()));
    builder.write(&mut frame, dns)?;
    anyhow::ensure!(frame.len() <= 1514, "mDNS announcement exceeds AWDL MTU");
    Ok(frame)
}
