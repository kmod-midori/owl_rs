// SPDX-License-Identifier: GPL-3.0-or-later
//! Application deadlines, configured in seconds on the main command line.
use clap::Args;
use serde::{Deserialize, Serialize};
use std::time::Duration;

fn seconds(value: &str) -> Result<Duration, String> {
    let value = value
        .parse::<f64>()
        .map_err(|_| "use seconds, optionally fractional")?;
    if !value.is_finite() || !(0.0..=86400.0).contains(&value) {
        return Err("use finite seconds from 0 to 86400".into());
    }
    Duration::try_from_secs_f64(value).map_err(|error| error.to_string())
}
fn positive(value: &str) -> Result<Duration, String> {
    let duration = seconds(value)?;
    if duration.is_zero() {
        return Err("timeout must be greater than zero".into());
    }
    Ok(duration)
}
mod duration {
    use super::*;
    pub fn serialize<S: serde::Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_f64(d.as_secs_f64())
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let value = f64::deserialize(d)?;
        seconds(&value.to_string()).map_err(serde::de::Error::custom)
    }
}
macro_rules! deadlines {
    ($($field:ident, $flag:literal, $default:literal, $help:literal;)+) => {
        #[derive(Clone, Copy, Debug, Args, Serialize, Deserialize)]
        #[serde(default, deny_unknown_fields)]
        pub struct Timeouts {
            /// Quiet time after the final successful transfer and TCP drain.
            #[arg(long, global = true, help_heading="Timeouts (seconds)", default_value="5", value_name="SECONDS", value_parser=seconds)]
            #[serde(with="duration")]
            pub completion_grace: Duration,
            $(#[doc=$help]
            #[arg(long=$flag, global=true, help_heading="Timeouts (seconds)", default_value=$default, value_name="SECONDS", value_parser=positive)]
            #[serde(with="duration")]
            pub $field: Duration,)+
        }
        impl Default for Timeouts {
            fn default() -> Self { Self { completion_grace: Duration::from_secs(5), $($field: positive($default).unwrap(),)+ } }
        }
        impl Timeouts {
            pub fn explicit(matches: &clap::ArgMatches) -> bool {
                matches.value_source("completion_grace") == Some(clap::parser::ValueSource::CommandLine)
                    $(|| matches.value_source(stringify!($field)) == Some(clap::parser::ValueSource::CommandLine))+
            }
            pub fn validate(&self) -> anyhow::Result<()> {
                $(anyhow::ensure!(!self.$field.is_zero() && self.$field <= Duration::from_secs(86400), concat!("invalid ", $flag));)+
                anyhow::ensure!(self.completion_grace <= Duration::from_secs(86400), "invalid completion grace");
                anyhow::ensure!(self.upload_check <= self.upload_idle, "upload check interval must not exceed upload idle timeout");
                anyhow::ensure!(self.radio_quiet <= self.radio_drain, "radio quiet period must not exceed radio drain timeout");
                Ok(())
            }
        }
    }
}
deadlines! {
    retry_cache, "retry-cache-timeout", "0.5", "802.11 retry duplicate-cache lifetime.";
    capture_read, "capture-read-timeout", "0.001", "Packet capture read timeout (minimum resolution: one millisecond).";
    peer_idle, "peer-idle-timeout", "5", "AWDL neighbor inactivity deadline.";
    queued_packet, "queued-packet-timeout", "2", "Queued AWDL packet expiry.";
    discovery_cache, "discovery-cache-timeout", "120", "Local mDNS cache lifetime cap.";
    discovery_fallback, "discovery-fallback-timeout", "2", "Transient AWDL fallback discovery candidate lifetime.";
    ble_idle, "ble-idle-timeout", "120", "Idle session lifetime after an eligible BLE wake.";
    tcp_connect, "tcp-connect-timeout", "15", "Outgoing TCP connection deadline.";
    tls_handshake, "tls-handshake-timeout", "10", "Incoming TLS handshake deadline.";
    tls_connect, "tls-connect-timeout", "15", "Outgoing TLS handshake deadline.";
    http_headers, "http-header-timeout", "20", "Incoming HTTP header deadline.";
    http_request, "http-request-timeout", "15", "Outgoing Discover response deadline.";
    metadata_idle, "metadata-timeout", "20", "Plist/response body stall deadline.";
    approval, "approval-timeout", "60", "Incoming manual approval and outgoing Ask deadline.";
    upload_idle, "upload-idle-timeout", "20", "Incoming upload stall deadline.";
    upload_total, "upload-timeout", "600", "Incoming and outgoing upload deadline.";
    upload_check, "upload-check-interval", "2", "Quiet interval before checking for a complete archive without an HTTP terminator.";
    connection_drain, "connection-drain-timeout", "5", "Successful HTTP/TLS close deadline.";
    rejection_drain, "rejection-drain-timeout", "2", "Refusal response close deadline.";
    tcp_linger, "tcp-linger-timeout", "10", "Successful final TCP acknowledgment drain bound.";
    control_request, "control-request-timeout", "10", "Control socket request header deadline.";
    control_archive, "control-archive-timeout", "600", "Control socket archive receive deadline.";
    transport_shutdown, "transport-shutdown-timeout", "2", "Transport task shutdown deadline.";
    name_probe, "name-probe-timeout", "8", "Per-peer HTTPS name resolution deadline.";
    netlink, "netlink-timeout", "5", "Kernel netlink request deadline.";
    network_manager, "network-manager-timeout", "15", "NetworkManager setup and restoration command deadline.";
    reconnect, "reconnect-timeout", "10", "NetworkManager saved-AP reconnection wait.";
    ibss_ready, "ibss-ready-timeout", "10", "Ad-hoc cell readiness deadline.";
    ibss_tune, "ibss-tune-timeout", "15", "Ad-hoc channel retuning deadline.";
    radio_startup, "radio-startup-timeout", "15", "AWDL runtime startup deadline.";
    address_ready, "address-ready-timeout", "5", "AWDL IPv6 address readiness deadline.";
    radio_drain, "radio-drain-timeout", "2", "AWDL transmit queue shutdown deadline.";
    radio_quiet, "radio-quiet-period", "0.1", "Quiet period before ending AWDL queue drain.";
    ble_retry, "ble-retry-interval", "30", "BLE scan/advertisement retry interval.";
    ble_power_restore, "ble-power-restore-timeout", "5", "BLE adapter power restoration deadline.";
}
