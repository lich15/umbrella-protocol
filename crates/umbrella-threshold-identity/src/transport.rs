//! # Resilient transport selector
//!
//! Реализует fallback цепочку: TLS direct → Tor SOCKS proxy → mixnet →
//! alternative IPs. Каждый subsequent fallback добавляет latency, но устраняет
//! одну из network-level censorship методов.
//!
//! Resilient transport: TLS direct → Tor → mixnet → alt-IP fallback chain.
//! Latency degradation per fallback step.

use std::time::Duration;

/// Transport channel — abstract representation для тестов и runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportChannel {
    /// HTTPS prepared by `rustls` + system DNS. Lowest latency (~50ms).
    DirectTls,
    /// Tor SOCKS proxy (default port 9050). ~500ms RTT, ~200kbps.
    TorSocks,
    /// Optional Nym mixnet (research-grade). ~2s RTT.
    Mixnet,
    /// Hard-coded alternative IPs of our 5 servers (bypasses DNS censorship).
    /// Latency comparable to DirectTls; only used when system DNS fails.
    AlternativeIp,
}

impl TransportChannel {
    /// Returns expected RTT for this channel in milliseconds (rough estimate).
    pub fn expected_rtt_ms(self) -> u64 {
        match self {
            Self::DirectTls => 50,
            Self::AlternativeIp => 80,
            Self::TorSocks => 500,
            Self::Mixnet => 2000,
        }
    }
}

/// Selector that walks the fallback chain in order. Returns the first channel
/// that successfully passed `probe()`.
pub struct TransportSelector {
    /// Order tried — first channel checked first.
    pub fallback_chain: Vec<TransportChannel>,
    /// Per-channel probe timeout.
    pub probe_timeout: Duration,
}

impl Default for TransportSelector {
    fn default() -> Self {
        Self {
            fallback_chain: vec![
                TransportChannel::DirectTls,
                TransportChannel::AlternativeIp,
                TransportChannel::TorSocks,
                TransportChannel::Mixnet,
            ],
            probe_timeout: Duration::from_secs(5),
        }
    }
}

/// Result of probing one channel. Production code uses a real `Probe` impl
/// (e.g. TCP connect to `umbrellax.io:443`). Tests inject a deterministic
/// mock.
pub trait ChannelProbe {
    /// Returns true iff the channel reaches a Umbrella server within `timeout`.
    fn probe(&self, channel: TransportChannel, timeout: Duration) -> bool;
}

impl TransportSelector {
    /// Walks `fallback_chain` and returns the first channel that probes true.
    /// Returns `None` if all channels failed.
    pub fn pick<P: ChannelProbe>(&self, probe: &P) -> Option<TransportChannel> {
        for &channel in &self.fallback_chain {
            if probe.probe(channel, self.probe_timeout) {
                return Some(channel);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedProbe(Vec<TransportChannel>);

    impl ChannelProbe for FixedProbe {
        fn probe(&self, channel: TransportChannel, _timeout: Duration) -> bool {
            self.0.contains(&channel)
        }
    }

    #[test]
    fn prefers_direct_tls_when_available() {
        let sel = TransportSelector::default();
        let probe = FixedProbe(vec![
            TransportChannel::DirectTls,
            TransportChannel::AlternativeIp,
            TransportChannel::TorSocks,
        ]);
        assert_eq!(sel.pick(&probe), Some(TransportChannel::DirectTls));
    }

    #[test]
    fn falls_back_to_tor_when_direct_blocked() {
        let sel = TransportSelector::default();
        let probe = FixedProbe(vec![TransportChannel::TorSocks]);
        assert_eq!(sel.pick(&probe), Some(TransportChannel::TorSocks));
    }

    #[test]
    fn falls_back_to_alt_ip_when_dns_blocked() {
        let sel = TransportSelector::default();
        let probe = FixedProbe(vec![
            TransportChannel::AlternativeIp,
            TransportChannel::Mixnet,
        ]);
        assert_eq!(sel.pick(&probe), Some(TransportChannel::AlternativeIp));
    }

    #[test]
    fn returns_none_when_all_blocked() {
        let sel = TransportSelector::default();
        let probe = FixedProbe(vec![]);
        assert_eq!(sel.pick(&probe), None);
    }

    #[test]
    fn rtt_ordering_is_monotonic() {
        // DirectTls fastest, mixnet slowest.
        assert!(
            TransportChannel::DirectTls.expected_rtt_ms()
                <= TransportChannel::AlternativeIp.expected_rtt_ms()
        );
        assert!(
            TransportChannel::AlternativeIp.expected_rtt_ms()
                <= TransportChannel::TorSocks.expected_rtt_ms()
        );
        assert!(
            TransportChannel::TorSocks.expected_rtt_ms()
                <= TransportChannel::Mixnet.expected_rtt_ms()
        );
    }
}
