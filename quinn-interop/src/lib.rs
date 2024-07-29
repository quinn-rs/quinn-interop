use std::{convert::TryInto, sync::Arc, time::Duration};

use quinn::TransportConfig;

pub fn transport_config() -> Arc<TransportConfig> {
    let mut transport_config = TransportConfig::default();
    transport_config
        // quic-go's default, required for loss/corruption handling tests to pass reliably
        .max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()))
        .initial_rtt(Duration::from_millis(100))
        // Don't bother probing a known network environment, and avoid
        // https://github.com/quic-interop/quic-interop-runner/issues/398
        .mtu_discovery_config(None)
        // Known interface MTU, minus conservative IPv6 and UDP header sizes
        .initial_mtu(1500 - 40 - 8);
    Arc::new(transport_config)
}

pub const SUPPORTED_TESTS: &[&str] = &[
    "http3",
    "handshake",
    "transfer",
    "longrtt",
    "chacha20",
    "multiplexing",
    "retry",
    "resumption",
    "zerortt",
    "blackhole",
    "ecn",
    "amplificationlimit",
    "transferloss",
    "multiconnect",
    "transfercorruption",
    "ipv6",
    "goodput",
    "keyupdate",
    "crosstraffic",
];
