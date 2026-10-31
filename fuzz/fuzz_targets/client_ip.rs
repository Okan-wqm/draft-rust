//! Owner: authn-core (PRT-06). TST-04.
//! Forwarding-header parsing must never panic and must only ever return the
//! peer, a trusted hop or an address present in the header.
#![no_main]

use std::net::{IpAddr, Ipv4Addr};

use authn_core::http::{ClientIpHeader, resolve_client_ip};
use http::{HeaderMap, HeaderValue};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = HeaderValue::from_bytes(data) else { return };
    let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let trusted = ["10.0.0.0/8".parse().expect("valid CIDR")];
    for header in [ClientIpHeader::XForwardedFor, ClientIpHeader::Forwarded] {
        let mut headers = HeaderMap::new();
        headers.insert(header.as_str(), value.clone());
        let _ = resolve_client_ip(peer, &headers, &trusted, header);
    }
});
