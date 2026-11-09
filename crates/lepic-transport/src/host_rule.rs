// SPDX-License-Identifier: Apache-2.0
//! The host rule for hosts that come from untrusted input (RFC 0003 §5.14, Appendix B.2).
//!
//! A relay named in a payment link is the sender's choice, so the host is classified before the
//! client connects:
//!
//! - **Loopback** is refused: `localhost` and every name under it, 127.0.0.0/8, `::1`, the
//!   IPv4-mapped (`::ffff:a.b.c.d`) and IPv4-compatible (`::a.b.c.d`) forms of those, and the
//!   unspecified addresses `0.0.0.0` and `::`, which connect to the local machine on common
//!   systems.
//! - **Local network** is allowed and shown to the user: 10.0.0.0/8, 172.16.0.0/12,
//!   192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10, fc00::/7 and fe80::/10 (also through the
//!   IPv4-mapped form), and names ending in `.local`.
//! - Everything else is **public**.
//!
//! [`classify_name`] looks at the text before resolving. [`classify_addr`] and
//! [`classify_resolved`] look at addresses. The check that protects against DNS rebinding must
//! run on the addresses the client actually connects to, at connect time: classifying a lookup
//! made earlier and then connecting by name resolves the name a second time and can reach a
//! different address. Callers resolve once, classify those addresses, and connect to them.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use thiserror::Error;

/// Where a host that was not refused sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostClass {
    Public,
    LocalNetwork,
}

/// A host the client never connects to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum RefusedHost {
    #[error("the host is a loopback or unspecified address")]
    Loopback,
}

/// What the consumer is shown about a relay host before a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostReport {
    pub host: String,
    pub port: u16,
    /// Whether the host is in the relay list. Filled by the caller.
    pub in_relay_list: bool,
    pub class: HostClass,
}

/// Classifies a host name or literal before it is resolved. An IP literal is classified as an
/// address. Case and one trailing dot are ignored. A name that is neither `localhost`, under
/// it, nor ending in `.local` is public here: its addresses decide after resolving.
pub fn classify_name(name: &str) -> Result<HostClass, RefusedHost> {
    let name = name.strip_suffix('.').unwrap_or(name);
    let bare = name
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(name);
    if let Ok(addr) = bare.parse::<IpAddr>() {
        return classify_addr(addr);
    }
    let lower = name.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") {
        return Err(RefusedHost::Loopback);
    }
    if lower == "local" || lower.ends_with(".local") {
        return Ok(HostClass::LocalNetwork);
    }
    Ok(HostClass::Public)
}

/// Classifies one address.
pub fn classify_addr(addr: IpAddr) -> Result<HostClass, RefusedHost> {
    match addr {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

/// Classifies a name by the addresses it resolved to: refused when any address is loopback or
/// unspecified, local network when any is local, public otherwise. The name is checked first,
/// so `localhost` is refused whatever it resolves to. No addresses classify as the name does.
pub fn classify_resolved(name: &str, addrs: &[IpAddr]) -> Result<HostClass, RefusedHost> {
    let mut class = classify_name(name)?;
    for addr in addrs {
        if classify_addr(*addr)? == HostClass::LocalNetwork {
            class = HostClass::LocalNetwork;
        }
    }
    Ok(class)
}

fn classify_v4(addr: Ipv4Addr) -> Result<HostClass, RefusedHost> {
    if addr.is_loopback() || addr.is_unspecified() {
        return Err(RefusedHost::Loopback);
    }
    let [a, b, ..] = addr.octets();
    let local = a == 10
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 169 && b == 254)
        || (a == 100 && (64..=127).contains(&b));
    Ok(if local {
        HostClass::LocalNetwork
    } else {
        HostClass::Public
    })
}

fn classify_v6(addr: Ipv6Addr) -> Result<HostClass, RefusedHost> {
    if addr.is_loopback() || addr.is_unspecified() {
        return Err(RefusedHost::Loopback);
    }
    if let Some(v4) = embedded_v4(addr) {
        return classify_v4(v4);
    }
    let first = addr.segments().first().copied().unwrap_or(0);
    let local = (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80;
    Ok(if local {
        HostClass::LocalNetwork
    } else {
        HostClass::Public
    })
}

/// The IPv4 address inside an IPv4-mapped (`::ffff:a.b.c.d`) or IPv4-compatible (`::a.b.c.d`)
/// address. `::` and `::1` are handled before, so a compatible form here has a non-zero IPv4
/// part above 0.0.0.1.
fn embedded_v4(addr: Ipv6Addr) -> Option<Ipv4Addr> {
    let [s0, s1, s2, s3, s4, s5, hi, lo] = addr.segments();
    let [a, b] = hi.to_be_bytes();
    let [c, d] = lo.to_be_bytes();
    let zero_prefix = s0 == 0 && s1 == 0 && s2 == 0 && s3 == 0 && s4 == 0;
    (zero_prefix && (s5 == 0xffff || s5 == 0)).then(|| Ipv4Addr::new(a, b, c, d))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn loopback_and_unspecified_are_refused() {
        for text in [
            "127.0.0.1",
            "127.255.255.254",
            "127.1.2.3",
            "0.0.0.0",
            "::1",
            "::",
            "::ffff:127.0.0.1",
            "::ffff:7f00:1",
            "::127.0.0.1",
            "::ffff:0.0.0.0",
            "0:0:0:0:0:ffff:7f12:3456",
        ] {
            assert_eq!(
                classify_addr(addr(text)),
                Err(RefusedHost::Loopback),
                "{text}"
            );
        }
    }

    #[test]
    fn local_network_ranges() {
        for text in [
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "192.168.255.255",
            "169.254.1.1",
            "100.64.0.1",
            "100.127.255.255",
            "fc00::1",
            "fd12:3456::1",
            "fdff::1",
            "fe80::1",
            "febf::1",
            "::ffff:10.0.0.1",
            "::ffff:192.168.1.1",
            "::ffff:169.254.0.1",
            "::ffff:100.64.0.1",
            "::10.0.0.1",
        ] {
            assert_eq!(
                classify_addr(addr(text)),
                Ok(HostClass::LocalNetwork),
                "{text}"
            );
        }
    }

    #[test]
    fn range_edges_are_public() {
        for text in [
            "9.255.255.255",
            "11.0.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "192.167.255.255",
            "192.169.0.0",
            "169.253.255.255",
            "169.255.0.0",
            "100.63.255.255",
            "100.128.0.0",
            "128.0.0.1",
            "126.255.255.255",
            "8.8.8.8",
            "1.1.1.1",
            "2606:4700::1111",
            "2001:db8::1",
            "fbff::1",
            "fe00::1",
            "fec0::1",
            "::ffff:8.8.8.8",
            "::8.8.8.8",
            "::2",
        ] {
            assert_eq!(classify_addr(addr(text)), Ok(HostClass::Public), "{text}");
        }
    }

    #[test]
    fn names_before_resolving() {
        for name in [
            "localhost",
            "LOCALHOST",
            "localhost.",
            "a.localhost",
            "a.b.LocalHost",
            "a.localhost.",
            "127.0.0.1",
            "[::1]",
            "::1",
            "0.0.0.0",
        ] {
            assert_eq!(classify_name(name), Err(RefusedHost::Loopback), "{name}");
        }
        for name in [
            "printer.local",
            "PRINTER.LOCAL",
            "a.b.local.",
            "local",
            "192.168.1.5",
            "[fe80::1]",
            "10.1.2.3",
        ] {
            assert_eq!(classify_name(name), Ok(HostClass::LocalNetwork), "{name}");
        }
        for name in [
            "relay.example.com",
            "localhost.example.com",
            "mylocalhost",
            "notlocal",
            "local.example.com",
            "8.8.8.8",
            "",
        ] {
            assert_eq!(classify_name(name), Ok(HostClass::Public), "{name}");
        }
    }

    #[test]
    fn resolved_addresses_decide() {
        let public = addr("8.8.8.8");
        let local = addr("192.168.1.2");
        let loopback = addr("127.0.0.1");
        let name = "relay.example.com";
        assert_eq!(classify_resolved(name, &[public]), Ok(HostClass::Public));
        assert_eq!(classify_resolved(name, &[]), Ok(HostClass::Public));
        assert_eq!(
            classify_resolved(name, &[public, local]),
            Ok(HostClass::LocalNetwork)
        );
        assert_eq!(
            classify_resolved(name, &[local, public]),
            Ok(HostClass::LocalNetwork)
        );
        assert_eq!(
            classify_resolved(name, &[public, loopback]),
            Err(RefusedHost::Loopback)
        );
        assert_eq!(
            classify_resolved(name, &[loopback, local, public]),
            Err(RefusedHost::Loopback)
        );
        assert_eq!(
            classify_resolved(name, &[addr("::")]),
            Err(RefusedHost::Loopback)
        );
        assert_eq!(
            classify_resolved("printer.local", &[public]),
            Ok(HostClass::LocalNetwork)
        );
        assert_eq!(
            classify_resolved("localhost", &[public]),
            Err(RefusedHost::Loopback)
        );
    }

    #[test]
    fn report_carries_what_the_caller_filled() {
        let report = HostReport {
            host: "relay.example.com".to_owned(),
            port: 443,
            in_relay_list: true,
            class: HostClass::Public,
        };
        assert!(report.in_relay_list);
        assert_eq!(report.clone(), report);
    }
}
