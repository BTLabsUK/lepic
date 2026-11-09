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
mod tests;
