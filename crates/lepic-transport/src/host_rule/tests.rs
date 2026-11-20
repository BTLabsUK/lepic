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
