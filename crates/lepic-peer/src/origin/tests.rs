use super::*;

const ONION: &str = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";

#[test]
fn origins_are_scheme_lowercased_host_and_explicit_port() {
    let origin = Origin::new(WebScheme::Https, "Wallet.Example.", 443).unwrap();
    assert_eq!(origin.to_string(), "https://wallet.example:443");
    assert_eq!(
        Origin::parse("HTTPS://WALLET.example:443/").unwrap(),
        origin
    );
    let ipv6 = Origin::new(WebScheme::Http, "[::1]", 3415).unwrap();
    assert_eq!(ipv6.to_string(), "http://[::1]:3415");
    assert_eq!(Origin::parse("http://[::1]:3415").unwrap(), ipv6);
    assert_ne!(
        Origin::new(WebScheme::Http, "wallet.example", 443).unwrap(),
        origin
    );
}

#[test]
fn an_onion_origin_is_its_name_whatever_reached_it() {
    let upper = ONION.to_uppercase();
    let by_http = Origin::new(WebScheme::Http, &upper, 80).unwrap();
    let by_https = Origin::new(WebScheme::Https, ONION, 3415).unwrap();
    assert_eq!(by_http, by_https);
    assert_eq!(by_http.to_string(), ONION);
    assert!(by_http.is_onion());
    assert_eq!(Origin::parse(ONION).unwrap(), by_http);
    assert_eq!(
        Origin::parse(&format!("http://{ONION}:80")).unwrap(),
        by_http
    );
}

#[test]
fn refuses_origins_without_scheme_port_or_host() {
    for (text, error) in [
        ("wallet.example:443", OriginError::Scheme),
        ("ftp://wallet.example:21", OriginError::Scheme),
        ("https://wallet.example", OriginError::Port),
        ("https://wallet.example:0", OriginError::Port),
        ("https://wallet.example:x", OriginError::Port),
        ("https://:443", OriginError::NoHost),
        ("https://wal let:443", OriginError::Host),
        ("https://wallet.example/path:443", OriginError::Host),
        ("", OriginError::NoHost),
    ] {
        assert_eq!(Origin::parse(text), Err(error), "{text}");
    }
}

#[test]
fn targets_join_the_advert_path() {
    let target = PeerTarget::new(WebScheme::Http, "Wallet.Example", 3415, "/api/v1/inbox").unwrap();
    assert_eq!(target.info_uri(), "http://wallet.example:3415/api/v1/inbox");
    assert_eq!(
        target.envelope_uri(),
        "http://wallet.example:3415/api/v1/inbox"
    );
    assert_eq!(target.origin().to_string(), "http://wallet.example:3415");
    assert_eq!(
        PeerTarget::new(WebScheme::Http, "wallet.example", 3415, "api/v1/inbox"),
        Err(OriginError::Path)
    );
}
