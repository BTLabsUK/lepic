//! Address cases: the text a user or relay supplies, the network it is read on, and what upstream
//! makes of it. Accepted cases record every field and both printed forms.

use epic_util::secp::Secp256k1;
use epic_wallet_libwallet::{Address, EpicboxAddress};
use serde::Serialize;

use super::{ALICE, BOB, Network, TestKey, on_network, render, upstream_outcome};
use crate::{Error, Rendered, Upstream, hex};

#[derive(Serialize)]
struct Inputs<'a> {
    network: Network,
    text: &'a str,
}

/// `display` is upstream's `Display`, which is also the `from` and `to` form of `PostSlate`;
/// `json` is the address as it appears in the `destination` of an encrypted message.
#[derive(Serialize)]
struct Accepted {
    accepted: bool,
    public_key: String,
    public_key_hex: String,
    domain: String,
    port: Option<u16>,
    display: String,
    json: String,
}

#[derive(Serialize)]
struct Rejected {
    accepted: bool,
}

pub(super) struct Case {
    pub(super) name: &'static str,
    pub(super) network: Network,
    pub(super) text: String,
}

fn case(name: &'static str, network: Network, text: impl Into<String>) -> Case {
    Case {
        name,
        network,
        text: text.into(),
    }
}

pub(super) fn cases() -> Result<Vec<Case>, Error> {
    use Network::{Floonet, Mainnet};

    let alice = TestKey::new(ALICE)?;
    let bob = TestKey::new(BOB)?;
    let main = alice.address_key(Mainnet);
    let floo = alice.address_key(Floonet);

    let truncated: String = main.chars().take(51).collect();
    let mut bad_checksum = truncated.clone();
    bad_checksum.push(if main.ends_with('1') { '2' } else { '1' });
    let bad_character: String = main
        .chars()
        .enumerate()
        .map(|(at, c)| if at == 10 { '0' } else { c })
        .collect();

    Ok(vec![
        case("mainnet_key_only", Mainnet, main.clone()),
        case("mainnet_other_key", Mainnet, bob.address_key(Mainnet)),
        case(
            "mainnet_scheme_prefix",
            Mainnet,
            format!("epicbox://{main}"),
        ),
        case(
            "mainnet_domain",
            Mainnet,
            format!("{main}@relay.example.org"),
        ),
        case(
            "mainnet_default_domain_and_port",
            Mainnet,
            format!("{main}@epicbox.epiccash.com:443"),
        ),
        case(
            "mainnet_custom_port",
            Mainnet,
            format!("{main}@relay.example.org:13420"),
        ),
        case("mainnet_port_80", Mainnet, format!("{main}@localhost:80")),
        case(
            "mainnet_port_leading_zero",
            Mainnet,
            format!("{main}@relay.example.org:0443"),
        ),
        case(
            "mainnet_port_zero",
            Mainnet,
            format!("{main}@relay.example.org:0"),
        ),
        case(
            "mainnet_domain_case_kept",
            Mainnet,
            format!("{main}@Relay.Example.ORG"),
        ),
        case(
            "mainnet_scheme_domain_port",
            Mainnet,
            format!("epicbox://{main}@relay.example.org:13420"),
        ),
        case("floonet_key_only", Floonet, floo.clone()),
        case(
            "floonet_scheme_prefix",
            Floonet,
            format!("epicbox://{floo}"),
        ),
        case(
            "floonet_domain_port",
            Floonet,
            format!("{floo}@relay.example.org:13420"),
        ),
        case("invalid_floonet_key_on_mainnet", Mainnet, floo.clone()),
        case("invalid_mainnet_key_on_floonet", Floonet, main.clone()),
        case("invalid_checksum", Mainnet, bad_checksum),
        case("invalid_short_key", Mainnet, truncated),
        case("invalid_long_key", Mainnet, format!("{main}1")),
        case("invalid_non_base58_character", Mainnet, bad_character),
        case("invalid_hex_key", Mainnet, alice.public_hex()),
        case(
            "invalid_domain_character",
            Mainnet,
            format!("{main}@relay-1.example.org"),
        ),
        case("invalid_empty_domain", Mainnet, format!("{main}@")),
        case(
            "invalid_port_not_numeric",
            Mainnet,
            format!("{main}@relay.example.org:https"),
        ),
        case(
            "invalid_empty_port",
            Mainnet,
            format!("{main}@relay.example.org:"),
        ),
        case(
            "invalid_port_out_of_range",
            Mainnet,
            format!("{main}@relay.example.org:65536"),
        ),
        case("invalid_leading_space", Mainnet, format!(" {main}")),
        case("invalid_trailing_newline", Mainnet, format!("{main}\n")),
        case("invalid_scheme", Mainnet, format!("https://{main}")),
        case("invalid_empty", Mainnet, ""),
    ])
}

/// Upstream's verdict on a text is whether it yields an address.
pub(super) fn parse(network: Network, text: &str) -> Option<EpicboxAddress> {
    on_network(network, || {
        upstream_outcome(|| EpicboxAddress::from_str(text))
    })
}

fn accepted(network: Network, address: &EpicboxAddress) -> Result<Accepted, Error> {
    let public_key = on_network(network, || address.public_key())
        .map_err(Error::reference("address public key"))?;
    Ok(Accepted {
        accepted: true,
        public_key: address.public_key.clone(),
        public_key_hex: hex(public_key.serialize_vec(&Secp256k1::new(), true)),
        domain: address.domain.clone(),
        port: address.port,
        display: address.to_string(),
        json: serde_json::to_string(address)?,
    })
}

pub(super) fn generate(upstream: &Upstream) -> Result<Vec<Rendered>, Error> {
    cases()?
        .iter()
        .map(|case| {
            let name = format!("address_{}", case.name);
            let inputs = Inputs {
                network: case.network,
                text: &case.text,
            };
            match parse(case.network, &case.text) {
                Some(address) => render(&name, upstream, inputs, accepted(case.network, &address)?),
                None => render(&name, upstream, inputs, Rejected { accepted: false }),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_accepts_exactly_the_cases_not_named_invalid() -> Result<(), Error> {
        for case in cases()? {
            let accepted = parse(case.network, &case.text).is_some();
            assert_eq!(
                accepted,
                !case.name.starts_with("invalid_"),
                "{}",
                case.name
            );
        }
        Ok(())
    }

    #[test]
    fn display_reparses_to_the_same_address_except_an_explicit_443() -> Result<(), Error> {
        for case in cases()? {
            let Some(address) = parse(case.network, &case.text) else {
                continue;
            };
            let reparsed = parse(case.network, &address.to_string());
            let mut expected = address.clone();
            if expected.port == Some(443) {
                expected.port = None;
            }
            assert_eq!(reparsed, Some(expected), "{}", case.name);
        }
        Ok(())
    }
}
