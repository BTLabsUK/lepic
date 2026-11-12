// SPDX-License-Identifier: Apache-2.0
//! An Epicbox address a chat app made into a link.
//!
//! Pasted from a chat, `key@relay` often arrives as `https://key@relay/`. That text is the
//! Epicbox address, not a wallet URL. The check is by shape (the key's checksum is the address
//! parser's to check), so a real wallet URL never matches: it has no key in its user part, or a
//! port, a path or a query.

/// The shortest key text that can be an Epicbox key (a full one has 52 characters).
const MIN_KEY_LEN: usize = 40;

/// The Epicbox address (`key@relay`) in `text` when `text` is `http://` or `https://`, an
/// Epicbox key, `@`, a relay name with a dot and at most one `/`; `None` for anything else.
/// The scheme is read in any case; the key and relay are returned as written.
#[must_use]
pub fn epicbox_of_link(text: &str) -> Option<&str> {
    let text = text.trim();
    let rest = strip_scheme(text, "https://").or_else(|| strip_scheme(text, "http://"))?;
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let (key, relay) = rest.split_once('@')?;
    let key_ok = key.len() >= MIN_KEY_LEN && key.bytes().all(is_base58);
    let relay_ok = relay.contains('.')
        && !relay.starts_with('.')
        && !relay.ends_with('.')
        && relay
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        && relay
            .rsplit('.')
            .next()
            .is_some_and(|tld| tld.bytes().any(|b| b.is_ascii_alphabetic()));
    (key_ok && relay_ok).then_some(rest)
}

/// Whether [`epicbox_of_link`] finds an Epicbox address in `text`.
#[must_use]
pub fn is_epicbox_link(text: &str) -> bool {
    epicbox_of_link(text).is_some()
}

fn strip_scheme<'a>(text: &'a str, scheme: &str) -> Option<&'a str> {
    let head = text.get(..scheme.len())?;
    head.eq_ignore_ascii_case(scheme)
        .then(|| &text[scheme.len()..])
}

fn is_base58(b: u8) -> bool {
    b.is_ascii_alphanumeric() && !matches!(b, b'0' | b'O' | b'I' | b'l')
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "esbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn a_linked_address_is_the_address() {
        let address = format!("{KEY}@epicbox.epiccash.com");
        for text in [
            format!("http://{address}"),
            format!("https://{address}"),
            format!("https://{address}/"),
            format!("HTTPS://{address}"),
            format!(" https://{address}\n"),
        ] {
            assert_eq!(epicbox_of_link(&text), Some(address.as_str()), "{text}");
        }
    }

    #[test]
    fn a_wallet_url_is_not() {
        for text in [
            "http://192.168.1.5:3415",
            "https://wallet.example.org",
            "http://wallet.example.org:3415/",
            &format!("https://{KEY}@epicbox.epiccash.com/path"),
            &format!("https://{KEY}@epicbox.epiccash.com?x=1"),
            &format!("https://{KEY}@epicbox.epiccash.com:443"),
            &format!("https://{KEY}0@epicbox.epiccash.com"),
            "https://short@epicbox.epiccash.com",
            &format!("https://{KEY}@10.0.0.1"),
            &format!("{KEY}@epicbox.epiccash.com"),
            "",
        ] {
            assert_eq!(epicbox_of_link(text), None, "{text}");
        }
    }
}
