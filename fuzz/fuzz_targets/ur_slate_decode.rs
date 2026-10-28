//! Scanned `ur:epic-slate` QR texts, one per line, through the stateless decoder. A complete
//! code must yield bounded JSON text that encodes and decodes to itself.

#![no_main]

use lepic_slate::ur_slate::{MAX_SLATE_TEXT_LEN, decode_ur_slate, encode_ur_slate};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let parts: Vec<&str> = text.split('\n').collect();
    let Ok(progress) = decode_ur_slate(&parts) else {
        return;
    };
    assert!(
        progress.resolved_fragments <= progress.fragment_count,
        "more fragments resolved than the code has"
    );
    let Some(json) = progress.json else {
        return;
    };
    assert!(
        json.len() <= MAX_SLATE_TEXT_LEN,
        "decoded text is over the limit"
    );
    if let Ok(parts) = encode_ur_slate(&json, 200) {
        let again = decode_ur_slate(&parts)
            .ok()
            .and_then(|progress| progress.json);
        assert_eq!(
            again.as_deref(),
            Some(json.as_str()),
            "a decoded code re-encodes to itself"
        );
    }
});
