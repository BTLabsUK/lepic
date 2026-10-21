//! The decrypted Epicbox payload as the inbox classifies it, and the invoice message as a host
//! displays it.

#![no_main]

use lepic_wallet::epicbox_invoice::display_message;
use lepic_wallet::notice::{MAX_NOTICE_LEN, Payload, classify_text};
use lepic_slate::model::MAX_MESSAGE_LEN;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    match classify_text(text) {
        Payload::Notice(notice) => {
            assert!(
                text.len() <= MAX_NOTICE_LEN,
                "a notice longer than the bound was accepted"
            );
            let written = notice.encode();
            let again = written.as_text().map(classify_text);
            assert_eq!(
                again,
                Some(Payload::Notice(notice)),
                "an accepted notice does not read back from what it writes"
            );
        }
        Payload::Oversize => assert!(
            text.len() > MAX_NOTICE_LEN,
            "a short payload was called oversize"
        ),
        Payload::Slate | Payload::Unknown | Payload::Malformed => {}
    }
    let shown = display_message(text);
    assert!(
        shown.len() <= MAX_MESSAGE_LEN,
        "a displayed message is longer than the message bound"
    );
    assert!(
        !shown.chars().any(char::is_control),
        "a displayed message kept a control character"
    );
});
