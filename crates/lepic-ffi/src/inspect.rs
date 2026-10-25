//! Reading a slate the app holds as text, without a wallet.

use lepic_primitives::amount::Height;
use lepic_primitives::params::Network;
use lepic_transport::file::{FilePolicy, MAX_WIRE_SLATE_LEN};
use lepic_transport::policy::FormatPolicy as _;
use lepic_wallet::slate::{
    CodecRegistry, MediaType, Slate, Stage, V2JsonCodec, V3JsonCodec, WireOrigin, WireSlate,
};

use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::types::{SlateInfo, SlateMessage, SlateStage};

fn invalid_slate(message: impl Into<String>) -> WalletError {
    WalletError::new(WalletErrorKind::InvalidSlate, message)
}

/// Decodes `json` as `receive_slate` and `finalize_and_post` read slate text: by the file
/// method's rules, with the codecs and minimum fee of `network`.
pub(crate) fn inspect(json: String, network: Network) -> Result<SlateInfo, WalletError> {
    if json.len() > MAX_WIRE_SLATE_LEN {
        return Err(invalid_slate("slate text is longer than any slate"));
    }
    let base_fee = network.params().default_base_fee();
    let mut codecs = CodecRegistry::new();
    // Registration fails only for a duplicate id, and these ids differ.
    let _ = codecs.register(Box::new(V3JsonCodec::new(base_fee)));
    let _ = codecs.register(Box::new(V2JsonCodec::new(base_fee)));
    let slate = FilePolicy
        .decode(&codecs, &WireSlate::text(MediaType::JSON, json))
        .map_err(|error| WalletError::chained(WalletErrorKind::InvalidSlate, &error))?;
    slate_info(&slate)
}

fn slate_info(slate: &Slate) -> Result<SlateInfo, WalletError> {
    let version = slate
        .origin()
        .and_then(WireOrigin::legacy_header)
        .ok_or_else(|| invalid_slate("slate carries no version"))?
        .version;
    // Only messages whose signature verifies, made safe to display: the text is the other
    // party's and the app shows it before anything is signed.
    let messages = lepic_wallet::details::verified_messages(slate)
        .into_iter()
        .map(|message| SlateMessage {
            role: message.role.into(),
            text: message.text,
        })
        .collect();
    Ok(SlateInfo {
        slate_id: slate.id().to_string(),
        version,
        stage: match slate.stage() {
            Stage::S1 => SlateStage::S1,
            Stage::S2 => SlateStage::S2,
            Stage::S3 => SlateStage::S3,
            Stage::I1 => SlateStage::I1,
            Stage::I2 => SlateStage::I2,
            Stage::I3 => SlateStage::I3,
        },
        amount: slate.amount().value(),
        fee: slate.fee().value(),
        ttl_cutoff_height: slate.ttl_cutoff_height().map(Height::value),
        messages,
    })
}
