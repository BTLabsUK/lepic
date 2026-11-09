// SPDX-License-Identifier: Apache-2.0
//! The receiving side of the foreign API listeners of the HTTP and Tor methods: one
//! [`ReceiveHandler`] that turns a slate on the wire into the engine's receive, and the class
//! a failed receive is answered with.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use lepic_keychain::Identifier;
use lepic_legacy_rpc::{BlockFees, CoinbaseAnswer, ReceiveHandler, Refusal};
use lepic_primitives::amount::{Fee, Height};
use lepic_slate::codec::WireSlate;
use lepic_transport::method::Method;
use lepic_transport::transport::BoxFuture;
use lepic_wallet::coinbase::{Coinbase, CoinbaseRequest};
use lepic_wallet::{ProofKey, ReceiveError, ReceiveRequest, Received, WalletError};

/// What the receiver needs from whoever holds the wallet.
pub trait Host: Send + Sync + 'static {
    /// Receives `wire` over `method` and answers with the reply slate. A failure is already
    /// classed with [`refuse`]; the host logs it as it likes before returning.
    fn receive(
        &self,
        method: &Arc<dyn Method>,
        wire: &WireSlate,
        request: ReceiveRequest,
    ) -> BoxFuture<'_, Result<Received, Refusal>>;

    /// Builds a coinbase for a miner; any failure is [`Refusal::Unavailable`], logged by the host.
    fn build_coinbase(&self, request: CoinbaseRequest) -> BoxFuture<'_, Result<Coinbase, Refusal>>;

    /// A payment was received; `repeated` on `received` says a known slate was answered again.
    fn received(&self, received: &Received);

    /// A slate was refused, by the host or by the server before the host saw it.
    fn refused(&self, refusal: Refusal);
}

/// The one [`ReceiveHandler`] of the HTTP and Tor listeners: receives over `method` and signs
/// payment proofs with `proof_key`, the key of the address the listener serves.
pub struct Receiver<H: Host> {
    host: Arc<H>,
    method: Arc<dyn Method>,
    proof_key: ProofKey,
}

impl<H: Host> Receiver<H> {
    /// A receiver that hands slates to `host`.
    pub fn new(host: Arc<H>, method: Arc<dyn Method>, proof_key: ProofKey) -> Self {
        Self {
            host,
            method,
            proof_key,
        }
    }
}

impl<H: Host> ReceiveHandler for Receiver<H> {
    fn receive(&self, slate: WireSlate) -> BoxFuture<'_, Result<WireSlate, Refusal>> {
        Box::pin(async move {
            let request = ReceiveRequest {
                proof_key: self.proof_key,
                ..ReceiveRequest::default()
            };
            match self.host.receive(&self.method, &slate, request).await {
                Ok(received) => {
                    self.host.received(&received);
                    Ok(received.reply)
                }
                Err(refusal) => {
                    self.host.refused(refusal);
                    Err(refusal)
                }
            }
        })
    }

    fn refused(&self, refusal: Refusal) {
        self.host.refused(refusal);
    }

    fn build_coinbase(&self, fees: BlockFees) -> BoxFuture<'_, Result<CoinbaseAnswer, Refusal>> {
        Box::pin(async move {
            let coinbase = self.host.build_coinbase(coinbase_request(fees)).await?;
            Ok(coinbase_answer(&coinbase))
        })
    }
}

/// Counts of what a listener answered.
#[derive(Debug, Default)]
pub struct Counts {
    /// Payments received.
    pub received: AtomicU32,
    /// Known slates answered again.
    pub repeated: AtomicU32,
    /// Slates refused.
    pub refused: AtomicU32,
}

impl Counts {
    /// Counts a payment received, or answered again when `received.repeated`.
    pub fn count_received(&self, received: &Received) {
        let count = if received.repeated {
            &self.repeated
        } else {
            &self.received
        };
        count.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts a slate refused.
    pub fn count_refused(&self) {
        self.refused.fetch_add(1, Ordering::Relaxed);
    }

    /// Payments received so far.
    pub fn received(&self) -> u32 {
        self.received.load(Ordering::Relaxed)
    }

    /// Known slates answered again so far.
    pub fn repeated(&self) -> u32 {
        self.repeated.load(Ordering::Relaxed)
    }

    /// Slates refused so far.
    pub fn refused(&self) -> u32 {
        self.refused.load(Ordering::Relaxed)
    }
}

/// The miner's block fees as the engine takes them. A key that is no identifier is one the
/// wallet never gave out: `None`, and the engine takes a new key, as upstream does for a key
/// it does not find.
pub fn coinbase_request(fees: BlockFees) -> CoinbaseRequest {
    CoinbaseRequest {
        fees: Fee::new(fees.fees),
        height: Height::new(fees.height),
        key_id: fees
            .key_id
            .and_then(|bytes| Identifier::from_bytes(&bytes).ok()),
    }
}

/// The node's view of a coinbase the wallet built.
pub fn coinbase_answer(coinbase: &Coinbase) -> CoinbaseAnswer {
    CoinbaseAnswer {
        commit: *coinbase.output.commitment.as_bytes(),
        proof: coinbase.output.proof.as_bytes().to_vec(),
        excess: *coinbase.kernel.excess.as_bytes(),
        excess_sig: coinbase.kernel.excess_sig.to_compact(),
        key_id: coinbase.key_id.to_bytes(),
    }
}

/// The class the foreign server answers a failed receive with: [`Refusal::Rejected`] when the
/// same slate would fail the same way again, so the sender gains nothing by trying again, as
/// the engine's inbox decides for a message; [`Refusal::Unavailable`] for everything about
/// this wallet, its node or the process that may pass.
pub fn refuse(error: &ReceiveError) -> Refusal {
    match error {
        ReceiveError::Decode(_)
        | ReceiveError::WrongStage { .. }
        | ReceiveError::ZeroAmount
        | ReceiveError::AlreadyReceived { .. }
        | ReceiveError::Expired { .. }
        | ReceiveError::AheadOfTip { .. }
        | ReceiveError::FeeBelowMinimum { .. }
        | ReceiveError::FeeOverflow
        | ReceiveError::MessageSignature { .. }
        | ReceiveError::ForeignProofAddress
        | ReceiveError::Refused
        | ReceiveError::UnknownTransport { .. }
        | ReceiveError::Output(_)
        | ReceiveError::Signing(_)
        | ReceiveError::Excess(_)
        | ReceiveError::Slate(_)
        | ReceiveError::Encode(_) => Refusal::Rejected,
        ReceiveError::Wallet(
            WalletError::Config(_)
            | WalletError::WrongPassword
            | WalletError::Mnemonic(_)
            | WalletError::WalletSeedFile(_)
            | WalletError::Account(_)
            | WalletError::Transition(_)
            | WalletError::PartnerPosted { .. }
            | WalletError::OnChain(_)
            | WalletError::InPool(_)
            | WalletError::NotReleasable { .. }
            | WalletError::ChangedDuringCancel(_)
            | WalletError::InvalidListing,
        ) => Refusal::Rejected,
        _ => Refusal::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use lepic_slate::error::DecodeError;
    use lepic_slate::stage::Stage;

    use super::*;

    #[test]
    fn refusal_classes_follow_who_is_at_fault() {
        let height = Height::new(10);
        let fee = Fee::new(1);
        for (error, class) in [
            (
                ReceiveError::Decode(DecodeError::UnknownFormat),
                Refusal::Rejected,
            ),
            (
                ReceiveError::WrongStage { stage: Stage::S2 },
                Refusal::Rejected,
            ),
            (ReceiveError::ZeroAmount, Refusal::Rejected),
            (
                ReceiveError::Expired {
                    cutoff: height,
                    tip: height,
                },
                Refusal::Rejected,
            ),
            (
                ReceiveError::AheadOfTip {
                    height,
                    limit: height,
                },
                Refusal::Rejected,
            ),
            (
                ReceiveError::FeeBelowMinimum { fee, minimum: fee },
                Refusal::Rejected,
            ),
            (ReceiveError::FeeOverflow, Refusal::Rejected),
            (
                ReceiveError::Output(lepic_keychain::ProofError::InvalidNonce),
                Refusal::Rejected,
            ),
            (
                ReceiveError::Excess(lepic_primitives::committed::KernelSumError::Mismatch),
                Refusal::Rejected,
            ),
            (
                ReceiveError::Encode(lepic_transport::error::FormatError::CodecNotRegistered {
                    codec: lepic_legacy_slate::v2_json::LEGACY_V2_JSON,
                }),
                Refusal::Rejected,
            ),
            (ReceiveError::ForeignProofAddress, Refusal::Rejected),
            (ReceiveError::Refused, Refusal::Rejected),
            (
                ReceiveError::Wallet(WalletError::WrongPassword),
                Refusal::Rejected,
            ),
            (
                ReceiveError::Wallet(WalletError::InvalidListing),
                Refusal::Rejected,
            ),
            (ReceiveError::OpenReceipts(None), Refusal::Unavailable),
            (
                ReceiveError::Wallet(WalletError::Locked),
                Refusal::Unavailable,
            ),
            (
                ReceiveError::Wallet(WalletError::NoWallet),
                Refusal::Unavailable,
            ),
            (
                ReceiveError::Wallet(WalletError::RestoreScanRequired),
                Refusal::Unavailable,
            ),
            (
                ReceiveError::Wallet(WalletError::WalletExists),
                Refusal::Unavailable,
            ),
        ] {
            assert_eq!(refuse(&error), class, "{error:?}");
        }
    }
}
