// SPDX-License-Identifier: Apache-2.0
//! The values the app chooses for a wallet: limits and presets that are the app's policy, not
//! the engine's. Every field is optional, and `None` is the value LEPIC used before the field
//! existed, so a wallet opened with [`HostPolicy::default`] behaves as it always did.

use std::time::Duration;

use std::num::NonZeroUsize;

use lepic_primitives::amount::Amount;
use lepic_wallet::WalletPolicy;
use lepic_wallet::epicbox_invoice::{DEFAULT_INVOICE_EXPIRY, InvoiceExpiry};
use lepic_wallet::invoice::{
    INVOICE_TTL_BLOCKS, MAX_INVOICE_TTL_LEAD_BLOCKS, MAX_INVOICE_TTL_LEAD_CEILING_BLOCKS,
    PayRequest,
};
use lepic_wallet::selection::{Commitment, SelectionStrategy as EngineStrategy};
use lepic_wallet::send::SendRequest;

use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::types::{SelectionStrategy, SendOptions};
use crate::pin::PinPolicy;
use crate::session::DEFAULT_ACCOUNT;

/// Policy of one wallet, read when it is created, restored or opened. A value that is out of
/// range fails that call with `InvalidArgument`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HostPolicy {
    /// The strategy of a send given no options. Default `Smallest`.
    pub default_strategy: Option<SelectionStrategy>,
    /// Blocks after which this wallet neither finalizes nor posts an app send and expires it
    /// if unanswered; file slates carry it as their TTL. At least 1. Default 1,440, a day.
    pub send_ttl_blocks: Option<u64>,
    /// The TTL of an invoice the app issues, so a payer refuses a request older than it.
    /// At least 1. Default 1,440, a day. It does not move `max_invoice_ttl_lead_blocks`.
    pub invoice_ttl_blocks: Option<u64>,
    /// The most change outputs a send may ask for; each one costs a range proof. At least 1.
    /// Default 10.
    pub max_change_outputs: Option<u32>,
    /// The most outputs one send may be told to leave out. Default 500; 0 allows none.
    pub max_excluded_outputs: Option<u32>,
    /// How long an unpaid Epicbox invoice is kept when a sweep names no window, in seconds.
    /// At least 1 and at most `invoice_expiry_max_s`. Default 86,400, a day.
    pub invoice_expiry_default_s: Option<u64>,
    /// The longest window a sweep may name, in seconds. At least 1. Default 172,800, two days.
    pub invoice_expiry_max_s: Option<u64>,
    /// How far above the chain tip a payer accepts an invoice's TTL cutoff, in blocks, from 1
    /// to 525,600. Default 2,880. The lag below the tip is not a setting.
    pub max_invoice_ttl_lead_blocks: Option<u64>,
    /// Open receipts kept from one sender key. At least 1. Default 10.
    pub max_open_receipts_per_sender: Option<u32>,
    /// Open receipts kept in all. At least 1. Default 100.
    pub max_open_receipts: Option<u32>,
    /// The minimum confirmations of a wallet that never set its own. At least 1. Default 6.
    /// LEPIC sets no upper bound for it, nor for `set_minimum_confirmations`: a count above what
    /// the chain has makes nothing spendable, and the app decides how deep it lets users ask.
    pub default_minimum_confirmations: Option<u64>,
    /// Contact checks one contact gets answered in an hour; a further one is dropped without
    /// an answer. At least 1, at most `contact_check_answers_per_day`. Default 1.
    pub contact_check_answers_per_hour: Option<u32>,
    /// Contact checks one contact gets answered in a day. From 1 to 24. Default 3.
    pub contact_check_answers_per_day: Option<u32>,
    /// Times a contact mailbox message that fails for a lasting reason is kept for the next
    /// collect before it is dropped. A failure that passes (node, relay or store not
    /// answering, wallet locked) keeps it without counting. From 1 to 10. Default 3.
    pub contact_hold_attempts: Option<u32>,
    /// How long such a message is kept after it was first kept, in seconds. From 1 to 86,400.
    /// Default 180.
    pub contact_hold_patience_s: Option<u64>,
    /// Refuse a payment nobody asked for: an S1 at the payments address, over HTTP or Tor, or
    /// from a contact. A LEPIC sender hears `declined` and cancels its send (ADR 0045). A
    /// payment for a listing and a slate taken by hand are still received. Default off.
    pub refuse_unsolicited_payments: Option<bool>,
    /// Refuse an invoice from a contact instead of parking it, answered `declined`. A plain
    /// Epicbox invoice is refused anyway. Default off.
    pub refuse_unsolicited_invoices: Option<bool>,
    /// Whether `start_tor` with `publish_onion` also publishes the previous onion, the one
    /// LEPIC 0.3.1 and earlier published (ADR 0044), on its own listener, so senders that saved
    /// it still reach the wallet. Payment proofs asked for there are signed with the
    /// payment-proof key, as before. While it is published it links the Tor and Epicbox
    /// identities. Default false.
    pub publish_previous_onion: Option<bool>,
}

/// How a runtime treats PINs, chosen when the app creates it with
/// [`LepicRuntime::with_pin_settings`]. `None` is the value used before the field existed.
///
/// [`LepicRuntime::with_pin_settings`]: crate::api::runtime::LepicRuntime::with_pin_settings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PinSettings {
    /// The fewest characters a new PIN has, at least 1. Unlocking never checks it. Default 6.
    pub min_len: Option<u32>,
    /// Wrong PINs before attempts start to wait. Default 3.
    pub free_failures: Option<u32>,
    /// The wait after `free_failures` failures, in seconds; it doubles with each further
    /// failure. Default 30.
    pub first_delay_s: Option<u64>,
    /// The longest wait, in seconds. At least `first_delay_s`. Default 3,600.
    pub max_delay_s: Option<u64>,
}

impl PinSettings {
    pub(crate) fn resolve(self) -> Result<PinPolicy, WalletError> {
        let base = PinPolicy::DEFAULT;
        let min_len = self.min_len.map_or(base.min_len, |len| len as usize);
        let first_delay = self
            .first_delay_s
            .map_or(base.first_delay, Duration::from_secs);
        let max_delay = self.max_delay_s.map_or(base.max_delay, Duration::from_secs);
        if min_len == 0 || max_delay < first_delay {
            return Err(WalletError::new(
                WalletErrorKind::InvalidArgument,
                "pin settings are out of range".to_owned(),
            ));
        }
        Ok(PinPolicy {
            min_len,
            free_failures: self.free_failures.unwrap_or(base.free_failures),
            first_delay,
            max_delay,
        })
    }
}

/// [`HostPolicy`] with every default filled in and every value checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Policy {
    pub(crate) strategy: SelectionStrategy,
    pub(crate) send_ttl_blocks: u64,
    pub(crate) invoice_ttl_blocks: u64,
    pub(crate) max_change_outputs: usize,
    pub(crate) max_excluded_outputs: usize,
    pub(crate) invoice_expiry_default: Duration,
    pub(crate) invoice_expiry_max: Duration,
    pub(crate) max_invoice_ttl_lead_blocks: u64,
    pub(crate) publish_previous_onion: bool,
    pub(crate) wallet: WalletPolicy,
}

/// The longest an unpaid invoice may be kept unless the app sets another: two days.
const DEFAULT_INVOICE_EXPIRY_MAX: Duration = Duration::from_secs(48 * 60 * 60);

fn invalid(what: &str) -> WalletError {
    WalletError::new(WalletErrorKind::InvalidArgument, what.to_owned())
}

fn at_least_one(value: u64, what: &str) -> Result<u64, WalletError> {
    if value == 0 {
        return Err(invalid(&format!("{what} must be at least 1")));
    }
    Ok(value)
}

fn engine_strategy(strategy: SelectionStrategy) -> EngineStrategy {
    match strategy {
        SelectionStrategy::Smallest => EngineStrategy::Smallest,
        SelectionStrategy::All => EngineStrategy::All,
    }
}

fn count(value: u32, what: &str) -> Result<usize, WalletError> {
    usize::try_from(at_least_one(u64::from(value), what)?).map_err(|_| invalid(what))
}

impl Policy {
    /// Fills in the defaults and fails with `InvalidArgument` for a value out of range.
    pub(crate) fn resolve(policy: &HostPolicy) -> Result<Self, WalletError> {
        let defaults = WalletPolicy::DEFAULT;
        let lead = policy
            .max_invoice_ttl_lead_blocks
            .unwrap_or(MAX_INVOICE_TTL_LEAD_BLOCKS);
        if !(1..=MAX_INVOICE_TTL_LEAD_CEILING_BLOCKS).contains(&lead) {
            return Err(invalid(&format!(
                "max invoice ttl lead must be from 1 to {MAX_INVOICE_TTL_LEAD_CEILING_BLOCKS} blocks"
            )));
        }
        let expiry_default = match policy.invoice_expiry_default_s {
            Some(seconds) => Duration::from_secs(at_least_one(seconds, "invoice expiry default")?),
            None => DEFAULT_INVOICE_EXPIRY,
        };
        let expiry_max = match policy.invoice_expiry_max_s {
            Some(seconds) => Duration::from_secs(at_least_one(seconds, "invoice expiry max")?),
            None => DEFAULT_INVOICE_EXPIRY_MAX,
        };
        if expiry_default > expiry_max {
            return Err(invalid("invoice expiry default is above its max"));
        }
        let wallet = WalletPolicy {
            max_open_receipts_per_sender: policy
                .max_open_receipts_per_sender
                .map_or(Ok(defaults.max_open_receipts_per_sender), |n| {
                    count(n, "max open receipts per sender")
                })?,
            max_open_receipts: policy
                .max_open_receipts
                .map_or(Ok(defaults.max_open_receipts), |n| {
                    count(n, "max open receipts")
                })?,
            default_minimum_confirmations: policy
                .default_minimum_confirmations
                .map_or(Ok(defaults.default_minimum_confirmations), |n| {
                    at_least_one(n, "default minimum confirmations")
                })?,
            contact_check_answers_per_hour: policy
                .contact_check_answers_per_hour
                .unwrap_or(defaults.contact_check_answers_per_hour),
            contact_check_answers_per_day: policy
                .contact_check_answers_per_day
                .unwrap_or(defaults.contact_check_answers_per_day),
            contact_hold_attempts: policy
                .contact_hold_attempts
                .unwrap_or(defaults.contact_hold_attempts),
            contact_hold_patience: policy
                .contact_hold_patience_s
                .map_or(defaults.contact_hold_patience, Duration::from_secs),
            refuse_unsolicited_payments: policy
                .refuse_unsolicited_payments
                .unwrap_or(defaults.refuse_unsolicited_payments),
            refuse_unsolicited_invoices: policy
                .refuse_unsolicited_invoices
                .unwrap_or(defaults.refuse_unsolicited_invoices),
        };
        wallet
            .validate()
            .map_err(|error| invalid(&error.to_string()))?;
        Ok(Self {
            strategy: policy
                .default_strategy
                .unwrap_or(SelectionStrategy::Smallest),
            send_ttl_blocks: policy
                .send_ttl_blocks
                .map_or(Ok(INVOICE_TTL_BLOCKS), |n| at_least_one(n, "send ttl"))?,
            invoice_ttl_blocks: policy
                .invoice_ttl_blocks
                .map_or(Ok(INVOICE_TTL_BLOCKS), |n| at_least_one(n, "invoice ttl"))?,
            max_change_outputs: policy
                .max_change_outputs
                .map_or(Ok(10), |n| count(n, "max change outputs"))?,
            max_excluded_outputs: policy.max_excluded_outputs.map_or(Ok(500), |n| {
                usize::try_from(n).map_err(|_| invalid("max excluded outputs"))
            })?,
            invoice_expiry_default: expiry_default,
            invoice_expiry_max: expiry_max,
            max_invoice_ttl_lead_blocks: lead,
            publish_previous_onion: policy.publish_previous_onion.unwrap_or(false),
            wallet,
        })
    }

    /// A send with the binding's default selection, as [`Policy::send_request_with`] without
    /// options makes it.
    pub(crate) fn send_request(
        &self,
        amount: u64,
        minimum_confirmations: u64,
        message: Option<String>,
    ) -> SendRequest {
        SendRequest {
            minimum_confirmations,
            message,
            strategy: engine_strategy(self.strategy),
            local_ttl_blocks: Some(self.send_ttl_blocks),
            ..SendRequest::new(DEFAULT_ACCOUNT, Amount::new(amount))
        }
    }

    /// Fails with `InvalidArgument` for change outputs outside 1..=`max_change_outputs`.
    pub(crate) fn send_request_with(
        &self,
        amount: u64,
        minimum_confirmations: u64,
        message: Option<String>,
        options: Option<SendOptions>,
    ) -> Result<SendRequest, WalletError> {
        let request = self.send_request(amount, minimum_confirmations, message);
        let Some(options) = options else {
            return Ok(request);
        };
        let (strategy, change_outputs, exclude_outputs) = self.selection_choice(&options)?;
        Ok(SendRequest {
            strategy,
            change_outputs,
            exclude_outputs,
            ..request
        })
    }

    /// [`Policy::send_request_with`] for the file method, whose slate carries the limit as its
    /// TTL.
    pub(crate) fn file_send_request(
        &self,
        amount: u64,
        minimum_confirmations: u64,
        message: Option<String>,
        options: Option<SendOptions>,
    ) -> Result<SendRequest, WalletError> {
        Ok(SendRequest {
            ttl_blocks: Some(self.send_ttl_blocks),
            ..self.send_request_with(amount, minimum_confirmations, message, options)?
        })
    }

    pub(crate) fn pay_request(
        &self,
        amount: u64,
        minimum_confirmations: u64,
        message: Option<String>,
        options: Option<SendOptions>,
    ) -> Result<PayRequest, WalletError> {
        let defaults = self.send_request_with(amount, minimum_confirmations, message, options)?;
        Ok(PayRequest {
            minimum_confirmations,
            strategy: defaults.strategy,
            change_outputs: defaults.change_outputs,
            message: defaults.message,
            exclude_outputs: defaults.exclude_outputs,
            max_ttl_lead_blocks: self.max_invoice_ttl_lead_blocks,
            ..PayRequest::new(DEFAULT_ACCOUNT, Amount::new(amount))
        })
    }

    /// The engine's strategy, change outputs and excluded outputs for `options`. Fails with
    /// `InvalidArgument` for change outputs outside 1..=`max_change_outputs`, an excluded
    /// output that is not a commitment, or more than `max_excluded_outputs` of them.
    pub(crate) fn selection_choice(
        &self,
        options: &SendOptions,
    ) -> Result<(EngineStrategy, NonZeroUsize, Vec<Commitment>), WalletError> {
        let max_excluded = self.max_excluded_outputs;
        if options.exclude_outputs.len() > max_excluded {
            return Err(invalid(&format!(
                "at most {max_excluded} outputs may be excluded"
            )));
        }
        let exclude = options
            .exclude_outputs
            .iter()
            .map(|hex| {
                Commitment::from_hex(hex)
                    .map_err(|_| invalid("an excluded output is not a commitment"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let max = self.max_change_outputs;
        let change_outputs = usize::try_from(options.change_outputs)
            .ok()
            .filter(|count| *count <= max)
            .and_then(NonZeroUsize::new)
            .ok_or_else(|| invalid(&format!("change outputs must be from 1 to {max}")))?;
        Ok((engine_strategy(options.strategy), change_outputs, exclude))
    }

    /// `seconds` as the window after which unpaid invoices expire; `None` is the policy's
    /// default. Fails with `InvalidArgument` for zero or more than the policy's maximum.
    pub(crate) fn invoice_expiry(
        &self,
        seconds: Option<u64>,
    ) -> Result<InvoiceExpiry, WalletError> {
        let window = seconds.map_or(self.invoice_expiry_default, Duration::from_secs);
        if window > self.invoice_expiry_max {
            return Err(invalid(
                "invoice expiry is above the longest the app allows",
            ));
        }
        Ok(InvoiceExpiry::new(window)?)
    }

    /// The policy of a host that passes nothing.
    #[cfg(test)]
    pub(crate) fn shipped() -> Self {
        match Self::resolve(&HostPolicy::default()) {
            Ok(policy) => policy,
            Err(error) => panic!("the default policy is valid: {error:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_host_that_passes_nothing_gets_the_values_before_they_were_parameters() {
        let policy = Policy::resolve(&HostPolicy::default()).unwrap();
        assert_eq!(policy.strategy, SelectionStrategy::Smallest);
        assert_eq!(policy.send_ttl_blocks, 1_440);
        assert_eq!(policy.invoice_ttl_blocks, 1_440);
        assert_eq!(policy.max_change_outputs, 10);
        assert_eq!(policy.max_excluded_outputs, 500);
        assert_eq!(policy.invoice_expiry_default, Duration::from_secs(86_400));
        assert_eq!(policy.invoice_expiry_max, Duration::from_secs(172_800));
        assert_eq!(policy.max_invoice_ttl_lead_blocks, 2_880);
        assert_eq!(policy.wallet.max_open_receipts_per_sender, 10);
        assert_eq!(policy.wallet.max_open_receipts, 100);
        assert_eq!(policy.wallet.default_minimum_confirmations, 6);
        assert!(!policy.wallet.refuse_unsolicited_payments);
        assert!(!policy.wallet.refuse_unsolicited_invoices);
    }

    #[test]
    fn the_refusal_switches_reach_the_wallet_one_by_one() {
        let payments = Policy::resolve(&HostPolicy {
            refuse_unsolicited_payments: Some(true),
            ..HostPolicy::default()
        })
        .unwrap();
        assert!(payments.wallet.refuse_unsolicited_payments);
        assert!(!payments.wallet.refuse_unsolicited_invoices);
        let invoices = Policy::resolve(&HostPolicy {
            refuse_unsolicited_invoices: Some(true),
            ..HostPolicy::default()
        })
        .unwrap();
        assert!(!invoices.wallet.refuse_unsolicited_payments);
        assert!(invoices.wallet.refuse_unsolicited_invoices);
    }

    #[test]
    fn app_sends_carry_a_local_limit_and_file_sends_a_ttl_too() {
        let policy = Policy::shipped();
        let request = policy.send_request_with(1, 1, None, None).unwrap();
        assert_eq!(request.local_ttl_blocks, Some(1_440));
        assert_eq!(request.ttl_blocks, None);
        assert_eq!(request.strategy, EngineStrategy::Smallest);

        let file = policy.file_send_request(1, 1, None, None).unwrap();
        assert_eq!(file.local_ttl_blocks, Some(1_440));
        assert_eq!(file.ttl_blocks, Some(1_440));
    }

    #[test]
    fn a_host_ttl_and_change_cap_reach_the_requests() {
        let policy = Policy::resolve(&HostPolicy {
            send_ttl_blocks: Some(100),
            max_change_outputs: Some(2),
            ..HostPolicy::default()
        })
        .unwrap();
        let file = policy.file_send_request(1, 1, None, None).unwrap();
        assert_eq!(file.ttl_blocks, Some(100));
        let options = |change_outputs| SendOptions {
            strategy: SelectionStrategy::Smallest,
            change_outputs,
            exclude_outputs: Vec::new(),
        };
        assert!(
            policy
                .send_request_with(1, 1, None, Some(options(2)))
                .is_ok()
        );
        assert!(
            policy
                .send_request_with(1, 1, None, Some(options(3)))
                .is_err()
        );
    }

    #[test]
    fn invoice_expiry_follows_the_policy() {
        let policy = Policy::shipped();
        assert_eq!(
            policy.invoice_expiry(None).unwrap().window(),
            Duration::from_secs(86_400)
        );
        assert!(policy.invoice_expiry(Some(172_800)).is_ok());
        assert!(policy.invoice_expiry(Some(172_801)).is_err());
        assert!(policy.invoice_expiry(Some(0)).is_err());
        let long = Policy::resolve(&HostPolicy {
            invoice_expiry_max_s: Some(1_000_000),
            ..HostPolicy::default()
        })
        .unwrap();
        assert!(long.invoice_expiry(Some(1_000_000)).is_ok());
    }

    #[test]
    fn the_previous_onion_is_not_published_unless_the_host_turns_it_on() {
        assert!(!Policy::shipped().publish_previous_onion);
        let on = Policy::resolve(&HostPolicy {
            publish_previous_onion: Some(true),
            ..HostPolicy::default()
        })
        .unwrap();
        assert!(on.publish_previous_onion);
    }

    #[test]
    fn the_invoice_ttl_does_not_move_the_lead_cap() {
        let policy = Policy::resolve(&HostPolicy {
            invoice_ttl_blocks: Some(5_000),
            ..HostPolicy::default()
        })
        .unwrap();
        assert_eq!(policy.max_invoice_ttl_lead_blocks, 2_880);
    }

    #[test]
    fn values_out_of_range_are_refused() {
        let refused = |policy: HostPolicy| {
            assert_eq!(
                Policy::resolve(&policy).unwrap_err().kind,
                WalletErrorKind::InvalidArgument
            );
        };
        let none = HostPolicy::default;
        refused(HostPolicy {
            send_ttl_blocks: Some(0),
            ..none()
        });
        refused(HostPolicy {
            invoice_ttl_blocks: Some(0),
            ..none()
        });
        refused(HostPolicy {
            max_change_outputs: Some(0),
            ..none()
        });
        refused(HostPolicy {
            max_open_receipts: Some(0),
            ..none()
        });
        refused(HostPolicy {
            max_open_receipts_per_sender: Some(0),
            ..none()
        });
        refused(HostPolicy {
            default_minimum_confirmations: Some(0),
            ..none()
        });
        refused(HostPolicy {
            max_invoice_ttl_lead_blocks: Some(0),
            ..none()
        });
        refused(HostPolicy {
            max_invoice_ttl_lead_blocks: Some(MAX_INVOICE_TTL_LEAD_CEILING_BLOCKS + 1),
            ..none()
        });
        refused(HostPolicy {
            invoice_expiry_max_s: Some(3_600),
            ..none()
        });
        refused(HostPolicy {
            invoice_expiry_default_s: Some(0),
            ..none()
        });
    }

    #[test]
    fn pin_settings_that_pass_nothing_are_the_values_before_they_were_parameters() {
        let policy = PinSettings::default().resolve().unwrap();
        assert_eq!(policy, PinPolicy::DEFAULT);
        assert_eq!(policy.min_len, 6);
        assert_eq!(policy.free_failures, 3);
        assert_eq!(policy.first_delay, Duration::from_secs(30));
        assert_eq!(policy.max_delay, Duration::from_secs(3600));
        assert!(
            PinSettings {
                min_len: Some(0),
                ..PinSettings::default()
            }
            .resolve()
            .is_err()
        );
    }
}
