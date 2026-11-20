// SPDX-License-Identifier: Apache-2.0
//! Which outputs this wallet can spend, as found while it is unlocked. A send checks every
//! unspent output of the account by deriving its key and commitment, inside the store
//! transaction that selects and stores the send; without a cache each send repeats those
//! derivations and holds the store, which reads take too, for all of them. The answers go
//! with the session: locking or closing the wallet drops them.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use lepic_crypto::Commitment;
use lepic_keychain::{Identifier, Keychain, SwitchCommitment};
use lepic_store::{KeyId, OutputRecord};

/// What the check of an output read: its commitment, key and value. The answer for these three
/// never changes, so a stored row that changes any of them is checked again.
type Checked = (Commitment, KeyId, u64);

#[derive(Default)]
pub(crate) struct CheckedOutputs {
    answers: Mutex<HashMap<Checked, bool>>,
}

impl CheckedOutputs {
    /// Whether `output`'s stored commitment is the one its key and value derive with the
    /// regular switch commitment. Derived once per session for each output.
    pub(crate) fn derives(&self, keychain: &Keychain, output: &OutputRecord) -> bool {
        let checked = (output.id.commitment, output.key_id, output.amount.value());
        if let Some(answer) = self.lock().get(&checked) {
            return *answer;
        }
        let derived = Identifier::from_bytes(&output.key_id.0)
            .ok()
            .and_then(|key_id| {
                keychain
                    .commit(output.amount.value(), &key_id, SwitchCommitment::Regular)
                    .ok()
            });
        let answer = derived == Some(output.id.commitment);
        self.lock().insert(checked, answer);
        answer
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<Checked, bool>> {
        self.answers.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use lepic_keychain::Seed;
    use lepic_primitives::amount::{Amount, Height};
    use lepic_primitives::output::{OutputFeatures, OutputIdentifier};
    use lepic_primitives::params::Network;
    use lepic_store::{AccountIndex, OutputStatus};

    use super::*;
    use crate::send::spendable_here;

    fn keychain(byte: u8) -> Keychain {
        Keychain::from_seed(&Seed::from_entropy(&[byte; 32]).unwrap(), Network::Floonet).unwrap()
    }

    fn outputs(keychain: &Keychain, count: u32) -> Vec<OutputRecord> {
        (0..count)
            .map(|child| {
                let key_id = Identifier::new(3, [0, 0, child, 0]).unwrap();
                let value = 10_000_000 + u64::from(child);
                let commitment = keychain
                    .commit(value, &key_id, SwitchCommitment::Regular)
                    .unwrap();
                OutputRecord {
                    id: OutputIdentifier::new(OutputFeatures::Plain, commitment),
                    key_id: KeyId(key_id.to_bytes()),
                    account: AccountIndex(0),
                    amount: Amount::new(value),
                    status: OutputStatus::Unspent,
                    height: Height::new(10),
                    lock_height: Height::ZERO,
                    mmr_index: None,
                    tx: None,
                }
            })
            .collect()
    }

    /// The serve load bug: every send derived the key of each unspent output again, under the
    /// store lock. A second check with a keychain that derives none of them still finds them
    /// all, so it derived nothing.
    #[test]
    fn a_second_send_derives_no_output_again() {
        let mine = keychain(7);
        let other = keychain(8);
        let checked = CheckedOutputs::default();
        let outputs = outputs(&mine, 800);

        assert_eq!(
            spendable_here(&mine, &checked, outputs.clone(), &[]).len(),
            800
        );
        assert_eq!(
            spendable_here(&other, &checked, outputs.clone(), &[]).len(),
            800
        );

        assert!(spendable_here(&other, &CheckedOutputs::default(), outputs, &[]).is_empty());
    }

    #[test]
    fn a_changed_row_is_checked_again() {
        let mine = keychain(7);
        let checked = CheckedOutputs::default();
        let output = outputs(&mine, 1).remove(0);
        assert!(checked.derives(&mine, &output));

        let changed = OutputRecord {
            amount: Amount::new(output.amount.value() + 1),
            ..output.clone()
        };
        assert!(!checked.derives(&mine, &changed));
        assert!(checked.derives(&keychain(8), &output));
    }
}
