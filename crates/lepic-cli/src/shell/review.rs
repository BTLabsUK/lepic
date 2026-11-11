// SPDX-License-Identifier: Apache-2.0
//! The review the shell shows before `tx send`, and the question that follows it.

use crate::amount::format_units;
use crate::commands::Reviewed;
use crate::shell::live::printable;

/// What a send will do, from the fee estimate on the open wallet. Amounts in base units.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Review {
    /// Where it goes, as typed after `--to`, `--to-file` or `--to-contact`.
    pub to: String,
    pub amount: u64,
    pub fee: u64,
    /// The account's spendable balance before the send.
    pub spendable: u64,
    /// How the slate travels: `epicbox`, `tor`, `http`, `file` or `contact`.
    pub delivery: &'static str,
    /// The network the wallet sends on.
    pub network: String,
}

impl Review {
    pub(crate) const fn total(&self) -> u64 {
        self.amount.saturating_add(self.fee)
    }

    /// What the send is held to once the user answers yes.
    pub(crate) const fn reviewed(&self) -> Reviewed {
        Reviewed {
            amount: self.amount,
            fee: self.fee,
        }
    }

    /// The review, one field a line.
    pub(crate) fn lines(&self) -> Vec<String> {
        let epic = |units: u64| format!("{} EPIC", format_units(units));
        let rows = [
            ("To", printable(&self.to)),
            ("Amount", epic(self.amount)),
            ("Fee", epic(self.fee)),
            ("Total", epic(self.total())),
            (
                "Spendable after",
                epic(self.spendable.saturating_sub(self.total())),
            ),
            ("Delivery", self.delivery.to_owned()),
            ("Network", self.network.clone()),
        ];
        let mut lines: Vec<String> = rows
            .iter()
            .map(|(name, value)| format!("  {name:<15}  {value}"))
            .collect();
        lines.push("A sent payment cannot be reversed.".to_owned());
        lines
    }

    /// The question asked after the review; only `y` sends.
    pub(crate) fn question(&self) -> String {
        format!("Send {} EPIC in total? [y/N] ", format_units(self.total()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn review() -> Review {
        Review {
            to: "epic1qqexample".to_owned(),
            amount: 150_000_000,
            fee: 800_000,
            spendable: 849_200_000,
            delivery: "epicbox",
            network: "floonet".to_owned(),
        }
    }

    #[test]
    fn the_review_names_every_field() {
        assert_eq!(
            review().lines(),
            [
                "  To               epic1qqexample",
                "  Amount           1.50000000 EPIC",
                "  Fee              0.00800000 EPIC",
                "  Total            1.50800000 EPIC",
                "  Spendable after  6.98400000 EPIC",
                "  Delivery         epicbox",
                "  Network          floonet",
                "A sent payment cannot be reversed.",
            ]
        );
        assert_eq!(review().question(), "Send 1.50800000 EPIC in total? [y/N] ");
    }

    #[test]
    fn the_send_takes_no_more_than_the_review_showed() {
        let reviewed = review().reviewed();
        assert!(reviewed.check(150_000_000, 800_000).is_ok());
        assert!(reviewed.check(150_000_000, 700_000).is_ok());
        let error = reviewed.check(150_000_000, 900_000).unwrap_err();
        assert_eq!(
            error.to_string(),
            "the send would now take 1.50900000 EPIC in total, not the 1.50800000 EPIC \
             reviewed: nothing was sent"
        );
        assert_eq!(error.kind(), crate::exit::ErrorKind::Rejected);
        assert!(reviewed.check(140_000_000, 800_000).is_err());
    }

    #[test]
    fn the_review_never_shows_control_characters_or_a_negative_balance() {
        let review = Review {
            to: "a\u{1b}[31mb".to_owned(),
            spendable: 1,
            ..review()
        };
        let lines = review.lines();
        assert!(!lines[0].contains('\u{1b}'));
        assert_eq!(lines[4], "  Spendable after  0.00000000 EPIC");
    }
}
