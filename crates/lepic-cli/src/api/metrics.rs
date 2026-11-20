// SPDX-License-Identifier: Apache-2.0
//! The Prometheus text exposition format, version 0.0.4, for `GET /metrics`: a family is its
//! `# HELP` and `# TYPE` lines once, then its samples, each with its labels.

use std::collections::BTreeSet;

/// The `Content-Type` of the exposition.
pub(crate) const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// What a family measures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// A value that goes up and down.
    Gauge,
    /// A value that only goes up while the process runs; its name ends in `_total`.
    Counter,
}

impl Kind {
    const fn word(self) -> &'static str {
        match self {
            Self::Gauge => "gauge",
            Self::Counter => "counter",
        }
    }
}

/// One value of a family, with its labels.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Sample {
    labels: Vec<(&'static str, String)>,
    value: u64,
}

impl Sample {
    /// A value with no labels.
    pub(crate) const fn bare(value: u64) -> Self {
        Self {
            labels: Vec::new(),
            value,
        }
    }

    /// A value with `labels`, written in the order given.
    pub(crate) fn labelled<const N: usize>(labels: [(&'static str, &str); N], value: u64) -> Self {
        Self {
            labels: labels
                .into_iter()
                .map(|(name, text)| (name, text.to_owned()))
                .collect(),
            value,
        }
    }
}

/// An exposition under construction.
#[derive(Debug, Default)]
pub(crate) struct Exposition {
    text: String,
    families: BTreeSet<String>,
}

impl Exposition {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Adds the family `name`. Its samples are written sorted by their labels, so two scrapes of
    /// the same facts read the same. A family already added is left as it was.
    pub(crate) fn family(&mut self, name: &str, kind: Kind, help: &str, mut samples: Vec<Sample>) {
        if !self.families.insert(name.to_owned()) {
            return;
        }
        samples.sort();
        self.text.push_str("# HELP ");
        self.text.push_str(name);
        self.text.push(' ');
        escape(&mut self.text, help, false);
        self.text.push_str("\n# TYPE ");
        self.text.push_str(name);
        self.text.push(' ');
        self.text.push_str(kind.word());
        self.text.push('\n');
        for sample in samples {
            self.text.push_str(name);
            if !sample.labels.is_empty() {
                self.text.push('{');
                for (index, (label, value)) in sample.labels.iter().enumerate() {
                    if index > 0 {
                        self.text.push(',');
                    }
                    self.text.push_str(label);
                    self.text.push_str("=\"");
                    escape(&mut self.text, value, true);
                    self.text.push('"');
                }
                self.text.push('}');
            }
            self.text.push(' ');
            self.text.push_str(&sample.value.to_string());
            self.text.push('\n');
        }
    }

    pub(crate) fn finish(self) -> String {
        self.text
    }
}

/// Writes `text` with `\` and a line feed escaped, and `"` too in a label value.
fn escape(out: &mut String, text: &str, quotes: bool) {
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '"' if quotes => out.push_str("\\\""),
            c => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn a_family_is_help_type_and_its_samples() {
        let mut out = Exposition::new();
        out.family(
            "lepic_up",
            Kind::Gauge,
            "Whether it runs.",
            vec![Sample::bare(1)],
        );
        assert_eq!(
            out.finish(),
            "# HELP lepic_up Whether it runs.\n# TYPE lepic_up gauge\nlepic_up 1\n"
        );
    }

    #[test]
    fn a_counter_is_typed_counter() {
        let mut out = Exposition::new();
        out.family(
            "lepic_things_total",
            Kind::Counter,
            "Things.",
            vec![Sample::bare(7)],
        );
        assert!(out.finish().contains("# TYPE lepic_things_total counter\n"));
    }

    #[test]
    fn labels_are_written_in_order_and_values_are_escaped() {
        let mut out = Exposition::new();
        out.family(
            "lepic_x",
            Kind::Gauge,
            "X.",
            vec![Sample::labelled(
                [("a", "back\\slash"), ("b", "say \"hi\"\nnow")],
                3,
            )],
        );
        assert_eq!(
            out.finish(),
            "# HELP lepic_x X.\n# TYPE lepic_x gauge\n\
             lepic_x{a=\"back\\\\slash\",b=\"say \\\"hi\\\"\\nnow\"} 3\n"
        );
    }

    #[test]
    fn help_escapes_backslash_and_newline_but_keeps_quotes() {
        let mut out = Exposition::new();
        out.family("lepic_x", Kind::Gauge, "a \"b\"\\c\nd", Vec::new());
        assert_eq!(
            out.finish(),
            "# HELP lepic_x a \"b\"\\\\c\\nd\n# TYPE lepic_x gauge\n"
        );
    }

    #[test]
    fn a_family_is_written_once() {
        let mut out = Exposition::new();
        out.family("lepic_x", Kind::Gauge, "First.", vec![Sample::bare(1)]);
        out.family("lepic_x", Kind::Gauge, "Second.", vec![Sample::bare(2)]);
        let text = out.finish();
        assert_eq!(text.matches("# HELP lepic_x ").count(), 1);
        assert_eq!(text.matches("# TYPE lepic_x ").count(), 1);
        assert!(text.contains("First.") && text.ends_with("lepic_x 1\n"));
    }

    #[test]
    fn samples_of_a_family_follow_one_after_the_other_in_label_order() {
        let mut out = Exposition::new();
        out.family(
            "lepic_b",
            Kind::Gauge,
            "B.",
            vec![
                Sample::labelled([("state", "locked")], 2),
                Sample::labelled([("state", "confirming")], 1),
                Sample::labelled([("state", "spendable")], 3),
            ],
        );
        out.family("lepic_a", Kind::Gauge, "A.", vec![Sample::bare(9)]);
        let text = out.finish();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines,
            [
                "# HELP lepic_b B.",
                "# TYPE lepic_b gauge",
                "lepic_b{state=\"confirming\"} 1",
                "lepic_b{state=\"locked\"} 2",
                "lepic_b{state=\"spendable\"} 3",
                "# HELP lepic_a A.",
                "# TYPE lepic_a gauge",
                "lepic_a 9",
            ]
        );
    }

    #[test]
    fn a_family_with_no_samples_still_says_what_it_is() {
        let mut out = Exposition::new();
        out.family("lepic_x", Kind::Gauge, "X.", Vec::new());
        assert_eq!(out.finish(), "# HELP lepic_x X.\n# TYPE lepic_x gauge\n");
    }

    #[test]
    fn the_content_type_names_the_format_version() {
        assert_eq!(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8");
    }
}
