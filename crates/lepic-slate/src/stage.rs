//! Flows and the stages a slate passes through in each.

use crate::role::Role;

/// Who starts the slate. In the standard flow the sender asks the receiver to accept funds; in
/// the invoice flow the receiver asks the sender to pay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Flow {
    Standard,
    Invoice,
}

impl Flow {
    pub const fn initiator(self) -> Role {
        match self {
            Self::Standard => Role::Sender,
            Self::Invoice => Role::Receiver,
        }
    }

    pub const fn responder(self) -> Role {
        self.initiator().counterparty()
    }

    pub const fn first_stage(self) -> Stage {
        match self {
            Self::Standard => Stage::S1,
            Self::Invoice => Stage::I1,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Invoice => "invoice",
        }
    }
}

impl std::fmt::Display for Flow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How far a slate has progressed. Stage 1 is the initiator's proposal, stage 2 the
/// responder's signed reply, stage 3 the initiator's finalized transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stage {
    S1,
    S2,
    S3,
    I1,
    I2,
    I3,
}

/// The step within a flow, independent of the flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Step {
    Proposed,
    Responded,
    Finalized,
}

impl Stage {
    pub const ALL: [Self; 6] = [Self::S1, Self::S2, Self::S3, Self::I1, Self::I2, Self::I3];

    pub const fn new(flow: Flow, step: Step) -> Self {
        match (flow, step) {
            (Flow::Standard, Step::Proposed) => Self::S1,
            (Flow::Standard, Step::Responded) => Self::S2,
            (Flow::Standard, Step::Finalized) => Self::S3,
            (Flow::Invoice, Step::Proposed) => Self::I1,
            (Flow::Invoice, Step::Responded) => Self::I2,
            (Flow::Invoice, Step::Finalized) => Self::I3,
        }
    }

    pub const fn flow(self) -> Flow {
        match self {
            Self::S1 | Self::S2 | Self::S3 => Flow::Standard,
            Self::I1 | Self::I2 | Self::I3 => Flow::Invoice,
        }
    }

    pub const fn step(self) -> Step {
        match self {
            Self::S1 | Self::I1 => Step::Proposed,
            Self::S2 | Self::I2 => Step::Responded,
            Self::S3 | Self::I3 => Step::Finalized,
        }
    }

    pub const fn next(self) -> Option<Self> {
        match self {
            Self::S1 => Some(Self::S2),
            Self::S2 => Some(Self::S3),
            Self::I1 => Some(Self::I2),
            Self::I2 => Some(Self::I3),
            Self::S3 | Self::I3 => None,
        }
    }

    pub const fn is_final(self) -> bool {
        matches!(self.step(), Step::Finalized)
    }

    /// The party expected to act on a slate in this stage, or `None` once it is final.
    pub const fn next_actor(self) -> Option<Role> {
        match self.step() {
            Step::Proposed => Some(self.flow().responder()),
            Step::Responded => Some(self.flow().initiator()),
            Step::Finalized => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::S1 => "S1",
            Self::S2 => "S2",
            Self::S3 => "S3",
            Self::I1 => "I1",
            Self::I2 => "I2",
            Self::I3 => "I3",
        }
    }
}

impl std::fmt::Display for Stage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_is_rebuilt_from_its_flow_and_step() {
        for stage in Stage::ALL {
            assert_eq!(Stage::new(stage.flow(), stage.step()), stage);
        }
    }

    #[test]
    fn invoice_flow_is_started_by_the_receiver() {
        assert_eq!(Flow::Invoice.initiator(), Role::Receiver);
        assert_eq!(Stage::I1.next_actor(), Some(Role::Sender));
        assert_eq!(Stage::I2.next_actor(), Some(Role::Receiver));
        assert_eq!(Stage::I3.next_actor(), None);
    }

    #[test]
    fn stages_advance_within_their_flow() {
        for stage in Stage::ALL {
            if let Some(next) = stage.next() {
                assert_eq!(next.flow(), stage.flow());
                assert!(next.step() > stage.step());
            } else {
                assert!(stage.is_final());
            }
        }
    }
}
