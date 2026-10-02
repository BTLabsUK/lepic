//! The two parties of a slate, named by the direction funds move rather than by position.

/// A party to a two-party transaction. The sender pays and the receiver is paid, whichever of
/// them started the slate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Role {
    Sender,
    Receiver,
}

impl Role {
    pub const ALL: [Self; 2] = [Self::Sender, Self::Receiver];

    pub const fn counterparty(self) -> Self {
        match self {
            Self::Sender => Self::Receiver,
            Self::Receiver => Self::Sender,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sender => "sender",
            Self::Receiver => "receiver",
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
