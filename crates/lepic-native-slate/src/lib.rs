// SPDX-License-Identifier: Apache-2.0
//! The native slate codec `lepic.v1`: a compact, fixed-layout binary slate with an extension
//! tail.
//!
//! A slate starts with a 51-byte header: the magic `89 45 53 4C`, the format version `01`, the
//! network (`00` mainnet, `01` floonet), the stage (S1–S3 are 1–3, I1–I3 are 4–6), the flags,
//! the kernel features, the block header version, the slate id, the amount, the fee and the
//! height. All integers are big-endian. The body follows: the lock height when the kernel is
//! height-locked, the TTL cutoff when its flag is set, the offset, the sender and the receiver
//! as their stage has them, the payment proof when its flag is set, the inputs, the outputs, the
//! kernel at a final stage, and last the extension tail (see [`tail`]).
//!
//! The format carries what the other party needs and nothing else. A proposal (S1, I1) has no
//! inputs or outputs, and an answer (S2, I2) leaves out the initiator's message.
//! [`NativeSlate::new`] drops both, and decoding refuses them, so each slate has one encoding
//! and `encode(decode(x)) == x`.
//!
//! The block header version follows the network's fork table: 6 below the first hard fork, 7
//! from it. A slate whose header version differs from the one its height takes is refused, and
//! so is a slate of another network than the codec's.
//!
//! [`NativeSlate`] keeps the tail. [`NativeV1Codec`], the [`Codec`](lepic_slate::codec::Codec)
//! form, checks the tail on decode and then drops it, unknown records included, and encodes
//! with an empty tail. [`SlateView`] is a JSON form that names every field.
//!
//! Every refusal is a typed [`NativeError`], found before anything larger than the input is
//! allocated.

mod codec;
mod error;
mod slate;
pub mod tail;
mod view;
mod wire;

use lepic_slate::codec::{CodecId, MediaType};

pub use codec::NativeV1Codec;
pub use error::{NativeError, TailError};
pub use slate::{
    FLAG_PROOF, FLAG_RECEIVER_MESSAGE, FLAG_RESERVED, FLAG_SENDER_MESSAGE, FLAG_TTL, INPUT_LEN,
    NativeSlate, OUTPUT_LEN,
};
pub use tail::{ReplyKey, ReplyMailbox, Tail, UnknownRecord};
pub use view::{
    InputView, KernelView, MailboxView, MessageView, OutputView, ParticipantView, PaymentProofView,
    SlateView, TailView, UnknownRecordView,
};

/// The id `lepic.v1` is stored and negotiated under. It never changes.
pub const NATIVE_V1: CodecId = CodecId::new("lepic.v1");
/// Media type of a `lepic.v1` slate.
pub const MEDIA_TYPE: MediaType = MediaType::new("application/vnd.lepic.slate");
/// First bytes of every `lepic.v1` slate.
pub const MAGIC: [u8; 4] = [0x89, 0x45, 0x53, 0x4C];
/// The format version this crate reads and writes.
pub const VERSION: u8 = 1;
/// Length of the fixed header.
pub const HEADER_LEN: usize = 51;
