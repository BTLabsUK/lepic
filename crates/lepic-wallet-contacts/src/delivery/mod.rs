// SPDX-License-Identifier: Apache-2.0
//! The delivery layer: one carrier for the mailboxes the wallet watches and the posts it sends,
//! and a router that hands each pushed message to the handler of its class.
//!
//! The carrier claims the rows of the watch set on the contacts' shared mux/1 sessions and posts
//! on an Epicbox route, on a held session when it can, and on an `http` or `tor` route through
//! the host's poster. The router waits on those sessions and
//! acknowledges a message only once its handler stored it.
//!
//! The features reach the mailboxes through [`transport::Transport`] alone. The adapter behind
//! it is `carrier`, `epicbox`, `peer`, `router`, `watch` and `crate::relay`; no other module
//! names a mux/1 session.

pub(crate) mod carrier;
pub(crate) mod epicbox;
pub(crate) mod fill;
pub(crate) mod outbox;
pub(crate) mod peer;
pub(crate) mod reconcile;
pub(crate) mod refusal;
pub(crate) mod router;
#[cfg(test)]
pub(crate) mod testing;
pub(crate) mod transport;
pub(crate) mod watch;
