// SPDX-License-Identifier: Apache-2.0
//! The wait a mailbox or peer asked for, and the mailbox an error names, read from an error a
//! host got.
//!
//! A refused post carries its wait as data on the error that names it: on
//! [`ClientError::PostRefused`] for a mailbox, on [`PeerClientError`] for a peer. The error a
//! host gets wraps those (a send's transport error, a contact error, the host's own), so the
//! wait is read by walking the error's sources. The mailbox a refusal came from, or that an old
//! link names, is read the same way.

use std::error::Error;
use std::time::Duration;

use lepic_epic1::LinkError;
use lepic_epicbox::ClientError;
use lepic_peer::PeerClientError;

/// The wait `error`, or an error in its chain of sources, says to keep before posting again:
/// the first the chain names. `None` when no refusal in it named one.
#[must_use]
pub fn retry_after_of(error: &(dyn Error + 'static)) -> Option<Duration> {
    let mut next = Some(error);
    while let Some(error) = next {
        let wait = match (
            error.downcast_ref::<ClientError>(),
            error.downcast_ref::<PeerClientError>(),
        ) {
            (Some(client), _) => client.retry_after(),
            (
                None,
                Some(
                    PeerClientError::NotReady { retry_after }
                    | PeerClientError::RateLimited { retry_after },
                ),
            ) => *retry_after,
            _ => None,
        };
        if wait.is_some() {
            return wait;
        }
        next = error.source();
    }
    None
}

/// The mailbox, `host[:port]`, that `error`, or an error in its chain of sources, names: the relay
/// that refused a post, or the one an epic1 link of an earlier release names. The first the chain
/// names; `None` when none does, as for a refusal of a native endpoint or a bare address.
#[must_use]
pub fn mailbox_of(error: &(dyn Error + 'static)) -> Option<String> {
    let mut next = Some(error);
    while let Some(error) = next {
        let named = match (
            error.downcast_ref::<ClientError>(),
            error.downcast_ref::<LinkError>(),
        ) {
            (Some(client), _) => client.mailbox().map(str::to_owned),
            (None, Some(LinkError::EarlierAddress { mailbox })) => mailbox.clone(),
            _ => None,
        };
        if named.is_some() {
            return named;
        }
        next = error.source();
    }
    None
}

#[cfg(test)]
mod tests {
    use lepic_epicbox::{MailboxError, RelayErrorKind};

    use super::*;
    use crate::ContactError;

    fn refused(wait: Option<u64>) -> ClientError {
        ClientError::PostRefused {
            kind: RelayErrorKind::InvalidRequest,
            description: Some("Rate limit exceeded.".to_owned()),
            retry_after: wait.map(Duration::from_secs),
            mailbox: None,
        }
    }

    #[test]
    fn a_refused_post_names_its_mailbox_through_the_errors_around_it() {
        let relay = lepic_epicbox::RelayEndpoint::new(
            lepic_epicbox::Domain::parse("relay.test").expect("domain"),
            Some(443),
            lepic_epicbox::Security::Tls,
        );
        let named = refused(None).at_relay(&relay);
        let error = ContactError::Relay(MailboxError::Protocol(named));
        assert_eq!(mailbox_of(&error).as_deref(), Some("relay.test:443"));
        // A refusal that names none, and an error that is no refusal, name none.
        let unnamed = ContactError::Relay(MailboxError::Protocol(refused(None)));
        assert_eq!(mailbox_of(&unnamed), None);
        assert_eq!(mailbox_of(&ContactError::Offline), None);
    }

    #[test]
    fn a_link_of_an_earlier_release_names_the_mailbox_it_carries() {
        let named = ContactError::Epic1Link(LinkError::EarlierAddress {
            mailbox: Some("box.example:8443".to_owned()),
        });
        assert_eq!(mailbox_of(&named).as_deref(), Some("box.example:8443"));
        let bare = ContactError::Epic1Link(LinkError::EarlierAddress { mailbox: None });
        assert_eq!(mailbox_of(&bare), None);
    }

    #[test]
    fn a_refused_post_gives_its_wait_through_the_errors_around_it() {
        let error = ContactError::Relay(MailboxError::Protocol(refused(Some(30))));
        assert_eq!(retry_after_of(&error), Some(Duration::from_secs(30)));
        assert_eq!(
            retry_after_of(&refused(Some(7))),
            Some(Duration::from_secs(7))
        );
    }

    #[test]
    fn a_peer_that_names_a_wait_gives_it() {
        let wait = Some(Duration::from_secs(9));
        for error in [
            PeerClientError::NotReady { retry_after: wait },
            PeerClientError::RateLimited { retry_after: wait },
        ] {
            assert_eq!(retry_after_of(&error), wait);
        }
        assert_eq!(
            retry_after_of(&PeerClientError::RateLimited { retry_after: None }),
            None
        );
    }

    #[test]
    fn an_error_that_names_no_wait_gives_none() {
        assert_eq!(retry_after_of(&refused(None)), None);
        assert_eq!(
            retry_after_of(&ContactError::Relay(MailboxError::Protocol(
                ClientError::Relay {
                    kind: RelayErrorKind::InvalidRequest
                }
            ))),
            None
        );
        assert_eq!(retry_after_of(&ContactError::Offline), None);
    }
}
