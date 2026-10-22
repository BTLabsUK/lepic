//! The listener the wallet's onion forwards to.

use lepic_foreign::{Exposure, ListenSettings};

/// Settings for the listener behind the onion, on `127.0.0.1` at a free port. Tor connects
/// to it from `127.0.0.1` for every sender, so a limit per remote address would make all
/// senders share it: the listener's whole connection cap is the limit per address instead,
/// and tor limits each sender's circuit to
/// [`MAX_STREAMS_PER_CIRCUIT`](crate::control::MAX_STREAMS_PER_CIRCUIT) streams. The
/// connection cap and the request and payment budgets still bound the work of all senders
/// together.
#[must_use]
pub const fn listen_settings() -> ListenSettings {
    let mut settings = ListenSettings::new(Exposure::LocalOnly, 0);
    settings.max_connections_per_address = settings.max_connections;
    settings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_sender_shares_only_the_whole_connection_cap() {
        let settings = listen_settings();
        let plain = ListenSettings::new(Exposure::LocalOnly, 0);
        assert_eq!(settings.exposure, Exposure::LocalOnly);
        assert_eq!(settings.port, 0);
        assert_eq!(settings.max_connections, plain.max_connections);
        assert_eq!(
            settings.max_connections_per_address,
            settings.max_connections
        );
        assert_eq!(settings.requests_per_minute, plain.requests_per_minute);
        assert_eq!(settings.receives_per_minute, plain.receives_per_minute);
    }
}
