// SPDX-License-Identifier: Apache-2.0
//! The native direct endpoint (ADR 0052) as the HTTP and Tor methods reach it: the advert a
//! listener's `check_version` answer carries, and the endpoint it names, posted to the way the
//! method reaches the listener. Sealing and opening the envelopes is the caller's.

use lepic_peer::{
    Advert, FORMAT_LEPIC_V1, Origin, OriginError, PROTOCOL, PeerClient, PeerClientError,
    PeerTarget, WebScheme,
};
use lepic_transport::transport::{BoxFuture, Destination};
use thiserror::Error;

use super::{ClientError, Http, ListenerUrl, PlainHttp, Scheme};

/// What a listener's `check_version` answer says about its native endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    origin: Origin,
    scheme: WebScheme,
    host: String,
    port: u16,
    advert: Option<Advert>,
}

impl Probe {
    /// The answer of the listener at `host:port` reached with `scheme`. An advert of another
    /// protocol, or one without `lepic.v1`, is one this build cannot use and counts as none.
    pub fn new(
        scheme: WebScheme,
        host: &str,
        port: u16,
        advert: Option<Advert>,
    ) -> Result<Self, OriginError> {
        let origin = Origin::new(scheme, host, port)?;
        let advert =
            advert.filter(|advert| advert.protocol == PROTOCOL && advert.offers(FORMAT_LEPIC_V1));
        Ok(Self {
            origin,
            scheme,
            host: host.to_owned(),
            port,
            advert,
        })
    }

    /// The origin a pin of the listener's key is kept under.
    pub const fn origin(&self) -> &Origin {
        &self.origin
    }

    /// The listener's advert, when it serves an endpoint this build speaks.
    pub const fn advert(&self) -> Option<&Advert> {
        self.advert.as_ref()
    }

    /// The endpoint `advert` names, on the host and port the listener was reached at.
    pub fn target(&self, advert: &Advert) -> Result<PeerTarget, OriginError> {
        PeerTarget::new(self.scheme, &self.host, self.port, &advert.path)
    }
}

/// Why a listener's advert could not be read.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProbeError {
    #[error(transparent)]
    Http(#[from] ClientError),
    #[cfg(feature = "tor")]
    #[error(transparent)]
    Tor(#[from] crate::tor::TorSendError),
    #[error("the address could not be used: {0}")]
    Origin(#[from] OriginError),
}

/// A method's way to a listener's native endpoint.
pub trait DirectPeer: Send + Sync {
    /// The listener's `check_version` answer at `to`, an address of the method.
    fn probe<'a>(&'a self, to: &'a Destination) -> BoxFuture<'a, Result<Probe, ProbeError>>;

    /// Posts `envelope` to `target` and returns the reply envelope as it came.
    fn post<'a>(
        &'a self,
        target: &'a PeerTarget,
        envelope: &'a [u8],
    ) -> BoxFuture<'a, Result<Vec<u8>, PeerClientError>>;
}

/// The native endpoints of HTTP listeners: the advert read through an [`Http`] method, the
/// envelope posted through a [`PeerClient`].
#[derive(Debug, Clone)]
pub struct HttpPeer {
    http: Http,
    client: PeerClient,
}

impl HttpPeer {
    /// Reads adverts through `http` and posts through `client`; the client decides which
    /// computers a post may reach.
    pub fn new(http: Http, client: PeerClient) -> Self {
        Self { http, client }
    }
}

impl Http {
    /// The `check_version` answer of the listener at `to`, as a send's first call reads it.
    pub async fn probe(&self, to: &Destination) -> Result<Probe, ProbeError> {
        // As for a send, the destination already carries the user's plain-HTTP choice.
        let url = ListenerUrl::parse(to.as_str(), PlainHttp::Allowed).map_err(ClientError::from)?;
        let version = self.client.check_version(&url).await?;
        let scheme = match url.scheme() {
            Scheme::Http => WebScheme::Http,
            Scheme::Https => WebScheme::Https,
        };
        Ok(Probe::new(scheme, url.host(), url.port(), version.lepic)?)
    }
}

impl DirectPeer for HttpPeer {
    fn probe<'a>(&'a self, to: &'a Destination) -> BoxFuture<'a, Result<Probe, ProbeError>> {
        Box::pin(self.http.probe(to))
    }

    fn post<'a>(
        &'a self,
        target: &'a PeerTarget,
        envelope: &'a [u8],
    ) -> BoxFuture<'a, Result<Vec<u8>, PeerClientError>> {
        Box::pin(self.client.post_slate(target, envelope))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_advert_this_build_cannot_use_counts_as_none() {
        let advert = Advert::new([3; 32]);
        let probe = |advert| Probe::new(WebScheme::Http, "Wallet.Example", 3415, advert).unwrap();
        assert_eq!(probe(Some(advert.clone())).advert(), Some(&advert));
        let other = Advert {
            protocol: 2,
            ..advert.clone()
        };
        assert_eq!(probe(Some(other)).advert(), None);
        let other = Advert {
            formats: vec!["other".to_owned()],
            ..advert.clone()
        };
        assert_eq!(probe(Some(other)).advert(), None);
        let probed = probe(Some(advert.clone()));
        assert_eq!(probed.origin().to_string(), "http://wallet.example:3415");
        assert_eq!(
            probed.target(&advert).unwrap().slates_uri(),
            "http://wallet.example:3415/v1/peer/slates"
        );
    }
}
