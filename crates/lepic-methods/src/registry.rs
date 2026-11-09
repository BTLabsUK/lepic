// SPDX-License-Identifier: Apache-2.0
//! The methods a consumer offers, looked up by id. Adding a method is one module plus one
//! [`Methods::register`] call.

use std::sync::Arc;

use lepic_transport::method::{Method, MethodLookup};
use lepic_transport::transport::TransportId;
use thiserror::Error;

/// A method registry that cannot accept a registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RegistryError {
    #[error("transport {transport} is already registered")]
    DuplicateTransport { transport: TransportId },
}

/// The registered methods, in registration order.
#[derive(Default)]
pub struct Methods {
    methods: Vec<Arc<dyn Method>>,
}

impl Methods {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `method`, refusing one whose id is already registered.
    pub fn register(&mut self, method: Arc<dyn Method>) -> Result<(), RegistryError> {
        let id = method.id();
        if self.get(id).is_some() {
            return Err(RegistryError::DuplicateTransport { transport: id });
        }
        self.methods.push(method);
        Ok(())
    }

    /// The method registered under `id`.
    pub fn get(&self, id: TransportId) -> Option<&Arc<dyn Method>> {
        self.methods.iter().find(|method| method.id() == id)
    }

    /// The ids of the registered methods, in registration order.
    pub fn ids(&self) -> Vec<TransportId> {
        self.methods.iter().map(|method| method.id()).collect()
    }

    /// The registered methods, in registration order.
    pub fn iter(&self) -> impl Iterator<Item = &Arc<dyn Method>> {
        self.methods.iter()
    }
}

impl MethodLookup for Methods {
    fn method_named(&self, name: &str) -> Option<Arc<dyn Method>> {
        self.iter()
            .find(|method| method.id().as_str() == name)
            .cloned()
    }
}

impl std::fmt::Debug for Methods {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.ids()).finish()
    }
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (docs/rules.md).
    #![allow(clippy::unwrap_used)]

    use lepic_slate::codec::{CodecId, EncodeContext};
    use lepic_slate::model::Slate;
    use lepic_transport::method::Carries;
    use lepic_transport::policy::{Encoding, FormatPolicy};

    use super::*;

    const STUB: TransportId = TransportId::new("stub");

    /// A method with no codecs of its own, so the registry is tested without any wire format.
    struct Stub;

    impl FormatPolicy for Stub {
        fn accepted(&self) -> &[CodecId] {
            &[]
        }

        fn for_new_slate(&self, _slate: &Slate, _context: &EncodeContext) -> Encoding {
            Encoding {
                codec: CodecId::new("stub"),
                legacy_header: None,
            }
        }

        fn for_reply(&self, slate: &Slate, context: &EncodeContext) -> Encoding {
            self.for_new_slate(slate, context)
        }
    }

    impl lepic_transport::transport::Transport for Stub {
        fn id(&self) -> TransportId {
            STUB
        }

        fn policy(&self) -> &dyn FormatPolicy {
            self
        }
    }

    impl Method for Stub {
        fn carries(&self) -> Carries {
            Carries::default()
        }

        fn notice_lengths(&self) -> &'static [usize] {
            &[]
        }
    }

    #[test]
    fn a_registered_method_is_found_by_id() {
        let mut methods = Methods::new();
        methods.register(Arc::new(Stub)).unwrap();
        assert_eq!(methods.get(STUB).map(|method| method.id()), Some(STUB));
        assert_eq!(methods.ids(), [STUB]);
        assert_eq!(methods.iter().count(), 1);
    }

    #[test]
    fn an_unknown_id_is_absent() {
        let methods = Methods::new();
        assert!(methods.get(STUB).is_none());
        assert!(methods.ids().is_empty());
    }

    #[test]
    fn a_duplicate_id_is_refused() {
        let mut methods = Methods::new();
        methods.register(Arc::new(Stub)).unwrap();
        let error = methods.register(Arc::new(Stub)).unwrap_err();
        assert_eq!(error, RegistryError::DuplicateTransport { transport: STUB });
        assert_eq!(methods.ids(), [STUB]);
    }

    /// Without the legacy formats the method defaults know no codec: a slate is refused as an
    /// unknown format rather than decoded.
    #[cfg(not(feature = "legacy"))]
    #[test]
    fn without_legacy_the_defaults_decode_nothing() {
        use lepic_primitives::params::Network;
        use lepic_slate::codec::{MediaType, WireSlate};
        use lepic_slate::error::DecodeError;

        let wire = WireSlate::text(MediaType::JSON, "{}".to_owned());
        let decoded = Method::decode(&Stub, Network::Mainnet, &wire);
        assert!(matches!(decoded, Err(DecodeError::UnknownFormat)));
    }
}
