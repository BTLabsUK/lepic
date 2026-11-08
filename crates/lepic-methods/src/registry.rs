// SPDX-License-Identifier: Apache-2.0
//! The methods a consumer offers, looked up by id. Adding a method is one module plus one
//! [`Methods::register`] call.

use std::sync::Arc;

use lepic_transport::method::Method;
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

impl std::fmt::Debug for Methods {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.ids()).finish()
    }
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (docs/rules.md).
    #![allow(clippy::unwrap_used)]

    use lepic_transport::file::{FILE, FileTransport};

    use super::*;

    #[test]
    fn a_registered_method_is_found_by_id() {
        let mut methods = Methods::new();
        methods
            .register(Arc::new(FileTransport::default()))
            .unwrap();
        assert_eq!(methods.get(FILE).map(|method| method.id()), Some(FILE));
        assert_eq!(methods.ids(), [FILE]);
        assert_eq!(methods.iter().count(), 1);
    }

    #[test]
    fn an_unknown_id_is_absent() {
        let methods = Methods::new();
        assert!(methods.get(FILE).is_none());
        assert!(methods.ids().is_empty());
    }

    #[test]
    fn a_duplicate_id_is_refused() {
        let mut methods = Methods::new();
        methods
            .register(Arc::new(FileTransport::default()))
            .unwrap();
        let error = methods
            .register(Arc::new(FileTransport::default()))
            .unwrap_err();
        assert_eq!(error, RegistryError::DuplicateTransport { transport: FILE });
        assert_eq!(methods.ids(), [FILE]);
    }
}
