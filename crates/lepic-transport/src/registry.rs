//! The transports a wallet offers, looked up by id. Adding a method is one module plus one
//! [`TransportRegistry::register`] call.

use crate::error::RegistryError;
use crate::transport::{Transport, TransportId};

#[derive(Default)]
pub struct TransportRegistry {
    transports: Vec<Box<dyn Transport>>,
}

impl TransportRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, transport: Box<dyn Transport>) -> Result<(), RegistryError> {
        let id = transport.id();
        if self.get(id).is_some() {
            return Err(RegistryError::DuplicateTransport { transport: id });
        }
        self.transports.push(transport);
        Ok(())
    }

    pub fn get(&self, id: TransportId) -> Option<&dyn Transport> {
        self.transports
            .iter()
            .map(Box::as_ref)
            .find(|transport| transport.id() == id)
    }

    pub fn ids(&self) -> impl Iterator<Item = TransportId> + '_ {
        self.transports.iter().map(|transport| transport.id())
    }
}

impl std::fmt::Debug for TransportRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.ids()).finish()
    }
}
