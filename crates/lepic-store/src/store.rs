use crate::account::AccountRepository;
use crate::context::ContextRepository;
use crate::error::StoreError;
use crate::invoice::InvoiceRepository;
use crate::output::OutputRepository;
use crate::peer::PeerRepository;
use crate::relay::RelayRepository;
use crate::settings::SettingsRepository;
use crate::slate::SlateRepository;
use crate::transaction::TransactionRepository;

/// Every repository, as seen inside one store transaction.
pub trait Repositories:
    AccountRepository
    + OutputRepository
    + TransactionRepository
    + SlateRepository
    + ContextRepository
    + RelayRepository
    + SettingsRepository
    + InvoiceRepository
    + PeerRepository
{
}

impl<T> Repositories for T where
    T: AccountRepository
        + OutputRepository
        + TransactionRepository
        + SlateRepository
        + ContextRepository
        + RelayRepository
        + SettingsRepository
        + InvoiceRepository
        + PeerRepository
{
}

/// The wallet's storage port. All access happens inside a transaction that spans every
/// repository: a `write` whose closure returns `Err` leaves nothing behind, one that returns
/// `Ok` is durable when `write` returns.
pub trait WalletStore: Send + Sync {
    /// Runs `operation` against a consistent snapshot.
    fn read<R, E>(&self, operation: impl FnOnce(&dyn Repositories) -> Result<R, E>) -> Result<R, E>
    where
        E: From<StoreError>;

    /// Runs `operation` in one atomic write transaction, serialised with every other writer.
    fn write<R, E>(
        &self,
        operation: impl FnOnce(&mut dyn Repositories) -> Result<R, E>,
    ) -> Result<R, E>
    where
        E: From<StoreError>;
}
