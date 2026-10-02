use crate::error::StoreError;

pub trait SettingsRepository {
    /// Inserts or replaces the value stored under `key`.
    fn put_setting(&mut self, key: &str, value: &str) -> Result<(), StoreError>;

    fn setting(&self, key: &str) -> Result<Option<String>, StoreError>;

    /// Removes the setting if it is stored.
    fn delete_setting(&mut self, key: &str) -> Result<(), StoreError>;
}
