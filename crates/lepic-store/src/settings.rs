// SPDX-License-Identifier: Apache-2.0
use crate::error::StoreError;

pub trait SettingsRepository {
    /// Inserts or replaces the value stored under `key`.
    fn put_setting(&mut self, key: &str, value: &str) -> Result<(), StoreError>;

    fn setting(&self, key: &str) -> Result<Option<String>, StoreError>;

    /// The settings whose key starts with `prefix`, as `(key, value)` in key order.
    fn settings_with_prefix(&self, prefix: &str) -> Result<Vec<(String, String)>, StoreError>;

    /// Removes the setting if it is stored.
    fn delete_setting(&mut self, key: &str) -> Result<(), StoreError>;
}
