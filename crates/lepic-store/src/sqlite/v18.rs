// SPDX-License-Identifier: Apache-2.0
//! Fills the delivery tables schema version 18 adds from what version 17 kept: the mailboxes
//! the wallet watches, the contact posts it still owes, and the delivery state of payments with
//! a caller's alias. Epic1 links and payments kept by version 17 are not carried over.
//!
//! The settings read here belong to other crates; each fill reads a frozen copy of the fields
//! it needs and names the file that writes them. A row that does not read, or that the new
//! table cannot hold, is skipped and counted: a wallet must open after an update whatever its
//! stored data holds. Only SQL errors fail the migration. Old rows stay as they are, except the
//! `api.alias.*` settings, which the alias fill deletes once read.

use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;
use serde::de::IgnoredAny;
use tracing::warn;
use uuid::Uuid;

use crate::delivery::{
    MAX_ALIAS_LEN, MAX_ENVELOPE_LEN, MAX_KEY_REF_LEN, MAX_RELAY_LEN, MAX_ROUTE_VALUE_LEN,
    MailClass, OutboxState,
};
use crate::error::StoreError;
use crate::slate::SlateStage;

/// `lepic-wallet-contacts/src/collect.rs`, `OLD_SALT_PREFIX`.
const OLD_SALT_PREFIX: &str = "contact.oldsalt.";
/// `lepic-wallet-contacts/src/in_person.rs`, `CODE_PREFIX`.
const CODE_PREFIX: &str = "inperson.code.";
/// The settings key wallet API builds before schema 20 used.
const ALIAS_PREFIX: &str = "api.alias.";

/// The contact outbox only ever posted to Epicbox mailboxes.
const EPICBOX_ROUTE: &str = "epicbox";

/// `lepic-wallet-contacts/src/collect.rs`, `OldSalt`.
#[derive(Deserialize)]
struct OldSalt {
    #[serde(rename = "salt")]
    _salt: String,
}

/// `lepic-wallet-contacts/src/in_person.rs`, `CodeState`.
#[derive(Deserialize)]
struct CodeState {
    tx_id: u32,
    #[serde(rename = "account")]
    _account: u32,
    #[serde(rename = "kind")]
    _kind: IgnoredAny,
    #[serde(rename = "ttl_cutoff")]
    _ttl_cutoff: u64,
    mailbox: Option<String>,
    #[serde(rename = "closed")]
    _closed: bool,
    finalized: Option<u32>,
    #[serde(rename = "answers")]
    _answers: IgnoredAny,
}

/// Now, in the nanoseconds the store keeps times in. A clock before 1970 or past 2262 reads as
/// 1970: every expiring row is then kept, and expires on the first run with a sane clock.
pub(super) fn clock_nanos() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|since| i64::try_from(since.as_nanos()).ok())
        .unwrap_or(0)
}

/// One source of the fill: writes its rows, and returns how many records it skipped.
type Fill = fn(&Connection, i64) -> Result<usize, StoreError>;

/// Fills the version 18 tables, with `now` in nanoseconds since 1970.
pub(super) fn fill(conn: &Connection, now: i64) -> Result<(), StoreError> {
    let sources: [(&str, Fill); 6] = [
        ("contact mailboxes", watch_contacts),
        ("old contact salts", watch_old_salts),
        ("pairings", watch_pairings),
        ("in-person codes", watch_in_person),
        ("contact outbox", outbox_from_contacts),
        ("payment aliases", deliveries_from_aliases),
    ];
    for (source, fill_from) in sources {
        let skipped = fill_from(conn, now)?;
        if skipped > 0 {
            warn!(
                count = skipped,
                source, "unreadable records skipped by the schema 18 fill"
            );
        }
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Adds the watch row unless one is there for the key and relay. Returns `false`, writing
/// nothing, when the table cannot hold it.
fn watch(
    conn: &Connection,
    key_ref: &str,
    relay: &str,
    class: MailClass,
    expires_at: Option<i64>,
) -> Result<bool, StoreError> {
    let fits = |text: &str, max: usize| !text.is_empty() && text.len() <= max;
    if !fits(key_ref, MAX_KEY_REF_LEN) || !fits(relay, MAX_RELAY_LEN) {
        return Ok(false);
    }
    conn.execute(
        "INSERT INTO watch_set (key_ref, relay, class, expires_at) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (key_ref, relay) DO NOTHING",
        params![key_ref, relay, class.code(), expires_at],
    )?;
    Ok(true)
}

fn count(skipped: &mut usize, written: bool) {
    if !written {
        *skipped = skipped.saturating_add(1);
    }
}

/// The settings under `prefix`, with the prefix cut from the key. `LIKE` ignores ASCII case, so
/// the cut also checks it.
fn settings_with_prefix(
    conn: &Connection,
    prefix: &str,
) -> Result<Vec<(String, String)>, StoreError> {
    let mut statement =
        conn.prepare("SELECT key, value FROM settings WHERE key LIKE ?1 || '%' ORDER BY key")?;
    let rows = statement
        .query_map([prefix], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows
        .into_iter()
        .filter_map(|(key, value)| Some((key.strip_prefix(prefix)?.to_owned(), value)))
        .collect())
}

fn transaction_state(conn: &Connection, tx_id: u32) -> Result<Option<String>, StoreError> {
    Ok(conn
        .query_row(
            "SELECT state FROM transactions WHERE id = ?1",
            [i64::from(tx_id)],
            |row| row.get(0),
        )
        .optional()?)
}

/// A contact the collect reads mailboxes of (`lepic-wallet-contacts/src/collect.rs`): it has a
/// peer card and a mailbox, and did not end on a key mismatch.
struct WatchedContact {
    id_hex: String,
    home_relay: String,
    prev_relay: Option<String>,
    prev_until: Option<i64>,
}

fn watched_contacts(conn: &Connection) -> Result<Vec<WatchedContact>, StoreError> {
    let mut statement = conn.prepare(
        "SELECT c.contact_id, m.home_relay, m.prev_relay, m.prev_until
         FROM contacts c JOIN contact_mailboxes m ON m.contact_id = c.contact_id
         WHERE c.card IS NOT NULL AND (c.ended_reason IS NULL OR c.ended_reason != 'mismatch')
         ORDER BY c.contact_id",
    )?;
    let contacts = statement
        .query_map([], |row| {
            Ok(WatchedContact {
                id_hex: hex(&row.get::<_, Vec<u8>>(0)?),
                home_relay: row.get(1)?,
                prev_relay: row.get(2)?,
                prev_until: row.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(contacts)
}

/// A contact's mailbox on its home relay, and on the relay it moved from while the drain of
/// that relay lasts.
fn watch_contacts(conn: &Connection, now: i64) -> Result<usize, StoreError> {
    let mut skipped = 0;
    for contact in watched_contacts(conn)? {
        let key_ref = format!("contact:{}", contact.id_hex);
        let written = watch(
            conn,
            &key_ref,
            &contact.home_relay,
            MailClass::Contact,
            None,
        )?;
        count(&mut skipped, written);
        if let (Some(relay), Some(until)) = (contact.prev_relay, contact.prev_until)
            && until > now
        {
            let written = watch(conn, &key_ref, &relay, MailClass::PreviousHome, Some(until))?;
            count(&mut skipped, written);
        }
    }
    Ok(skipped)
}

/// The mailbox under a contact's old box salt, read on its home relay until the contact writes
/// to the new one.
fn watch_old_salts(conn: &Connection, _now: i64) -> Result<usize, StoreError> {
    let contacts = watched_contacts(conn)?;
    let mut skipped = 0;
    for (id_hex, value) in settings_with_prefix(conn, OLD_SALT_PREFIX)? {
        let Some(contact) = contacts.iter().find(|contact| contact.id_hex == id_hex) else {
            continue;
        };
        if serde_json::from_str::<OldSalt>(&value).is_err() {
            count(&mut skipped, false);
            continue;
        }
        let key_ref = format!("contact-old-salt:{id_hex}");
        let written = watch(
            conn,
            &key_ref,
            &contact.home_relay,
            MailClass::Contact,
            None,
        )?;
        count(&mut skipped, written);
    }
    Ok(skipped)
}

/// Every pairing in progress, on the relay of the mailbox it is answered at: the text after the
/// last `@` of `our_mailbox`, an Epicbox address as `key@domain[:port]`.
fn watch_pairings(conn: &Connection, _now: i64) -> Result<usize, StoreError> {
    let mut statement = conn
        .prepare("SELECT pairing_id, our_mailbox, expires_at FROM pairings ORDER BY pairing_id")?;
    let pairings = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut skipped = 0;
    for (id, mailbox, expires_at) in pairings {
        let Some((_, relay)) = mailbox.rsplit_once('@') else {
            count(&mut skipped, false);
            continue;
        };
        let key_ref = format!("pairing:{}", hex(&id));
        let written = watch(conn, &key_ref, relay, MailClass::Pairing, Some(expires_at))?;
        count(&mut skipped, written);
    }
    Ok(skipped)
}

/// The settings under `prefix` whose key ends in a slate id, with the id in its canonical form.
fn slate_settings(conn: &Connection, prefix: &str) -> Result<Vec<(Uuid, String)>, StoreError> {
    Ok(settings_with_prefix(conn, prefix)?
        .into_iter()
        .map(|(id, value)| (Uuid::parse_str(&id).unwrap_or(Uuid::nil()), value))
        .collect())
}

/// The reply mailbox of an in-person code whose transaction is open and not finalized. Its end
/// is a block height, which the watch set does not keep.
fn watch_in_person(conn: &Connection, _now: i64) -> Result<usize, StoreError> {
    let mut skipped = 0;
    for (slate_id, value) in slate_settings(conn, CODE_PREFIX)? {
        let state = serde_json::from_str::<CodeState>(&value).ok();
        let Some(state) = state.filter(|_| !slate_id.is_nil()) else {
            count(&mut skipped, false);
            continue;
        };
        let open = matches!(
            transaction_state(conn, state.tx_id)?.as_deref(),
            Some("received" | "sent")
        );
        if let (true, None, Some(relay)) = (open, state.finalized, state.mailbox) {
            let key_ref = format!("inperson:{slate_id}");
            let written = watch(conn, &key_ref, &relay, MailClass::InPerson, None)?;
            count(&mut skipped, written);
        }
    }
    Ok(skipped)
}

/// A contact outbox row as the native outbox entry of its payment, sent from the contact's
/// mailbox, with its stage, when it was stored and when it was delivered. `delivered` becomes
/// `posted`; `stuck` (undelivered for a day, retried only when the user asks) becomes `failed`.
/// A stage this version does not know is left out.
fn outbox_from_contacts(conn: &Connection, _now: i64) -> Result<usize, StoreError> {
    let mut statement = conn.prepare(
        "SELECT contact_id, slate_id, payload, destination, attempts, next_try_at, state, stage,
             created_at, delivered_at
         FROM contact_outbox ORDER BY id",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok(ContactOutboxRow {
                contact_id: row.get(0)?,
                slate_id: row.get(1)?,
                payload: row.get(2)?,
                destination: row.get(3)?,
                attempts: row.get(4)?,
                next_try_at: row.get(5)?,
                state: row.get(6)?,
                stage: row.get(7)?,
                created_at: row.get(8)?,
                delivered_at: row.get(9)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut skipped = 0;
    for row in rows {
        let state = match row.state.as_str() {
            "queued" => Some(OutboxState::Queued),
            "delivered" => Some(OutboxState::Posted),
            "stuck" => Some(OutboxState::Failed),
            _ => None,
        };
        let from_ref = format!("contact:{}", hex(&row.contact_id));
        let fits = row.slate_id.len() == 16
            && from_ref.len() <= MAX_KEY_REF_LEN
            && !row.payload.is_empty()
            && row.payload.len() <= MAX_ENVELOPE_LEN
            && !row.destination.is_empty()
            && row.destination.len() <= MAX_ROUTE_VALUE_LEN
            && u32::try_from(row.attempts).is_ok();
        let Some(state) = state.filter(|_| fits) else {
            count(&mut skipped, false);
            continue;
        };
        let stage = SlateStage::from_code(&row.stage).map(SlateStage::code);
        conn.execute(
            "INSERT INTO native_outbox (payment_id, from_ref, route_method, route_value,
                 envelope, state, attempts, next_at, cutoff_height, stage, created_at, posted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, ?9, ?10, ?11)",
            params![
                row.slate_id,
                from_ref,
                EPICBOX_ROUTE,
                row.destination,
                row.payload,
                state.code(),
                row.attempts,
                row.next_try_at,
                stage,
                row.created_at,
                row.delivered_at,
            ],
        )?;
    }
    Ok(skipped)
}

/// The columns of a contact outbox row the native outbox takes.
struct ContactOutboxRow {
    contact_id: Vec<u8>,
    slate_id: Vec<u8>,
    payload: String,
    destination: String,
    attempts: i64,
    next_try_at: i64,
    state: String,
    stage: String,
    created_at: i64,
    delivered_at: Option<i64>,
}

/// A caller's alias of a payment: set on the payment's row, or on a new row without a state.
/// A payment keeps one alias, the first by alias order; a second one is skipped. Each alias
/// setting is deleted once read: no later step and no build reads them.
fn deliveries_from_aliases(conn: &Connection, now: i64) -> Result<usize, StoreError> {
    let mut skipped = 0;
    for (alias, value) in settings_with_prefix(conn, ALIAS_PREFIX)? {
        conn.execute(
            "DELETE FROM settings WHERE key = ?1",
            [format!("{ALIAS_PREFIX}{alias}")],
        )?;
        let payment = Uuid::parse_str(&value).ok();
        let fits = !alias.is_empty() && alias.len() <= MAX_ALIAS_LEN;
        let Some(payment) = payment.filter(|_| fits) else {
            count(&mut skipped, false);
            continue;
        };
        let payment = &payment.as_bytes()[..];
        let existing: Option<Option<String>> = conn
            .query_row(
                "SELECT alias FROM payment_delivery WHERE payment_id = ?1",
                [payment],
                |row| row.get(0),
            )
            .optional()?;
        match existing {
            Some(Some(_)) => count(&mut skipped, false),
            Some(None) => {
                conn.execute(
                    "UPDATE payment_delivery SET alias = ?2 WHERE payment_id = ?1",
                    params![payment, alias],
                )?;
            }
            None => {
                conn.execute(
                    "INSERT INTO payment_delivery (payment_id, alias, state, state_reason,
                         updated_at)
                     VALUES (?1, ?2, NULL, NULL, ?3)",
                    params![payment, alias, now],
                )?;
            }
        }
    }
    Ok(skipped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::StoreKeys;
    use crate::sqlite::schema::migrate_to;

    /// 2027-01-15, in nanoseconds.
    const NOW: i64 = 1_800_000_000 * 1_000_000_000;

    /// A database at version 17 holding `seed`, with the version 18 tables added and empty.
    fn v17_with_new_tables(seed: &str) -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        let keys = StoreKeys::from_bytes([1; 32], [2; 32]);
        migrate_to(&mut conn, 17, &keys).unwrap();
        conn.execute_batch(
            "INSERT INTO accounts (idx, label, next_child) VALUES (0, 'default', 0);",
        )
        .unwrap();
        conn.execute_batch(seed).unwrap();
        conn.execute_batch(crate::sqlite::schema::MIGRATIONS[17])
            .unwrap();
        conn
    }

    fn watch_rows(conn: &Connection) -> Vec<(String, String, String, Option<i64>)> {
        conn.prepare(
            "SELECT key_ref, relay, class, expires_at FROM watch_set ORDER BY relay, key_ref",
        )
        .unwrap()
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
    }

    fn row(
        key_ref: &str,
        relay: &str,
        class: &str,
        expires_at: Option<i64>,
    ) -> (String, String, String, Option<i64>) {
        (
            key_ref.to_owned(),
            relay.to_owned(),
            class.to_owned(),
            expires_at,
        )
    }

    fn contact(id: &str, card: &str, ended: &str) -> String {
        format!(
            "INSERT INTO contacts (contact_id, card, label, state, allow_invoices, seal,
                 imported_from_backup, created_at, updated_at, account, slot, box_salt, own_card,
                 ended_reason)
             VALUES (X'{id}', {card}, 'c', 'paired', 0, 'on', 0, 1, 1, 0,
                 (SELECT count(*) FROM contacts), X'11111111111111111111111111111111', X'aa',
                 {ended});"
        )
    }

    fn transaction(id: u32, state: &str) -> String {
        format!(
            "INSERT INTO transactions (id, account, direction, state, amount_credited,
                 amount_debited, created_at, updated_at)
             VALUES ({id}, 0, 'outgoing', '{state}', 0, 0, 1, 1);"
        )
    }

    type OutboxRow = (
        i64,
        Vec<u8>,
        String,
        String,
        String,
        String,
        String,
        i64,
        i64,
        Option<i64>,
    );

    const C1: &str = "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1";
    const C2: &str = "c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2";
    const C3: &str = "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3";
    const C4: &str = "c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4";
    const SLATE_A: &str = "a1a1a1a1-a1a1-a1a1-a1a1-a1a1a1a1a1a1";
    const SLATE_B: &str = "b2b2b2b2-b2b2-b2b2-b2b2-b2b2b2b2b2b2";
    const SLATE_C: &str = "c3c3c3c3-c3c3-c3c3-c3c3-c3c3c3c3c3c3";

    fn mailbox(id: &str, home: &str, prev: &str, until: &str) -> String {
        format!(
            "INSERT INTO contact_mailboxes (contact_id, peer_mailbox, our_mailbox, home_relay,
                 prev_relay, prev_until)
             VALUES (X'{id}', 'p@{home}', 'o@{home}', '{home}', {prev}, {until});"
        )
    }

    #[test]
    fn contacts_are_watched_on_their_home_and_while_draining_their_previous_relay() {
        let later = NOW + 1;
        let seed = [
            contact(C1, "X'b1'", "NULL"),
            mailbox(C1, "relay-a", "'relay-old'", &later.to_string()),
            contact(C2, "X'b2'", "NULL"),
            mailbox(C2, "relay-b:8443", "'relay-gone'", &NOW.to_string()),
            // No peer card yet: a card shown and never answered.
            contact(C3, "NULL", "NULL"),
            mailbox(C3, "relay-c", "NULL", "NULL"),
            // Ended on a key mismatch: nothing is read from it.
            contact(C4, "X'b4'", "'mismatch'"),
            mailbox(C4, "relay-d", "NULL", "NULL"),
            contact("c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5", "X'b5'", "'unpaired'"),
            mailbox("c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5", "", "NULL", "NULL"),
        ]
        .concat();
        let conn = v17_with_new_tables(&seed);

        assert_eq!(watch_contacts(&conn, NOW).unwrap(), 1);
        assert_eq!(
            watch_rows(&conn),
            [
                row(&format!("contact:{C1}"), "relay-a", "contact", None),
                row(&format!("contact:{C2}"), "relay-b:8443", "contact", None),
                row(
                    &format!("contact:{C1}"),
                    "relay-old",
                    "previous-home",
                    Some(later)
                ),
            ]
        );
    }

    #[test]
    fn an_old_salt_is_watched_on_its_contacts_home_relay() {
        let seed = [
            contact(C1, "X'b1'", "NULL"),
            mailbox(C1, "relay-a", "NULL", "NULL"),
            contact(C2, "X'b2'", "NULL"),
            mailbox(C2, "relay-b", "NULL", "NULL"),
            format!(
                "INSERT INTO settings (key, value) VALUES
                     ('contact.oldsalt.{C1}', '{{\"salt\":\"0101\"}}'),
                     ('contact.oldsalt.{C2}', 'not json'),
                     ('contact.oldsalt.{C3}', '{{\"salt\":\"0303\"}}');"
            ),
        ]
        .concat();
        let conn = v17_with_new_tables(&seed);

        assert_eq!(watch_old_salts(&conn, NOW).unwrap(), 1);
        assert_eq!(
            watch_rows(&conn),
            [row(
                &format!("contact-old-salt:{C1}"),
                "relay-a",
                "contact",
                None
            )]
        );
    }

    #[test]
    fn a_pairing_is_watched_on_the_relay_of_its_mailbox_until_it_expires() {
        let seed = format!(
            "INSERT INTO pairings (pairing_id, role, contact_id, sealed, invite_id, expires_at,
                 our_mailbox, state, created_at, invite)
             VALUES (X'{C1}', 'inviter', X'{C1}', X'00', X'01', 500, 'key@relay-a:9000',
                     'pending-invite', 1, X'dd'),
                    (X'{C2}', 'inviter', X'{C2}', X'00', X'02', 600, 'no-relay',
                     'pending-invite', 1, X'dd');"
        );
        let conn = v17_with_new_tables(&seed);

        assert_eq!(watch_pairings(&conn, NOW).unwrap(), 1);
        assert_eq!(
            watch_rows(&conn),
            [row(
                &format!("pairing:{C1}"),
                "relay-a:9000",
                "pairing",
                Some(500)
            )]
        );
    }

    fn code(tx_id: u32, mailbox: &str, finalized: &str) -> String {
        format!(
            "{{\"tx_id\":{tx_id},\"account\":0,\"kind\":\"send\",\"ttl_cutoff\":900,
              \"mailbox\":{mailbox},\"closed\":false,\"finalized\":{finalized},\"answers\":[]}}"
        )
    }

    #[test]
    fn an_open_in_person_code_is_watched_at_its_reply_relay() {
        let seed = [
            transaction(1, "received"),
            transaction(2, "sent"),
            transaction(3, "confirmed"),
            format!(
                "INSERT INTO settings (key, value) VALUES
                     ('inperson.code.{SLATE_A}', '{}'),
                     ('inperson.code.{SLATE_B}', '{}'),
                     ('inperson.code.{SLATE_C}', '{}'),
                     ('inperson.code.d4d4d4d4-d4d4-d4d4-d4d4-d4d4d4d4d4d4', '{}'),
                     ('inperson.code.e5e5e5e5-e5e5-e5e5-e5e5-e5e5e5e5e5e5', '{{}}'),
                     ('inperson.reply.{SLATE_A}', '{{}}');",
                code(1, "\"relay-a\"", "null"),
                code(2, "\"relay-b\"", "7"),
                code(3, "\"relay-c\"", "null"),
                code(2, "null", "null"),
            ),
        ]
        .concat();
        let conn = v17_with_new_tables(&seed);

        assert_eq!(watch_in_person(&conn, NOW).unwrap(), 1);
        assert_eq!(
            watch_rows(&conn),
            [row(
                &format!("inperson:{SLATE_A}"),
                "relay-a",
                "in-person",
                None
            )]
        );
    }

    #[test]
    fn each_contact_outbox_row_becomes_a_native_outbox_entry_of_its_payment() {
        let seed = [
            contact(C1, "X'b1'", "NULL"),
            format!(
                "INSERT INTO contact_outbox (id, contact_id, slate_id, stage, payload,
                     destination, attempts, next_try_at, state, created_at, delivered_at)
                 VALUES
                     (1, X'{C1}', X'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1', 'S1', 'env-1',
                      'box@relay-a', 0, 10, 'queued', 1, NULL),
                     (2, X'{C1}', X'b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2', 'S2', 'env-2',
                      'box@relay-a:9000', 3, 20, 'delivered', 2, 15),
                     (3, X'{C1}', X'c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3', 'invoice1', 'env-3',
                      'box@relay-a', 9, 30, 'stuck', 3, NULL),
                     (4, X'{C1}', X'd4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4', 'standard1', '',
                      'box@relay-a', 0, 40, 'queued', 1, NULL),
                     (5, X'{C1}', X'e5', 'standard1', 'env-5', 'box@relay-a', 0, 50, 'queued',
                      1, NULL),
                     (6, X'{C1}', X'f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6', 'standard1', 'env-6',
                      'box@relay-a', 0, 60, 'lost', 1, NULL);"
            ),
        ]
        .concat();
        let conn = v17_with_new_tables(&seed);

        assert_eq!(outbox_from_contacts(&conn, NOW).unwrap(), 3);
        let rows: Vec<OutboxRow> = conn
            .prepare("SELECT * FROM native_outbox ORDER BY id")
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                ))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let from = format!("contact:{C1}");
        let entry = |id: i64,
                     slate: u8,
                     route: &str,
                     envelope: &str,
                     state: &str,
                     attempts: i64,
                     next: i64| {
            (
                id,
                vec![slate; 16],
                from.clone(),
                "epicbox".to_owned(),
                route.to_owned(),
                envelope.to_owned(),
                state.to_owned(),
                attempts,
                next,
                None,
            )
        };
        assert_eq!(
            rows,
            [
                entry(1, 0xa1, "box@relay-a", "env-1", "queued", 0, 10),
                entry(2, 0xb2, "box@relay-a:9000", "env-2", "posted", 3, 20),
                entry(3, 0xc3, "box@relay-a", "env-3", "failed", 9, 30),
            ]
        );
        // The stage, the time stored and the time delivered come along; a stage this version
        // does not know is left out.
        let times: Vec<(Option<String>, i64, Option<i64>)> = conn
            .prepare("SELECT stage, created_at, posted_at FROM native_outbox ORDER BY id")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            times,
            [
                (Some("S1".to_owned()), 1, None),
                (Some("S2".to_owned()), 2, Some(15)),
                (None, 3, None),
            ]
        );
    }

    type DeliveryRow = (Vec<u8>, Option<String>, Option<String>, Option<String>, i64);

    fn deliveries(conn: &Connection) -> Vec<DeliveryRow> {
        conn.prepare("SELECT * FROM payment_delivery ORDER BY payment_id")
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    #[test]
    fn an_alias_joins_its_payments_row_or_makes_one_and_a_payment_keeps_one_alias() {
        let long = "x".repeat(MAX_ALIAS_LEN + 1);
        let seed = format!(
            "INSERT INTO settings (key, value) VALUES
                 ('api.alias.order-1', '{SLATE_A}'),
                 ('api.alias.order-2', '{SLATE_B}'),
                 ('api.alias.order-3', '{SLATE_B}'),
                 ('api.alias.order-4', 'not a slate'),
                 ('api.alias.{long}', '{SLATE_C}');"
        );
        let conn = v17_with_new_tables(&seed);
        conn.execute(
            "INSERT INTO payment_delivery (payment_id, alias, state, state_reason, updated_at)
             VALUES (?1, NULL, 'posted', NULL, ?2)",
            params![&[0xa1_u8; 16][..], NOW],
        )
        .unwrap();

        assert_eq!(deliveries_from_aliases(&conn, NOW).unwrap(), 3);
        assert_eq!(
            deliveries(&conn),
            [
                (
                    vec![0xa1; 16],
                    Some("order-1".to_owned()),
                    Some("posted".to_owned()),
                    None,
                    NOW
                ),
                (vec![0xb2; 16], Some("order-2".to_owned()), None, None, NOW),
            ]
        );
        let left: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM settings WHERE key LIKE 'api.alias.%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(left, 0);
    }
}
