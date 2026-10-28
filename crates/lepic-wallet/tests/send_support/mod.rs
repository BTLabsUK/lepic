// SPDX-License-Identifier: Apache-2.0
//! A funded sender for the send and cancel tests: the wallet of the G-03 `send_file_plain`
//! sender, holding the coinbase output that case spends, on a node at the case's height.

// Each test binary uses a different subset of these helpers, and test helpers may unwrap and
// panic (docs/rules.md).
#![allow(dead_code, clippy::unwrap_used, clippy::panic)]

use std::sync::{Arc, PoisonError};

use blake2::Blake2bMac;
use blake2::digest::consts::U32;
use blake2::digest::{FixedOutput, KeyInit, Update};
use lepic_keychain::{Identifier, Keychain, Seed, SwitchCommitment};
use lepic_primitives::amount::{Amount, Height};
use lepic_primitives::output::{OutputFeatures, OutputIdentifier};
use lepic_primitives::params::Network;
use lepic_slate::codec::legacy::v2_json::{LEGACY_V2_JSON, V2JsonCodec};
use lepic_slate::codec::legacy::v3_json::V3JsonCodec;
use lepic_slate::codec::{CodecId, EncodeContext, WireSlate};
use lepic_slate::model::Slate;
use lepic_slate::registry::CodecRegistry;
use lepic_store::{
    AccountIndex, AccountRecord, ContextKey, KeyId, OutboxStatus, OutputRecord, OutputStatus,
    ParticipantId, Repositories, StoreError, StoredOutbox, StoredTransaction, WalletStore,
};
use lepic_transport::file::FilePolicy;
use lepic_transport::loopback::LoopbackTransport;
use lepic_transport::policy::{Encoding, FormatPolicy};
use lepic_transport::registry::TransportRegistry;
use lepic_transport::transport::{Destination, Inbound, Transport};
use lepic_wallet::{Clock, Ports, StoreOpener, Wallet, WalletConfig};
use uuid::Uuid;

use crate::support::{
    Harness, LOOPBACK, TestStore, TestStores, TestVault, TestWallet, complete_restore_scan,
    password,
};

pub const SENDER_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
    abandon abandon abandon abandon abandon art";

pub const ACCOUNT: AccountIndex = AccountIndex(0);

/// The coinbase output `send_file_plain` spends: key `m/0/0/0`, mined at height 1.
pub const FUNDING: u64 = 1_457_920_000;

/// The case's chain tip, and the next unused output key child of the sender's account there.
pub const TIP: u64 = 4;
pub const NEXT_CHILD: u32 = 4;

pub const PEER: &str = "peer";

/// The G-03 `send_file_plain` S1 as upstream wrote it.
pub const SEND_FILE_PLAIN_S1: &str =
    include_str!("../../../../testdata/vectors/slates/send_file_plain_s1_v3.json");

pub struct Sender {
    pub harness: Harness,
    pub wallet: TestWallet,
    /// The wallet's database, opened under the wallet's own context key.
    pub store: TestStore,
    pub keychain: Keychain,
    /// The other end of the wallet's loopback transport.
    pub peer: LoopbackTransport,
}

impl Sender {
    /// The funded sender with the file policy on its loopback transport.
    pub fn new() -> Self {
        Self::with_policy(Arc::new(FilePolicy))
    }

    /// The funded sender whose loopback transport speaks `policy`.
    pub fn with_policy(policy: Arc<dyn FormatPolicy>) -> Self {
        Self::with_policy_and_clock(policy, None)
    }

    /// The funded sender reading `clock`, for tests that move the chain days ahead.
    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self::with_policy_and_clock(Arc::new(FilePolicy), Some(clock))
    }

    fn with_policy_and_clock(policy: Arc<dyn FormatPolicy>, clock: Option<Arc<dyn Clock>>) -> Self {
        Self::build(clock, |harness, peer| {
            let (own, other) = LoopbackTransport::pair(
                LOOPBACK,
                policy,
                Destination::new("wallet".to_owned()),
                Destination::new(PEER.to_owned()),
            );
            *peer = Some(other);
            let mut registry = TransportRegistry::new();
            registry.register(Box::new(own)).unwrap();
            (harness.config(Network::Floonet), registry)
        })
    }

    /// The funded sender with extra transports next to the loopback one.
    pub fn with_transports(extra: Vec<Box<dyn Transport>>) -> Self {
        Self::build(None, |harness, peer| {
            let mut registry = harness.transports();
            *peer = harness
                .peer
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            let mut config = harness.config(Network::Floonet);
            for transport in extra {
                config.transports.push(transport.id());
                registry.register(transport).unwrap();
            }
            (config, registry)
        })
    }

    fn build(
        clock: Option<Arc<dyn Clock>>,
        transports: impl FnOnce(
            &Harness,
            &mut Option<LoopbackTransport>,
        ) -> (WalletConfig, TransportRegistry),
    ) -> Self {
        let harness = Harness::new();
        let mut peer = None;
        let (config, registry) = transports(&harness, &mut peer);
        let mut ports: Ports<_, TestStores, TestVault> = Ports {
            transports: registry,
            ..harness.ports(harness.vault.clone())
        };
        if let Some(clock) = clock {
            ports.clock = clock;
        }
        let wallet = Wallet::new(config, ports).unwrap();
        harness
            .block_on(wallet.restore(password("sender"), SENDER_MNEMONIC))
            .unwrap();
        harness
            .node
            .update_chain(|chain| chain.tip.height = Height::new(TIP));
        complete_restore_scan(&harness.runtime, &wallet);

        let seed = Seed::from_mnemonic(SENDER_MNEMONIC).unwrap();
        let store = harness
            .stores
            .open(&harness.data_dir, context_key(&seed))
            .unwrap();
        let keychain = Keychain::from_seed(&seed, Network::Floonet).unwrap();
        let funding = output(&keychain, 0, FUNDING, OutputFeatures::Coinbase);
        store
            .write(|repos| {
                repos.put_account(&AccountRecord {
                    index: ACCOUNT,
                    label: "default".to_owned(),
                    next_child: NEXT_CHILD,
                })?;
                repos.put_output(&funding)
            })
            .unwrap();
        Self {
            harness,
            wallet,
            store,
            keychain,
            peer: peer.unwrap(),
        }
    }

    pub fn read<T>(&self, read: impl FnOnce(&dyn Repositories) -> Result<T, StoreError>) -> T {
        self.store.read(read).unwrap()
    }

    pub fn transactions(&self) -> Vec<StoredTransaction> {
        self.read(|repos| repos.transactions(ACCOUNT))
    }

    pub fn outputs(&self) -> Vec<OutputRecord> {
        self.read(|repos| repos.outputs(ACCOUNT, None))
    }

    pub fn outbox(&self, status: OutboxStatus) -> Vec<StoredOutbox> {
        self.read(|repos| repos.outbox(status))
    }

    pub fn next_child(&self) -> u32 {
        self.read(|repos| repos.account(ACCOUNT))
            .unwrap()
            .next_child
    }

    pub fn has_sender_context(&self, slate_id: Uuid) -> bool {
        self.read(|repos| repos.context(slate_id, ParticipantId(0)))
            .is_some()
    }

    /// The next slate the peer received, decoded by its shape.
    pub fn received(&self) -> Option<(WireSlate, Slate)> {
        let envelope = self.harness.block_on(self.peer.next_envelope()).unwrap()?;
        let wire = envelope.wire().clone();
        let slate = legacy_codecs().decode(&wire).unwrap();
        Some((wire, slate))
    }

    /// Adds an unspent coinbase output of `value` at child `child`, as mined at height 1.
    pub fn fund(&self, child: u32, value: u64) {
        let funding = output(&self.keychain, child, value, OutputFeatures::Coinbase);
        self.store
            .write(|repos| repos.put_output(&funding))
            .unwrap();
    }
}

/// An output of the sender's at child `child` of the default account.
pub fn output(
    keychain: &Keychain,
    child: u32,
    value: u64,
    features: OutputFeatures,
) -> OutputRecord {
    let id = Identifier::new(3, [0, 0, child, 0]).unwrap();
    OutputRecord {
        id: OutputIdentifier::new(
            features,
            keychain
                .commit(value, &id, SwitchCommitment::Regular)
                .unwrap(),
        ),
        key_id: KeyId(id.to_bytes()),
        account: ACCOUNT,
        amount: Amount::new(value),
        status: OutputStatus::Unspent,
        height: Height::new(1),
        lock_height: Height::ZERO,
        mmr_index: None,
        tx: None,
    }
}

/// The key `lifecycle::context_key` derives, which `tests/lifecycle_logs.rs` also recomputes.
pub fn context_key(seed: &Seed) -> ContextKey {
    let mut mac = <Blake2bMac<U32> as KeyInit>::new_from_slice(seed.expose_bytes()).unwrap();
    mac.update(b"lepic-wallet private context key v1");
    ContextKey::from_bytes(mac.finalize_fixed().into())
}

pub fn legacy_codecs() -> CodecRegistry {
    let base_fee = Network::Floonet.params().default_base_fee();
    let mut codecs = CodecRegistry::new();
    codecs
        .register(Box::new(V2JsonCodec::new(base_fee)))
        .unwrap();
    codecs
        .register(Box::new(V3JsonCodec::new(base_fee)))
        .unwrap();
    codecs
}

/// The legacy Epicbox rule of ADR 0003 as far as a new slate goes: always the V2 shape, with
/// the header of a slate created here.
#[derive(Debug, Clone, Copy)]
pub struct V2Only;

impl FormatPolicy for V2Only {
    fn accepted(&self) -> &[CodecId] {
        &[LEGACY_V2_JSON]
    }

    fn for_new_slate(&self, _: &Slate, _: &EncodeContext) -> Encoding {
        Encoding {
            codec: LEGACY_V2_JSON,
            legacy_header: None,
        }
    }

    fn for_reply(&self, slate: &Slate, context: &EncodeContext) -> Encoding {
        self.for_new_slate(slate, context)
    }
}

pub fn uuid(slate_id: lepic_slate::model::SlateId) -> Uuid {
    Uuid::from_bytes(*slate_id.as_bytes())
}
