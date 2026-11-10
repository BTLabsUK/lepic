// SPDX-License-Identifier: Apache-2.0
//! A receiving wallet over test ports, and the G-03 slate vectors it is checked against.
//!
//! Each standard-flow case is received the way the upstream receiver received it: the S1 its
//! method delivered, the receiver's mnemonic and output key, a node at the slate's height, and
//! an RNG that repeats the byte 1, which gives the nonces `epic-wallet`'s test-RNG mode uses.

// Each test binary uses a different subset of these helpers.
#![allow(dead_code)]

use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::support::{
    FixedClock, TestStore, TestStores, TestVault, complete_restore_scan, fixed_time, password,
};
use lepic_keychain::{Identifier, Seed};
use lepic_legacy_slate::v2_json::LEGACY_V2_JSON;
use lepic_legacy_slate::v3_json::LEGACY_V3_JSON;
use lepic_node::mock::{ChainState, MockNode};
use lepic_node::{NodeClient, NodeVersion, Tip};
use lepic_primitives::amount::Height;
use lepic_primitives::hash::Hash;
use lepic_primitives::params::Network;
use lepic_slate::codec::{Codec, CodecId, EncodeContext, MediaType, WireSlate};
use lepic_slate::error::EncodeError;
use lepic_slate::model::Slate;
use lepic_slate::origin::WireOrigin;
use lepic_store::{AccountIndex, StoreError, StoreKeys, WalletStore};
use lepic_transport::file::{FILE, FilePolicy};
use lepic_transport::loopback::LoopbackTransport;
use lepic_transport::method::Method;
use lepic_transport::policy::{Encoding, FormatPolicy};
use lepic_transport::transport::{Destination, TransportId};
use lepic_wallet::{
    NodeEndpoint, Ports, ReceiveError, ReceiveRequest, SharedRng, Wallet, WalletConfig, WalletName,
    WalletPolicy,
};
use rand_core::{TryCryptoRng, TryRng};
use serde_json::Value;
use tokio::runtime::Runtime;

pub const PASSWORD: &str = "receiver password";

/// Stands in for the Epicbox transport, whose policy replies in the shape and header of the
/// inbound slate (ADR 0003).
pub const EPICBOX: TransportId = TransportId::new("epicbox");
/// The HTTP listener's transport, whose listeners sign under more than one key.
pub const HTTP: TransportId = TransportId::new("http");

pub const DATA_DIR: &str = "/receiver";

/// Repeats one byte. With 1 it yields the secret nonces `[1; 32]` that upstream's test-RNG mode
/// uses for the partial signature and the message signature.
pub struct RepeatingRng(u8);

impl TryRng for RepeatingRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(u32::from_le_bytes([self.0; 4]))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(u64::from_le_bytes([self.0; 8]))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        dst.fill(self.0);
        Ok(())
    }
}

impl TryCryptoRng for RepeatingRng {}

/// Replies in the codec and header the slate arrived with, as the Epicbox method does.
pub struct EchoPolicy;

impl FormatPolicy for EchoPolicy {
    fn accepted(&self) -> &[CodecId] {
        &[LEGACY_V3_JSON, LEGACY_V2_JSON]
    }

    fn for_new_slate(&self, _slate: &Slate, _context: &EncodeContext) -> Encoding {
        Encoding {
            codec: LEGACY_V2_JSON,
            legacy_header: None,
        }
    }

    fn for_reply(&self, slate: &Slate, _context: &EncodeContext) -> Encoding {
        let origin = slate.origin().unwrap();
        Encoding {
            codec: origin.codec(),
            legacy_header: origin.legacy_header(),
        }
    }
}

pub fn vector_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/vectors/slates")
}

pub fn vector(name: &str) -> Value {
    let path = vector_dir().join(format!("{name}.json"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path:?}: {error}"));
    serde_json::from_str(&text).unwrap()
}

pub fn has_vector(name: &str) -> bool {
    vector_dir().join(format!("{name}.json")).is_file()
}

/// Every standard-flow case: the cases that have an S2 written by the receiver.
pub fn standard_cases() -> Vec<String> {
    let mut cases: Vec<String> = std::fs::read_dir(vector_dir())
        .unwrap()
        .filter_map(|entry| {
            let name = entry.unwrap().file_name().into_string().unwrap();
            let stem = name.strip_suffix(".json")?;
            let case = stem.strip_suffix("_s2_v3")?;
            Some(case.to_owned())
        })
        .collect();
    cases.sort();
    cases
}

pub fn text(value: &Value) -> &str {
    value
        .as_str()
        .unwrap_or_else(|| panic!("not a string: {value}"))
}

pub fn json(vector: &Value) -> String {
    text(&vector["expected"]["json"]).to_owned()
}

pub fn wire(json: &str) -> WireSlate {
    WireSlate::text(MediaType::JSON, json.to_owned())
}

pub fn receiver_entry(vector: &Value) -> &Value {
    vector["inputs"]["wallets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|wallet| wallet["role"] == "receiver")
        .unwrap()
}

pub fn receiver_mnemonic(vector: &Value) -> String {
    text(&receiver_entry(vector)["mnemonic"]).to_owned()
}

/// The key upstream's receiver used for its output, which depends on the outputs it had
/// created before the case.
pub fn receiver_output_key(vector: &Value) -> Identifier {
    let outputs = receiver_entry(vector)["outputs"].as_array().unwrap();
    assert_eq!(outputs.len(), 1);
    Identifier::from_hex(text(&outputs[0]["key_id"])).unwrap()
}

pub fn transport_of(method: &str) -> TransportId {
    match method {
        "file" => FILE,
        "epicbox" => EPICBOX,
        other => panic!("unknown method {other}"),
    }
}

pub fn node_at(height: u64) -> MockNode {
    MockNode::from_chain(ChainState::new(
        NodeVersion {
            node_version: "4.0.4".to_owned(),
            block_header_version: 6,
        },
        Tip {
            height: Height::new(height),
            last_block_pushed: Hash::from_slice(&[0; 32]).unwrap(),
        },
    ))
}

pub type ReceiverWallet = Wallet<NodeClient<MockNode>, TestStores, TestVault>;

/// A receiving wallet restored from a mnemonic, with the file transport and the echo transport.
pub struct Receiver {
    runtime: Runtime,
    stores: TestStores,
    pub node: MockNode,
    pub seed: Seed,
    pub wallet: ReceiverWallet,
    /// The wallet's ends of the file and echo loopback pairs.
    methods: Vec<Arc<dyn Method>>,
}

impl Receiver {
    /// The wallet restored and scanned, ready to receive.
    pub fn new(mnemonic: &str, tip: u64) -> Self {
        let receiver = Self::restored_without_scan(mnemonic, tip);
        receiver.complete_restore_scan();
        receiver
    }

    /// The wallet under `policy`, restored and scanned, ready to receive.
    pub fn with_policy(mnemonic: &str, tip: u64, policy: WalletPolicy) -> Self {
        let receiver = Self::restored_with(mnemonic, tip, policy);
        receiver.complete_restore_scan();
        receiver
    }

    /// The wallet restored onto an empty database, before the scan it needs.
    pub fn restored_without_scan(mnemonic: &str, tip: u64) -> Self {
        Self::restored_with(mnemonic, tip, WalletPolicy::default())
    }

    fn restored_with(mnemonic: &str, tip: u64, policy: WalletPolicy) -> Self {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let stores = TestStores::default();
        let node = node_at(tip);
        let mut methods: Vec<Arc<dyn Method>> = Vec::new();
        for (id, policy) in [
            (FILE, Arc::new(FilePolicy) as Arc<dyn FormatPolicy>),
            (EPICBOX, Arc::new(EchoPolicy)),
            (HTTP, Arc::new(EchoPolicy)),
        ] {
            let (own, _peer) = LoopbackTransport::pair(
                id,
                policy,
                Destination::new("receiver".to_owned()),
                Destination::new("sender".to_owned()),
            );
            methods.push(Arc::new(own));
        }
        let ports = Ports {
            node: node.client(),
            stores: stores.clone(),
            secrets: TestVault::default(),
            clock: Arc::new(FixedClock(fixed_time())),
            rng: SharedRng::new(RepeatingRng(1)),
            runtime: runtime.handle().clone(),
            methods: None,
        };
        let config = WalletConfig {
            name: WalletName::new("receiver").unwrap(),
            network: Network::Floonet,
            data_dir: PathBuf::from(DATA_DIR),
            node: NodeEndpoint::parse("http://127.0.0.1:13413").unwrap(),
            policy,
            offline: false,
            host_features: 0,
            profile: 0,
            domain: None,
            native_direct: false,
        };
        let wallet = Wallet::new(config, ports).unwrap();
        runtime
            .block_on(wallet.restore(password(PASSWORD), mnemonic))
            .unwrap();
        Self {
            runtime,
            stores,
            node,
            seed: Seed::from_mnemonic(mnemonic).unwrap(),
            wallet,
            methods,
        }
    }

    pub fn block_on<T>(&self, future: impl Future<Output = T>) -> T {
        self.runtime.block_on(future)
    }

    /// The wallet's end of the transport `transport` names.
    pub fn method(&self, transport: TransportId) -> Arc<dyn Method> {
        let method = self.methods.iter().find(|method| method.id() == transport);
        Arc::clone(method.unwrap_or_else(|| panic!("no transport {transport}")))
    }

    pub fn complete_restore_scan(&self) {
        complete_restore_scan(&self.runtime, &self.wallet);
    }

    pub fn receive(
        &self,
        transport: TransportId,
        json: &str,
        message: Option<&str>,
    ) -> Result<lepic_wallet::Received, ReceiveError> {
        self.receive_with(
            transport,
            json,
            ReceiveRequest {
                account: None,
                message: message.map(str::to_owned),
                ..ReceiveRequest::default()
            },
        )
    }

    pub fn receive_with(
        &self,
        transport: TransportId,
        json: &str,
        request: ReceiveRequest,
    ) -> Result<lepic_wallet::Received, ReceiveError> {
        self.runtime.block_on(
            self.wallet
                .receive(&self.method(transport), &wire(json), request),
        )
    }

    /// The wallet's database, opened with the key the engine seals contexts under.
    pub fn store(&self) -> TestStore {
        let keys = lepic_wallet::lifecycle::store_keys(&self.seed).unwrap();
        self.stores.open_for_test(
            Path::new(DATA_DIR),
            keys,
            &lepic_wallet::store_key(&self.seed).unwrap(),
        )
    }

    /// Moves the default account's key counter to `key_id`, the key the next output takes.
    pub fn reserve_up_to(&self, key_id: Identifier) {
        let child = key_id.components()[2];
        assert_eq!(key_id, Identifier::new(3, [0, 0, child, 0]).unwrap());
        self.store()
            .write(|repos| {
                let mut account = repos.account(AccountIndex(0))?.unwrap();
                account.next_child = child;
                repos.put_account(&account)
            })
            .unwrap();
    }

    /// Receives the same slate twice with both receives in flight at once.
    pub fn receive_twice_at_once(
        &self,
        transport: TransportId,
        json: &str,
    ) -> (
        Result<lepic_wallet::Received, ReceiveError>,
        Result<lepic_wallet::Received, ReceiveError>,
    ) {
        let (a, b) = (wire(json), wire(json));
        let method = self.method(transport);
        self.runtime.block_on(async {
            tokio::join!(
                self.wallet.receive(&method, &a, ReceiveRequest::default()),
                self.wallet.receive(&method, &b, ReceiveRequest::default())
            )
        })
    }

    /// Moves the node's tip to `height` and refreshes, which expires what the tip has passed.
    pub fn refresh_at(&self, height: u64) {
        assert!(
            self.node
                .update_chain(|chain| chain.tip.height = Height::new(height))
        );
        self.runtime.block_on(self.wallet.refresh()).unwrap();
    }

    pub fn cancel(&self, tx_id: lepic_store::TxId) {
        self.runtime.block_on(self.wallet.cancel(tx_id)).unwrap();
    }

    /// The default account's key counter: the child index the next output key takes.
    pub fn next_child(&self) -> u32 {
        self.store()
            .read(|repos| Ok::<_, StoreError>(repos.account(AccountIndex(0))?.unwrap().next_child))
            .unwrap()
    }

    pub fn transaction_count(&self) -> usize {
        self.store()
            .read(|repos| Ok::<_, StoreError>(repos.transactions(AccountIndex(0))?.len()))
            .unwrap()
    }
}

pub trait OpenForTest {
    fn open_for_test(
        &self,
        data_dir: &Path,
        keys: StoreKeys,
        store_key: &lepic_store::StoreKey,
    ) -> TestStore;
}

impl OpenForTest for TestStores {
    fn open_for_test(
        &self,
        data_dir: &Path,
        keys: StoreKeys,
        store_key: &lepic_store::StoreKey,
    ) -> TestStore {
        assert!(!self.is_empty(data_dir));
        lepic_wallet::StoreOpener::open(self, data_dir, keys, store_key).unwrap()
    }
}

/// What the receiver received in a case: the S1 its method delivered.
pub fn delivered_s1(case: &str) -> (Value, TransportId) {
    let s2 = vector(&format!("{case}_s2_v3"));
    let method = text(&s2["inputs"]["method"]).to_owned();
    (
        vector(&format!("{case}_s1_{method}")),
        transport_of(&method),
    )
}

pub fn responder_message(vector: &Value) -> Option<String> {
    vector["inputs"]["options"]["responder_message"]
        .as_str()
        .map(str::to_owned)
}

pub fn slate_height(s1: &Value) -> u64 {
    let slate: Value = serde_json::from_str(&json(s1)).unwrap();
    match &slate["height"] {
        Value::String(height) => height.parse().unwrap(),
        other => other.as_u64().unwrap(),
    }
}

/// The V3 and V2 encodings upstream records keep the header the receiver read.
pub fn encode_as(codec: &dyn Codec, slate: &Slate) -> Result<WireSlate, EncodeError> {
    let header = slate.origin().and_then(WireOrigin::legacy_header).unwrap();
    let context = EncodeContext {
        block_header_version: header.block_header_version,
    };
    codec.encode(slate, &context)
}
