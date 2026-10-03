//! Test support for the Dart package tests: an in-process scripted node. It works only in a
//! library built with the `mock` feature, which app builds never enable; elsewhere every call
//! fails with `Unsupported`.

use flutter_rust_bridge::frb;

use crate::api::diagnostics::LogLevel;
use crate::api::error::{WalletError, WalletErrorKind};
use crate::api::runtime::LepicRuntime;
use crate::api::types::Chain;

/// A scripted chain that stands in for the node of every wallet of the runtimes it creates.
#[frb(opaque)]
pub struct MockChain {
    #[cfg(feature = "mock")]
    backend: crate::mock::MockBackend,
}

#[cfg(not(feature = "mock"))]
fn unsupported() -> WalletError {
    WalletError::new(
        WalletErrorKind::Unsupported,
        "this library was built without the mock feature",
    )
}

impl MockChain {
    /// An empty chain whose tip is at `height`.
    #[frb(sync)]
    pub fn new(height: u64) -> Result<MockChain, WalletError> {
        #[cfg(feature = "mock")]
        {
            Ok(Self {
                backend: crate::mock::MockBackend::new(height)?,
            })
        }
        #[cfg(not(feature = "mock"))]
        {
            let _ = height;
            Err(unsupported())
        }
    }

    /// A runtime whose wallets all talk to this chain, whatever node they are configured
    /// with, and seal vaults with the cheapest Argon2 setting so tests stay fast.
    #[frb(sync)]
    pub fn runtime(&self, log_level: LogLevel) -> Result<LepicRuntime, WalletError> {
        #[cfg(feature = "mock")]
        {
            let kdf = lepic_keychain::KdfParams::new(8, 1, 1)
                .map_err(|error| WalletError::new(WalletErrorKind::Other, error.to_string()))?;
            LepicRuntime::start(
                log_level,
                crate::node::NodeFactory::Mock(self.backend.clone()),
                kdf,
            )
        }
        #[cfg(not(feature = "mock"))]
        {
            let _ = log_level;
            Err(unsupported())
        }
    }

    #[frb(sync)]
    pub fn height(&self) -> u64 {
        #[cfg(feature = "mock")]
        {
            self.backend.height()
        }
        #[cfg(not(feature = "mock"))]
        {
            0
        }
    }

    #[frb(sync)]
    pub fn set_height(&self, height: u64) {
        #[cfg(feature = "mock")]
        self.backend.set_height(height);
        #[cfg(not(feature = "mock"))]
        let _ = height;
    }

    /// Mines a plain output of `amount` for key `m/0/0/<child>` of the wallet with `mnemonic`
    /// into the tip block.
    #[frb(sync)]
    pub fn fund(
        &self,
        mnemonic: String,
        chain: Chain,
        amount: u64,
        child: u32,
    ) -> Result<(), WalletError> {
        #[cfg(feature = "mock")]
        {
            self.backend.fund(
                &crate::session::normalize_phrase(&mnemonic),
                chain.network(),
                amount,
                child,
            )
        }
        #[cfg(not(feature = "mock"))]
        {
            let _ = (mnemonic, chain, amount, child);
            Err(unsupported())
        }
    }

    /// How many transactions wallets have posted to this chain.
    #[frb(sync)]
    pub fn pushed_count(&self) -> u32 {
        #[cfg(feature = "mock")]
        {
            u32::try_from(self.backend.pushed_count()).unwrap_or(u32::MAX)
        }
        #[cfg(not(feature = "mock"))]
        {
            0
        }
    }

    /// Mines every posted transaction into the tip block.
    #[frb(sync)]
    pub fn mine_pushed(&self) {
        #[cfg(feature = "mock")]
        self.backend.mine_pushed();
    }

    /// Makes the next node request panic inside the engine operation that sends it.
    #[frb(sync)]
    pub fn panic_on_next_node_call(&self) {
        #[cfg(feature = "mock")]
        self.backend.panic_on_next_call();
    }
}
