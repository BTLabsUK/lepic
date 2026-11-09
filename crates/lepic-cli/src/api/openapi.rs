// SPDX-License-Identifier: Apache-2.0
//! The OpenAPI document: the owner routes, the payment endpoint `serve --http` answers, and the
//! problem every owner route may answer with.

use hyper::body::Bytes;
use utoipa::openapi::schema::Ref;
use utoipa::openapi::security::{SecurityRequirement, SecurityScheme};
use utoipa::openapi::{Content, OpenApi as Document, RefOr, ResponseBuilder};
use utoipa::{Modify, OpenApi as _};

pub(crate) fn document() -> Document {
    super::Document::openapi()
}

/// The document as `docs/api/openapi.json` holds it.
pub(crate) fn rendered() -> Bytes {
    // Serializing the document cannot fail: its maps have string keys.
    let mut text = document().to_pretty_json().unwrap_or_default();
    text.push('\n');
    text.into()
}

/// Adds the problem response to every owner operation.
pub(crate) struct Problems;

impl Modify for Problems {
    fn modify(&self, openapi: &mut Document) {
        let problem = ResponseBuilder::new()
            .description("An error, as RFC 9457 problem details")
            .content(
                "application/problem+json",
                Content::new(Some(Ref::from_schema_name("Problem"))),
            )
            .build();
        let owner = openapi
            .paths
            .paths
            .iter_mut()
            .filter(|(path, _)| path.starts_with("/v1/"));
        for (_, item) in owner {
            let operations = [
                &mut item.get,
                &mut item.put,
                &mut item.post,
                &mut item.delete,
                &mut item.patch,
            ];
            for operation in operations.into_iter().flatten() {
                operation
                    .responses
                    .responses
                    .insert("default".to_owned(), RefOr::T(problem.clone()));
            }
        }
    }
}

/// The name of the owner TLS listener's security scheme.
const OWNER_TLS: &str = "ownerTls";

/// Declares the owner TLS scheme and lets a request in on either listener: the socket, where
/// the peer's uid is the credential and the document has no scheme for it, or owner TLS.
pub(crate) struct Security;

impl Modify for Security {
    fn modify(&self, openapi: &mut Document) {
        let tls = SecurityScheme::MutualTls {
            description: Some(
                "A client certificate whose Ed25519 key `lepic api client add` listed in the \
                 wallet's `api-clients` file."
                    .to_owned(),
            ),
            deprecated: None,
            extensions: None,
        };
        openapi
            .components
            .get_or_insert_with(Default::default)
            .add_security_scheme(OWNER_TLS, tls);
        openapi.security = Some(vec![
            SecurityRequirement::default(),
            SecurityRequirement::new(OWNER_TLS, Vec::<String>::new()),
        ]);
    }
}

/// The payment endpoint's JSON-RPC, described here and answered by lepic-legacy-rpc.
#[expect(dead_code, reason = "the types only describe the wire")]
pub(crate) mod foreign {
    use utoipa::ToSchema;

    /// The payment endpoint
    ///
    /// JSON-RPC 2.0 as other Epic wallets post it, answered by the listener `serve --http`
    /// adds, with its own limits and no authentication. `build_coinbase` is answered only
    /// with `--coinbase`. The wire format is the network's.
    #[utoipa::path(
        post,
        path = "/v2/foreign",
        tag = "payments",
        security(()),
        request_body = ForeignRequest,
        responses((status = 200, body = ForeignResponse)),
    )]
    pub(crate) fn foreign() {}

    /// Always `"2.0"`.
    #[derive(ToSchema)]
    enum JsonRpc {
        #[serde(rename = "2.0")]
        V2,
    }

    /// The request's id, echoed in the answer.
    #[derive(ToSchema)]
    #[serde(untagged)]
    enum RpcId {
        Number(i64),
        Text(String),
    }

    #[derive(ToSchema)]
    #[serde(untagged)]
    enum ForeignRequest {
        CheckVersion(CheckVersionRequest),
        ReceiveTx(ReceiveTxRequest),
        BuildCoinbase(BuildCoinbaseRequest),
    }

    /// The API version and the slate versions this wallet reads.
    #[derive(ToSchema)]
    struct CheckVersionRequest {
        jsonrpc: JsonRpc,
        id: Option<RpcId>,
        method: CheckVersion,
    }

    #[derive(ToSchema)]
    enum CheckVersion {
        #[serde(rename = "check_version")]
        Method,
    }

    /// Receive a slate; the answer is the reply slate.
    #[derive(ToSchema)]
    struct ReceiveTxRequest {
        jsonrpc: JsonRpc,
        id: Option<RpcId>,
        method: ReceiveTx,
        /// `[slate, null, null, null]`: the V2 or V3 slate object, then three entries the
        /// wallet ignores.
        #[schema(value_type = Vec<Value>)]
        params: (),
    }

    #[derive(ToSchema)]
    enum ReceiveTx {
        #[serde(rename = "receive_tx")]
        Method,
    }

    /// Build the coinbase output and kernel of a block a miner works on.
    #[derive(ToSchema)]
    struct BuildCoinbaseRequest {
        jsonrpc: JsonRpc,
        id: Option<RpcId>,
        method: BuildCoinbase,
        /// By name, or by position as a one-element array.
        params: BuildCoinbaseParams,
    }

    #[derive(ToSchema)]
    enum BuildCoinbase {
        #[serde(rename = "build_coinbase")]
        Method,
    }

    #[derive(ToSchema)]
    struct BuildCoinbaseParams {
        block_fees: BlockFees,
    }

    #[derive(ToSchema)]
    struct BlockFees {
        /// The block's fees in base units, as a number or decimal text.
        #[schema(value_type = String)]
        fees: (),
        /// The block's height, as a number or decimal text.
        #[schema(value_type = String)]
        height: (),
        /// The key id to build with, hex; the wallet picks one when absent.
        key_id: Option<String>,
    }

    /// The answer: `result` to a call that was understood, `error` to one that was not.
    #[derive(ToSchema)]
    struct ForeignResponse {
        jsonrpc: JsonRpc,
        id: Option<RpcId>,
        result: Option<ForeignResult>,
        error: Option<RpcError>,
    }

    /// `Ok` with the method's answer, or `Err` with the reason the wallet refused.
    #[derive(ToSchema)]
    struct ForeignResult {
        #[serde(rename = "Ok")]
        ok: Option<ForeignAnswer>,
        #[serde(rename = "Err")]
        err: Option<Refusal>,
    }

    #[derive(ToSchema)]
    #[serde(untagged)]
    enum ForeignAnswer {
        Version(VersionAnswer),
        Slate(ReplySlate),
        Coinbase(CoinbaseAnswer),
    }

    /// `receive_tx`: the reply slate object, in the version it was sent in.
    #[derive(ToSchema)]
    struct ReplySlate {}

    /// `check_version`.
    #[derive(ToSchema)]
    struct VersionAnswer {
        foreign_api_version: u16,
        /// For example `["V3", "V2"]`.
        supported_slate_versions: Vec<String>,
    }

    /// `build_coinbase`.
    #[derive(ToSchema)]
    struct CoinbaseAnswer {
        output: CoinbaseOutput,
        kernel: CoinbaseKernel,
        /// Hex.
        key_id: String,
    }

    #[derive(ToSchema)]
    struct CoinbaseOutput {
        /// `Coinbase`.
        features: String,
        /// Hex.
        commit: String,
        /// Hex.
        proof: String,
    }

    #[derive(ToSchema)]
    struct CoinbaseKernel {
        /// `Coinbase`.
        features: String,
        /// Decimal text, `"0"`.
        fee: String,
        /// Decimal text, `"0"`.
        lock_height: String,
        /// Hex.
        excess: String,
        /// Hex.
        excess_sig: String,
    }

    #[derive(ToSchema)]
    struct Refusal {
        #[serde(rename = "GenericError")]
        generic_error: String,
    }

    /// A JSON-RPC error: a request that was not JSON-RPC, or a method the wallet lacks.
    #[derive(ToSchema)]
    struct RpcError {
        code: i32,
        message: String,
    }
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (docs/rules.md).
    #![allow(clippy::unwrap_used)]

    use std::path::Path;

    use super::*;

    #[test]
    fn the_committed_document_is_the_generated_one() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/api/openapi.json");
        let generated = rendered();
        if std::env::var_os("LEPIC_BLESS").is_some() {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, &generated).unwrap();
        }
        let committed = std::fs::read(&path).unwrap_or_default();
        assert!(
            committed == generated,
            "docs/api/openapi.json differs from what the code generates; regenerate it with \
             LEPIC_BLESS=1 cargo test -p lepic-cli --lib the_committed_document_is_the_generated_one"
        );
    }
}
