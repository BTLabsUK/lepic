// SPDX-License-Identifier: Apache-2.0
//! The OpenAPI document `docs/api/openapi.json` is the contract of the wallet API: serve answers
//! what it describes, and the router is built from it. Each operation gives a path and method, an
//! `operationId` that names its handler ([`Op`]), the least role that may call it (`x-role`),
//! and whether only the socket answers it (`x-socket-only`).

use hyper::Method;
use serde_json::Value;

use super::ops::Op;
use super::problem::Problem;
use crate::api_clients::Role;

/// The document, served as is at `GET /api/v1/openapi.json`.
pub(crate) const DOCUMENT: &str = include_str!("../../../../docs/api/openapi.json");

/// Where the document's paths are mounted.
pub(crate) const PREFIX: &str = "/api/v1";

/// The extension naming an operation's least role.
const ROLE: &str = "x-role";

/// The extension that keeps an operation off the TLS listener.
const SOCKET_ONLY: &str = "x-socket-only";

const METHODS: [(&str, Method); 5] = [
    ("get", Method::GET),
    ("put", Method::PUT),
    ("post", Method::POST),
    ("delete", Method::DELETE),
    ("patch", Method::PATCH),
];

#[derive(Debug)]
enum Segment {
    Literal(String),
    Param(String),
}

/// One operation of a path.
#[derive(Debug)]
pub(crate) struct Operation {
    pub(crate) op: Op,
    pub(crate) method: Method,
    /// The least role that may call it; the handler asks for more when the body needs it.
    pub(crate) role: Role,
    pub(crate) socket_only: bool,
}

#[derive(Debug)]
struct Route {
    segments: Vec<Segment>,
    operations: Vec<Operation>,
}

impl Route {
    /// The path parameters, when `path` (below [`PREFIX`]) is this route's.
    fn matches(&self, path: &str) -> Option<Vec<(String, String)>> {
        let mut parts = path.strip_prefix('/')?.split('/');
        let mut params = Vec::new();
        for segment in &self.segments {
            let part = parts.next()?;
            match segment {
                Segment::Literal(literal) if literal == part => {}
                Segment::Literal(_) => return None,
                Segment::Param(_) if part.is_empty() => return None,
                Segment::Param(name) => {
                    params.push((name.clone(), super::decode(part, false).ok()?));
                }
            }
        }
        parts.next().is_none().then_some(params)
    }

    fn literals(&self) -> usize {
        self.segments
            .iter()
            .filter(|segment| matches!(segment, Segment::Literal(_)))
            .count()
    }
}

/// A route's path parameters, by name, decoded.
pub(crate) type Params = Vec<(String, String)>;

/// The operations by path and method.
#[derive(Debug)]
pub(crate) struct Router(Vec<Route>);

impl Router {
    /// The router of [`DOCUMENT`]. A test checks it parses and routes every [`Op`], so a broken
    /// document never ships; were it broken, serve would answer 404 to every path.
    pub(crate) fn new() -> Self {
        Self::parse(DOCUMENT).unwrap_or_else(|error| {
            tracing::error!(error, "the OpenAPI document is broken; nothing is routed");
            Self(Vec::new())
        })
    }

    fn parse(document: &str) -> Result<Self, String> {
        let document: Value = serde_json::from_str(document).map_err(|error| error.to_string())?;
        let paths = document
            .get("paths")
            .and_then(Value::as_object)
            .ok_or("no paths")?;
        let mut routes = Vec::with_capacity(paths.len());
        for (path, item) in paths {
            let mut operations = Vec::new();
            for (key, method) in METHODS {
                let Some(operation) = item.get(key) else {
                    continue;
                };
                let id = operation
                    .get("operationId")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("{key} {path} has no operationId"))?;
                let op = Op::from_id(id).ok_or_else(|| format!("no handler for {id}"))?;
                let role = operation
                    .get(ROLE)
                    .and_then(Value::as_str)
                    .and_then(Role::parse)
                    .ok_or_else(|| format!("{id} has no valid {ROLE}"))?;
                let socket_only = operation.get(SOCKET_ONLY) == Some(&Value::Bool(true));
                operations.push(Operation {
                    op,
                    method,
                    role,
                    socket_only,
                });
            }
            let segments = path
                .trim_start_matches('/')
                .split('/')
                .map(|segment| match segment.strip_prefix('{') {
                    Some(param) => Segment::Param(param.trim_end_matches('}').to_owned()),
                    None => Segment::Literal(segment.to_owned()),
                })
                .collect();
            routes.push(Route {
                segments,
                operations,
            });
        }
        Ok(Self(routes))
    }

    /// The operation `method` names at `path`, and the path parameters. Where a literal segment
    /// and a parameter both match (`/contacts/export`, `/contacts/{id}`), the route with more
    /// literal segments wins. 404 for a path outside [`PREFIX`] or no route, 405 with `Allow`
    /// for a route without `method`.
    pub(crate) fn find(
        &self,
        method: &Method,
        path: &str,
    ) -> Result<(&Operation, Params), Problem> {
        let below = path
            .strip_prefix(PREFIX)
            .filter(|below| below.starts_with('/'))
            .ok_or_else(Problem::no_route)?;
        let (route, params) = self
            .0
            .iter()
            .filter_map(|route| Some((route, route.matches(below)?)))
            .max_by_key(|(route, _)| route.literals())
            .ok_or_else(Problem::no_route)?;
        match route.operations.iter().find(|known| known.method == method) {
            Some(operation) => Ok((operation, params)),
            None => {
                let allow: Vec<_> = route
                    .operations
                    .iter()
                    .map(|known| known.method.as_str())
                    .collect();
                Err(Problem::method_not_allowed(allow.join(", ")))
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn operations(&self) -> impl Iterator<Item = &Operation> {
        self.0.iter().flat_map(|route| &route.operations)
    }
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (docs/rules.md).
    #![allow(clippy::unwrap_used)]

    use std::collections::HashSet;

    use hyper::StatusCode;

    use super::*;

    #[test]
    fn the_document_routes_every_operation_once() {
        let router = Router::parse(DOCUMENT).unwrap();
        let routed: Vec<Op> = router.operations().map(|operation| operation.op).collect();
        let unique: HashSet<Op> = routed.iter().copied().collect();
        assert_eq!(routed.len(), unique.len(), "an operation is routed twice");
        for op in Op::ALL {
            assert!(unique.contains(op), "{} is not in the document", op.id());
        }
        assert_eq!(routed.len(), 61);
    }

    #[test]
    fn the_roles_are_those_the_design_counts() {
        let router = Router::new();
        let count = |role| {
            router
                .operations()
                .filter(|operation| operation.role == role)
                .count()
        };
        assert_eq!(
            [count(Role::Read), count(Role::Receive), count(Role::Full)],
            // Post and cancel route at `receive`; their handlers ask `full` of all but an
            // invoice this wallet issued.
            [23, 9, 29]
        );
        let socket_only: HashSet<Op> = router
            .operations()
            .filter(|operation| operation.socket_only)
            .map(|operation| operation.op)
            .collect();
        let expected = [
            Op::ChangeWalletPassword,
            Op::ExportContacts,
            Op::ImportContacts,
        ];
        assert_eq!(socket_only, expected.into_iter().collect());
    }

    #[test]
    fn a_path_parameter_is_matched_and_a_wrong_method_names_the_allowed_ones() {
        let router = Router::new();
        let id = "0b9c3a3e-6d0f-4c69-9a0e-7f6f2a4c1d11";
        let (operation, params) = router
            .find(&Method::GET, &format!("/api/v1/payments/{id}"))
            .unwrap();
        assert_eq!(operation.op, Op::GetPayment);
        assert_eq!(params, [("id".to_owned(), id.to_owned())]);
        let refused = router
            .find(&Method::DELETE, "/api/v1/payments")
            .unwrap_err();
        assert_eq!(refused.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(refused.allow(), Some("GET, POST"));
        for path in [
            "/api/v1/payments/",
            "/api/v1/nothing",
            "/api/v1",
            "/api/v1/",
            "/api/v1x/status",
            "/v1/status",
            "/api/v1/inbox",
            "/v2/foreign",
        ] {
            let refused = router.find(&Method::GET, path).unwrap_err();
            assert_eq!(refused.status(), StatusCode::NOT_FOUND, "{path}");
        }
    }

    #[test]
    fn a_literal_route_wins_over_the_id_route() {
        let router = Router::new();
        let (operation, params) = router
            .find(&Method::POST, "/api/v1/contacts/export")
            .unwrap();
        assert_eq!(operation.op, Op::ExportContacts);
        assert!(params.is_empty());
        let (operation, params) = router
            .find(&Method::DELETE, "/api/v1/contacts/ab12")
            .unwrap();
        assert_eq!(operation.op, Op::DeleteContact);
        assert_eq!(params, [("id".to_owned(), "ab12".to_owned())]);
        let (operation, _) = router
            .find(&Method::POST, "/api/v1/payments/estimate")
            .unwrap();
        assert_eq!(operation.op, Op::EstimatePayment);
    }

    #[test]
    fn a_path_parameter_is_percent_decoded() {
        let router = Router::new();
        let (operation, params) = router
            .find(
                &Method::DELETE,
                "/api/v1/peers/https%3A%2F%2Fwallet.example%3A443",
            )
            .unwrap();
        assert_eq!(operation.op, Op::DeletePeer);
        assert_eq!(
            params,
            [("origin".to_owned(), "https://wallet.example:443".to_owned())]
        );
    }

    #[test]
    fn a_plus_in_a_path_segment_stays_a_plus() {
        let router = Router::new();
        let (_, params) = router
            .find(&Method::DELETE, "/api/v1/peers/a+b%20c")
            .unwrap();
        assert_eq!(params, [("origin".to_owned(), "a+b c".to_owned())]);
    }
}
