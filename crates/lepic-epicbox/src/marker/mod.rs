// SPDX-License-Identifier: Apache-2.0
//! The LEPIC marker: the `"lepic":{"version":1}` key a LEPIC wallet adds to the V2 and V3 JSON
//! slates it sends over Epicbox, so the peer knows it runs LEPIC, and the reply key a file or
//! paste slate may carry in it for a sealed answer (RFC 0002 section 5). It is a LEPIC feature,
//! not Epic compatibility: stock `epic-wallet` ignores and drops the key.

pub mod v2;
pub mod v3;
