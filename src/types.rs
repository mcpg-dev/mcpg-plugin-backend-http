//! Operator-facing spec for the HTTP backend plugin.
//!
//! The runtime profile + method / call-mode / response shapes moved to
//! the shared `net-core` crate when grpc/graphql began reusing the
//! HTTP-over-reqwest core; they are re-exported here so the rest of the
//! http crate keeps importing them via `types::`.

use std::collections::BTreeMap;

use serde::Deserialize;

pub use mcpg_plugin_backend_net_core::types::{
    HttpBackendMethod, HttpCallMode, HttpRequestProfile, HttpResponseSummary, RetrySafetyContext,
};

/// Operator-facing spec for the `http` backend binding — the single
/// source of truth for the kind's field shape, defaults, and
/// value-validation. Deserializes the operator's verbatim binding YAML
/// 1:1 (the generic `{ kind: http, …spec }` form), so the field set and
/// every `#[serde(default = …)]` must match what an operator writes.
///
/// `timeout_ms` defaults to 2000 ms and `max_response_bytes` to 4096
/// bytes; `method` defaults to POST and `expected_status_codes` to
/// `[200]`. These are the canonical binding defaults — value-validation
/// lives in [`HttpBackendPlugin::register_profile`].
#[derive(Debug, Clone, Deserialize)]
pub struct HttpBackendSpec {
    pub url: String,
    #[serde(default = "default_method")]
    pub method: HttpBackendMethod,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default = "default_expected_status_codes")]
    pub expected_status_codes: Vec<u16>,
    #[serde(default)]
    pub require_json_response: bool,
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: usize,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub allow_private_backends: bool,
}

fn default_method() -> HttpBackendMethod {
    HttpBackendMethod::Post
}
fn default_expected_status_codes() -> Vec<u16> {
    vec![200]
}
fn default_max_response_bytes() -> usize {
    4096
}
fn default_timeout_ms() -> u64 {
    2000
}
