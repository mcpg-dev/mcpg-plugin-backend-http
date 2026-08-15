//! Dynamic resource template completion for the HTTP backend plugin.
//!
//! Operator-facing config is parsed inline on every call (stateless,
//! mirrors the SQL plugin):
//!
//! ```yaml
//! variable_completions:
//!   repo:
//!     kind: dynamic
//!     backend: my-http-binding
//!     config:
//!       method: GET                      # default GET
//!       path: "/completions/repos"       # appended to the binding's base URL
//!       query_params:
//!         prefix: "${arguments.prefix}"
//!         owner: "${arguments.context.owner}"
//!       headers:
//!         X-Var-Name: "${arguments.var_name}"
//!       response_path: "$.values"        # JSONPath; default "$"
//!       body_template: "..."             # POST only; CEL-templated
//! ```
//!
//! The HTTP plugin reuses its tool-call primitives (per-cred client
//! cache, DNS-rebinding guard, body-limit truncation, `mcpg_expr` CEL
//! engine). Completion just plugs them into a different request shape
//! and a different return type (Vec<String>).

use std::collections::BTreeMap;

use mcpg_expr::{DynamicValue, ExprContext, ExprRequestContext};
use mcpg_plugin_protocol::BackendError;
use reqwest::Method;
use serde::Deserialize;
use serde_json::Value;
use serde_json_path::JsonPath;
use url::Url;

use crate::exec;
use crate::types::HttpBackendMethod;
use mcpg_plugin_backend_net_core::runtime::NetworkProfileRuntime;

/// Per-(binding, variable) completion config. Parsed on every call —
/// the HTTP plugin holds no per-completion runtime state.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct HttpCompletionConfig {
    /// HTTP verb. GET (default) sends `query_params`; POST sends
    /// `body_template` as the JSON body. Other verbs are not
    /// supported — completion endpoints are always read-shaped.
    /// Uses the shared [`HttpBackendMethod`] type (case-insensitive:
    /// `get`/`GET`/`Get`), the same vocabulary as the binding `method:`.
    #[serde(default = "default_method")]
    pub method: HttpBackendMethod,
    /// Path appended to the binding's base URL. Required. CEL-
    /// templated (`${arguments.prefix}`, `${arguments.context.X}`).
    pub path: String,
    /// Per-key query string entries; values are CEL-templated.
    #[serde(default)]
    pub query_params: BTreeMap<String, String>,
    /// Per-key request headers; values are CEL-templated. Filtered
    /// against the protected-headers list before the request.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// JSONPath to extract the candidate string list. Default `"$"`
    /// assumes the response body is a top-level JSON array of
    /// strings. Operators specify `"$.values"` or `"$.results[*].name"`
    /// for arbitrary shapes.
    #[serde(default = "default_response_path")]
    pub response_path: String,
    /// CEL-templated request body (POST only). Ignored for GET.
    #[serde(default)]
    pub body_template: Option<String>,
}

fn default_method() -> HttpBackendMethod {
    HttpBackendMethod::Get
}

fn default_response_path() -> String {
    "$".to_owned()
}

/// Run an operator-declared HTTP completion endpoint.
///
/// Errors flow as `BackendError::InvalidSpec` for config mistakes
/// (unparseable JSONPath, bad URL, header injection) and
/// `BackendError::Transport` for upstream / network failures. The
/// gateway dispatcher treats both as "no completion values" — UX
/// hint, not load-bearing.
pub(crate) async fn run_http_completion(
    runtime: &NetworkProfileRuntime,
    cfg: HttpCompletionConfig,
    backend_name: &str,
    variable_name: &str,
    prefix: &str,
    context: &BTreeMap<String, String>,
) -> Result<Vec<String>, BackendError> {
    // 1. Parse the JSONPath up front. Bad path is operator config error
    //    — `InvalidSpec` so the gateway logs the cause; downstream call
    //    is not attempted.
    let path = JsonPath::parse(&cfg.response_path).map_err(|e| BackendError::InvalidSpec {
        message: format!("variable_completions.config.response_path: {e}"),
    })?;

    // 2. Build the CEL context. We expose `$arguments.prefix`,
    //    `$arguments.var_name`, and `$arguments.context.<key>` —
    //    plumbing the completion inputs through the same
    //    `mcpg_expr::DynamicValue` pipeline used for tool-call URL +
    //    headers. Identity / session / env are intentionally absent;
    //    completion runs on a per-keystroke cadence and operator
    //    completion endpoints should not depend on full identity
    //    propagation.
    let mut context_value = serde_json::Map::with_capacity(context.len());
    for (k, v) in context {
        context_value.insert(k.clone(), Value::String(v.clone()));
    }
    let arguments = serde_json::json!({
        "prefix": prefix,
        "var_name": variable_name,
        "context": Value::Object(context_value),
    });
    let expr_ctx = ExprContext {
        arguments,
        tool_name: format!("{backend_name}:completion:{variable_name}"),
        context: ExprRequestContext::default(),
        steps: None,
        env: std::sync::Arc::new(std::collections::HashMap::new()),
    };

    // 3. Resolve the completion endpoint's URL: join the operator's
    //    `path` (CEL-templated) onto the binding's base URL. We do not
    //    re-evaluate the binding URL's CEL — it's the per-binding base
    //    that completion is anchored to.
    let path_dv =
        DynamicValue::<String>::parse(&cfg.path).map_err(|e| BackendError::InvalidSpec {
            message: format!("variable_completions.config.path expression: {e}"),
        })?;
    let resolved_path = path_dv
        .resolve(&expr_ctx)
        .map_err(|e| BackendError::InvalidSpec {
            message: format!("variable_completions.config.path evaluation: {e}"),
        })?;
    let base_url = Url::parse(&runtime.profile().url).map_err(|e| BackendError::Transport {
        message: format!("HTTP binding base URL is not parseable: {e}"),
    })?;
    let mut request_url = resolve_completion_url(&base_url, &resolved_path)?;

    // 4. Resolve query-param + header expressions. `validate_header_value`
    //    catches CRLF injection in CEL output — same gate as the tool-
    //    call path.
    let mut resolved_query: Vec<(String, String)> = Vec::with_capacity(cfg.query_params.len());
    for (k, v) in &cfg.query_params {
        let dv = DynamicValue::<String>::parse(v).map_err(|e| BackendError::InvalidSpec {
            message: format!("variable_completions.config.query_params['{k}'] expression: {e}"),
        })?;
        let value = dv
            .resolve(&expr_ctx)
            .map_err(|e| BackendError::InvalidSpec {
                message: format!("variable_completions.config.query_params['{k}'] evaluation: {e}"),
            })?;
        resolved_query.push((k.clone(), value));
    }
    if !resolved_query.is_empty() {
        let mut pairs = request_url.query_pairs_mut();
        for (k, v) in &resolved_query {
            pairs.append_pair(k, v);
        }
        drop(pairs);
    }

    let mut resolved_headers: Vec<(String, String)> = Vec::with_capacity(cfg.headers.len());
    for (name, expr_src) in &cfg.headers {
        let dv =
            DynamicValue::<String>::parse(expr_src).map_err(|e| BackendError::InvalidSpec {
                message: format!("variable_completions.config.headers['{name}'] expression: {e}"),
            })?;
        let value = dv
            .resolve(&expr_ctx)
            .map_err(|e| BackendError::InvalidSpec {
                message: format!("variable_completions.config.headers['{name}'] evaluation: {e}"),
            })?;
        mcpg_expr::validate_header_value(name, &value).map_err(|e| BackendError::InvalidSpec {
            message: format!("completion header '{name}': {e}"),
        })?;
        resolved_headers.push((name.clone(), value));
    }

    // 5. Resolve the body template for POST.
    let body: Option<Value> = match (cfg.method, cfg.body_template.as_deref()) {
        (HttpBackendMethod::Post, Some(src)) => {
            let dv = DynamicValue::<String>::parse(src).map_err(|e| BackendError::InvalidSpec {
                message: format!("variable_completions.config.body_template expression: {e}"),
            })?;
            let rendered = dv
                .resolve(&expr_ctx)
                .map_err(|e| BackendError::InvalidSpec {
                    message: format!("variable_completions.config.body_template evaluation: {e}"),
                })?;
            let parsed: Value =
                serde_json::from_str(&rendered).map_err(|e| BackendError::InvalidSpec {
                    message: format!("body_template did not render to valid JSON: {e}"),
                })?;
            Some(parsed)
        }
        _ => None,
    };

    // 6. Pull a client from the registry. Reuses the tool-call code
    //    path so completion endpoints inherit per-cred isolation,
    //    DNS-rebinding guard (enforced inside `build_http_client`),
    //    and idle eviction. We key on the binding's base URL +
    //    operator headers (post-CEL); the cache hit-rate matches
    //    tool calls when no `cred://` refs are present.
    let client = runtime
        .resolve_static_client()
        .await
        .map_err(|e| BackendError::Transport {
            message: format!("building HTTP completion client: {e}"),
        })?;

    // 7. Issue the request. Per-call timeout is left to the gateway's
    //    3s `tokio::time::timeout` wrapper — typical tool-call
    //    timeouts of 30s+ are too lax for keystroke-driven completion.
    let method = match cfg.method {
        HttpBackendMethod::Get => Method::GET,
        HttpBackendMethod::Post => Method::POST,
    };
    let mut req = client.request(method, request_url);
    for (name, value) in &resolved_headers {
        req = req.header(name, value);
    }
    if let Some(body_value) = body.as_ref() {
        req = req.json(body_value);
    }
    let resp = req.send().await.map_err(|e| BackendError::Transport {
        message: format!("HTTP completion request failed: {e}"),
    })?;
    let status = resp.status();
    if !status.is_success() {
        return Err(BackendError::Transport {
            message: format!("HTTP completion endpoint returned non-success status {status}"),
        });
    }

    // 8. Drain the body under the binding's max_response_bytes cap,
    //    then JSON-parse. Same primitive the tool-call path uses, so
    //    operators that already tuned `max_response_bytes` for their
    //    binding inherit it for completion too.
    let limit = runtime.profile().max_response_bytes;
    let bytes = exec::read_response_with_limit(resp, limit)
        .await
        .map_err(|e| BackendError::Transport {
            message: format!("HTTP completion body read failed: {e}"),
        })?;
    let value: Value = match serde_json::from_slice(&bytes.0) {
        Ok(v) => v,
        Err(_) => {
            // Truncated bodies and non-JSON responses degrade to empty
            // completion — same UX-hint posture as JSONPath misses.
            return Ok(vec![]);
        }
    };

    // 9. JSONPath extract. Non-string matches are skipped; an empty
    //    match list returns an empty Vec. Both match the "completion
    //    is a UX hint, not load-bearing" contract.
    let nodes = path.query(&value).all();
    let mut out: Vec<String> = Vec::with_capacity(nodes.len());
    for node in nodes {
        match node {
            Value::String(s) => out.push(s.clone()),
            Value::Array(arr) => {
                // Convenience: if the JSONPath query returns a single
                // top-level array (the common `$` case for `["a","b"]`),
                // splat the strings.
                for item in arr {
                    if let Value::String(s) = item {
                        out.push(s.clone());
                    }
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

/// Join a CEL-resolved completion `path` onto the binding base URL and
/// enforce same-origin (SSRF guard).
///
/// `resolved_path` is CEL-templated over attacker-supplied completion
/// arguments, and `Url::join` lets an absolute (`https://evil/…`) or
/// protocol-relative (`//evil/…`) value REPLACE the authority. The
/// DNS-rebinding guard in `build_http_client` pins only the binding's BASE
/// host, so an off-origin join would reach an unpinned host (cloud metadata,
/// loopback, internal services). The operator's `path` config is meant to be
/// a path under the binding base — reject any join that changed scheme, host,
/// or port.
fn resolve_completion_url(base_url: &Url, resolved_path: &str) -> Result<Url, BackendError> {
    let request_url = base_url
        .join(resolved_path)
        .map_err(|e| BackendError::InvalidSpec {
            message: format!("joining completion path '{resolved_path}' onto base URL: {e}"),
        })?;
    let same_origin = request_url.scheme() == base_url.scheme()
        && request_url.host_str() == base_url.host_str()
        && request_url.port_or_known_default() == base_url.port_or_known_default();
    if !same_origin {
        return Err(BackendError::InvalidSpec {
            message: format!(
                "completion path '{resolved_path}' resolved to a different origin \
                 ({}://{}) than the binding base; cross-origin completion targets are \
                 refused (SSRF guard)",
                request_url.scheme(),
                request_url.host_str().unwrap_or("<none>"),
            ),
        });
    }
    Ok(request_url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn parse_config_minimal() {
        let cfg: HttpCompletionConfig =
            serde_json::from_value(serde_json::json!({ "path": "/foo" })).unwrap();
        assert_eq!(cfg.path, "/foo");
        assert_eq!(cfg.method, HttpBackendMethod::Get);
        assert_eq!(cfg.response_path, "$");
    }

    #[tokio::test]
    async fn parse_config_post_body() {
        let cfg: HttpCompletionConfig = serde_json::from_value(serde_json::json!({
            "method": "POST",
            "path": "/bar",
            "body_template": "{\"q\": \"${arguments.prefix}\"}"
        }))
        .unwrap();
        assert_eq!(cfg.method, HttpBackendMethod::Post);
        assert!(cfg.body_template.is_some());
    }

    #[tokio::test]
    async fn parse_config_method_is_case_insensitive() {
        // Completion uses the shared HttpBackendMethod, so every common
        // casing parses — including lowercase `get`/`post`.
        for (raw, want) in [
            ("get", HttpBackendMethod::Get),
            ("GET", HttpBackendMethod::Get),
            ("Get", HttpBackendMethod::Get),
            ("post", HttpBackendMethod::Post),
            ("POST", HttpBackendMethod::Post),
            ("Post", HttpBackendMethod::Post),
        ] {
            let cfg: HttpCompletionConfig =
                serde_json::from_value(serde_json::json!({ "method": raw, "path": "/p" }))
                    .unwrap_or_else(|e| panic!("method `{raw}` should parse: {e}"));
            assert_eq!(cfg.method, want, "method `{raw}`");
        }
    }

    #[tokio::test]
    async fn parse_config_rejects_missing_path() {
        let err =
            serde_json::from_value::<HttpCompletionConfig>(serde_json::json!({})).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("path"), "{msg}");
    }

    // ----- SSRF guard on the CEL-resolved completion path -----

    #[test]
    fn completion_url_allows_same_origin_paths() {
        let base = Url::parse("https://api.example.com/v1/complete").unwrap();
        for p in ["suggest", "/v1/suggest", "./suggest", "../other"] {
            let got = resolve_completion_url(&base, p)
                .unwrap_or_else(|e| panic!("path `{p}` should be allowed: {e}"));
            assert_eq!(got.host_str(), Some("api.example.com"), "path `{p}`");
            assert_eq!(got.scheme(), "https", "path `{p}`");
        }
    }

    #[test]
    fn completion_url_rejects_offorigin_join() {
        let base = Url::parse("https://api.example.com/v1/complete").unwrap();
        // Absolute URL, protocol-relative, host swap, scheme downgrade, and
        // the classic cloud-metadata target — every join that changes the
        // origin must be refused.
        for p in [
            "https://evil.example.net/x",
            "//169.254.169.254/latest/meta-data/",
            "http://api.example.com/v1/suggest", // scheme downgrade
            "https://api.example.com:8443/v1/x", // port change
            "file:///etc/passwd",
        ] {
            let err = resolve_completion_url(&base, p)
                .expect_err(&format!("off-origin path `{p}` must be rejected"));
            assert!(
                matches!(err, BackendError::InvalidSpec { .. }),
                "path `{p}` -> {err:?}"
            );
        }
    }
}
