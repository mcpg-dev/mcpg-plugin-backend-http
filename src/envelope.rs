//! HTTP-family structured response envelope for the HTTP backend plugin.
//!
//! The downstream-error classification + retry-guidance shaping is
//! shared with grpc/graphql and lives in `net-core`'s `retry` module;
//! it is re-exported here so the rest of the http crate keeps using
//! `envelope::`. This module owns only [`build_envelope`] — the
//! HTTP-specific structured-content layout the gateway projects onto
//! `tools/call`.
//!
//! The `BackendResponse.payload` returned by the plugin is a UTF-8
//! JSON document with the same shape the gateway used to assemble
//! inline in `build_http_call_structured_content`, so the gateway's
//! existing `tools/call` projection wraps the bytes verbatim.

use serde_json::Value;

pub use mcpg_plugin_backend_net_core::retry::{
    DownstreamHttpError, parse_and_validate_json_response, transport_downstream_error,
    validate_expected_status_codes,
};

use crate::types::{HttpCallMode, HttpRequestProfile, HttpResponseSummary};

/// Build the structured-content envelope a gateway adapter projects
/// onto `tools/call`. Mirrors `build_http_call_structured_content` in
/// the gateway's pre-extraction path. `tool_name` and `profile_name`
/// stay at the top of the envelope so audit/log consumers can match
/// across the lift; `family_fields` carries the HTTP-specific
/// duplicates the projection layer historically denormalised for
/// human readability.
#[allow(clippy::too_many_arguments)]
pub fn build_envelope(
    tool_name: &str,
    profile_name: &str,
    profile: &HttpRequestProfile,
    call_mode: HttpCallMode,
    request_arguments: &Value,
    request_body: Option<&Value>,
    request_query: Option<&str>,
    response: Option<&HttpResponseSummary>,
    response_json: Option<&Value>,
    response_json_parse_error: Option<&str>,
    downstream_error: Option<&DownstreamHttpError>,
    downstream_errors: &[DownstreamHttpError],
    error: Option<&str>,
    // `display_url` / `display_headers`: per-call effective values
    // surfaced to operators in the structured envelope. The plugin
    // evaluates operator CEL templates per call, so these
    // carry the post-substitution url + headers. `None` falls back
    // to the registered profile values (offline tests).
    display_url: Option<&str>,
    display_headers: Option<&std::collections::BTreeMap<String, String>>,
) -> Value {
    let mut base = serde_json::json!({
        "toolName": tool_name,
        "profile": profile_name,
        "requestKind": call_mode.request_kind(),
        "request": serde_json::json!({
            "kind": call_mode.request_kind(),
            "arguments": request_arguments,
            "body": request_body,
            "query": request_query,
        }),
        "response": response.map(|r| serde_json::json!({
            "durationMs": r.duration_ms,
            "statusCode": r.status_code,
            "contentType": r.content_type,
            "body": r.body,
            "bodyTruncated": r.body_truncated,
            "json": response_json,
            "jsonParseError": response_json_parse_error,
        })),
        "error": error,
    });
    let map = base.as_object_mut().expect("base is object");
    map.insert(
        "downstreamError".to_owned(),
        downstream_error
            .map(|e| serde_json::to_value(e).expect("serializable"))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "downstreamErrors".to_owned(),
        serde_json::to_value(downstream_errors).expect("serializable"),
    );

    let effective_url = display_url.unwrap_or(profile.url.as_str());
    let effective_headers = display_headers.unwrap_or(&profile.headers);
    let family = serde_json::json!({
        "url": effective_url,
        "timeoutMs": profile.timeout.as_millis() as u64,
        "maxResponseBytes": profile.max_response_bytes,
        "expectedStatusCodes": profile.expected_status_codes,
        "requireJsonResponse": profile.require_json_response,
        "requestHeaders": effective_headers,
        "requestArguments": request_arguments,
        "requestBody": request_body,
        "requestQuery": request_query,
        "durationMs": response.map(|r| r.duration_ms),
        "statusCode": response.map(|r| r.status_code),
        "responseContentType": response.and_then(|r| r.content_type.as_deref()),
        "body": response.map(|r| r.body.as_str()),
        "bodyTruncated": response.map(|r| r.body_truncated),
        "responseJson": response_json,
        "responseJsonParseError": response_json_parse_error,
    });
    if let Value::Object(family_map) = family {
        for (k, v) in family_map {
            map.insert(k, v);
        }
    }

    base
}
