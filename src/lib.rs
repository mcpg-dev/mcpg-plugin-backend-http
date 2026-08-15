//! HTTP backend binding plugin for mcpg.
//!
//! Implements [`HttpBackendPlugin`] — `BackendPlugin` for `kind:
//! "http"`. Dispatches tool calls as outbound HTTP/1.1+2 requests
//! via `reqwest`, with per-binding URL + headers + method, DNS
//! rebinding protection, structured response envelopes, and
//! per-caller `cred://` resolution backed by an internal
//! [`ClientRegistry`](client_registry::ClientRegistry).
//!
//! ## Client caching
//!
//! The plugin caches one `reqwest::Client` per resolved-credential
//! bundle (BLAKE3 digest over URL + header values), with LRU + idle
//! eviction and a revocation subscriber wired to `BackendHost::
//! subscribe_credential_revoked`. Static-cred profiles (no
//! `cred://` references) hit a single cached entry on every call.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use mcpg_plugin_protocol::audit::{AuditEvent, AuditOutcome};
use mcpg_plugin_protocol::types::PluginIdentity;
use mcpg_plugin_protocol::{
    BackendChunk, BackendChunkStream, BackendError, BackendHost, BackendPlugin, BackendRequest,
    BackendResponse, PluginManifest, firstparty_manifest,
};
use mcpg_plugin_sdk::HostHandle;
use tokio::sync::RwLock;
use tracing::debug;

// The HTTP-over-reqwest core (per-cred client cache, DNS-rebinding /
// SSRF guard, per-call exec primitives, downstream-error retry shaping,
// and the per-profile resolution runtime) now lives in the shared
// `net-core` crate so grpc/graphql reuse one copy. These aliases keep
// the http crate's existing `exec::` / `client_registry::` paths
// resolving unchanged; the resolution layer comes in via `runtime`.
use mcpg_plugin_backend_net_core::runtime::{
    NetworkProfileRuntime, ResolvedCall, build_expr_context,
};
use mcpg_plugin_backend_net_core::{client_registry, exec};
/// cdylib sync bridge (backend-plugin-migration — http is the final
/// backend to go dynamic).
pub mod cdylib;
mod completion;
mod envelope;
mod types;

pub use client_registry::{
    CredDigest, IdleSweeper, collect_cred_refs, digest_credential_bundle, static_digest,
};
pub use envelope::DownstreamHttpError;
pub use types::{
    HttpBackendMethod, HttpBackendSpec, HttpCallMode, HttpRequestProfile, HttpResponseSummary,
    RetrySafetyContext,
};

/// Embedded plugin descriptor — passed to
/// [`mcpg_plugin_host::FirstPartyRegistrar::register`] at gateway
/// startup.
pub const BINDING_DESCRIPTOR_YAML: &str = include_str!("../plugin.yaml");

/// Bounded outcome label for the unified
/// host-handle metric pair. The set MUST stay closed so the host
/// metrics-rs recorder doesn't blow up on cardinality.
///
/// Status-class bucketing is intentional: per-status labels would
/// explode cardinality (every upstream that returns numerically
/// distinct 4xx values would carve a fresh time-series), so 4xx
/// rolls to `http_4xx` and 5xx rolls to `http_5xx`. Transport-level
/// failures split into `timeout` (reqwest's `Error::is_timeout`)
/// and a generic `transport` bucket for everything else (DNS, TLS,
/// connection refused, body-read mid-stream, …).
///
/// `invalid_spec` covers payload-parse failures + the resolution
/// path's CEL / cred errors that the plugin maps to the same
/// envelope-time error shape.
fn host_outcome_label_for_status(status: u16) -> &'static str {
    match status {
        200..=299 => "ok",
        400..=499 => "http_4xx",
        500..=599 => "http_5xx",
        // Out-of-range (1xx/3xx slip through here when the operator
        // didn't whitelist them) — treat as ok for the metric label;
        // the envelope's expected_status_codes validation handles the
        // semantic mismatch.
        _ => "ok",
    }
}

/// Derive the bounded outcome label for the
/// transport-error path (no HTTP status). reqwest's error chain
/// distinguishes timeout via [`reqwest::Error::is_timeout`]; we
/// don't have a typed error here (the resolution layer flattens
/// to `String`), so we substring-sniff the message for the
/// canonical `"operation timed out"` / `"timeout"` marker reqwest
/// emits via its underlying hyper/tokio stack.
fn host_outcome_label_for_transport_error(message: &str) -> &'static str {
    let lower = message.to_ascii_lowercase();
    if lower.contains("timed out") || lower.contains("timeout") {
        "timeout"
    } else {
        "transport"
    }
}

/// Bounded set of dotted audit-event action
/// names emitted on notable HTTP backend failures. Returns `None`
/// for success and for 4xx (4xx is normal traffic — auth probes,
/// optimistic-concurrency conflicts, rate-limit denials — audit-
/// emitting every one would drown the audit log). Driver-class
/// failures (transport timeout / transport error / 5xx) emit an
/// audit event so operators can reconstruct upstream outages,
/// DNS failures, and infrastructure regressions after the fact.
///
/// `invalid_spec` (CEL / cred-resolution / payload-parse failures)
/// also emits — these are NOT operator-class config-drift bugs
/// like SQL's `InvalidSpec` (which fires identically on every
/// retry at registration time); the HTTP plugin's `InvalidSpec`
/// path fires per-call when CEL templates can't be evaluated
/// against the current arguments / identity, which IS forensically
/// interesting.
fn audit_action_for_outcome(label: &str) -> Option<&'static str> {
    match label {
        "timeout" => Some("dev.mcpg.backend.http.request_timeout"),
        "transport" => Some("dev.mcpg.backend.http.request_failed"),
        "http_5xx" => Some("dev.mcpg.backend.http.upstream_5xx"),
        "invalid_spec" => Some("dev.mcpg.backend.http.request_failed"),
        // ok, http_4xx → no audit emission.
        _ => None,
    }
}

/// Best-effort RFC 3339 timestamp for audit
/// event `occurred_at`. The plugin already pulls in `chrono` for
/// this; audit sinks sort lexicographically by `occurred_at`, so
/// the calendar-correct format matters.
fn rfc3339_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Synthetic identity for audit events emitted
/// on inbound requests that carry no caller attribution (system-
/// initiated paths: health probes, retry-from-watch, admin tools).
/// Audit sinks treat `kind = "system"` specially so these events
/// are easy to filter out of caller-attributed dashboards. Mirrors
/// the SQL plugin's synthetic identity exactly so cross-plugin
/// audit search treats system traffic uniformly.
fn synthetic_system_identity() -> PluginIdentity {
    PluginIdentity {
        kind: "system".into(),
        trust_level: "verified".into(),
        subject_id: Some("dev.mcpg.backend.http".into()),
        auth_provider: None,
        issuer: None,
        roles: vec![],
        groups: vec![],
        scopes: vec![],
        attributes: Default::default(),
    }
}

/// `BackendPlugin` implementation for `kind: "http"`.
pub struct HttpBackendPlugin {
    manifest: PluginManifest,
    profiles: RwLock<BTreeMap<String, NetworkProfileRuntime>>,
    /// The unified host surface. Installed once
    /// at boot by the gateway via
    /// [`HttpBackendPlugin::set_host_handle`] before any `execute()`
    /// traffic flows. When `None` (test harnesses that construct the
    /// plugin without wiring a host), the per-call HostHandle
    /// observability triad short-circuits to no-ops and the plugin's
    /// existing internal `tracing::*` / `metrics::*` calls carry the
    /// load.
    ///
    /// Coexistence with the per-`ProfileRuntime` `host: Arc<dyn
    /// BackendHost>` is intentional — `BackendHost` is the
    /// re-entrant-dispatch trait (cred resolution, secret
    /// rotation, revocation); `HostHandle` is the unified
    /// observability + secret / config surface. The two are
    /// orthogonal and both stay wired.
    host_handle: OnceLock<HostHandle>,
}

impl Default for HttpBackendPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpBackendPlugin {
    #[must_use]
    pub fn new() -> Self {
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.backend.http",
                name: "HTTP Binding",
                class: Backend,
            },
            profiles: RwLock::new(BTreeMap::new()),
            host_handle: OnceLock::new(),
        }
    }

    /// Install the unified [`HostHandle`] surface
    /// for per-call observability. The gateway calls this exactly
    /// once at boot, after constructing the plugin via
    /// [`HttpBackendPlugin::new`] but before any `execute()` traffic
    /// is dispatched, threading a handle built from the late-bound
    /// `HostServices` via [`HostHandle::from_services`].
    ///
    /// Idempotent — a second call is silently a no-op so test
    /// harnesses that construct the plugin without a host can still
    /// call this safely from a reload path. The returned `bool`
    /// indicates whether the handle was installed (`true`) or the
    /// slot was already occupied (`false`).
    pub fn set_host_handle(&self, host: HostHandle) -> bool {
        self.host_handle.set(host).is_ok()
    }

    /// Borrow the installed unified host
    /// surface, if any. Returns `None` in test harnesses that
    /// constructed the plugin via [`HttpBackendPlugin::new`] without
    /// calling [`HttpBackendPlugin::set_host_handle`]. Callers MUST
    /// treat `None` as "skip the host triad" — the plugin's internal
    /// `tracing::*` + `metrics::*` calls remain wired and carry the
    /// load through the triad-floor sinks.
    fn host_handle(&self) -> Option<&HostHandle> {
        self.host_handle.get()
    }

    /// Emit the per-call observability triad
    /// (latency histogram + call counter + optional audit event)
    /// through the installed [`HostHandle`]. Short-circuits to a
    /// no-op when no handle is installed (test paths).
    ///
    /// Cardinality budget: outcome ∈ {ok, http_4xx, http_5xx,
    /// timeout, transport, invalid_spec, profile_not_found}. The
    /// backend name is NOT attached to metric labels — the host's
    /// metric sink already adds `plugin_alias` automatically.
    ///
    /// Audit emission is gated by [`audit_action_for_outcome`]:
    /// success + http_4xx do not emit, timeout / transport /
    /// http_5xx / invalid_spec do. Emission flows through
    /// `tokio::task::spawn_blocking` because `HostHandle::audit_event`
    /// is sync and bridges to an async `HostServices::audit_event`
    /// via `Handle::block_on` on the static-firstparty path —
    /// calling that directly from this async worker would panic
    /// (`Cannot start a runtime from within a runtime`). Async
    /// variants on `HostHandle` would let async-native plugins
    /// skip the spawn_blocking detour.
    #[allow(clippy::too_many_arguments)] // Bounded set of per-call observability fields.
    async fn emit_host_observability(
        &self,
        backend_name: &str,
        outcome_label: &'static str,
        status_code: Option<u16>,
        reason: Option<&str>,
        identity: Option<&PluginIdentity>,
        request_id: &str,
        duration: Duration,
    ) {
        let Some(host) = self.host_handle() else {
            return;
        };
        let elapsed_secs = duration.as_secs_f64();
        host.histogram(
            "mcpg_http_backend_latency_seconds",
            elapsed_secs,
            &[("outcome", outcome_label)],
        );
        host.counter(
            "mcpg_http_backend_calls_total",
            1,
            &[("outcome", outcome_label)],
        );

        if let Some(action) = audit_action_for_outcome(outcome_label) {
            let actor = identity.cloned().unwrap_or_else(synthetic_system_identity);
            let mut details = serde_json::json!({
                "backend": backend_name,
                "duration_ms": duration.as_millis() as u64,
                "outcome": outcome_label,
                "alias": host.alias(),
            });
            if let Some(status) = status_code {
                details
                    .as_object_mut()
                    .expect("json object")
                    .insert("status_code".into(), serde_json::Value::from(status));
            }
            if let Some(reason) = reason {
                details.as_object_mut().expect("json object").insert(
                    "reason".into(),
                    serde_json::Value::String(reason.to_owned()),
                );
            }
            let event = AuditEvent {
                event_id: format!("http-{}-{}", request_id, duration.as_nanos()),
                occurred_at: rfc3339_now(),
                actor,
                action: action.to_owned(),
                resource: Some(format!("http-binding://{backend_name}")),
                outcome: AuditOutcome::Failure,
                request_id: Some(request_id.to_owned()),
                node_id: None,
                details,
                prev_event_hash: None,
            };
            let host_for_audit = host.clone();
            if let Err(join_err) = tokio::task::spawn_blocking(move || {
                let _ = host_for_audit.audit_event(event);
            })
            .await
            {
                // Cancelled or panicked — log at debug and
                // continue; audit emission is best-effort.
                debug!(
                    target: "mcpg::http::host_handle",
                    error = %join_err,
                    "host_handle.audit_event spawn_blocking failed"
                );
            }
        }
    }

    /// Per-call preparation shared by `execute` + `execute_streaming`:
    /// look up the runtime, parse arguments JSON, derive request body
    /// / query string, capture trace headers, and run CEL + cred
    /// resolution. Returns everything the caller needs to either
    /// drive a buffered call or start a streaming one.
    async fn prepare_call(
        &self,
        backend_name: &str,
        request: &BackendRequest,
    ) -> Result<PreparedCall, BackendError> {
        let runtime = {
            let guard = self.profiles.read().await;
            guard
                .get(backend_name)
                .cloned()
                .ok_or_else(|| BackendError::ProfileNotFound {
                    backend_name: backend_name.to_owned(),
                })?
        };

        let arguments: serde_json::Value = if request.payload.is_empty() {
            serde_json::json!({})
        } else {
            serde_json::from_slice(&request.payload).map_err(|e| BackendError::InvalidSpec {
                message: format!("HTTP plugin payload is not valid JSON: {e}"),
            })?
        };

        let call_mode = HttpCallMode::for_method(runtime.profile().method);

        let tool_name = request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("mcpg-tool-name"))
            .map(|(_, v)| v.as_str())
            .unwrap_or(backend_name)
            .to_owned();

        let (request_body, request_query) = match call_mode {
            HttpCallMode::JsonBody => (Some(arguments.clone()), None::<String>),
            HttpCallMode::QueryString => {
                let q = exec::build_query_string(&arguments).map_err(|e| {
                    BackendError::InvalidSpec {
                        message: format!("HTTP query call: {e}"),
                    }
                })?;
                (None, Some(q))
            }
        };

        let trace_headers: Vec<(String, String)> = request
            .headers
            .iter()
            .filter(|(k, _)| {
                let lower = k.to_ascii_lowercase();
                lower == "traceparent" || lower == "tracestate"
            })
            .cloned()
            .collect();

        // Flag whether the operator pinned their own `Idempotency-Key`
        // header at config time. Case-insensitive per HTTP/1.1
        // (RFC 7230 §3.2). Operator pin wins over the gateway-injected
        // hint.
        let operator_has_idempotency_key = runtime.operator_has_header("idempotency-key");

        // Clone the gateway-supplied key out of
        // `BackendRequest.idempotency` so the buffered + streaming
        // dispatch paths share a single source. The key has already
        // been validated by `idempotency::validate_request_key` at
        // the gateway edge (≤255 ASCII bytes, non-empty).
        let idempotency_key = request.idempotency.as_ref().map(|hint| hint.key.clone());

        let expr_ctx = build_expr_context(&arguments, &tool_name, request);
        let resolution = runtime
            .resolve_client(&expr_ctx, request, backend_name)
            .await;

        Ok(PreparedCall {
            runtime,
            arguments,
            tool_name,
            call_mode,
            request_body,
            request_query,
            trace_headers,
            idempotency_key,
            operator_has_idempotency_key,
            resolution,
        })
    }
}

impl std::fmt::Debug for HttpBackendPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpBackendPlugin")
            .field("id", &self.manifest.id)
            .finish()
    }
}

#[async_trait]
impl BackendPlugin for HttpBackendPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        "http"
    }

    async fn register_profile(
        &self,
        backend_name: &str,
        spec: &serde_json::Value,
        host: Arc<dyn BackendHost>,
    ) -> Result<(), BackendError> {
        let parsed: HttpBackendSpec =
            serde_json::from_value(spec.clone()).map_err(|e| BackendError::InvalidSpec {
                message: format!("HTTP binding spec: {e}"),
            })?;

        if parsed.url.trim().is_empty() {
            return Err(BackendError::InvalidSpec {
                message: "url must not be empty".into(),
            });
        }
        if !parsed.url.starts_with("http://") && !parsed.url.starts_with("https://") {
            return Err(BackendError::InvalidSpec {
                message: format!(
                    "url must start with http:// or https://, got '{}'",
                    parsed.url
                ),
            });
        }
        if parsed.timeout_ms == 0 {
            return Err(BackendError::InvalidSpec {
                message: "timeout_ms must be greater than 0".into(),
            });
        }
        if parsed.max_response_bytes == 0 {
            return Err(BackendError::InvalidSpec {
                message: "max_response_bytes must be greater than 0".into(),
            });
        }
        if parsed.expected_status_codes.is_empty() {
            return Err(BackendError::InvalidSpec {
                message: "expected_status_codes must not be empty".into(),
            });
        }
        for code in &parsed.expected_status_codes {
            if !(100..=599).contains(code) {
                return Err(BackendError::InvalidSpec {
                    message: format!(
                        "expected_status_codes entries must be valid HTTP status \
                         codes (100-599), got {code}"
                    ),
                });
            }
        }
        // Header keys/values are reflected verbatim onto the outbound
        // request, so a CR/LF would enable request splitting — reject at
        // registration (an empty key is never a valid header name).
        for (header_name, header_value) in &parsed.headers {
            if header_name.trim().is_empty() {
                return Err(BackendError::InvalidSpec {
                    message: "headers keys must not be empty".into(),
                });
            }
            if header_name.contains(['\r', '\n']) {
                return Err(BackendError::InvalidSpec {
                    message: "headers keys must not contain CR or LF characters".into(),
                });
            }
            if header_value.contains(['\r', '\n']) {
                return Err(BackendError::InvalidSpec {
                    message: "headers values must not contain CR or LF characters".into(),
                });
            }
        }

        // Secret rotation: the `__mcpg_secret_refs` hint the
        // gateway injects post-resolution tells us which `vault://...`
        // URIs touched this profile — net-core's rotation subscription
        // only evicts cached clients when one of these rotates.
        let secret_refs: Vec<String> = spec
            .get("__mcpg_secret_refs")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();

        debug!(
            backend = %backend_name,
            url = %parsed.url,
            method = ?parsed.method,
            timeout_ms = parsed.timeout_ms,
            "registered HTTP binding profile"
        );

        let profile = HttpRequestProfile {
            url: parsed.url.clone(),
            method: parsed.method,
            headers: parsed.headers.clone(),
            expected_status_codes: parsed.expected_status_codes.clone(),
            require_json_response: parsed.require_json_response,
            max_response_bytes: parsed.max_response_bytes,
            timeout: Duration::from_millis(parsed.timeout_ms),
            allow_private_backends: parsed.allow_private_backends,
        };

        // The CEL-compile + per-cred client cache + revocation /
        // rotation / idle-sweeper wiring + per-call resolution all live
        // in the shared net-core runtime now.
        let runtime = NetworkProfileRuntime::register(
            backend_name,
            parsed.url,
            parsed.headers,
            profile,
            host,
            secret_refs,
        )
        .map_err(|e| BackendError::InvalidSpec {
            message: format!("HTTP binding spec: {e}"),
        })?;
        self.profiles
            .write()
            .await
            .insert(backend_name.to_owned(), runtime);
        Ok(())
    }

    async fn execute(
        &self,
        backend_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError> {
        // Open the host-attributed span BEFORE
        // `prepare_call` so the span covers the whole request
        // window (including profile lookup + payload parse + CEL
        // resolution). Bounded attrs: backend name (config-bounded)
        // + request id (already on the inbound span). The full URL
        // is NEVER attached as a span attribute — it would explode
        // cardinality + leak resolved credentials (resolved-URL may
        // carry post-cred:// substitution). The method is captured
        // post-`prepare_call` as a span event when known.
        let t0 = Instant::now();
        let request_id = request.request_id.clone();
        let identity = request.identity.clone();
        let host_span = self.host_handle().map(|h| {
            h.span(
                "http_backend.execute",
                serde_json::json!({
                    "backend": backend_name,
                    "request_id": request_id,
                }),
            )
        });

        let prep_result = self.prepare_call(backend_name, &request).await;
        // `prepare_call` failures map onto bounded outcome labels —
        // `ProfileNotFound` short-circuits without per-call work,
        // `InvalidSpec` covers payload-parse + CEL templating + cred
        // resolution issues. Both bypass the upstream HTTP call so
        // we emit the metric pair + (for invalid_spec) the audit
        // event before returning the typed error.
        let prep = match prep_result {
            Ok(p) => p,
            Err(err) => {
                let label = match &err {
                    BackendError::ProfileNotFound { .. } => "profile_not_found",
                    BackendError::InvalidSpec { .. } => "invalid_spec",
                    BackendError::Timeout { .. } => "timeout",
                    BackendError::Transport { .. } => "transport",
                };
                self.emit_host_observability(
                    backend_name,
                    label,
                    None,
                    Some(&err.to_string()),
                    identity.as_ref(),
                    request_id.as_str(),
                    t0.elapsed(),
                )
                .await;
                drop(host_span);
                return Err(err);
            }
        };

        let response = match prep.resolution.as_ref() {
            Ok(r) => {
                exec::execute_http_call(
                    &r.client,
                    prep.runtime.profile(),
                    prep.call_mode,
                    prep.request_body.as_ref().unwrap_or(&prep.arguments),
                    prep.request_query.as_deref(),
                    &prep.trace_headers,
                    prep.idempotency_key.as_deref(),
                    prep.operator_has_idempotency_key,
                    &r.resolved_url,
                )
                .await
            }
            Err(e) => Err(e.clone()),
        };

        // Derive the bounded outcome label
        // BEFORE envelope shaping so we capture it for the metric
        // pair regardless of whether envelope serialization fails
        // later. Status-class bucketing keeps the label set
        // closed; transport errors get a one-pass timeout-vs-other
        // sniff. The audit reason is the underlying error string
        // — resolution failures already populated `prep.resolution`'s
        // `Err` arm, so we route through that when the upstream-call
        // error string is the empty sentinel.
        let outcome_label: &'static str = match response.as_ref() {
            Ok(summary) => host_outcome_label_for_status(summary.status_code),
            Err(message) => {
                if message.is_empty() {
                    // Resolution failure path — CEL / cred resolution
                    // surfaced an error before the upstream call ran.
                    // The plugin maps these to `invalid_spec` because
                    // they're config-evaluation errors (per-call CEL
                    // can fail mid-traffic, unlike SQL where
                    // `InvalidSpec` only fires at register time).
                    "invalid_spec"
                } else {
                    host_outcome_label_for_transport_error(message)
                }
            }
        };

        let audit_reason: Option<String> = match response.as_ref() {
            Ok(_) => None,
            Err(message) if !message.is_empty() => Some(message.clone()),
            Err(_) => prep.resolution.as_ref().err().cloned(),
        };

        let envelope = build_envelope_from_outcome(&prep, backend_name, response.as_ref());

        self.emit_host_observability(
            backend_name,
            outcome_label,
            response.as_ref().ok().map(|s| s.status_code),
            audit_reason.as_deref(),
            identity.as_ref(),
            request_id.as_str(),
            t0.elapsed(),
        )
        .await;

        let payload = serde_json::to_vec(&envelope).map_err(|e| BackendError::Transport {
            message: format!("HTTP plugin envelope serialization failed: {e}"),
        })?;

        // Explicit drop so SpanGuard::Drop fires AFTER metric +
        // audit emission — the host sink should see span_end last.
        drop(host_span);

        Ok(BackendResponse {
            payload,
            truncated: false,
        })
    }

    /// Streaming override. Mirrors `execute` for non-streaming
    /// upstream responses (single `Done` chunk, no fake Progress).
    /// When the upstream signals streaming via `Transfer-Encoding:
    /// chunked`, `Content-Type: text/event-stream`, or absent
    /// `Content-Length`, the plugin emits one
    /// [`BackendChunk::Progress`] per body chunk (cumulative byte
    /// count + label) before the terminal `Done`.
    ///
    /// All envelope-shaping (status validation, JSON parse, body
    /// truncation cap, downstream error mapping, post-CEL URL +
    /// header reflection) is identical to `execute` — the override
    /// only adds the per-chunk Progress emission. DNS rebinding,
    /// body limit, and cred:// resolution flow through the same
    /// helpers.
    async fn execute_streaming(
        &self,
        backend_name: &str,
        request: BackendRequest,
    ) -> Result<BackendChunkStream, BackendError> {
        use futures::stream::StreamExt;

        // Mirror `execute`'s triad on the
        // streaming path. The span opens here and is dropped at all
        // terminal exits (resolution failure, start error, buffered
        // short-circuit, unfold-Done, unfold-Err). The host_handle
        // clone lets us emit metric + audit from inside the unfold
        // closure where `&self` is no longer reachable.
        let t0 = Instant::now();
        let request_id = request.request_id.clone();
        let identity = request.identity.clone();
        let host_span = self.host_handle().map(|h| {
            h.span(
                "http_backend.execute_streaming",
                serde_json::json!({
                    "backend": backend_name,
                    "request_id": request_id,
                }),
            )
        });

        let prep_result = self.prepare_call(backend_name, &request).await;
        let prep = match prep_result {
            Ok(p) => p,
            Err(err) => {
                let label = match &err {
                    BackendError::ProfileNotFound { .. } => "profile_not_found",
                    BackendError::InvalidSpec { .. } => "invalid_spec",
                    BackendError::Timeout { .. } => "timeout",
                    BackendError::Transport { .. } => "transport",
                };
                self.emit_host_observability(
                    backend_name,
                    label,
                    None,
                    Some(&err.to_string()),
                    identity.as_ref(),
                    request_id.as_str(),
                    t0.elapsed(),
                )
                .await;
                drop(host_span);
                return Err(err);
            }
        };
        let backend_name_owned = backend_name.to_owned();

        // Resolution failure path: build the transport-error
        // envelope synchronously and emit a single Done.
        let resolved = match prep.resolution.as_ref() {
            Ok(r) => r.client.clone(),
            Err(res_err) => {
                let envelope =
                    build_envelope_from_outcome(&prep, &backend_name_owned, Err(&String::new()));
                let payload =
                    serde_json::to_vec(&envelope).map_err(|e| BackendError::Transport {
                        message: format!("HTTP plugin envelope serialization failed: {e}"),
                    })?;
                self.emit_host_observability(
                    &backend_name_owned,
                    "invalid_spec",
                    None,
                    Some(res_err),
                    identity.as_ref(),
                    request_id.as_str(),
                    t0.elapsed(),
                )
                .await;
                drop(host_span);
                let stream = futures::stream::once(async move {
                    Ok(BackendChunk::Done(BackendResponse {
                        payload,
                        truncated: false,
                    }))
                });
                return Ok(Box::pin(stream));
            }
        };
        let resolved_url = prep
            .resolution
            .as_ref()
            .map(|r| r.resolved_url.clone())
            .expect("resolution Ok above");

        // Start the upstream HTTP request. Errors here are transport
        // failures — same envelope shape as the buffered path.
        let handle = match exec::start_http_call_streaming(
            &resolved,
            prep.runtime.profile(),
            prep.call_mode,
            prep.request_body.as_ref().unwrap_or(&prep.arguments),
            prep.request_query.as_deref(),
            &prep.trace_headers,
            prep.idempotency_key.as_deref(),
            prep.operator_has_idempotency_key,
            &resolved_url,
        )
        .await
        {
            Ok(h) => h,
            Err(error) => {
                let envelope = build_envelope_from_outcome(&prep, &backend_name_owned, Err(&error));
                let payload =
                    serde_json::to_vec(&envelope).map_err(|e| BackendError::Transport {
                        message: format!("HTTP plugin envelope serialization failed: {e}"),
                    })?;
                let label = host_outcome_label_for_transport_error(&error);
                self.emit_host_observability(
                    &backend_name_owned,
                    label,
                    None,
                    Some(&error),
                    identity.as_ref(),
                    request_id.as_str(),
                    t0.elapsed(),
                )
                .await;
                drop(host_span);
                let stream = futures::stream::once(async move {
                    Ok(BackendChunk::Done(BackendResponse {
                        payload,
                        truncated: false,
                    }))
                });
                return Ok(Box::pin(stream));
            }
        };

        // Buffered upstream (Content-Length set, not SSE, not
        // chunked) → drain the body in one shot and emit a single
        // Done. Avoids spurious Progress for tiny replies.
        if !handle.is_streaming {
            let exec::HttpStreamHandle {
                response,
                status_code,
                content_type,
                retry_after_ms,
                started_at,
                ..
            } = handle;
            let limit = prep.runtime.profile().max_response_bytes;
            let mut body_stream = Box::pin(exec::read_body_streaming(response, limit));
            let mut final_body = String::new();
            let mut final_truncated = false;
            let mut error: Option<String> = None;
            while let Some(step) = body_stream.next().await {
                match step {
                    Ok(exec::BodyReadStep::Progress { .. }) => {}
                    Ok(exec::BodyReadStep::Done { body, truncated }) => {
                        final_body = body;
                        final_truncated = truncated;
                    }
                    Err(e) => {
                        error = Some(e);
                        break;
                    }
                }
            }
            let response = match error {
                Some(e) => Err(e),
                None => Ok(exec::finalize_http_summary(
                    status_code,
                    content_type,
                    retry_after_ms,
                    started_at,
                    final_body,
                    final_truncated,
                )),
            };
            let outcome_label: &'static str = match response.as_ref() {
                Ok(summary) => host_outcome_label_for_status(summary.status_code),
                Err(message) => host_outcome_label_for_transport_error(message),
            };
            let audit_reason: Option<String> = match response.as_ref() {
                Ok(_) => None,
                Err(message) => Some(message.clone()),
            };
            let envelope =
                build_envelope_from_outcome(&prep, &backend_name_owned, response.as_ref());
            let payload = serde_json::to_vec(&envelope).map_err(|e| BackendError::Transport {
                message: format!("HTTP plugin envelope serialization failed: {e}"),
            })?;
            self.emit_host_observability(
                &backend_name_owned,
                outcome_label,
                response.as_ref().ok().map(|s| s.status_code),
                audit_reason.as_deref(),
                identity.as_ref(),
                request_id.as_str(),
                t0.elapsed(),
            )
            .await;
            drop(host_span);
            let stream = futures::stream::once(async move {
                Ok(BackendChunk::Done(BackendResponse {
                    payload,
                    truncated: false,
                }))
            });
            return Ok(Box::pin(stream));
        }

        // Streaming upstream — drain the body and emit one Progress
        // per chunk, then a Done with the assembled envelope.
        //
        // The host triad is emitted from inside
        // the unfold closure when the terminal Done / Err arm fires.
        // `host_handle.clone()` + `t0` + `request_id` + `identity`
        // capture the per-call context the closure needs after `self`
        // is no longer reachable. The host_span SpanGuard moves into
        // the state so its Drop fires when the unfold state itself
        // is dropped (typically when the caller drops the BackendChunkStream).
        let exec::HttpStreamHandle {
            response,
            status_code,
            content_type,
            retry_after_ms,
            started_at,
            ..
        } = handle;
        let limit = prep.runtime.profile().max_response_bytes;
        let body_stream = exec::read_body_streaming(response, limit);
        let host_handle_for_state = self.host_handle().cloned();

        let initial_state = StreamingState::new(
            prep,
            backend_name_owned,
            body_stream,
            status_code,
            content_type,
            retry_after_ms,
            started_at,
            host_handle_for_state,
            host_span,
            t0,
            request_id,
            identity,
        );
        let stream = futures::stream::unfold(initial_state, move |mut state| async move {
            if state.terminated {
                return None;
            }
            if let Some(item) = state.body_stream.as_mut().unwrap().next().await {
                match item {
                    Ok(exec::BodyReadStep::Progress { cumulative_bytes }) => {
                        state.progress_index = state.progress_index.saturating_add(1);
                        let chunk = BackendChunk::Progress {
                            progress: state.progress_index,
                            total: None,
                            message: format!("received {cumulative_bytes} bytes"),
                        };
                        Some((Ok(chunk), state))
                    }
                    Ok(exec::BodyReadStep::Done { body, truncated }) => {
                        let summary = exec::finalize_http_summary(
                            state.status_code,
                            state.content_type.clone(),
                            state.retry_after_ms,
                            state.started_at,
                            body,
                            truncated,
                        );
                        let envelope = build_envelope_from_outcome(
                            &state.prep,
                            &state.backend_name,
                            Ok(&summary),
                        );
                        let payload = match serde_json::to_vec(&envelope) {
                            Ok(p) => p,
                            Err(e) => {
                                state.terminated = true;
                                return Some((
                                    Err(BackendError::Transport {
                                        message: format!(
                                            "HTTP plugin envelope serialization failed: {e}"
                                        ),
                                    }),
                                    state,
                                ));
                            }
                        };
                        state.terminated = true;
                        state
                            .emit_observability_from_stream(
                                host_outcome_label_for_status(summary.status_code),
                                Some(summary.status_code),
                                None,
                            )
                            .await;
                        Some((
                            Ok(BackendChunk::Done(BackendResponse {
                                payload,
                                truncated: false,
                            })),
                            state,
                        ))
                    }
                    Err(error) => {
                        let envelope = build_envelope_from_outcome(
                            &state.prep,
                            &state.backend_name,
                            Err(&error),
                        );
                        let payload = match serde_json::to_vec(&envelope) {
                            Ok(p) => p,
                            Err(e) => {
                                state.terminated = true;
                                return Some((
                                    Err(BackendError::Transport {
                                        message: format!(
                                            "HTTP plugin envelope serialization failed: {e}"
                                        ),
                                    }),
                                    state,
                                ));
                            }
                        };
                        state.terminated = true;
                        let label = host_outcome_label_for_transport_error(&error);
                        state
                            .emit_observability_from_stream(label, None, Some(error.clone()))
                            .await;
                        Some((
                            Ok(BackendChunk::Done(BackendResponse {
                                payload,
                                truncated: false,
                            })),
                            state,
                        ))
                    }
                }
            } else {
                None
            }
        });

        Ok(Box::pin(stream))
    }

    /// Dynamic resource-template completion. The operator declares a
    /// completion endpoint per-(binding, variable) under
    /// `variable_completions`; the plugin parses the config blob
    /// inline (stateless, mirrors SQL), fans out a GET/POST against
    /// the operator's `path` (joined onto the binding's base URL),
    /// and JSONPath-extracts the candidate list. CEL templating is
    /// shared with tool-call URL/header resolution; the per-cred
    /// `ClientRegistry` is shared so completion endpoints inherit
    /// the same credential identity as tool calls. Per-call timeout
    /// is owned by the gateway dispatcher's 3s wrapper — typical
    /// tool-call timeouts are too lax for keystroke-driven completion.
    async fn complete_template_variable(
        &self,
        backend_name: &str,
        variable_name: &str,
        prefix: &str,
        config: &serde_json::Value,
        context: &BTreeMap<String, String>,
    ) -> Result<Vec<String>, BackendError> {
        let cfg: completion::HttpCompletionConfig = serde_json::from_value(config.clone())
            .map_err(|e| BackendError::InvalidSpec {
                message: format!("variable_completions.config: {e}"),
            })?;
        let runtime = {
            let guard = self.profiles.read().await;
            guard
                .get(backend_name)
                .cloned()
                .ok_or_else(|| BackendError::ProfileNotFound {
                    backend_name: backend_name.to_owned(),
                })?
        };
        completion::run_http_completion(&runtime, cfg, backend_name, variable_name, prefix, context)
            .await
    }

    fn audit_metadata(&self, _backend_name: &str) -> serde_json::Map<String, serde_json::Value> {
        let mut map = serde_json::Map::new();
        map.insert("http.transport".to_owned(), serde_json::json!("plugin"));
        map
    }
}

/// Output of [`HttpBackendPlugin::prepare_call`] — everything the
/// `execute` / `execute_streaming` paths need after request parsing +
/// CEL/cred resolution. `resolution` carries the `Result` so the caller
/// can branch on success vs transport-error envelope shaping;
/// `ResolvedCall` is the shared net-core resolution output.
struct PreparedCall {
    runtime: NetworkProfileRuntime,
    arguments: serde_json::Value,
    tool_name: String,
    call_mode: HttpCallMode,
    request_body: Option<serde_json::Value>,
    request_query: Option<String>,
    trace_headers: Vec<(String, String)>,
    /// Gateway-supplied idempotency key cloned out of
    /// `BackendRequest.idempotency` at prepare-call time so the
    /// buffered + streaming exec paths share a single source.
    /// `None` when the caller didn't ride a `dev.mcpg/idempotency-key`.
    idempotency_key: Option<String>,
    /// Flag set when the operator's compiled header map already binds
    /// `Idempotency-Key` (case-insensitive match). When true,
    /// gateway-injected propagation is suppressed — the operator's
    /// static config wins on conflict, mirroring the
    /// explicit-`_meta`-vs-HTTP-header precedence the gateway
    /// applies at the inbound edge.
    operator_has_idempotency_key: bool,
    resolution: Result<ResolvedCall, String>,
}

/// Build the response envelope from a finished HTTP call (or its
/// transport / resolution error). Identical shape across the buffered
/// `execute` and streaming `execute_streaming` paths so clients see
/// the same envelope regardless of whether they opted into progress.
fn build_envelope_from_outcome(
    prep: &PreparedCall,
    backend_name: &str,
    response: Result<&HttpResponseSummary, &String>,
) -> serde_json::Value {
    let profile = prep.runtime.profile();
    let display_headers = match prep.resolution.as_ref() {
        Ok(r) => Some(r.resolved_headers.clone()),
        Err(_) => None,
    };
    let display_headers_ref = display_headers.as_ref();
    let display_url_string = prep
        .resolution
        .as_ref()
        .map(|r| r.resolved_url.clone())
        .ok();

    match response {
        Ok(summary) => {
            let mut downstream_errors = envelope::validate_expected_status_codes(
                &profile.expected_status_codes,
                summary.status_code,
                summary.retry_after_ms,
                prep.call_mode.retry_safety_context(),
            )
            .into_iter()
            .collect::<Vec<_>>();
            let (response_json, response_json_parse_error, json_validation_error) =
                envelope::parse_and_validate_json_response(summary, profile.require_json_response);
            if let Some(err) = json_validation_error {
                downstream_errors.push(err);
            }
            let primary = downstream_errors.first().cloned();

            envelope::build_envelope(
                &prep.tool_name,
                backend_name,
                profile,
                prep.call_mode,
                &prep.arguments,
                prep.request_body.as_ref(),
                prep.request_query.as_deref(),
                Some(summary),
                response_json.as_ref(),
                response_json_parse_error.as_deref(),
                primary.as_ref(),
                &downstream_errors,
                None,
                display_url_string.as_deref(),
                display_headers_ref,
            )
        }
        Err(error) => {
            // Resolution-failure path: `prep.resolution` is `Err(_)`
            // and `error` is the empty-string sentinel. Use the
            // resolution error message instead.
            let effective_error: String = if error.is_empty() {
                prep.resolution
                    .as_ref()
                    .err()
                    .cloned()
                    .unwrap_or_else(|| "unknown HTTP plugin error".to_owned())
            } else {
                error.clone()
            };
            let downstream = envelope::transport_downstream_error(
                &effective_error,
                prep.call_mode.retry_safety_context(),
            );
            envelope::build_envelope(
                &prep.tool_name,
                backend_name,
                profile,
                prep.call_mode,
                &prep.arguments,
                prep.request_body.as_ref(),
                prep.request_query.as_deref(),
                None,
                None,
                None,
                Some(&downstream),
                std::slice::from_ref(&downstream),
                Some(&effective_error),
                display_url_string.as_deref(),
                display_headers_ref,
            )
        }
    }
}

/// Pinned heap-allocated body-stream type used by [`StreamingState`].
/// Kept local so the trait-object box doesn't bleed into public API.
type BoxedBodyStream =
    std::pin::Pin<Box<dyn futures::Stream<Item = Result<exec::BodyReadStep, String>> + Send>>;

/// Per-stream state carried through `futures::stream::unfold` for
/// the streaming `execute_streaming` path. Holds enough context to
/// build the terminal envelope at body-end without re-running CEL /
/// cred resolution.
///
/// The host triad context (handle clone, span
/// guard, t0, request id, identity) lives here so the unfold's
/// terminal Done / Err arms can emit metric + audit + close the
/// span after `&self` is no longer reachable.
struct StreamingState {
    prep: PreparedCall,
    backend_name: String,
    body_stream: Option<BoxedBodyStream>,
    status_code: u16,
    content_type: Option<String>,
    retry_after_ms: Option<u64>,
    started_at: std::time::Instant,
    progress_index: u32,
    terminated: bool,
    /// Cloned host handle the unfold closure
    /// uses to emit the metric pair + audit event when the unfold
    /// reaches a terminal Done / Err. `None` when no `HostHandle`
    /// was installed.
    host_handle: Option<HostHandle>,
    /// Held for the duration of the stream so
    /// `span_end` fires when the unfold state itself is dropped
    /// (typically when the caller drops the BackendChunkStream).
    /// `Option` so the unfold's terminal arm can `.take()` and
    /// drop AFTER the metric + audit emission — same ordering as
    /// the buffered `execute` path.
    host_span: Option<mcpg_plugin_sdk::SpanGuard>,
    /// Call-start instant captured at
    /// `execute_streaming`'s top, used to derive the latency
    /// histogram value at terminal-arm emission time.
    call_started_at: Instant,
    /// Inbound request id propagated to audit
    /// `request_id` + audit event_id suffix.
    request_id: String,
    /// Caller identity for audit `actor`.
    /// `None` falls back to `synthetic_system_identity` at emission
    /// time.
    identity: Option<PluginIdentity>,
}

impl StreamingState {
    #[allow(clippy::too_many_arguments)] // Bounded per-call host-triad context.
    fn new(
        prep: PreparedCall,
        backend_name: String,
        body_stream: impl futures::Stream<Item = Result<exec::BodyReadStep, String>> + Send + 'static,
        status_code: u16,
        content_type: Option<String>,
        retry_after_ms: Option<u64>,
        started_at: std::time::Instant,
        host_handle: Option<HostHandle>,
        host_span: Option<mcpg_plugin_sdk::SpanGuard>,
        call_started_at: Instant,
        request_id: String,
        identity: Option<PluginIdentity>,
    ) -> Self {
        Self {
            prep,
            backend_name,
            body_stream: Some(Box::pin(body_stream)),
            status_code,
            content_type,
            retry_after_ms,
            started_at,
            progress_index: 0,
            terminated: false,
            host_handle,
            host_span,
            call_started_at,
            request_id,
            identity,
        }
    }

    /// Emit the per-call observability triad
    /// from inside the streaming unfold closure. Mirrors
    /// [`HttpBackendPlugin::emit_host_observability`] but reads the
    /// host handle + call context off `self` so it can run after
    /// the plugin reference is gone. Drops the span AFTER emission
    /// so the host sink sees span_end last.
    async fn emit_observability_from_stream(
        &mut self,
        outcome_label: &'static str,
        status_code: Option<u16>,
        reason: Option<String>,
    ) {
        let Some(host) = self.host_handle.as_ref() else {
            // Still drop the span guard so its lifetime ends here.
            self.host_span.take();
            return;
        };
        let duration = self.call_started_at.elapsed();
        host.histogram(
            "mcpg_http_backend_latency_seconds",
            duration.as_secs_f64(),
            &[("outcome", outcome_label)],
        );
        host.counter(
            "mcpg_http_backend_calls_total",
            1,
            &[("outcome", outcome_label)],
        );

        if let Some(action) = audit_action_for_outcome(outcome_label) {
            let actor = self
                .identity
                .clone()
                .unwrap_or_else(synthetic_system_identity);
            let mut details = serde_json::json!({
                "backend": self.backend_name,
                "duration_ms": duration.as_millis() as u64,
                "outcome": outcome_label,
                "alias": host.alias(),
            });
            if let Some(status) = status_code {
                details
                    .as_object_mut()
                    .expect("json object")
                    .insert("status_code".into(), serde_json::Value::from(status));
            }
            if let Some(reason) = reason.as_ref() {
                details
                    .as_object_mut()
                    .expect("json object")
                    .insert("reason".into(), serde_json::Value::String(reason.clone()));
            }
            let event = AuditEvent {
                event_id: format!("http-{}-{}", self.request_id, duration.as_nanos()),
                occurred_at: rfc3339_now(),
                actor,
                action: action.to_owned(),
                resource: Some(format!("http-binding://{}", self.backend_name)),
                outcome: AuditOutcome::Failure,
                request_id: Some(self.request_id.clone()),
                node_id: None,
                details,
                prev_event_hash: None,
            };
            let host_for_audit = host.clone();
            if let Err(join_err) = tokio::task::spawn_blocking(move || {
                let _ = host_for_audit.audit_event(event);
            })
            .await
            {
                debug!(
                    target: "mcpg::http::host_handle",
                    error = %join_err,
                    "host_handle.audit_event spawn_blocking failed"
                );
            }
        }

        // Drop the span AFTER metric + audit emission so the host
        // sink sees the span_end last.
        self.host_span.take();
    }
}

// CEL context building + per-call client resolution + the cred-ref
// scan now live in the shared net-core `runtime` module
// (`build_expr_context`, `NetworkProfileRuntime::resolve_client`,
// `NetworkProfileRuntime::register`).

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn no_op_host() -> Arc<dyn BackendHost> {
        Arc::new(NoOpHost) as Arc<dyn BackendHost>
    }

    #[test]
    fn binding_plugin_kind_is_http() {
        let plugin = HttpBackendPlugin::new();
        assert_eq!(plugin.kind(), "http");
    }

    #[test]
    fn manifest_advertises_first_party_id() {
        let plugin = HttpBackendPlugin::new();
        assert_eq!(plugin.manifest().id, "dev.mcpg.backend.http");
    }

    #[tokio::test]
    async fn register_profile_accepts_minimal_post_spec() {
        let plugin = HttpBackendPlugin::new();
        let spec = serde_json::json!({
            "url": "https://api.example.com/v1/foo",
            "method": "post",
        });
        plugin
            .register_profile("test", &spec, no_op_host())
            .await
            .expect("register");
        let profiles = plugin.profiles.read().await;
        assert!(profiles.contains_key("test"));
        let runtime = profiles.get("test").unwrap();
        assert_eq!(runtime.profile().url, "https://api.example.com/v1/foo");
        assert_eq!(runtime.profile().method, HttpBackendMethod::Post);
        assert!(!runtime.has_cred_refs());
    }

    #[tokio::test]
    async fn register_profile_detects_cred_refs_in_url() {
        let plugin = HttpBackendPlugin::new();
        let spec = serde_json::json!({
            "url": "https://api.example.com/v1/cred://oauth/api",
            "method": "post",
        });
        plugin
            .register_profile("test", &spec, no_op_host())
            .await
            .expect("register");
        let runtime = {
            let g = plugin.profiles.read().await;
            g.get("test").cloned().unwrap()
        };
        assert!(runtime.has_cred_refs());
    }

    #[tokio::test]
    async fn register_profile_detects_cred_refs_in_headers() {
        let plugin = HttpBackendPlugin::new();
        let spec = serde_json::json!({
            "url": "https://api.example.com/v1/foo",
            "method": "post",
            "headers": {
                "Authorization": "Bearer cred://oauth/api"
            }
        });
        plugin
            .register_profile("test", &spec, no_op_host())
            .await
            .expect("register");
        let runtime = {
            let g = plugin.profiles.read().await;
            g.get("test").cloned().unwrap()
        };
        assert!(runtime.has_cred_refs());
    }

    #[tokio::test]
    async fn register_profile_rejects_empty_url() {
        let plugin = HttpBackendPlugin::new();
        let spec = serde_json::json!({ "url": "" });
        let err = plugin
            .register_profile("test", &spec, no_op_host())
            .await
            .expect_err("empty url");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_profile_rejects_non_http_scheme() {
        let plugin = HttpBackendPlugin::new();
        let spec = serde_json::json!({ "url": "ftp://example.com/" });
        let err = plugin
            .register_profile("test", &spec, no_op_host())
            .await
            .expect_err("non-http scheme");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_profile_rejects_invalid_status_code() {
        let plugin = HttpBackendPlugin::new();
        let spec = serde_json::json!({
            "url": "https://example.com/",
            "expected_status_codes": [200, 999],
        });
        let err = plugin
            .register_profile("test", &spec, no_op_host())
            .await
            .expect_err("999 invalid");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_profile_rejects_empty_expected_status_codes() {
        let plugin = HttpBackendPlugin::new();
        let spec = serde_json::json!({
            "url": "https://example.com/",
            "expected_status_codes": [],
        });
        let err = plugin
            .register_profile("test", &spec, no_op_host())
            .await
            .expect_err("empty expected_status_codes");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_profile_rejects_crlf_in_header_value() {
        let plugin = HttpBackendPlugin::new();
        let spec = serde_json::json!({
            "url": "https://example.com/",
            "headers": { "X-Inject": "value\r\nX-Smuggled: 1" },
        });
        let err = plugin
            .register_profile("test", &spec, no_op_host())
            .await
            .expect_err("CRLF in header value");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    /// Conformance: a spec OMITTING every defaulted field resolves to the
    /// canonical binding defaults the gateway's typed path materialized
    /// (method=POST, timeout_ms=2000, max_response_bytes=4096,
    /// expected_status_codes=[200], require_json_response=false). This is
    /// the R2 secure-default gate — the plugin is now the single source of
    /// truth for these defaults, so they must equal the gateway's.
    #[tokio::test]
    async fn register_profile_materializes_canonical_defaults() {
        let plugin = HttpBackendPlugin::new();
        // Only the required `url` — everything else defaulted.
        let spec = serde_json::json!({ "url": "https://api.example.com/v1/foo" });
        plugin
            .register_profile("test", &spec, no_op_host())
            .await
            .expect("register");
        let profiles = plugin.profiles.read().await;
        let profile = profiles.get("test").expect("profile").profile();
        assert_eq!(profile.method, HttpBackendMethod::Post);
        assert_eq!(profile.timeout, Duration::from_millis(2000));
        assert_eq!(profile.max_response_bytes, 4096);
        assert_eq!(profile.expected_status_codes, vec![200]);
        assert!(!profile.require_json_response);
    }

    /// Conformance: the spec `Deserialize` defaults match the canonical
    /// gateway defaults field-for-field (a direct check on the
    /// `#[serde(default)]` values, independent of the runtime profile).
    #[test]
    fn spec_deserialize_defaults_match_gateway_typed_path() {
        let parsed: HttpBackendSpec =
            serde_json::from_value(serde_json::json!({ "url": "https://x/" })).expect("parse");
        assert_eq!(parsed.method, HttpBackendMethod::Post);
        assert_eq!(parsed.timeout_ms, 2000);
        assert_eq!(parsed.max_response_bytes, 4096);
        assert_eq!(parsed.expected_status_codes, vec![200]);
        assert!(!parsed.require_json_response);
        assert!(parsed.headers.is_empty());
        assert!(!parsed.allow_private_backends);
    }

    #[tokio::test]
    async fn execute_unknown_profile_returns_profile_not_found() {
        let plugin = HttpBackendPlugin::new();
        let req = BackendRequest {
            payload: vec![],
            headers: vec![],
            request_id: "rq-1".into(),
            session_id: None,
            identity: None,
            idempotency: None,
        };
        let err = plugin.execute("missing", req).await.expect_err("missing");
        assert!(matches!(err, BackendError::ProfileNotFound { .. }));
    }

    #[tokio::test]
    async fn execute_rejects_non_json_payload() {
        let plugin = HttpBackendPlugin::new();
        let spec = serde_json::json!({ "url": "https://example.com/" });
        plugin
            .register_profile("test", &spec, no_op_host())
            .await
            .expect("register");
        let req = BackendRequest {
            payload: b"not json".to_vec(),
            headers: vec![],
            request_id: "rq-1".into(),
            session_id: None,
            identity: None,
            idempotency: None,
        };
        let err = plugin.execute("test", req).await.expect_err("invalid json");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    /// Minimal `BackendHost` for tests. Returns NotImplemented for
    /// every host call.
    struct NoOpHost;

    #[async_trait]
    impl BackendHost for NoOpHost {
        async fn invoke_tool(
            &self,
            _ctx: &mcpg_plugin_protocol::BackendInvocationContext,
            _tool_name: &str,
            _args: &serde_json::Value,
        ) -> Result<serde_json::Value, mcpg_plugin_protocol::BackendHostError> {
            Err(mcpg_plugin_protocol::BackendHostError::NotImplemented)
        }
    }
}
