//! cdylib sync bridge — adapts the async [`HttpBackendPlugin`]
//! ([`mcpg_plugin_protocol::BackendPlugin`]) onto the sync FFI trait the
//! cdylib vtable expects ([`SyncBackendPlugin`]). HTTP is the final
//! backend to move off the static path (backend-plugin-migration aim:
//! zero static backends — the gateway becomes a thin, fully-customizable
//! host).
//!
//! Structure mirrors the proven kafka / nats / sql / LLM bridges:
//! - a private multi-thread runtime + `block_on` for the async methods;
//! - the make-time [`HostHandle`] is wrapped as an `Arc<dyn BackendHost>`
//!   (via [`HostHandleBackendHost`]) and passed to `register_profile`,
//!   and also installed on the inner plugin via `set_host_handle` for
//!   per-call observability (span / latency histogram / counters);
//! - `execute_streaming` drains the inner async chunk stream on the
//!   runtime, pushing each chunk across the FFI, with a per-token
//!   `Notify` so `cancel_stream` stops the drain promptly (same as the
//!   LLM bridges — HTTP genuinely streams, so it is NOT the buffered
//!   default);
//! - `complete_template_variable` + `audit_metadata` are forwarded too
//!   (HTTP overrides both — the latter via the v36 audit_metadata slot).
//!
//! The HTTP plugin owns its DNS-rebinding/SSRF guard, `cred://`
//! resolution, body-limit truncation, and envelope shaping — none of
//! that changes; only the registration + dispatch path becomes dynamic.

use std::sync::Arc;

use mcpg_plugin_protocol::{
    BackendError, BackendPlugin, BackendRequest, BackendResponse, PluginManifest,
};
use mcpg_plugin_sdk::ffi::{BackendChunkEmitter, SyncBackendPlugin};
use mcpg_plugin_sdk::{HostHandle, HostHandleBackendHost};

use crate::HttpBackendPlugin;

/// Build the private multi-thread runtime the bridge uses to `block_on`
/// the async inner plugin. Two workers + `enable_all`, matching the
/// nats/sql/LLM bridges.
fn build_bridge_runtime(thread_name: &str) -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name(thread_name.to_owned())
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("http cdylib: tokio runtime init failed: {e}"))
}

/// Per-stream cancel state: a sticky `CancellationToken` (the drain task's
/// `select!` arm) + a completion channel `cancel_stream` blocks on, so it
/// returns only once the drain task has stopped emitting — the host frees
/// the stream bridge the moment `cancel_stream` returns.
type LiveStreams = std::sync::Mutex<
    std::collections::HashMap<
        usize,
        (
            tokio_util::sync::CancellationToken,
            std::sync::mpsc::Receiver<()>,
        ),
    >,
>;

/// `SyncBackendPlugin` bridge over [`HttpBackendPlugin`].
pub struct HttpBackendCdylib {
    inner: HttpBackendPlugin,
    host: Arc<dyn mcpg_plugin_protocol::BackendHost>,
    rt: tokio::runtime::Runtime,
    /// Live `execute_streaming` drains keyed by the cancel token returned
    /// to the host. See [`LiveStreams`].
    streams: Arc<LiveStreams>,
    next_stream_id: Arc<std::sync::atomic::AtomicUsize>,
}

impl HttpBackendCdylib {
    /// Infallible cdylib factory. `config_json` is ignored — HTTP carries
    /// no plugin-level config (per-binding url/method/headers/etc. arrive
    /// via `register_profile`). Installs the host handle on the inner
    /// plugin for observability and wraps it as the `BackendHost`
    /// `register_profile` consumes.
    pub fn from_host_config(_config_json: &str, host: HostHandle) -> Self {
        let inner = HttpBackendPlugin::new();
        let _installed = inner.set_host_handle(host.clone());
        Self {
            inner,
            host: Arc::new(HostHandleBackendHost::new(host)),
            rt: build_bridge_runtime("mcpg-backend-http"),
            streams: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            next_stream_id: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }
}

impl SyncBackendPlugin for HttpBackendCdylib {
    fn manifest(&self) -> &PluginManifest {
        BackendPlugin::manifest(&self.inner)
    }

    fn kind(&self) -> &str {
        BackendPlugin::kind(&self.inner)
    }

    fn register_profile(
        &self,
        profile_name: &str,
        spec: &serde_json::Value,
    ) -> Result<(), BackendError> {
        self.rt.block_on(BackendPlugin::register_profile(
            &self.inner,
            profile_name,
            spec,
            Arc::clone(&self.host),
        ))
    }

    fn execute(
        &self,
        profile_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError> {
        self.rt
            .block_on(BackendPlugin::execute(&self.inner, profile_name, request))
    }

    fn execute_streaming(
        &self,
        profile_name: &str,
        request: BackendRequest,
        emit: BackendChunkEmitter,
    ) -> Result<usize, BackendError> {
        use futures::StreamExt;
        // Open the inner async stream (borrows `inner` only for this
        // await), then drain it on the private runtime, pushing each chunk
        // across the FFI via `emit`. A per-token sticky `CancellationToken`
        // lets `cancel_stream` stop the drain promptly even mid `next()`,
        // and a completion channel lets it wait for the drain to finish.
        let stream = self.rt.block_on(BackendPlugin::execute_streaming(
            &self.inner,
            profile_name,
            request,
        ))?;
        let cancel = tokio_util::sync::CancellationToken::new();
        let (done_tx, done_rx) = std::sync::mpsc::sync_channel::<()>(1);
        // Non-zero token (0 is reserved for "nothing to cancel").
        let token = self
            .next_stream_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .wrapping_add(1);
        self.streams
            .lock()
            .expect("stream registry poisoned")
            .insert(token, (cancel.clone(), done_rx));
        let streams = Arc::clone(&self.streams);
        self.rt.spawn(async move {
            let mut stream = stream;
            loop {
                tokio::select! {
                    // Sticky: stays ready once cancelled, so a task re-parked
                    // after a chunk still observes it (no lost wakeup, unlike
                    // `Notify::notify_waiters`).
                    _ = cancel.cancelled() => break,
                    item = stream.next() => match item {
                        Some(chunk) => emit(chunk),
                        None => break,
                    },
                }
            }
            streams
                .lock()
                .expect("stream registry poisoned")
                .remove(&token);
            // Unblock a waiting `cancel_stream`: no further `emit` calls
            // will occur, so the host may free the bridge.
            let _ = done_tx.send(());
        });
        Ok(token)
    }

    fn cancel_stream(&self, token: usize) {
        // Take the entry out under the lock, then release it before blocking
        // so concurrent stream ops aren't held up.
        let entry = self
            .streams
            .lock()
            .expect("stream registry poisoned")
            .remove(&token);
        if let Some((cancel, done_rx)) = entry {
            cancel.cancel();
            // Block until the drain task has left its loop — the host frees
            // the stream bridge the instant we return, so no `emit` may run
            // afterwards. A plain channel recv (NOT a nested `block_on`,
            // which would panic if this runs inside a runtime); the drain
            // task makes progress on the wrapper's own runtime. `Err` => the
            // task already finished (its `done_tx` was dropped).
            let _ = done_rx.recv();
        }
    }

    fn complete_template_variable(
        &self,
        profile_name: &str,
        variable_name: &str,
        prefix: &str,
        config: &serde_json::Value,
        context: &std::collections::BTreeMap<String, String>,
    ) -> Result<Vec<String>, BackendError> {
        self.rt.block_on(BackendPlugin::complete_template_variable(
            &self.inner,
            profile_name,
            variable_name,
            prefix,
            config,
            context,
        ))
    }

    fn audit_metadata(&self, profile_name: &str) -> serde_json::Map<String, serde_json::Value> {
        BackendPlugin::audit_metadata(&self.inner, profile_name)
    }
}

// cdylib export — one `backend` entity under `dev.mcpg.backend.http`.
mcpg_plugin_sdk::declare_plugin! {
    plugin_id: "dev.mcpg.backend.http",
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[::mcpg_plugin_protocol::capability::Capability::NetworkOutbound],
    // Residual per-kind facts the gateway reads back by kind. http is an
    // HTTP/1.1 transport, so the generic prober reaches the binding's
    // `url` (empty path ⇒ the bare base URL, matching the old typed HEAD
    // probe), and it may appear as a backend pipeline step. label = kind
    // ("http"), no dynamic tool list, and NO transport-only fields — the
    // `url` and `headers` legitimately carry per-caller `cred://` refs.
    backend_profile: ::mcpg_plugin_protocol::manifest::BackendProfile {
        health_probe: ::mcpg_plugin_protocol::manifest::HealthProbeDecl::Http {
            path: ::std::string::String::new(),
        },
        pipeline_capable: true,
        ..::core::default::Default::default()
    },
    entities: [
        backend as binding {
            inner_name: "",
            plugin_type: HttpBackendCdylib,
            factory: |cfg, host: ::mcpg_plugin_sdk::HostHandle|
                HttpBackendCdylib::from_host_config(cfg, host),
        },
    ],
}
