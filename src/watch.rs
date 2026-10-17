//! `watch_strategy` entity (`http_poll`): an HTTP endpoint polled for
//! changes, each one an MCP Event.
//!
//! Two modes. `snapshot` (the default) reads the whole collection each poll
//! — an RSS, Atom or JSON Feed (`format: feed`), or a JSON array of items
//! (`format: json`) — and reports each item created, modified or removed as
//! the shared `object.changed` event, through the SDK's inventory helper;
//! `ETag` and `Last-Modified` make an unchanged endpoint answer 304 without
//! a body. `cursor` follows an API's change cursor: each item it returns is
//! one `http.item` event, and the cursor advances only once the gateway has
//! acknowledged the page, so a restart resumes where it stopped and nothing
//! is lost.
//!
//! Every request goes through the HTTP backend's guarded client: the host
//! resolves to a public address unless `allow_private_backends`, the address
//! is pinned for the request, and redirects are not followed.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use mcpg_plugin_backend_net_core::client::build_http_client;
use mcpg_plugin_backend_net_core::types::{HttpBackendMethod, HttpRequestProfile};
use mcpg_plugin_protocol::backend::{WatchError, WatchEvent};
use mcpg_plugin_protocol::{PluginManifest, firstparty_manifest};
use mcpg_plugin_sdk::HostHandle;
use mcpg_plugin_sdk::ffi::{SyncWatchStrategyPlugin, WatchHandleBox};
use mcpg_plugin_sdk::inventory::{
    self, Describe, InventoryHooks, InventoryOptions, InventoryStart, ObjectEntry,
    acknowledge_inventory_watch, cancel_inventory_watch, spawn_inventory_watch_hooked,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};

pub const PLUGIN_ID: &str = "dev.mcpg.backend.http";

/// The strategy discriminator this entity handles.
pub const WATCH_KIND: &str = "http_poll";

/// The event type of each item in `cursor` mode.
pub const ITEM_EVENT_TYPE: &str = "http.item";

const CURSOR_VERSION: u64 = 1;

/// Largest body the watch reads.
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Largest item an event carries whole.
const MAX_ITEM_BYTES: usize = 64 * 1024;

/// Largest feed summary or content an event carries.
const MAX_TEXT_BYTES: usize = 8 * 1024;

/// Shortest interval between two polls: an HTTP endpoint is someone's.
const MIN_INTERVAL_MS: u64 = 1_000;

fn default_interval_ms() -> u64 {
    60_000
}

fn default_timeout_ms() -> u64 {
    10_000
}

fn default_max_response_bytes() -> usize {
    1024 * 1024
}

/// What the endpoint returns.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Format {
    /// A JSON array of items.
    #[default]
    Json,
    /// An RSS, Atom or JSON Feed.
    Feed,
}

/// How the watch reads the endpoint.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Mode {
    /// The whole collection each poll.
    #[default]
    Snapshot,
    /// Items after a cursor, a page at a time.
    Cursor,
}

/// What a snapshot does with an item that leaves the collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Removals {
    /// Report it deleted: the collection is the whole state.
    Report,
    /// Forget it: a feed shows only its latest items.
    Ignore,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchSpec {
    /// The endpoint; resolved before the watch starts, so it may carry
    /// `${env.X}` / `${secret.X}`. It is never logged.
    url: String,
    /// Request headers, resolved the same way (`Authorization`, …).
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    format: Format,
    #[serde(default)]
    mode: Mode,
    /// JSON pointer to the array of items; `""` = the body is the array.
    #[serde(default)]
    items_pointer: String,
    /// JSON pointer, in an item, to its id.
    #[serde(default)]
    id_pointer: Option<String>,
    /// JSON pointer, in an item, to when it last changed (RFC 3339 or Unix
    /// seconds).
    #[serde(default)]
    updated_pointer: Option<String>,
    /// Snapshot: `report` (JSON default) or `ignore` (feed default).
    #[serde(default)]
    removals: Option<Removals>,
    /// Cursor: the query parameter the cursor goes in.
    #[serde(default)]
    cursor_param: Option<String>,
    /// Cursor: JSON pointer to the next cursor; without it, the last item's
    /// id is the next cursor.
    #[serde(default)]
    next_cursor_pointer: Option<String>,
    /// Cursor: JSON pointer to a boolean that says another page follows.
    #[serde(default)]
    has_more_pointer: Option<String>,
    /// Cursor: where a first start reads from; without it, the first page.
    #[serde(default)]
    initial_cursor: Option<String>,
    #[serde(default = "default_interval_ms")]
    interval_ms: u64,
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
    #[serde(default = "default_max_response_bytes")]
    max_response_bytes: usize,
    #[serde(default)]
    allow_private_backends: bool,
    #[serde(default = "inventory::defaults::max_files")]
    max_items: usize,
    #[serde(default)]
    start_at: InventoryStart,
    #[serde(default = "inventory::defaults::snapshot_bytes")]
    snapshot_bytes: usize,
    #[serde(default = "inventory::defaults::max_in_flight")]
    max_in_flight: usize,
    #[serde(default = "inventory::defaults::ack_timeout_ms")]
    ack_timeout_ms: u64,
}

/// The endpoint without credentials or query: what an event names.
fn location_of(url: &url::Url) -> String {
    let mut location = format!("{}://{}", url.scheme(), url.host_str().unwrap_or(""));
    if let Some(port) = url.port() {
        location.push_str(&format!(":{port}"));
    }
    location.push_str(url.path());
    location
}

/// A short digest of what an item says, so any change of it is a
/// modification.
fn digest(text: &str) -> String {
    blake3::hash(text.as_bytes()).to_hex()[..16].to_owned()
}

/// A string id from an item's id value.
fn id_text(value: &Value) -> Option<String> {
    match value {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Unix milliseconds from an RFC 3339 string or Unix seconds.
fn time_of(value: &Value) -> Option<i64> {
    match value {
        Value::String(s) => chrono::DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|t| t.timestamp_millis()),
        Value::Number(n) => n.as_f64().map(|secs| (secs * 1_000.0) as i64),
        _ => None,
    }
}

fn capped(text: &str) -> String {
    if text.len() <= MAX_TEXT_BYTES {
        return text.to_owned();
    }
    let mut end = MAX_TEXT_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// The item a JSON event carries, or a marker when it is too large.
fn carried(item: &Value) -> Map<String, Value> {
    let mut extra = Map::new();
    let size = serde_json::to_vec(item).map_or(usize::MAX, |b| b.len());
    if size <= MAX_ITEM_BYTES {
        extra.insert("item".into(), item.clone());
    } else {
        extra.insert("itemTruncated".into(), json!(true));
        extra.insert("itemSize".into(), json!(size));
    }
    extra
}

/// One collection as the inventory reads it, and what each item's event
/// carries.
type Collection = (Vec<ObjectEntry>, HashMap<String, Map<String, Value>>);

/// The items of a JSON body.
fn json_items(
    body: &[u8],
    items_pointer: &str,
    id_pointer: &str,
    updated_pointer: Option<&str>,
) -> Result<Vec<(String, Value, Option<i64>)>, String> {
    let body: Value =
        serde_json::from_slice(body).map_err(|e| format!("the response is not JSON: {e}"))?;
    let items = body
        .pointer(items_pointer)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("no array at items_pointer '{items_pointer}'"))?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let Some(id) = item.pointer(id_pointer).and_then(id_text) else {
            tracing::warn!(id_pointer, "http_poll: an item has no id; it is skipped");
            continue;
        };
        let updated = updated_pointer
            .and_then(|p| item.pointer(p))
            .and_then(time_of);
        out.push((id, item.clone(), updated));
    }
    Ok(out)
}

fn json_collection(
    body: &[u8],
    items_pointer: &str,
    id_pointer: &str,
    updated_pointer: Option<&str>,
) -> Result<Collection, String> {
    let mut entries = Vec::new();
    let mut extras = HashMap::new();
    for (id, item, updated) in json_items(body, items_pointer, id_pointer, updated_pointer)? {
        entries.push(ObjectEntry {
            key: id.clone(),
            size: None,
            modified_at_ms: updated,
            etag: None,
            version: Some(digest(&item.to_string())),
        });
        extras.insert(id, carried(&item));
    }
    Ok((entries, extras))
}

fn feed_collection(body: &[u8]) -> Result<Collection, String> {
    let feed =
        feed_rs::parser::parse(body).map_err(|e| format!("the response is not a feed: {e}"))?;
    let feed_title = feed.title.as_ref().map(|t| t.content.clone());
    let mut entries = Vec::new();
    let mut extras = HashMap::new();
    for entry in feed.entries {
        let title = entry.title.as_ref().map(|t| t.content.clone());
        let link = entry.links.first().map(|l| l.href.clone());
        let summary = entry.summary.as_ref().map(|t| capped(&t.content));
        let content = entry
            .content
            .as_ref()
            .and_then(|c| c.body.as_deref())
            .map(capped);
        let updated = entry.updated.or(entry.published);
        let said = format!(
            "{}\u{0}{}\u{0}{}\u{0}{}",
            title.as_deref().unwrap_or(""),
            link.as_deref().unwrap_or(""),
            summary.as_deref().unwrap_or(""),
            content.as_deref().unwrap_or("")
        );
        entries.push(ObjectEntry {
            key: entry.id.clone(),
            size: None,
            modified_at_ms: updated.map(|t| t.timestamp_millis()),
            etag: None,
            version: Some(digest(&said)),
        });
        let mut extra = Map::new();
        extra.insert("id".into(), json!(entry.id));
        if let Some(title) = title {
            extra.insert("title".into(), json!(title));
        }
        if let Some(link) = link {
            extra.insert("link".into(), json!(link));
        }
        if let Some(published) = entry.published {
            extra.insert("published".into(), json!(published.to_rfc3339()));
        }
        if let Some(updated) = entry.updated {
            extra.insert("updated".into(), json!(updated.to_rfc3339()));
        }
        if let Some(summary) = summary {
            extra.insert("summary".into(), json!(summary));
        }
        if let Some(content) = content {
            extra.insert("content".into(), json!(content));
        }
        let authors: Vec<&str> = entry.authors.iter().map(|p| p.name.as_str()).collect();
        if !authors.is_empty() {
            extra.insert("authors".into(), json!(authors));
        }
        let categories: Vec<&str> = entry.categories.iter().map(|c| c.term.as_str()).collect();
        if !categories.is_empty() {
            extra.insert("categories".into(), json!(categories));
        }
        if let Some(feed_title) = &feed_title {
            extra.insert("feedTitle".into(), json!(feed_title));
        }
        extras.insert(entry.id, extra);
    }
    Ok((entries, extras))
}

/// One GET's outcome.
enum Fetched {
    Body(Vec<u8>, Option<String>, Option<String>),
    NotModified,
}

/// How the watch reaches the endpoint.
#[derive(Clone)]
struct Endpoint {
    url: url::Url,
    headers: BTreeMap<String, String>,
    timeout: Duration,
    max_response_bytes: usize,
    allow_private: bool,
}

impl Endpoint {
    /// GET `url` (this endpoint's, or one with a cursor), conditionally on
    /// `etag` and `last_modified`.
    async fn get(
        &self,
        url: &url::Url,
        etag: Option<&str>,
        last_modified: Option<&str>,
    ) -> Result<Fetched, String> {
        let profile = HttpRequestProfile {
            url: url.to_string(),
            method: HttpBackendMethod::Get,
            headers: self.headers.clone(),
            expected_status_codes: vec![200],
            require_json_response: false,
            max_response_bytes: self.max_response_bytes,
            timeout: self.timeout,
            allow_private_backends: self.allow_private,
        };
        // A new client per poll: its DNS pin follows the host's address.
        let client = build_http_client(&profile, url.as_str(), &self.headers)
            .await
            .map_err(|e| format!("HTTP client: {e}"))?;
        let mut request = client.get(url.clone());
        if let Some(etag) = etag {
            request = request.header(reqwest::header::IF_NONE_MATCH, etag);
        }
        if let Some(last_modified) = last_modified {
            request = request.header(reqwest::header::IF_MODIFIED_SINCE, last_modified);
        }
        let response = request.send().await.map_err(|e| {
            // reqwest names the URL, which may carry a credential.
            format!("HTTP request failed: {}", e.without_url())
        })?;
        let status = response.status();
        if status == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(Fetched::NotModified);
        }
        if !status.is_success() {
            return Err(format!("HTTP {status}"));
        }
        let header = |name: reqwest::header::HeaderName| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        let (etag, last_modified) = (
            header(reqwest::header::ETAG),
            header(reqwest::header::LAST_MODIFIED),
        );
        let (body, truncated) = mcpg_plugin_backend_net_core::exec::read_response_with_limit(
            response,
            self.max_response_bytes,
        )
        .await?;
        if truncated {
            return Err(format!(
                "the response is larger than max_response_bytes ({})",
                self.max_response_bytes
            ));
        }
        Ok(Fetched::Body(body, etag, last_modified))
    }
}

/// A snapshot watch's memory between polls: the validators of the last
/// answer, its collection, and what each item's event carries.
#[derive(Default)]
struct Snapshot {
    etag: Option<String>,
    last_modified: Option<String>,
    entries: Vec<ObjectEntry>,
    extras: HashMap<String, Map<String, Value>>,
}

/// A cursor watch, as its handle holds it.
struct CursorWatch {
    acks: Sender<Value>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

enum WatchState {
    Snapshot(WatchHandleBox),
    Cursor(CursorWatch),
}

/// A cursor's position, as the gateway stores it.
fn cursor_position(cursor: Option<&str>, seq: u64) -> Value {
    json!({ "v": CURSOR_VERSION, "cursor": cursor, "seq": seq })
}

/// `url` with `param` set to `cursor`.
fn with_cursor(url: &url::Url, param: &str, cursor: Option<&str>) -> url::Url {
    let mut url = url.clone();
    let kept: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(k, _)| k != param)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    {
        let mut query = url.query_pairs_mut();
        query.clear();
        for (k, v) in &kept {
            query.append_pair(k, v);
        }
        if let Some(cursor) = cursor {
            query.append_pair(param, cursor);
        }
    }
    if url.query() == Some("") {
        url.set_query(None);
    }
    url
}

/// What a cursor watch reads its pages with.
struct CursorRead {
    endpoint: Endpoint,
    location: String,
    param: String,
    items_pointer: String,
    id_pointer: String,
    next_cursor_pointer: Option<String>,
    has_more_pointer: Option<String>,
    interval: Duration,
    ack_timeout: Duration,
}

/// The cursor loop: read a page after the cursor, emit its items, and
/// advance only once the gateway has acknowledged the page's last item.
fn cursor_loop(
    rt: tokio::runtime::Runtime,
    read: CursorRead,
    mut cursor: Option<String>,
    event_source: bool,
    emit: Box<dyn Fn(&str) + Send + Sync + 'static>,
    acks: Receiver<Value>,
    stop: Arc<AtomicBool>,
) {
    let mut seq = 0u64;
    let mut backoff = Duration::from_millis(500);
    let wait = |delay: Duration| -> bool {
        let until = Instant::now() + delay;
        while Instant::now() < until {
            if stop.load(Ordering::Acquire) {
                return false;
            }
            std::thread::sleep(Duration::from_millis(50).min(delay));
        }
        !stop.load(Ordering::Acquire)
    };
    while !stop.load(Ordering::Acquire) {
        let url = with_cursor(&read.endpoint.url, &read.param, cursor.as_deref());
        let page = rt
            .block_on(read.endpoint.get(&url, None, None))
            .and_then(|fetched| {
                let Fetched::Body(body, _, _) = fetched else {
                    return Ok(None);
                };
                let parsed: Value = serde_json::from_slice(&body)
                    .map_err(|e| format!("the response is not JSON: {e}"))?;
                let items = json_items(&body, &read.items_pointer, &read.id_pointer, None)?;
                let next = match &read.next_cursor_pointer {
                    Some(p) => parsed.pointer(p).and_then(id_text),
                    None => items.last().map(|(id, _, _)| id.clone()),
                };
                let more = read
                    .has_more_pointer
                    .as_ref()
                    .and_then(|p| parsed.pointer(p))
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                Ok(Some((items, next, more)))
            });
        let (items, next, more) = match page {
            Ok(Some(page)) => {
                backoff = Duration::from_millis(500);
                page
            }
            Ok(None) => (Vec::new(), None, false),
            Err(error) => {
                tracing::warn!(location = %read.location, error = %error, "http_poll: page read failed; retrying");
                if !wait(backoff) {
                    return;
                }
                backoff = (backoff * 2).min(Duration::from_secs(60));
                continue;
            }
        };
        if items.is_empty() {
            if !wait(read.interval) {
                return;
            }
            continue;
        }
        if !event_source {
            emit(r#"{}"#);
            cursor = next.or(cursor);
            if !more && !wait(read.interval) {
                return;
            }
            continue;
        }
        let last = items.len() - 1;
        let mut awaited = None;
        for (index, (id, item, _)) in items.into_iter().enumerate() {
            seq += 1;
            // An item before the page's last resumes at the page's start, so
            // a restart reads the page again; its ids deduplicate.
            let position = if index == last {
                awaited = Some(seq);
                cursor_position(next.as_deref().or(cursor.as_deref()), seq)
            } else {
                cursor_position(cursor.as_deref(), seq)
            };
            let mut data = carried(&item);
            data.insert("url".into(), json!(read.location));
            data.insert("id".into(), json!(id));
            let event = WatchEvent {
                event_id: Some(id),
                event_type: Some(ITEM_EVENT_TYPE.to_owned()),
                data: Some(Value::Object(data)),
                upstream_cursor: Some(position),
                ..WatchEvent::default()
            };
            if let Ok(json) = serde_json::to_string(&event) {
                emit(&json);
            }
        }
        // Advance only on the gateway's word: a page it dropped is read
        // again.
        let deadline = Instant::now() + read.ack_timeout;
        let mut acknowledged = false;
        while !acknowledged && !stop.load(Ordering::Acquire) {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match acks.recv_timeout(left.min(Duration::from_millis(200))) {
                Ok(position) => {
                    acknowledged = position.get("seq").and_then(Value::as_u64) == awaited;
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
        }
        if acknowledged {
            cursor = next.or(cursor);
            if !more && !wait(read.interval) {
                return;
            }
        } else if !stop.load(Ordering::Acquire) {
            tracing::warn!(location = %read.location, "http_poll: the gateway did not acknowledge a page in time; it is read again");
        }
    }
}

/// `watch_strategy` entity. Stateless beyond its manifest — each watcher's
/// endpoint arrives on the per-watch spec.
pub struct HttpWatchCdylib {
    manifest: PluginManifest,
}

impl HttpWatchCdylib {
    /// Infallible cdylib factory; the watch carries no plugin-level config.
    pub fn from_host_config(_config_json: &str, _host: HostHandle) -> Self {
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.backend.http",
                name: "HTTP Poll Watch Strategy",
                class: WatchStrategy,
            },
        }
    }
}

impl SyncWatchStrategyPlugin for HttpWatchCdylib {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        WATCH_KIND
    }

    fn watch(
        &self,
        resource_uri: &str,
        spec: &Value,
        emit_event: Box<dyn Fn(&str) + Send + Sync + 'static>,
    ) -> Result<WatchHandleBox, WatchError> {
        let (spec, resume) = mcpg_plugin_protocol::take_watch_resume(spec);
        let parsed: WatchSpec =
            serde_json::from_value(spec).map_err(|e| WatchError::InvalidSpec {
                message: format!("invalid http_poll watch spec: {e}"),
            })?;
        let invalid = |m: String| WatchError::InvalidSpec { message: m };
        if parsed.url.contains("cred://") || parsed.headers.values().any(|v| v.contains("cred://"))
        {
            return Err(invalid(
                "url and headers must not carry cred:// — a watch has no caller; use \
                 ${env.X} / ${secret.X} / vault:// (resolved before the watch starts)"
                    .into(),
            ));
        }
        // The URL may carry a credential, so its parse error is not echoed.
        let url = url::Url::parse(&parsed.url).map_err(|_| invalid("url is not a URL".into()))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(invalid("url must be http:// or https://".into()));
        }
        if parsed.interval_ms < MIN_INTERVAL_MS {
            return Err(invalid(format!(
                "interval_ms must be at least {MIN_INTERVAL_MS}"
            )));
        }
        if parsed.timeout_ms == 0 {
            return Err(invalid("timeout_ms must be greater than 0".into()));
        }
        if !(1..=MAX_RESPONSE_BYTES).contains(&parsed.max_response_bytes) {
            return Err(invalid(format!(
                "max_response_bytes must be 1 to {MAX_RESPONSE_BYTES}"
            )));
        }
        if !(1..=100_000).contains(&parsed.max_items) {
            return Err(invalid("max_items must be 1 to 100000".into()));
        }
        for pointer in [
            Some(&parsed.items_pointer),
            parsed.id_pointer.as_ref(),
            parsed.updated_pointer.as_ref(),
            parsed.next_cursor_pointer.as_ref(),
            parsed.has_more_pointer.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if !pointer.is_empty() && !pointer.starts_with('/') {
                return Err(invalid(format!(
                    "'{pointer}' is not a JSON pointer: it starts with /"
                )));
            }
        }
        if parsed.format == Format::Json && parsed.id_pointer.is_none() {
            return Err(invalid("format json needs id_pointer".into()));
        }
        if parsed.mode == Mode::Cursor {
            if parsed.format == Format::Feed {
                return Err(invalid("mode cursor reads JSON, not a feed".into()));
            }
            if parsed.cursor_param.as_deref().is_none_or(str::is_empty) {
                return Err(invalid("mode cursor needs cursor_param".into()));
            }
        }
        let endpoint = Endpoint {
            url: url.clone(),
            headers: parsed.headers.clone(),
            timeout: Duration::from_millis(parsed.timeout_ms),
            max_response_bytes: parsed.max_response_bytes,
            allow_private: parsed.allow_private_backends,
        };
        let location = location_of(&url);
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("mcpg-http-watch")
            .enable_all()
            .build()
            .map_err(|e| WatchError::Subscribe {
                message: format!("http_poll: tokio runtime init failed: {e}"),
            })?;

        if parsed.mode == Mode::Cursor {
            let cursor = resume
                .as_ref()
                .and_then(|r| r.get("cursor"))
                .and_then(Value::as_str)
                .map(str::to_owned)
                .or(parsed.initial_cursor.clone());
            let read = CursorRead {
                endpoint,
                location,
                param: parsed.cursor_param.clone().unwrap_or_default(),
                items_pointer: parsed.items_pointer.clone(),
                id_pointer: parsed.id_pointer.clone().unwrap_or_default(),
                next_cursor_pointer: parsed.next_cursor_pointer.clone(),
                has_more_pointer: parsed.has_more_pointer.clone(),
                interval: Duration::from_millis(parsed.interval_ms),
                ack_timeout: Duration::from_millis(parsed.ack_timeout_ms),
            };
            let (acks, acked) = channel();
            let stop = Arc::new(AtomicBool::new(false));
            let stopping = Arc::clone(&stop);
            let event_source = mcpg_plugin_protocol::is_event_source(resource_uri);
            let join = std::thread::Builder::new()
                .name("mcpg-http-cursor".to_owned())
                .spawn(move || {
                    cursor_loop(rt, read, cursor, event_source, emit_event, acked, stopping)
                })
                .map_err(|e| WatchError::Subscribe {
                    message: format!("http_poll: cannot start its thread: {e}"),
                })?;
            let state = Box::new(WatchState::Cursor(CursorWatch {
                acks,
                stop,
                join: Some(join),
            }));
            return Ok(WatchHandleBox(Box::into_raw(state) as *mut ()));
        }

        let removals = parsed.removals.unwrap_or(match parsed.format {
            Format::Json => Removals::Report,
            Format::Feed => Removals::Ignore,
        });
        let snapshot = Arc::new(Mutex::new(Snapshot::default()));
        let rt = Arc::new(rt);
        let (list_rt, list_snapshot) = (Arc::clone(&rt), Arc::clone(&snapshot));
        let (format, items_pointer, id_pointer, updated_pointer, max_items) = (
            parsed.format,
            parsed.items_pointer.clone(),
            parsed.id_pointer.clone().unwrap_or_default(),
            parsed.updated_pointer.clone(),
            parsed.max_items,
        );
        let list = move || {
            let mut snapshot = list_snapshot.lock().unwrap_or_else(|e| e.into_inner());
            let fetched = list_rt.block_on(endpoint.get(
                &endpoint.url,
                snapshot.etag.as_deref(),
                snapshot.last_modified.as_deref(),
            ))?;
            let (body, etag, last_modified) = match fetched {
                Fetched::NotModified => return Ok(snapshot.entries.clone()),
                Fetched::Body(body, etag, last_modified) => (body, etag, last_modified),
            };
            let (mut entries, extras) = match format {
                Format::Feed => feed_collection(&body)?,
                Format::Json => json_collection(
                    &body,
                    &items_pointer,
                    &id_pointer,
                    updated_pointer.as_deref(),
                )?,
            };
            if entries.len() > max_items {
                tracing::warn!(
                    items = entries.len(),
                    max_items,
                    "http_poll: more items than max_items; the first are watched"
                );
                entries.truncate(max_items);
            }
            snapshot.etag = etag;
            snapshot.last_modified = last_modified;
            snapshot.entries = entries.clone();
            snapshot.extras = extras;
            Ok(entries)
        };
        let describe_snapshot = Arc::clone(&snapshot);
        let describe: Describe = Box::new(move |entries: &[ObjectEntry]| {
            let snapshot = describe_snapshot.lock().unwrap_or_else(|e| e.into_inner());
            entries
                .iter()
                .map(|e| snapshot.extras.get(&e.key).cloned())
                .collect()
        });
        let (handle, _waker) = spawn_inventory_watch_hooked(
            resource_uri,
            InventoryOptions {
                store: match parsed.format {
                    Format::Feed => "feed".into(),
                    Format::Json => "http".into(),
                },
                location,
                interval: Duration::from_millis(parsed.interval_ms),
                start: parsed.start_at,
                snapshot_bytes: parsed.snapshot_bytes,
                max_in_flight: parsed.max_in_flight,
                ack_timeout: Duration::from_millis(parsed.ack_timeout_ms),
            },
            resume,
            emit_event,
            list,
            InventoryHooks {
                describe: Some(describe),
                quiet_removals: removals == Removals::Ignore,
            },
        )?;
        // The runtime drops with the listing closure, on the watch's thread.
        drop(rt);
        let state = Box::new(WatchState::Snapshot(handle));
        Ok(WatchHandleBox(Box::into_raw(state) as *mut ()))
    }

    fn acknowledge(&self, watch_handle: &WatchHandleBox, position: &Value) {
        if watch_handle.0.is_null() {
            return;
        }
        // SAFETY: the pointer `watch` returned, still owned by the host,
        // which never acknowledges after cancel.
        #[allow(unsafe_code)]
        let state = unsafe { &*(watch_handle.0 as *const WatchState) };
        match state {
            WatchState::Snapshot(handle) => acknowledge_inventory_watch(handle, position),
            WatchState::Cursor(cursor) => {
                let _ = cursor.acks.send(position.clone());
            }
        }
    }

    fn cancel(&self, watch_handle: WatchHandleBox) {
        if watch_handle.0.is_null() {
            return;
        }
        // SAFETY: produced by `Box::into_raw` in `watch` and round-tripped by
        // the host exactly once.
        #[allow(unsafe_code)]
        let state = unsafe { Box::from_raw(watch_handle.0 as *mut WatchState) };
        match *state {
            WatchState::Snapshot(handle) => cancel_inventory_watch(handle),
            WatchState::Cursor(mut cursor) => {
                cursor.stop.store(true, Ordering::Release);
                if let Some(join) = cursor.join.take() {
                    let _ = join.join();
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "watch_tests.rs"]
mod tests;
