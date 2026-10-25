# HTTP Binding — `dev.mcpg.backend.http`

> class `backend` · `native` · package `mcpg-plugin-backend-http` · artifact `libmcpg_plugin_backend_http.so` · Apache-2.0

Backend binding plugin for the MCPG gateway that fronts a REST/JSON HTTP
endpoint. A POST binding sends the caller's arguments as a JSON body; a
GET binding renders them as a sorted query string. Reach for it whenever
an MCP tool, resource, or prompt is backed by an ordinary HTTP API — it
is the general-purpose binding, and the one to reach for before writing
a bespoke plugin. It declares `network_outbound` as a required
capability, so the matching `plugins[]` entry has to grant it or the
gateway refuses the plugin at boot.

## What it does
- Dispatches each call to the binding's `url` as a POST with a JSON body
  or a GET with a query string, chosen by `method`.
- Validates the response against `expected_status_codes` and, when
  `require_json_response` is set, against JSON parseability.
- Resolves the URL and every header value as a CEL template per call, so
  `${arguments.*}` and `${context.*}` reach the wire.
- Substitutes `${cred://issuer/target}` tokens in the URL and header
  values through the gateway's credential path, per caller identity, at
  dispatch time.
- Caches one `reqwest::Client` per resolved-credential bundle and evicts
  on credential revocation, secret rotation, and idle expiry.
- Blocks connections to private, loopback, and link-local addresses
  unless the binding opts in, and pins the validated address for the
  life of the client.
- Streams: when the upstream signals a streaming response, emits one
  progress chunk per body chunk before the terminal chunk, and stops
  promptly on cancellation.
- Propagates the gateway's idempotency hint as an `Idempotency-Key`
  request header, unless the operator pinned that header themselves.
- Serves dynamic resource-template completions by calling an
  operator-declared read-only endpoint.
- Emits a per-call span, latency histogram, call counter, and — for
  failure classes worth reconstructing after the fact — an audit event.

## Configuration
The `plugins:` entry loads the cdylib and takes no `config:` block; the
per-call configuration lives in each binding's `backend:` block, keyed by
the `kind: http` discriminator.

```yaml
plugins:
  - id: dev.mcpg.backend.http
    class: backend
    kind: native
    source:
      path: ./plugins/libmcpg_plugin_backend_http.so
    granted_capabilities:
      - network_outbound

mcp:
  capabilities:
    tools:
      - name: orders.fetch
        description: Fetch an order by id.
        backend:
          kind: http
          url: "https://orders.internal/v1/orders/${arguments.id}"
          method: get
          timeout_ms: 2000
          max_response_bytes: 65536
          expected_status_codes: [200]
          require_json_response: true
          headers:
            authorization: "Bearer ${cred://orders-oauth/api}"
        input_schema:
          type: object
          properties:
            id: { type: string }
          required: [id]
```

| Field | Type | Default | Description |
|---|---|---|---|
| `url` | string | — (required) | Target URL. Must start with `http://` or `https://`. CEL-templated, and may carry `${cred://issuer/target}`. |
| `method` | `post` \| `get` | `post` | POST sends a JSON body; GET sends a query string. Case-insensitive. |
| `headers` | map<string,string> | `{}` | Request headers. Values are CEL templates and may carry `${cred://issuer/target}`. |
| `expected_status_codes` | `[u16]` | `[200]` | Status codes treated as success. Must be non-empty; each entry in 100–599. |
| `require_json_response` | bool | `false` | Treat a non-JSON body as a downstream error. |
| `max_response_bytes` | usize | `4096` | Response body cap; oversized bodies are truncated. Must be greater than 0. |
| `timeout_ms` | u64 | `2000` | Per-call wall-clock timeout. Must be greater than 0. |
| `allow_private_backends` | bool | `gateway.server.allow_private_backends` | Permit connections to private/loopback/link-local addresses. The gateway sets it for every binding from `gateway.server.allow_private_backends`; a value in the binding is replaced. |

A GET binding renders arguments into the query string with sorted keys,
percent-encoded values, and array values repeating their key, so the
request is deterministic across calls.

## Security
Unlike the gRPC and GraphQL bindings, `url` here is *not* transport-only:
it legitimately carries per-caller `${cred://issuer/target}` tokens, and
so do header values. Only the `${…}` token form resolves — a bare
`cred://…` outside `${}` is a literal and travels to the upstream
untouched, which is what keeps a caller from smuggling a credential
reference through a request argument. Credential references are
collected from the *parsed* template structure, so a request argument
interpolated into a CEL segment can only ever be a value.

Header keys and values are reflected onto the outbound request, so
registration rejects an empty key and any CR or LF in a key or value —
that closes request splitting at config time rather than at dispatch.
Hop-by-hop and proxy-topology headers (`host`, `connection`,
`content-length`, `forwarded`, `via`, `x-real-ip`, `x-request-id`, any
`x-forwarded-*`, and — on a JSON call — `accept` and `content-type`) are
dropped rather than forwarded.

Outbound connections go through a DNS rebinding guard. Resolution walks
the address list, picks the first address outside the private, loopback,
CGNAT, and link-local ranges, and pins it on the client, so a DNS record
that flips to an internal address after validation cannot be reached; a
host that resolves only to private addresses fails the call with an
operator-facing guard error. Redirects are disabled.

## Response envelope
`execute` returns a JSON document carrying `toolName`, `profile`,
`requestKind` (`json_body` or `query_string`), a `request` object
(`arguments`, `body`, `query`), and a `response` object (`statusCode`,
`contentType`, `durationMs`, `body`, `bodyTruncated`, the parsed `json`,
and `jsonParseError`). The effective `url` and `requestHeaders` sit
alongside the binding's limits. The envelope is the caller's tool result,
and a header or URL may hold a resolved secret or credential, so the `url`
has no userinfo and every query value reads `[redacted]`, and
`requestHeaders` lists the header names with every value `[redacted]`.

The `downstreamError` slot holds the first classified failure, with the
full list under `downstreamErrors`. Each error carries a stable `code`,
`retryable`, `retryClass`, `backoffStrategy`, and `suggestedAction`,
plus `retryAfterMs` when the upstream sent a `Retry-After` header. Retry
guidance is shaped by call mode: a GET is classed as a read-only probe
and marked safe to retry automatically, while a POST is classed as
potentially non-idempotent and requires operator idempotency review.

## Change-watching
A resource binding can attach a `watch:` block so `resources/subscribe`
works against it. The polling strategy re-reads through this binding and
compares a hash of the result:

```yaml
mcp:
  capabilities:
    resources:
      - name: config.app_settings
        description: Application configuration.
        uri: "config://app/settings"
        mime_type: application/json
        backend:
          kind: http
          url: "https://config.internal/app"
          method: get
        watch:
          strategy:
            type: poll
            interval_ms: 30000
```

### Polled changes as MCP Events (`http_poll`)

A second entity, a `watch_strategy` of kind `http_poll`, turns an endpoint
into an MCP Events source. Every request goes through the same guarded
client as the tools: the host must resolve to a public address unless
`allow_private_backends`, the address is pinned, and redirects are not
followed. The URL and headers resolve before the watch starts
(`${env.X}`, `${secret.X}`, `vault://…`; `cred://` is rejected) and are
never logged; events name the endpoint without its query or credentials.

**`mode: snapshot`** (default) reads the whole collection each poll and
reports each item created, modified or removed as the shared
`object.changed` event. `ETag` and `Last-Modified` are sent back, so an
unchanged endpoint answers 304 without a body. A restart resumes exactly
while the collection fits `snapshot_bytes`.

- `format: feed` reads an RSS, Atom or JSON Feed (`store: feed`). An item's
  event carries `title`, `link`, `published`, `updated`, `summary`,
  `content`, `authors`, `categories` and `feedTitle`; an edit is
  `modified`. An item that scrolls out of the feed is forgotten, not
  deleted (`removals: ignore`, the feed default).
- `format: json` reads a JSON array at `items_pointer`, each item keyed by
  the value at `id_pointer` (`store: http`). Any change of an item is
  `modified`, an item that leaves is `deleted` (`removals: report`, the
  JSON default); the event carries the `item` (left out past 64 KiB, with
  its size).

```yaml
mcp:
  capabilities:
    events:
      - name: status.incident
        description: An incident on the provider's status feed.
        source:
          watch:
            strategy:
              type: plugin
              kind: http_poll
              url: https://status.example.com/history.atom
              format: feed
              interval_ms: 120000
            event_type: object.changed
```

**`mode: cursor`** follows an API's change cursor, for an append-only log
(an events API, an audit log): each item on a page is one `http.item`
event `{url, id, item}`, its id the event id. The cursor goes in the
`cursor_param` query parameter; the next one comes from
`next_cursor_pointer`, or is the last item's id. `has_more_pointer` reads
the next page at once. The cursor advances only once the gateway has
acknowledged the page's last item: a page it did not take in
`ack_timeout_ms` is read again, and its ids deduplicate. A restart resumes
at the stored cursor.

```yaml
            strategy:
              type: plugin
              kind: http_poll
              url: https://api.example.com/v1/events?limit=100
              headers: { Authorization: "Bearer ${env.API_TOKEN}" }
              mode: cursor
              items_pointer: /data
              id_pointer: /id
              cursor_param: starting_after
              has_more_pointer: /has_more
            event_type: http.item
```

| Field | Default | Notes |
|---|---|---|
| `url`, `headers` | — | The endpoint and its request headers. |
| `format` | `json` | `json` or `feed` (snapshot only). |
| `mode` | `snapshot` | `snapshot` or `cursor` (JSON only). |
| `items_pointer` | `""` | JSON pointer to the items; `""` = the body. |
| `id_pointer` | — | JSON pointer, in an item, to its id. Required for JSON. |
| `updated_pointer` | — | JSON pointer to when an item last changed (RFC 3339 or Unix seconds): its `modifiedAt`. |
| `removals` | `report` / `ignore` | What a snapshot does with an item that leaves. |
| `cursor_param`, `next_cursor_pointer`, `has_more_pointer`, `initial_cursor` | — | Cursor mode. |
| `interval_ms` | `60000` | At least 1000. |
| `timeout_ms` | `10000` | Budget of one request. |
| `max_response_bytes` | `1048576` | A larger response fails the poll rather than being read in part (at most 16 MiB). |
| `allow_private_backends` | `false` | Reach a private or loopback address. |
| `max_items`, `start_at`, `snapshot_bytes`, `max_in_flight`, `ack_timeout_ms` | `10000`, `now`, `131072`, `256`, `60000` | As for every inventory source. |

## Connection pooling
One `reqwest::Client` is cached per resolved-credential bundle, keyed by
a BLAKE3 digest over the post-substitution URL and header values. Two
callers whose credentials resolve differently get different clients, and
a binding with no credential tokens collapses to a single cached client
for every call. The cache holds at most 256 clients, a background sweep
runs every 60 seconds and drops entries idle for 15 minutes, and entries
are evicted immediately when the gateway signals credential revocation
or rotation of a secret this binding referenced.

## Observability
Per call the plugin opens a host span, records the
`mcpg_http_backend_latency_seconds` histogram, and increments
`mcpg_http_backend_calls_total`. Both carry a deliberately bounded
`outcome` label — `ok`, `http_4xx`, `http_5xx`, `timeout`, `transport`,
`invalid_spec`, `profile_not_found` — so per-status cardinality cannot
explode. Four of those outcomes also emit an audit event: `timeout` as
`dev.mcpg.backend.http.request_timeout`, `http_5xx` as
`dev.mcpg.backend.http.upstream_5xx`, and `transport` / `invalid_spec`
as `dev.mcpg.backend.http.request_failed`. Success and 4xx produce no
audit traffic, because auth probes, concurrency conflicts, and
rate-limit denials are normal.

## MCP surfaces & composition
The binding is declared per capability under `mcp.capabilities.*`; the
same `backend:` block shape works on every surface.

### As a pipeline step
`kind: http` is pipeline-capable. Step keys other than `id` and
`input_transform` flatten into the spec.

```yaml
backend:
  kind: pipeline
  steps:
    - kind: http
      id: fetch_order
      url: "https://orders.internal/v1/orders/${arguments.id}"
      method: get
```

### As a resource
The upstream's body is the resource. A body that is MCP `contents` (a
`contents` array of entries with `uri` and `text` or `blob`) is served as it
is; any other body is one text content of the requested URI, typed by the
binding's `mime_type` (else the response's `Content-Type`). A body longer than
`max_response_bytes`, or one that is not UTF-8, fails the read. A read passes
`uri` (and a template's variables) as its arguments, so a GET adds them to the
query string.

```yaml
mcp:
  capabilities:
    resources:
      - name: status.page
        description: Live service status.
        uri: "status://current"
        mime_type: application/json
        backend:
          kind: http
          url: "https://status.internal/current"
          method: get
```

### As a resource template
Variables captured from `uri_template` arrive in `arguments` under their
declared names, so they interpolate into the URL. `variable_completions`
with `kind: dynamic` routes `completion/complete` to this plugin, which
calls a read-only endpoint on the same binding and extracts candidates
with a JSONPath. Its config takes `method` (default `get`), `path`
(required, appended to the binding's base URL), `query_params`,
`headers`, `response_path` (default `"$"`), and `body_template` (POST
only); the gateway clamps the result to 100 values.

```yaml
mcp:
  capabilities:
    resource_templates:
      - name: repo.page
        description: A repository page.
        uri_template: "repo://{repo}"
        mime_type: application/json
        backend:
          kind: http
          url: "https://code.internal/api/repos/${arguments.repo}"
          method: get
        variable_completions:
          repo:
            kind: dynamic
            backend: repo.page
            config:
              method: get
              path: "/completions/repos"
              query_params:
                prefix: "${arguments.prefix}"
              response_path: "$.values"
```

### As a prompt
```yaml
mcp:
  capabilities:
    prompts:
      - name: orders.summarize
        description: Summarize an order for a support agent.
        prompt_arguments:
          - name: id
            required: true
        backend:
          kind: http
          url: "https://orders.internal/v1/orders/${arguments.id}/summary"
          method: get
```

### Schemas & annotations
Every binding accepts the MCP descriptor fields as siblings of
`backend:` — `title`, `input_schema`, `output_schema`, `icons`, and
`annotations` (`read_only`, `destructive`, `idempotent`, `open_world`).
A sibling `retry:` block (`max_attempts` default `3`,
`initial_backoff_ms` default `200`, `retry_on_status_codes` default
`[429, 502, 503, 504]`, `retry_on_transport_error` default true) governs
gateway-side retries, and `governance:` carries the trust floor and CEL
authorization for the surface.

## Build
Default feature set is OFF (avoids `mcpg_plugin_register` linker
collisions in the workspace build); opt in to the cdylib:

```bash
cargo build -p mcpg-plugin-backend-http --features cdylib-export --release   # → target/release/libmcpg_plugin_backend_http.so
```

Releases publish one OCI artifact per platform, under floating
`protocol-<major>-<os>-<arch>` tags. A `plugins:` entry can therefore set
`source.oci` to the untagged reference
`ghcr.io/mcpg-dev/plugins/backend-http` instead of `source.path`, and the
gateway appends the tag for the right os/arch/libc build on its host.

## Testing
```bash
cargo test -p mcpg-plugin-backend-http
```

The suite runs offline and needs no external service. Integration tests
drive a local `wiremock` server for the tool-call, per-credential
resolution, idempotency, observability, and completion paths, and a raw
TCP server that emits a chunked HTTP/1.1 response for the
streaming-progress path.

## Sign & load (production)
Sign the artifact, pin/verify via the entry's `signature:` block, and honour
revocations. See <https://mcpg.dev/docs/security/plugin-security>.

## See also
- Backend binding reference: <https://mcpg.dev/docs/reference/backends>
- Pipeline step kinds: <https://mcpg.dev/docs/reference/pipeline-steps>
- Full gateway config schema: <https://mcpg.dev/docs/reference/configuration>
- Siblings sharing the same HTTP core: `libs/plugins/backend/grpc`, `libs/plugins/backend/graphql`, `libs/plugins/backend/net-core`
