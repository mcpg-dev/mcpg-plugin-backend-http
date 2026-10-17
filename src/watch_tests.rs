use super::*;

fn stub_host() -> HostHandle {
    // SAFETY: `stub_host_ref` returns a process-static no-op host ref; the
    // factory ignores the host entirely.
    #[allow(unsafe_code)]
    unsafe {
        HostHandle::from_ffi(mcpg_plugin_sdk::testing::stub_host_ref())
    }
}

fn plugin() -> HttpWatchCdylib {
    HttpWatchCdylib::from_host_config("", stub_host())
}

fn refused(spec: Value) -> String {
    match plugin().watch("mcpg-event://feed", &spec, Box::new(|_| {})) {
        Err(WatchError::InvalidSpec { message }) => message,
        Err(other) => panic!("not a spec error: {other:?}"),
        Ok(handle) => {
            plugin().cancel(handle);
            panic!("accepted {spec}");
        }
    }
}

const RSS: &str = r#"<?xml version="1.0"?>
<rss version="2.0"><channel><title>Status</title>
<item><guid>inc-2</guid><title>Degraded API</title><link>https://status.example.com/inc-2</link>
<description>Investigating</description><pubDate>Sat, 10 Oct 2026 12:00:00 GMT</pubDate></item>
<item><guid>inc-1</guid><title>Resolved</title><link>https://status.example.com/inc-1</link></item>
</channel></rss>"#;

const ATOM: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom"><title>Releases</title><id>urn:releases</id>
<updated>2026-10-10T12:00:00Z</updated>
<entry><id>urn:v2</id><title>v2.0</title><updated>2026-10-10T12:00:00Z</updated>
<link href="https://example.com/v2"/><author><name>Ada</name></author>
<category term="release"/><summary>New things</summary></entry>
</feed>"#;

#[test]
fn manifest_and_kind_are_correct() {
    use mcpg_plugin_protocol::PluginClass;
    let p = plugin();
    assert_eq!(SyncWatchStrategyPlugin::manifest(&p).id, PLUGIN_ID);
    assert_eq!(
        SyncWatchStrategyPlugin::manifest(&p).plugin_class,
        PluginClass::WatchStrategy
    );
    assert_eq!(p.kind(), WATCH_KIND);
}

#[test]
fn a_bad_spec_is_refused_before_anything_is_called() {
    let with = |extra: Value| {
        let mut spec = json!({ "url": "https://api.example.com/items", "id_pointer": "/id" });
        for (k, v) in extra.as_object().unwrap() {
            spec[k] = v.clone();
        }
        spec
    };
    assert!(refused(with(json!({ "bogus": 1 }))).contains("unknown field"));
    assert!(refused(with(json!({ "url": "cred://vault/x" }))).contains("cred://"));
    assert!(
        refused(with(
            json!({ "headers": { "Authorization": "cred://vault/t" } })
        ))
        .contains("cred://")
    );
    let unparsable = refused(with(json!({ "url": "https://user:secret@[bad" })));
    assert!(unparsable.contains("not a URL") && !unparsable.contains("secret"));
    assert!(refused(with(json!({ "url": "ftp://x/y" }))).contains("http://"));
    assert!(refused(with(json!({ "interval_ms": 500 }))).contains("interval_ms"));
    assert!(refused(with(json!({ "timeout_ms": 0 }))).contains("timeout_ms"));
    assert!(refused(with(json!({ "max_response_bytes": 0 }))).contains("max_response_bytes"));
    assert!(refused(with(json!({ "max_items": 0 }))).contains("max_items"));
    assert!(refused(with(json!({ "id_pointer": "id" }))).contains("JSON pointer"));
    assert!(refused(json!({ "url": "https://api.example.com/items" })).contains("id_pointer"));
    assert!(refused(with(json!({ "mode": "cursor" }))).contains("cursor_param"));
    assert!(
        refused(with(
            json!({ "mode": "cursor", "format": "feed", "cursor_param": "c" })
        ))
        .contains("not a feed")
    );
}

#[test]
fn a_location_carries_no_credential_and_no_query() {
    let url = url::Url::parse("https://user:secret@api.example.com:8443/v1/items?token=t").unwrap();
    assert_eq!(location_of(&url), "https://api.example.com:8443/v1/items");
}

#[test]
fn a_cursor_replaces_its_parameter_and_keeps_the_others() {
    let url = url::Url::parse("https://api.example.com/events?limit=50&since=old").unwrap();
    assert_eq!(
        with_cursor(&url, "since", Some("c 2")).as_str(),
        "https://api.example.com/events?limit=50&since=c+2"
    );
    assert_eq!(
        with_cursor(&url, "since", None).as_str(),
        "https://api.example.com/events?limit=50"
    );
    let bare = url::Url::parse("https://api.example.com/events").unwrap();
    assert_eq!(
        with_cursor(&bare, "since", None).as_str(),
        "https://api.example.com/events"
    );
}

#[test]
fn json_items_are_keyed_by_their_id_and_versioned_by_their_content() {
    let body = json!({ "data": [
        { "id": 7, "status": "open", "updated_at": "2026-10-10T12:00:00Z" },
        { "id": "a", "status": "closed", "updated_at": 1_700_000_000 },
        { "status": "no id" },
    ]})
    .to_string();
    let (entries, extras) =
        json_collection(body.as_bytes(), "/data", "/id", Some("/updated_at")).unwrap();
    assert_eq!(entries.len(), 2, "an item without an id is skipped");
    assert_eq!(entries[0].key, "7");
    assert_eq!(entries[0].modified_at_ms, Some(1_791_633_600_000));
    assert_eq!(entries[1].modified_at_ms, Some(1_700_000_000_000));
    assert_eq!(extras["7"]["item"]["status"], json!("open"));
    let changed =
        json!({ "data": [{ "id": 7, "status": "closed", "updated_at": "2026-10-10T12:00:00Z" }] })
            .to_string();
    let (again, _) =
        json_collection(changed.as_bytes(), "/data", "/id", Some("/updated_at")).unwrap();
    assert_ne!(
        again[0].version, entries[0].version,
        "any change of the item"
    );
    assert!(
        json_collection(b"[]", "/data", "/id", None).is_err(),
        "no array there"
    );
    assert!(json_collection(b"not json", "", "/id", None).is_err());
    let (root, _) = json_collection(br#"[{"id":1}]"#, "", "/id", None).unwrap();
    assert_eq!(root[0].key, "1", "an empty pointer is the body");
}

#[test]
fn a_large_item_is_left_out_with_its_size() {
    let item = json!({ "id": 1, "blob": "x".repeat(MAX_ITEM_BYTES) });
    let extra = carried(&item);
    assert!(extra.get("item").is_none());
    assert_eq!(extra["itemTruncated"], json!(true));
}

#[test]
fn an_rss_feed_becomes_items_with_their_details() {
    let (entries, extras) = feed_collection(RSS.as_bytes()).unwrap();
    let keys: Vec<&str> = entries.iter().map(|e| e.key.as_str()).collect();
    assert_eq!(keys, ["inc-2", "inc-1"]);
    let incident = &extras["inc-2"];
    assert_eq!(incident["title"], json!("Degraded API"));
    assert_eq!(incident["link"], json!("https://status.example.com/inc-2"));
    assert_eq!(incident["summary"], json!("Investigating"));
    assert_eq!(incident["feedTitle"], json!("Status"));
    assert!(incident["published"].is_string());
    assert!(entries[0].modified_at_ms.is_some(), "the publish time");
}

#[test]
fn an_atom_feed_becomes_items_and_an_edit_is_a_new_version() {
    let (entries, extras) = feed_collection(ATOM.as_bytes()).unwrap();
    assert_eq!(entries[0].key, "urn:v2");
    assert_eq!(extras["urn:v2"]["authors"], json!(["Ada"]));
    assert_eq!(extras["urn:v2"]["categories"], json!(["release"]));
    let edited = ATOM.replace("New things", "Newer things");
    let (again, _) = feed_collection(edited.as_bytes()).unwrap();
    assert_ne!(again[0].version, entries[0].version);
    assert!(feed_collection(b"<html>not a feed</html>").is_err());
}

#[test]
fn times_read_as_rfc3339_or_unix_seconds() {
    assert_eq!(time_of(&json!("1970-01-01T00:00:01Z")), Some(1_000));
    assert_eq!(time_of(&json!(2)), Some(2_000));
    assert_eq!(time_of(&json!("yesterday")), None);
    assert_eq!(id_text(&json!("")), None);
    assert_eq!(id_text(&json!(12)), Some("12".into()));
}
