// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::records::{MeteringDelta, PlaneDisposition, RecordStore, SecretForm};
#[allow(unused_imports)]
use redis::Commands;
use std::sync::OnceLock;

use busbar_contract::abi::store::OpId;
use busbar_plugin_loader::dispatch::kinds::store::Store;
use busbar_plugin_loader::dispatch::{
    load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink,
};
use busbar_plugin_loader::store_v3::LoadedStore;
use busbar_test_kit::tcp_conns::TcpConns;

/// THE STORE UNDER TEST is the store as the host opens it: its door through the loader
/// (`load_linked`, `LoadedStore::open`), every op one connection through the host's connector path
/// (the loader's test connection table over plain TCP). The name the tests always used stands for it.
pub(crate) type ValkeyStore = LoadedStore;

/// One dispatcher and one connection table for every store the tests open (the host has one each).
fn host() -> &'static (
    Arc<Dispatcher>,
    Arc<dyn busbar_contract::conn::DeclaredConns>,
) {
    static HOST: OnceLock<(
        Arc<Dispatcher>,
        Arc<dyn busbar_contract::conn::DeclaredConns>,
    )> = OnceLock::new();
    HOST.get_or_init(|| {
        let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
        let conns: Arc<dyn busbar_contract::conn::DeclaredConns> =
            Arc::new(TcpConns::new(d.conn_waker()));
        (d, conns)
    })
}

/// The node's `op_id` allocator for the bridge's writes: a node half no earlier run used (the
/// dedupe is durable) and one counter.
fn mint() -> OpId {
    static NODE: OnceLock<u64> = OnceLock::new();
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let node = *NODE.get_or_init(|| {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        (t ^ (u64::from(std::process::id()) << 40)) | 1
    });
    OpId::from_parts(
        node,
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
    )
}

/// The store's door opened on `settings`, as the host opens it.
pub(crate) fn open_with(settings: &str) -> Result<LoadedStore, String> {
    let (d, conns) = host();
    let row = LinkedRow::of(crate::door).map_err(|e| e.to_string())?;
    let p = load_linked::<Store>(
        &row,
        Bind {
            instance: Arc::from("store-valkey-test"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: busbar_plugin_loader::dispatch::ConnTable::Host(conns.clone()),
        },
    )
    .map_err(|e| e.to_string())?;
    LoadedStore::open(p, d.clone(), settings.as_bytes(), mint)
}

/// `ValkeyStore::connect(url)`, as the tests always spelled it: the door opened on `{"url": url}`.
pub(crate) trait Connect: Sized {
    fn connect(url: &str) -> Result<Self, String>;
}

impl Connect for LoadedStore {
    fn connect(url: &str) -> Result<Self, String> {
        open_with(&serde_json::json!({ "url": url }).to_string())
    }
}

/// The verify path's read, which is no longer a store op: a credential's secret by `(kind,
/// public_id)`, read back through the revision delta (which carries every row, revoked or not).
trait Lookup {
    fn lookup_credential_secret(
        &self,
        kind: &str,
        public_id: &str,
    ) -> RecordStoreResult<Option<CredentialSecret>>;
}

impl Lookup for LoadedStore {
    fn lookup_credential_secret(
        &self,
        kind: &str,
        public_id: &str,
    ) -> RecordStoreResult<Option<CredentialSecret>> {
        Ok(self
            .list_credentials_since(0)?
            .into_iter()
            .find(|c| c.meta.kind == kind && c.meta.public_id == public_id))
    }
}

/// The tests' INDEPENDENT view of the live Valkey (the upstream client, never the store's own
/// path): what landed, and the cleanup the `RecordStore` surface deliberately cannot do.
pub(crate) trait Raw {
    fn with_conn<T>(
        &self,
        f: impl FnOnce(&mut redis::Connection) -> redis::RedisResult<T>,
    ) -> RecordStoreResult<T>;

    /// Remove a key row and every index entry pointing at it, tombstone included.
    fn purge_key_for_test(&self, id: &str) -> RecordStoreResult<()> {
        self.with_conn(|c| {
            redis::pipe()
                .atomic()
                .del(format!("{KEY_PREFIX}{id}"))
                .ignore()
                .srem(KEYS_INDEX, id)
                .ignore()
                .zrem(KEYS_BYREV, id)
                .ignore()
                .del(cred_ids_key(id))
                .ignore()
                .query(c)
        })
    }

    /// Remove a credential's id pointer. The slot row itself goes with its owning key.
    fn purge_credential_for_test(&self, id: &str) -> RecordStoreResult<()> {
        self.with_conn(|c| {
            redis::pipe()
                .atomic()
                .del(cred_id_key(id))
                .ignore()
                .query(c)
        })
    }

    /// Put an audit row at its `seq`, as a 1.5.5 build wrote it: no store op appends one any more
    /// (1.6.0's admin audit is plane records), so the reads are seeded under the store's feet.
    fn seed_audit_for_test(&self, r: &AuditRecord) -> RecordStoreResult<()> {
        let json = serde_json::to_string(r).expect("an audit row encodes");
        let score = clamp(r.seq);
        self.with_conn(|c| {
            redis::pipe()
                .atomic()
                .zadd(AUDIT_ZSET, json, score)
                .ignore()
                .query(c)
        })
    }

    /// Remove whatever occupies one audit `seq`.
    fn purge_audit_seq_for_test(&self, seq: u64) -> RecordStoreResult<()> {
        let score = clamp(seq);
        self.with_conn(|c| {
            redis::pipe()
                .atomic()
                .cmd("ZREMRANGEBYSCORE")
                .arg(AUDIT_ZSET)
                .arg(score)
                .arg(score)
                .ignore()
                .query(c)
        })
    }
}

impl Raw for LoadedStore {
    fn with_conn<T>(
        &self,
        f: impl FnOnce(&mut redis::Connection) -> redis::RedisResult<T>,
    ) -> RecordStoreResult<T> {
        let url = std::env::var("VALKEY_URL").expect("the live tests run with VALKEY_URL");
        let mut c = redis::Client::open(url.as_str())
            .and_then(|c| c.get_connection())
            .map_err(|e| RecordStoreError(format!("valkey connect: {e}")))?;
        f(&mut c).map_err(|e| RecordStoreError(format!("valkey command: {e}")))
    }
}

/// The password-scrub never lets the URL secret out in an error string, and the URL password
/// extractor handles every URL shape.
#[test]
fn password_scrub_and_extraction() {
    assert_eq!(
        url_password("redis://:s3cr3t@host:6379/0").as_deref(),
        Some("s3cr3t")
    );
    assert_eq!(
        url_password("rediss://user:p%40ss@host:6380").as_deref(),
        Some("p%40ss")
    );
    assert_eq!(url_password("redis://host:6379"), None);
    assert_eq!(url_password("redis://user@host:6379"), None);
    assert_eq!(url_password("not a url"), None);

    let msg = "connection refused for redis://:s3cr3t@host:6379/0".to_string();
    let scrubbed = scrub(msg, Some("s3cr3t"));
    assert!(!scrubbed.contains("s3cr3t"), "got {scrubbed}");
    assert!(scrubbed.contains("<redacted>"));
    assert_eq!(scrub("plain".into(), None), "plain");
    assert_eq!(scrub("plain".into(), Some("zz")), "plain");

    let raw = url_password("rediss://user:p%40ss@host:6380").expect("password");
    assert_eq!(raw, "p%40ss");
    let decoded_leak = "auth failed with password p@ss".to_string();
    let s = scrub(decoded_leak, Some(&raw));
    assert!(
        !s.contains("p@ss") && s.contains("<redacted>"),
        "the DECODED password form must be scrubbed too; got {s}"
    );
    let raw_leak = "dsn rediss://user:p%40ss@host:6380".to_string();
    let s2 = scrub(raw_leak, Some(&raw));
    assert!(
        !s2.contains("p%40ss"),
        "the raw password form is scrubbed; got {s2}"
    );
    assert_eq!(percent_decode("p%40ss"), "p@ss");
    assert_eq!(percent_decode("no-escape"), "no-escape");
    assert_eq!(
        percent_decode("bad%zz"),
        "bad%zz",
        "a malformed escape is left verbatim"
    );
}

#[test]
fn tls_url_scheme_is_accepted() {
    let t = parse_url("rediss://:pw@localhost:6380/0").expect("a rediss URL parses");
    assert!(t.tls);
    assert_eq!(t.addr, "localhost:6380");
    assert_eq!(t.auth, Some((None, "pw".to_string())));
}

/// The `valkeys://` spelling reads as `rediss://`: TLS, and `#insecure` its one fragment.
#[test]
fn valkeys_scheme_selects_tls_and_takes_insecure() {
    let t = parse_url("valkeys://host").expect("a valkeys URL parses");
    assert!(t.tls && !t.insecure, "valkeys:// is TLS, verified");
    assert_eq!(t.addr, "host:6379");
    let t = parse_url("valkeys://host#insecure").expect("valkeys + #insecure parses");
    assert!(
        t.tls && t.insecure,
        "valkeys://…#insecure is TLS, unverified"
    );
    assert!(!parse_url("valkey://host").unwrap().tls);
}

/// The URL reads as the upstream driver read it: user, percent-decoded password, port, database,
/// IPv6 literals, and its refusals in its words.
#[test]
fn urls_parse_as_the_upstream_driver_read_them() {
    let t = parse_url("redis://alice:p%40ss@db.internal:7000/3").unwrap();
    assert_eq!(
        (t.addr.as_str(), t.host.as_str(), t.tls, t.db),
        ("db.internal:7000", "db.internal", false, 3)
    );
    assert_eq!(t.auth, Some((Some("alice".into()), "p@ss".into())));
    let t = parse_url("valkey://[::1]/").unwrap();
    assert_eq!(
        (t.addr.as_str(), t.host.as_str(), t.db),
        ("[::1]:6379", "::1", 0)
    );
    assert_eq!(parse_url("redis://h").unwrap().auth, None);
    assert_eq!(
        parse_url("not-a-valkey-url").unwrap_err().to_string(),
        "Redis URL did not parse - InvalidClientConfig"
    );
    assert_eq!(
        parse_url("redis://h/x").unwrap_err().to_string(),
        "Invalid database number - InvalidClientConfig"
    );
    assert!(parse_url("http://h").is_err());
    assert_eq!(
        parse_url("redis://0.0.0.0:6379").unwrap_err().to_string(),
        "Cannot connect to a wildcard address (0.0.0.0 or ::) - InvalidClientConfig"
    );
    assert_eq!(
        parse_url("redis://h/?protocol=9").unwrap_err().to_string(),
        "Invalid protocol version - InvalidClientConfig: 9"
    );
    assert!(parse_url("redis://h/?protocol=resp3").is_ok());
    // `#insecure` is the one fragment a TLS URL takes; any other is refused in the driver's words.
    let t = parse_url("rediss://h:6380/#insecure").unwrap();
    assert!(t.tls && t.insecure);
    assert!(!parse_url("rediss://h:6380/").unwrap().insecure);
    assert_eq!(
        parse_url("rediss://h/#other").unwrap_err().to_string(),
        "only #insecure is supported as URL fragment - InvalidClientConfig"
    );
}

/// The unix-socket URLs 1.5.5's driver read (VALKEY-UNIX): the path is the connector's
/// `unix:<path>` target, the database, user and password come from the query.
#[test]
fn unix_socket_urls_parse_as_the_upstream_driver_read_them() {
    for url in [
        "redis+unix:///run/valkey.sock",
        "unix:///run/valkey.sock",
        "valkey+unix:///run/valkey.sock",
        "unix:/run/valkey.sock",
    ] {
        let t = parse_url(url).unwrap_or_else(|e| panic!("{url}: {e}"));
        assert_eq!(
            (t.addr.as_str(), t.tls, t.db),
            ("unix:/run/valkey.sock", false, 0)
        );
        assert_eq!(t.auth, None);
    }
    let t = parse_url("redis+unix:///run/v.sock?db=2&user=%25al&pass=%26%3F+x").unwrap();
    assert_eq!(t.db, 2);
    assert_eq!(t.auth, Some((Some("%al".into()), "&? x".into())));
    assert_eq!(
        parse_url("unix:///run/v.sock?db=x")
            .unwrap_err()
            .to_string(),
        "Invalid database number - InvalidClientConfig"
    );
}

#[test]
fn row_escaping_quotes_the_separator_and_itself() {
    assert_eq!(escape("a|b", ROW_SEP), "a\\|b");
    assert_eq!(escape("back\\slash", ROW_SEP), "back\\\\slash");
    assert_eq!(escape("plain-id-123", ROW_SEP), "plain-id-123");
}

/// End-to-end against a REAL Valkey, gated on `VALKEY_URL` (a docker service in CI). Skips
/// cleanly when unset LOCALLY; under `CI` a missing URL is a HARD FAILURE, never a silent skip.
pub(crate) fn live_store() -> Option<ValkeyStore> {
    let url = match std::env::var("VALKEY_URL") {
        Ok(url) => url,
        Err(_) if std::env::var_os("CI").is_some() => {
            panic!(
                "VALKEY_URL is unset under CI: the Valkey service container must provision \
                 it. Refusing to silently skip the only live-DB coverage in CI."
            );
        }
        Err(_) => {
            eprintln!(
                "skip: set VALKEY_URL to run the store-valkey tests (e.g. redis://127.0.0.1:6380/0)"
            );
            return None;
        }
    };
    // Deliberately NO namespace wipe here: `cargo test` runs tests in parallel by default, and
    // every test in this file shares ONE Valkey instance — a per-test wipe would race every
    // OTHER concurrently-running test's writes (this was tried and produced exactly that failure
    // mode: "unknown id" errors from a test's own key vanishing mid-flight under a sibling test's
    // wipe). Isolation instead comes from every test using its own distinct key id namespace
    // (`vk_<test-specific-name>`) — collisions across tests are a review-time discipline, not a
    // runtime guard, same as the crate's pre-existing test suite already relied on.
    Some(ValkeyStore::connect(&url).expect("connect"))
}

fn vk(id: &str) -> VirtualKey {
    VirtualKey {
        id: id.to_string(),
        generation_hash: format!("binding:{id}:g0"),
        name: "test key".to_string(),
        allowed_scopes: None,
        enabled: true,
        created_at: 1000,
        group: None,
        labels: Default::default(),
        expires_at: None,
        deleted_at: None,
        revision: 0,
        ..Default::default()
    }
}

fn cred_meta(key_id: &str, public_id: &str, slot: u8) -> CredentialMeta {
    CredentialMeta {
        // Includes `public_id`, not just `key_id`/`slot`: in production a credential's `id` is a
        // fresh UUID per mint, unique regardless of which slot it lands in (see
        // `revoke_by_a_reclaimed_slots_old_id_must_not_touch_the_new_occupant`'s doc) — two
        // DIFFERENT credentials must never share a fixture-derived id just because they target the
        // same (key_id, slot), or a test exercising "a different credential collides with a live
        // slot" stops being realistic.
        id: format!("cred_{key_id}_{slot}_{public_id}"),
        key_id: key_id.to_string(),
        kind: "sigv4".to_string(),
        slot,
        public_id: public_id.to_string(),
        secret_form: SecretForm::Recoverable,
        created_at: 1000,
        updated_at: 1000,
        expires_at: None,
        revoked_at: None,
        revoke_reason: None,
        revision: 0,
    }
}

fn cred(key_id: &str, public_id: &str, slot: u8) -> CredentialSecret {
    CredentialSecret {
        meta: cred_meta(key_id, public_id, slot),
        secret: format!("v1:plain:{public_id}-secret"),
    }
}

/// Per-invocation-unique identifier for tests whose fixture touches a uniqueness constraint
/// (credential `public_id`, an accumulating usage/metering counter) rather than an idempotent
/// overwrite. Ordinary point-write tests are already safe to rerun because `put_key`/`SET` simply
/// overwrites the same row every time -- but a SETNX-style uniqueness check (`public_id` already
/// claimed) or an accumulating counter (`add_usage`/`add_metering`) sees a SECOND invocation's
/// identical literal id as a real collision with the FIRST invocation's leftover row, since this
/// suite deliberately never wipes the shared instance between runs (see `live_store()`). A fresh
/// process id per `cargo test` invocation, plus a counter for multiple calls within one process,
/// keeps those specific fixtures unique across repeated runs without reintroducing the per-test
/// wipe that was already tried and rejected for breaking intra-run parallelism.
fn unique_suffix() -> u64 {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    static RUN: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    let run = *RUN.get_or_init(|| {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        run_salt(std::process::id(), nanos)
    });
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    assert!(n < RUN_SPAN, "more than {RUN_SPAN} unique ids in one run");
    run * RUN_SPAN + n
}

/// Ids one run may mint; a suffix is `run_salt * RUN_SPAN + n`, below `1e9`, so `unique_bucket`'s
/// `base * 1e9 + suffix` stays injective in `base`.
const RUN_SPAN: u64 = 1_000;

/// A run's salt, below `1_000_000`: the pid and the start time folded together.
fn run_salt(pid: u32, nanos: u128) -> u64 {
    let folded = nanos ^ (nanos >> 64) ^ (u128::from(pid) << 20);
    (folded % 1_000_000) as u64
}

#[test]
fn unique_suffix_is_per_run_and_never_overflows_a_bucket() {
    assert_ne!(run_salt(100, 1_000_000_007), run_salt(100, 2_000_000_011));
    assert_ne!(run_salt(100, 1_000_000_007), run_salt(101, 1_000_000_007));
    assert!(run_salt(u32::MAX, u128::MAX) < 1_000_000);
    assert!(unique_suffix() < 1_000_000_000);
    assert_ne!(unique_bucket(20260731), unique_bucket(20260801));
}

fn uid(base: &str) -> String {
    format!("{base}_{}", unique_suffix())
}

/// Like `uid`, but for the `bucket: u64` metering fields -- a distinct numeric bucket per call,
/// same rationale as `uid` (metering counters accumulate across invocations of the same literal
/// bucket, so a fixed literal collides with a prior run's leftover row).
fn unique_bucket(base: u64) -> u64 {
    base * 1_000_000_000 + unique_suffix()
}

// ── Basic key CRUD ──────────────────────────────────────────────────────────────────────────

#[test]
fn put_get_roundtrips_a_key_and_stamps_revision() {
    let Some(store) = live_store() else { return };
    let id = uid("vk_1");
    store.put_key(&vk(&id)).unwrap();
    let back = store.get_key(&id).unwrap().expect("key exists");
    assert_eq!(back.id, id);
    assert!(back.deleted_at.is_none());
    assert!(back.revision > 0, "put_key must stamp a nonzero revision");
}

#[test]
fn list_keys_since_only_returns_keys_past_the_watermark() {
    let Some(store) = live_store() else { return };
    let (a, b) = (uid("vk_a"), uid("vk_b"));
    store.put_key(&vk(&a)).unwrap();
    let watermark = store.get_key(&a).unwrap().unwrap().revision;
    store.put_key(&vk(&b)).unwrap();
    let delta = store.list_keys_since(watermark).unwrap();
    // Tests run in parallel against one shared instance, so `delta` may legitimately also contain
    // OTHER tests' concurrently-created keys past this watermark — assert on presence/absence of
    // THIS test's own ids, not an exact global count.
    assert!(delta.iter().any(|k| k.id == b), "{b} must be in the delta");
    assert!(
        !delta.iter().any(|k| k.id == a),
        "{a} was created BEFORE the watermark and must not reappear"
    );
}

/// A row at revision 0 (never stamped) is returned by every delta, and `since = 0` returns every
/// row: the delta is `revision > since OR revision = 0`, for keys and credentials alike.
#[test]
fn a_revision_zero_row_is_in_every_delta() {
    let Some(store) = live_store() else { return };
    let (kid, pubid) = (uid("vk_rev0"), uid("AKIA_REV0"));
    let c = cred(&kid, &pubid, 0);
    store.put_key_with_credential(&vk(&kid), &c).unwrap();
    store
        .with_conn(|conn| {
            conn.zadd::<_, _, _, ()>(KEYS_BYREV, &kid, 0)?;
            conn.zadd::<_, _, _, ()>(CREDS_BYREV, slot_pointer(&c.meta), 0)
        })
        .unwrap();
    for since in [0, 1, u64::MAX / 2] {
        assert!(
            store
                .list_keys_since(since)
                .unwrap()
                .iter()
                .any(|k| k.id == kid),
            "key at revision 0 missing from the delta since {since}"
        );
        assert!(
            store
                .list_credentials_since(since)
                .unwrap()
                .iter()
                .any(|x| x.meta.id == c.meta.id),
            "credential at revision 0 missing from the delta since {since}"
        );
    }
}

#[test]
fn list_keys_is_unfiltered_including_tombstones() {
    let Some(store) = live_store() else { return };
    // This suite runs against a SHARED, PERSISTENT Valkey that is not flushed between runs, and
    // this test uses a FIXED id. It used to be self-healing only because `put_key` resurrected
    // whatever tombstone a prior run had left on that id; now that `put_key` refuses to clear a
    // tombstone, the fixture has to be removed explicitly.
    let _ = store.purge_key_for_test("vk_live");
    let _ = store.purge_key_for_test("vk_dead");
    store.put_key(&vk("vk_live")).unwrap();
    store.put_key(&vk("vk_dead")).unwrap();
    store.delete_key("vk_dead").unwrap();
    let all = store.list_keys().unwrap();
    // No exact-count assertion: the shared namespace accumulates keys across parallel tests AND
    // across repeated test-suite runs (no wipe — see live_store()'s doc). Assert presence of this
    // test's own ids instead.
    assert!(
        all.iter().any(|k| k.id == "vk_live"),
        "list_keys must include the live key"
    );
    let dead = all
        .iter()
        .find(|k| k.id == "vk_dead")
        .expect("list_keys must include tombstoned rows too");
    assert!(dead.deleted_at.is_some());
}

// ── Tombstone delete: the central behavior change ──────────────────────────────────────────

#[test]
fn delete_key_tombstones_not_removes() {
    let Some(store) = live_store() else { return };
    // This suite runs against a SHARED, PERSISTENT Valkey that is not flushed between runs, and
    // this test uses a FIXED id. It used to be self-healing only because `put_key` resurrected
    // whatever tombstone a prior run had left on that id; now that `put_key` refuses to clear a
    // tombstone, the fixture has to be removed explicitly.
    let _ = store.purge_key_for_test("vk_del");
    store.put_key(&vk("vk_del")).unwrap();
    store.delete_key("vk_del").unwrap();
    let row = store
        .get_key("vk_del")
        .unwrap()
        .expect("tombstoned row must still be readable");
    assert!(!row.enabled);
    assert!(row.deleted_at.is_some());
}

#[test]
fn delete_key_unknown_id_errors() {
    let Some(store) = live_store() else { return };
    assert!(
        store.delete_key("vk_never_existed").is_err(),
        "deleting a key that never existed must error, distinct from re-deleting a tombstone"
    );
}

#[test]
fn delete_key_is_idempotent_once_tombstoned() {
    let Some(store) = live_store() else { return };
    // This suite runs against a SHARED, PERSISTENT Valkey that is not flushed between runs, and
    // this test uses a FIXED id. It used to be self-healing only because `put_key` resurrected
    // whatever tombstone a prior run had left on that id; now that `put_key` refuses to clear a
    // tombstone, the fixture has to be removed explicitly.
    let _ = store.purge_key_for_test("vk_x");
    store.put_key(&vk("vk_x")).unwrap();
    store.delete_key("vk_x").unwrap();
    let rev_after_first = store.get_key("vk_x").unwrap().unwrap().revision;
    store.delete_key("vk_x").unwrap();
    let rev_after_second = store.get_key("vk_x").unwrap().unwrap().revision;
    assert_eq!(
        rev_after_first, rev_after_second,
        "a no-op re-delete must not stamp a new revision"
    );
}

/// HARDEST INVARIANT #1: delete_key destroys the credential's SECRET material, not just the
/// metadata — proven by directly inspecting the raw stored bytes at the credential row's key,
/// bypassing the Store trait entirely (mirrors the SQL backends' "connect independently of the
/// ABI" persistence proof).
#[test]
fn delete_key_destroys_credential_secret_material() {
    let Some(store) = live_store() else { return };
    // A FIXED id against the shared, persistent Valkey: a prior run's `delete_key` below left its
    // tombstone, and the atomic mint (like `put_key`) now refuses to clear one, so remove it first
    // (the same fixture cleanup `delete_key_removes_usage_windows` does).
    let _ = store.purge_key_for_test("vk_cred");
    let key = vk("vk_cred");
    let c = cred("vk_cred", "AKIA_LIVE", 0);
    store.put_key_with_credential(&key, &c).unwrap();

    // Prove the secret is really there before delete, by raw GET (bypassing the trait).
    let raw_before: Option<String> = store
        .with_conn(|conn| conn.get(cred_row_key("vk_cred", "sigv4", 0)))
        .unwrap();
    assert!(
        raw_before
            .as_deref()
            .unwrap_or("")
            .contains("AKIA_LIVE-secret"),
        "sanity: the secret must actually be stored before delete"
    );

    store.delete_key("vk_cred").unwrap();

    // The row must be GONE entirely (not tombstoned-with-secret-cleared) — a hard delete of the
    // credential row is fine here since the CONSUMER evicts via the key's own deleted_at delta.
    let raw_after: Option<String> = store
        .with_conn(|conn| conn.get(cred_row_key("vk_cred", "sigv4", 0)))
        .unwrap();
    assert!(
        raw_after.is_none(),
        "credential row must be hard-deleted, not merely blanked"
    );

    // The public_id reverse-lookup pointer must also be gone (no dangling "revoked but still
    // resolvable" credential).
    assert!(store
        .lookup_credential_secret("sigv4", "AKIA_LIVE")
        .unwrap()
        .is_none());
    assert!(store.list_credentials("vk_cred").unwrap().is_empty());
}

/// HARDEST INVARIANT #2: the credential-id and public_id reverse-lookup pointers are cleaned up
/// too, not just the row — otherwise `revoke_credential(old_id, ...)` after a delete would find a
/// dangling pointer to a row that no longer exists.
#[test]
fn delete_key_cleans_up_reverse_lookup_pointers() {
    let Some(store) = live_store() else { return };
    // A FIXED id against the shared, persistent Valkey: a prior run's `delete_key` below left its
    // tombstone, and the atomic mint (like `put_key`) now refuses to clear one, so remove it first
    // (the same fixture cleanup `delete_key_removes_usage_windows` does).
    let _ = store.purge_key_for_test("vk_ptr");
    let key = vk("vk_ptr");
    let c = cred("vk_ptr", "AKIA_PTR", 0);
    let cred_id = c.meta.id.clone();
    store.put_key_with_credential(&key, &c).unwrap();
    store.delete_key("vk_ptr").unwrap();

    let by_pub: Option<String> = store
        .with_conn(|conn| conn.get(cred_pub_key("sigv4", "AKIA_PTR")))
        .unwrap();
    assert!(
        by_pub.is_none(),
        "cred:pub pointer must be cleaned up on delete"
    );
    let by_id: Option<String> = store
        .with_conn(|conn| conn.get(cred_id_key(&cred_id)))
        .unwrap();
    assert!(
        by_id.is_none(),
        "cred:id pointer must be cleaned up on delete"
    );
}

#[test]
fn delete_key_keeps_the_usage_ledger() {
    let Some(store) = live_store() else { return };
    // This suite runs against a SHARED, PERSISTENT Valkey that is not flushed between runs, and
    // this test uses a FIXED id. It used to be self-healing only because `put_key` resurrected
    // whatever tombstone a prior run had left on that id; now that `put_key` refuses to clear a
    // tombstone, the fixture has to be removed explicitly.
    let _ = store.purge_key_for_test("vk_usage");
    store.put_key(&vk("vk_usage")).unwrap();
    store
        .add_usage(
            "vk_usage",
            1000,
            &UsageDelta {
                requests: 1,
                billable_requests: 1,
                models: vec![],
            },
        )
        .unwrap();
    let before = store.get_usage("vk_usage", 1000).unwrap();
    assert_eq!(before.requests, 1);
    store.delete_key("vk_usage").unwrap();
    let after = store.get_usage("vk_usage", 1000).unwrap();
    assert_eq!(
        after.requests, 1,
        "delete_key destroys credentials only: the usage ledger is billing evidence and stays"
    );
}

/// `delete_key` touches no usage window of any key, however the id is spelled (it once swept
/// `busbar:usage:<id>:*`, which a glob character in an id widened to other keys' windows).
#[test]
fn delete_key_leaves_every_usage_window_alone() {
    let Some(store) = live_store() else { return };
    let s = unique_suffix();
    let evil = format!("vk_evil_{s}_*");
    let victim = format!("vk_evil_{s}_victim");
    store.put_key(&vk(&evil)).unwrap();
    store.put_key(&vk(&victim)).unwrap();
    let d = UsageDelta {
        requests: 1,
        billable_requests: 1,
        models: vec![],
    };
    store.add_usage(&evil, 1000, &d).unwrap();
    store.add_usage(&victim, 1000, &d).unwrap();
    store.delete_key(&evil).unwrap();
    assert_eq!(store.get_usage(&victim, 1000).unwrap().requests, 1);
    assert_eq!(store.get_usage(&evil, 1000).unwrap().requests, 1);
}

// ── Credentials: slot bounds, revoke, secret isolation ──────────────────────────────────────

#[test]
fn put_credential_rejects_a_live_slot_but_allows_reclaiming_a_revoked_one() {
    let Some(store) = live_store() else { return };
    // Unique per run, like every other fixture here: literal ids collide when this binary's
    // tests run concurrently against one shared Valkey, and the loser fails on a row a
    // different test wrote.
    let vk_id = uid("vk_slot");
    let key = vk(&vk_id);
    let c0 = cred(&vk_id, &uid("AKIA_0"), 0);
    store.put_key_with_credential(&key, &c0).unwrap();

    // Minting into the SAME live slot must fail loudly, not silently overwrite.
    let pub_0b = uid("AKIA_0B");
    let c0b = cred(&vk_id, &pub_0b, 0);
    let e = store.put_credential(&c0b).unwrap_err().0;
    assert_eq!(
        e,
        format!(
            "put_credential: slot 0 for key '{vk_id}' kind 'sigv4' holds a live credential; \
             revoke it first"
        ),
        "minting into a slot holding a LIVE credential must be rejected, in the family's words"
    );
    let e = store.put_key_with_credential(&key, &c0b).unwrap_err().0;
    assert!(
        e.starts_with("put_key_with_credential: slot 0 for key "),
        "the refusal names the calling method: {e}"
    );

    // Revoke it, then reclaiming the slot must succeed.
    store.revoke_credential(&c0.meta.id, "rotated").unwrap();
    assert!(
        store.put_credential(&c0b).is_ok(),
        "a revoked slot must be reclaimable"
    );
    let live = store.lookup_credential_secret("sigv4", &pub_0b).unwrap();
    assert!(live.is_some());
}

#[test]
fn revoke_by_a_reclaimed_slots_old_id_must_not_touch_the_new_occupant() {
    // A minted credential's `id` is generated fresh per mint (a UUID in production) -- it is NEVER
    // reused, even when the SLOT it occupies is later reclaimed by a different credential after a
    // revoke. `put_credential`'s slot-reclaim path must therefore invalidate the PREVIOUS
    // occupant's own `cred:id:<id>` pointer, not just its `cred:pub:<public_id>` pointer -- else
    // that stale pointer keeps resolving to the slot, which now holds someone else's live
    // credential. A late/duplicate `revoke_credential(old_id)` call (idempotent-retry shaped, or
    // simply a caller that held on to the old id) would then revoke and secret-wipe the WRONG,
    // currently-live credential instead of being the no-op the trait's "Idempotent" contract
    // promises for an already-gone id.
    let Some(store) = live_store() else { return };
    let key_id = uid("vk_reclaim");
    let key = vk(&key_id);

    let mut c0 = cred(&key_id, &uid("AKIA_OLD"), 0);
    c0.meta.id = uid("cred_old");
    store.put_key_with_credential(&key, &c0).unwrap();
    store.revoke_credential(&c0.meta.id, "rotated").unwrap();

    // A brand-new credential, with its OWN distinct id, reclaims the now-revoked slot.
    let mut c1 = cred(&key_id, &uid("AKIA_NEW"), 0);
    c1.meta.id = uid("cred_new");
    store.put_credential(&c1).unwrap();

    // A stale/duplicate revoke against the OLD id must not reach into the slot (now occupied by c1)
    // and revoke/secret-wipe the new, live credential. It now ERRORS rather than returning Ok: the
    // old id's pointer went away when the slot was reclaimed, so it names no row, and the settled
    // contract makes that an error precisely so an operator is never told a revocation happened
    // when nothing was touched. Both halves matter, so both are asserted -- refused AND harmless.
    let err = store
        .revoke_credential(&c0.meta.id, "stale retry")
        .expect_err("the old id names no credential once its slot was reclaimed");
    assert!(
        err.to_string().contains("unknown id"),
        "the refusal must say why: {err}"
    );

    let live = store
        .lookup_credential_secret("sigv4", &c1.meta.public_id)
        .unwrap()
        .expect("the reclaiming credential must still resolve by its own public_id");
    assert!(
        live.meta.revoked_at.is_none(),
        "a revoke against the OLD credential's id must not revoke the NEW occupant of its \
         reclaimed slot"
    );
    assert_ne!(
        live.secret, "",
        "a revoke against the OLD credential's id must not destroy the NEW occupant's secret \
         material"
    );
}

#[test]
fn public_id_uniqueness_is_enforced_across_slots() {
    let Some(store) = live_store() else { return };
    let key_id = uid("vk_uniq");
    let public_id = uid("AKIA_DUP");
    let key = vk(&key_id);
    store.put_key(&key).unwrap();
    let c0 = cred(&key_id, &public_id, 0);
    store.put_credential(&c0).unwrap();
    // A different slot trying to claim the SAME public_id must fail.
    let mut c1 = cred_meta(&key_id, &public_id, 1);
    c1.id = "cred_other".to_string();
    let c1 = CredentialSecret {
        meta: c1,
        secret: "v1:plain:different".to_string(),
    };
    let e = store.put_credential(&c1).unwrap_err().0;
    assert_eq!(
        e,
        format!("put_credential: public_id '{public_id}' is already in use for kind 'sigv4'"),
        "UNIQUE(kind, public_id) must be enforced across different slots too"
    );
}

#[test]
fn revoke_credential_destroys_secret_and_is_idempotent() {
    let Some(store) = live_store() else { return };
    let key_id = uid("vk_revoke");
    let public_id = uid("AKIA_REV");
    let key = vk(&key_id);
    let c = cred(&key_id, &public_id, 0);
    store.put_key_with_credential(&key, &c).unwrap();

    store.revoke_credential(&c.meta.id, "compromised").unwrap();

    // lookup_credential_secret must now resolve to a row whose secret is blanked and whose
    // revoked_at is set — the SigV4 verify path checks revoked_at, but defense-in-depth means the
    // plaintext should be gone too.
    let resolved = store
        .lookup_credential_secret("sigv4", &public_id)
        .unwrap()
        .expect(
            "revoked credential row must still resolve by public_id (so a revoked-key request \
                 gets a correct 'revoked' rejection, not 'unknown')",
        );
    assert!(resolved.meta.revoked_at.is_some());
    assert_eq!(resolved.meta.secret_form, SecretForm::None);
    assert_eq!(
        resolved.secret, "",
        "secret material must be destroyed on revoke"
    );

    // Idempotent: revoking again must not error or clobber the original revoked_at reason.
    assert!(store.revoke_credential(&c.meta.id, "again").is_ok());
    let repeated = store
        .lookup_credential_secret("sigv4", &public_id)
        .unwrap()
        .unwrap();
    assert_eq!(repeated.meta, resolved.meta);
    assert_eq!(repeated.secret, resolved.secret);
}

#[test]
fn revoke_credential_unknown_id_errors() {
    let Some(store) = live_store() else { return };
    // This used to assert Ok, reading the trait's "Idempotent" as covering an unknown id. It does
    // not: idempotent covers revoking an ALREADY-REVOKED id. An id that names nothing is an error,
    // because a silent no-op lets an operator responding to a leak believe the credential is dead
    // while it is still live and still authenticating. Settled in the trait doc and asserted for
    // every backend by the shared conformance suite.
    assert!(
        store.revoke_credential("cred_never_existed", "n/a").is_err(),
        "revoking an id that names no credential must error, distinct from re-revoking a revoked one"
    );
}

/// A revoked credential id is never re-minted, in the family's words.
#[test]
fn a_revoked_credential_id_is_never_re_minted() {
    let Some(store) = live_store() else { return };
    let kid = uid("vk_remint");
    let c = cred(&kid, &uid("AKIA_REMINT"), 0);
    store.put_key_with_credential(&vk(&kid), &c).unwrap();
    store.revoke_credential(&c.meta.id, "gone").unwrap();
    let e = store.put_credential(&c).unwrap_err().0;
    assert_eq!(
        e,
        format!(
            "put_credential: credential '{}' is revoked; a revoked credential is never re-minted",
            c.meta.id
        )
    );
}

/// `put_key_with_credential` refuses up front and writes nothing: a key that carries a tombstone,
/// a stored tombstone at the id, a credential naming another key.
#[test]
fn put_key_with_credential_refuses_up_front_and_writes_nothing() {
    let Some(store) = live_store() else { return };
    let kid = uid("vk_mint_refused");
    let c = cred(&kid, &uid("AKIA_MINT_REFUSED"), 0);
    let mut dead = vk(&kid);
    dead.deleted_at = Some(5);
    let e = store.put_key_with_credential(&dead, &c).unwrap_err().0;
    assert_eq!(
        e,
        format!(
            "put_key_with_credential: key '{kid}' is tombstoned; a credential is never minted \
             onto it"
        )
    );
    assert!(store.get_key(&kid).unwrap().is_none(), "nothing written");

    let other = cred(&uid("vk_somebody_else"), &uid("AKIA_MINT_OTHER"), 0);
    let e = store
        .put_key_with_credential(&vk(&kid), &other)
        .unwrap_err()
        .0;
    assert_eq!(
        e,
        format!(
            "put_key_with_credential: the credential names key '{}', not the key '{kid}' being \
             minted with it",
            other.meta.key_id
        )
    );
    assert!(store.get_key(&kid).unwrap().is_none(), "nothing written");

    store.put_key(&vk(&kid)).unwrap();
    store.delete_key(&kid).unwrap();
    let e = store.put_key_with_credential(&vk(&kid), &c).unwrap_err().0;
    assert_eq!(
        e,
        format!("put_key_with_credential: '{kid}' is tombstoned and its id is never reissued")
    );
}

/// `put_credential`'s owner refusals, in the family's words.
#[test]
fn put_credential_owner_refusals_read_as_the_family_writes_them() {
    let Some(store) = live_store() else { return };
    let kid = uid("vk_owner_missing");
    let c = cred(&kid, &uid("AKIA_OWNER"), 0);
    let e = store.put_credential(&c).unwrap_err().0;
    assert_eq!(
        e,
        format!(
            "put_credential: key '{kid}' does not exist; a credential must hang off a real key"
        )
    );
    store.put_key(&vk(&kid)).unwrap();
    store.delete_key(&kid).unwrap();
    let e = store.put_credential(&c).unwrap_err().0;
    assert_eq!(
        e,
        format!(
            "put_credential: key '{kid}' is tombstoned; its credentials were revoked with it and \
             are never reissued"
        )
    );
}

/// A credential id is unique across slots: re-putting an existing id into another slot is refused
/// and writes nothing.
#[test]
fn a_credential_id_cannot_be_put_into_a_second_slot() {
    let Some(store) = live_store() else { return };
    let kid = uid("vk_id_twice");
    let c0 = cred(&kid, &uid("AKIA_TWICE_A"), 0);
    store.put_key_with_credential(&vk(&kid), &c0).unwrap();
    let mut c1 = cred(&kid, &uid("AKIA_TWICE_B"), 1);
    c1.meta.id = c0.meta.id.clone();
    let e = store.put_credential(&c1).unwrap_err().to_string();
    assert!(
        e.contains(&format!(
            "put_credential: credential '{}' already exists in another slot",
            c0.meta.id
        )),
        "{e}"
    );
    assert_eq!(store.list_credentials(&kid).unwrap().len(), 1);
}

/// `list_credentials` answers in `(kind, slot)` order, not the index set's order.
#[test]
fn list_credentials_is_ordered_by_kind_then_slot() {
    let Some(store) = live_store() else { return };
    let kid = uid("vk_order");
    let mut first = cred(&kid, &uid("AKIA_ORD_A"), 1);
    let mut second = cred(&kid, &uid("AKIA_ORD_B"), 0);
    second.meta.kind = "apikey".to_string();
    second.meta.id = format!("{}_apikey", second.meta.id);
    let third = cred(&kid, &uid("AKIA_ORD_C"), 0);
    first.meta.id = format!("{}_x", first.meta.id);
    store.put_key_with_credential(&vk(&kid), &first).unwrap();
    store.put_credential(&second).unwrap();
    store.put_credential(&third).unwrap();
    let got: Vec<(String, u8)> = store
        .list_credentials(&kid)
        .unwrap()
        .into_iter()
        .map(|m| (m.kind, m.slot))
        .collect();
    assert_eq!(
        got,
        vec![
            ("apikey".to_string(), 0),
            ("sigv4".to_string(), 0),
            ("sigv4".to_string(), 1)
        ]
    );
}

/// A store refusal reaches the caller exactly as written, with no backend prefix.
#[test]
fn store_refusals_reach_the_caller_exactly_as_written() {
    let Some(store) = live_store() else { return };
    let id = uid("vk_nowhere");
    assert_eq!(
        store.delete_key(&id).unwrap_err().0,
        format!("delete_key: unknown id '{id}'")
    );
    assert_eq!(
        store.revoke_credential(&id, "n/a").unwrap_err().0,
        format!("revoke_credential: unknown id '{id}'")
    );
}

#[test]
fn list_credentials_never_carries_the_secret() {
    let Some(store) = live_store() else { return };
    let key_id = uid("vk_meta");
    let public_id = uid("AKIA_META");
    let key = vk(&key_id);
    let c = cred(&key_id, &public_id, 0);
    store.put_key_with_credential(&key, &c).unwrap();
    let metas = store.list_credentials(&key_id).unwrap();
    assert_eq!(metas.len(), 1);
    assert_eq!(metas[0].public_id, public_id);
    // CredentialMeta has no secret field at all — this is a compile-time guarantee, not a
    // runtime check, but assert the shape we actually get back is the meta type.
    let _: &CredentialMeta = &metas[0];
}

#[test]
fn list_credentials_since_carries_the_secret_for_hydration() {
    let Some(store) = live_store() else { return };
    let key_id = uid("vk_hydrate");
    let public_id = uid("AKIA_HYDRATE");
    let key = vk(&key_id);
    let c = cred(&key_id, &public_id, 0);
    store.put_key_with_credential(&key, &c).unwrap();
    // since=0 legitimately also returns other tests' concurrently-created credentials (parallel
    // execution against one shared instance) — find THIS test's own row rather than assert an
    // exact global count.
    let delta = store.list_credentials_since(0).unwrap();
    let mine = delta
        .iter()
        .find(|cs| cs.meta.public_id == public_id)
        .expect("this test's credential must be in the delta");
    assert_eq!(
        mine.secret, c.secret,
        "hydration delta must carry the real secret"
    );
}

/// `put_key_with_credential` writes the key and its credential together (the atomic-failure side
/// is `store_conformance`'s `assert_put_key_with_credential_is_atomic`).
#[test]
fn put_key_with_credential_writes_the_key_and_its_credential() {
    let Some(store) = live_store() else { return };
    let key_id = uid("vk_atomic");
    let public_id = uid("AKIA_ATOMIC");
    let key = vk(&key_id);
    let c = cred(&key_id, &public_id, 0);
    store.put_key_with_credential(&key, &c).unwrap();
    assert!(store.get_key(&key_id).unwrap().is_some());
    assert!(store
        .lookup_credential_secret("sigv4", &public_id)
        .unwrap()
        .is_some());
}

/// `with_conn` (used by `put_credential`) is documented "Safe only for READ / idempotent ops," but
/// automatically reconnects-and-retries on any connection-level error (`is_timeout()` /
/// `is_io_error()` / `is_connection_dropped()`) by re-running the ENTIRE transaction closure. If a
/// connection blip drops the reply AFTER Valkey has already committed the EXEC server-side, that
/// retry replays `put_credential` with the SAME `CredentialSecret` against a slot that now already
/// holds it — exactly the scenario this test simulates directly (without needing to sever a real
/// TCP connection): calling `put_credential` twice in a row with the identical secret must be a
/// safe no-op, not the "slot holds a live credential" error a genuinely different mint would
/// correctly get. Without the retry-safety check, this call incorrectly reports failure for a
/// credential that is, in fact, already correctly and fully written.
#[test]
fn put_credential_replayed_with_the_same_credential_id_is_a_retry_safe_no_op() {
    let Some(store) = live_store() else { return };
    let key_id = uid("vk_replay");
    let public_id = uid("AKIA_REPLAY");
    let key = vk(&key_id);
    let c = cred(&key_id, &public_id, 0);
    store.put_key_with_credential(&key, &c).unwrap();

    // Replay the SAME put_credential call (same meta.id) — simulates `with_conn`'s reconnect
    // retry replaying this closure after the first attempt's EXEC actually landed but its ack
    // was lost.
    assert!(
        store.put_credential(&c).is_ok(),
        "replaying put_credential with the SAME credential id (its own already-committed write) \
         must be a retry-safe no-op, not an error"
    );
    let live = store
        .lookup_credential_secret("sigv4", &public_id)
        .unwrap()
        .expect("credential must still resolve after the replayed call");
    assert!(live.meta.revoked_at.is_none());
    assert_ne!(live.secret, "", "the replay must not have wiped the secret");
}

/// Same retry-safety class as above, for `put_key_with_credential`'s public_id occupancy check.
#[test]
fn put_key_with_credential_replayed_with_the_same_credential_id_is_a_retry_safe_no_op() {
    let Some(store) = live_store() else { return };
    let key_id = uid("vk_kwc_replay");
    let public_id = uid("AKIA_KWC_REPLAY");
    let key = vk(&key_id);
    let c = cred(&key_id, &public_id, 0);
    store.put_key_with_credential(&key, &c).unwrap();

    // Replay the SAME call — simulates the reconnect-retry replaying an already-committed mint.
    assert!(
        store.put_key_with_credential(&key, &c).is_ok(),
        "replaying put_key_with_credential with the SAME credential id (its own already-committed \
         write) must be a retry-safe no-op, not a 'public_id already claimed' error"
    );
    let live = store
        .lookup_credential_secret("sigv4", &public_id)
        .unwrap()
        .expect("credential must still resolve after the replayed call");
    assert_ne!(live.secret, "", "the replay must not have wiped the secret");
}

/// A credential row that does not decode fails the whole `delete_key`, leaving the key live and
/// the credential's pointers in place: skipping it would report success with pointers dangling.
#[test]
fn delete_key_fails_loud_on_a_corrupt_credential_row_instead_of_orphaning_pointers() {
    let Some(store) = live_store() else { return };
    let key_id = uid("vk_corrupt");
    let public_id = uid("AKIA_CORRUPT");
    let key = vk(&key_id);
    let c = cred(&key_id, &public_id, 0);
    store.put_key_with_credential(&key, &c).unwrap();

    // FIRST take this credential out of the `busbar:creds:byrev` index, THEN corrupt its row.
    // Order matters, and the DEL below does not make this redundant.
    //
    // `list_credentials_since` reads that index and NOTHING else, and it is a GLOBAL scan of every
    // credential ever written to this shared instance. The DEL at the end of this test removes the
    // poison row, but only AFTER `delete_key` has returned — so for the whole duration of that call
    // the row is live, indexed, and visible to any test scanning concurrently. This suite runs its
    // tests in parallel against ONE long-lived Valkey (see `live_store()`), so that window is not
    // theoretical: `list_credentials_since_carries_the_secret_for_hydration` loses the race and
    // fails with `credential decode failed: expected ident at line 1 column 2` — the literal string
    // `"not json"` written below, surfacing in a completely unrelated test.
    //
    // Dropping the index entry first costs this test nothing, because `delete_key` never consults
    // that index: it reaches the credential row through the key's own credential-id pointers, which
    // is exactly the path under test. So the corrupt row stays fully reachable by the code this
    // test exercises, and unreachable by the global scan it has no business breaking.
    store
        .with_conn(|conn| {
            conn.zrem::<_, _, ()>(CREDS_BYREV, format!("{key_id}:sigv4:0"))?;
            conn.set::<_, _, ()>(cred_row_key(&key_id, "sigv4", 0), "not json")
        })
        .unwrap();

    let result = store.delete_key(&key_id);
    // Clean up the corrupted row ourselves (bypassing the trait, same as we corrupted it): this
    // suite shares ONE long-lived Valkey instance with no per-test wipe (see `live_store()`'s doc),
    // and `delete_key` correctly refusing to touch the corrupt row means it is still sitting there
    // for every later-running test to trip over — a real, malformed row is exactly what THIS test
    // means to exercise, not something later tests should have to survive. (Tests running
    // CONCURRENTLY with this one are covered by the de-indexing above, not by this line, which
    // cannot run until `delete_key` has already returned.)
    let pointer_kept: bool = store
        .with_conn(|conn| conn.exists(cred_id_key(&c.meta.id)))
        .unwrap();
    store
        .with_conn(|conn| conn.del::<_, ()>(cred_row_key(&key_id, "sigv4", 0)))
        .unwrap();
    assert!(
        pointer_kept,
        "the failed delete left the credential's pointer alone"
    );
    assert!(
        store
            .get_key(&key_id)
            .unwrap()
            .unwrap()
            .deleted_at
            .is_none(),
        "the failed delete left the key live"
    );
    assert!(
        result.is_err(),
        "delete_key must fail loudly on a corrupt credential row rather than silently reporting \
         success while orphaning that row's reverse-lookup pointers"
    );
}

// ── Metering: field rename + new fields ─────────────────────────────────────────────────────

#[test]
fn metering_round_trips_all_fields_including_renamed_and_new_ones() {
    let Some(store) = live_store() else { return };
    let key_id = uid("vk_m");
    let bucket = unique_bucket(20260731);
    store
        .add_metering(&MeteringDelta {
            key_id: key_id.clone(),
            bucket,
            model: "claude".to_string(),
            provider: "anthropic".to_string(),
            tokens_input: 10,
            tokens_output: 5,
            tokens_cache_read: 2,
            tokens_cache_write: 3,
            requests: 1,
            billable_requests: 1,
            key_group_at_use: "growth".to_string(),
            pricing_version: "2026-07".to_string(),
            priced_from_ms: 0,
            usage_units: Default::default(),
        })
        .unwrap();
    let rows = store.list_metering(bucket).unwrap();
    assert_eq!(rows.len(), 1);
    let r = &rows[0];
    assert_eq!(
        r.tokens_cache_write, 3,
        "renamed from tokens_cache_creation"
    );
    assert_eq!(r.billable_requests, 1);
    assert_eq!(r.key_group_at_use, "growth");
    assert_eq!(r.pricing_version, "2026-07");
}

#[test]
fn metering_attribution_is_first_write_wins() {
    let Some(store) = live_store() else { return };
    let bucket = unique_bucket(20260801);
    let base = MeteringDelta {
        key_id: uid("vk_snap"),
        bucket,
        model: "m".to_string(),
        provider: "p".to_string(),
        tokens_input: 1,
        tokens_output: 1,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: "first-group".to_string(),
        pricing_version: "v1".to_string(),
        priced_from_ms: 0,
        usage_units: Default::default(),
    };
    store.add_metering(&base).unwrap();
    let mut second = base.clone();
    second.key_group_at_use = "second-group".to_string();
    second.pricing_version = "v2".to_string();
    store.add_metering(&second).unwrap();
    let rows = store.list_metering(bucket).unwrap();
    assert_eq!(
        rows[0].key_group_at_use, "first-group",
        "attribution snapshots at first use"
    );
    assert_eq!(rows[0].pricing_version, "v1");
    // But the counters still accumulate normally.
    assert_eq!(rows[0].requests, 2);
}

#[test]
fn metering_row_identity_does_not_collide_across_a_delimiter_character() {
    // `metering_row`'s key is `key_id|model|provider` joined with a bare, unescaped `|`. A model
    // or provider name containing `|` (an operator-authored config value -- lane/model names are
    // NOT restricted to a fixed charset anywhere in this crate or its callers) lets two otherwise
    // DISTINCT (key_id, model, provider) triples collide onto the same Valkey row: here
    // `("k", "a|b", "p")` and `("k", "a", "b|p")` both join to `"k|a|b|p"`. Two logically separate
    // metering rows would then merge their HINCRBY'd token/request counters into one -- a billing
    // correctness bug, not just a cosmetic key-name wart.
    let Some(store) = live_store() else { return };
    let bucket = unique_bucket(20260802);
    let key_id = uid("vk_delim");

    store
        .add_metering(&MeteringDelta {
            key_id: key_id.clone(),
            bucket,
            model: "a|b".to_string(),
            provider: "p".to_string(),
            tokens_input: 100,
            tokens_output: 0,
            tokens_cache_read: 0,
            tokens_cache_write: 0,
            requests: 1,
            billable_requests: 1,
            key_group_at_use: "g".to_string(),
            pricing_version: "v1".to_string(),
            priced_from_ms: 0,
            usage_units: Default::default(),
        })
        .unwrap();
    store
        .add_metering(&MeteringDelta {
            key_id: key_id.clone(),
            bucket,
            model: "a".to_string(),
            provider: "b|p".to_string(),
            tokens_input: 7,
            tokens_output: 0,
            tokens_cache_read: 0,
            tokens_cache_write: 0,
            requests: 1,
            billable_requests: 1,
            key_group_at_use: "g".to_string(),
            pricing_version: "v1".to_string(),
            priced_from_ms: 0,
            usage_units: Default::default(),
        })
        .unwrap();

    let rows = store.list_metering(bucket).unwrap();
    assert_eq!(
        rows.len(),
        2,
        "two distinct (key_id, model, provider) triples must never merge into one metering row, \
         even when a component contains the internal join delimiter"
    );
}

// ── Startup assertion ────────────────────────────────────────────────────────────────────────

/// HARDEST INVARIANT #4: `connect()` refuses to start when `maxmemory-policy` is not
/// `noeviction`. Proven live: flip the real server's policy, attempt connect, restore it
/// regardless of outcome (test hygiene — never leave the shared container misconfigured for
/// other tests).
///
/// `#[ignore]`d for the same reason as `wipes_the_entire_namespace_destructively`: this test
/// mutates GLOBAL server config (`CONFIG SET maxmemory-policy`), which races every OTHER test's
/// concurrent `connect()` call under the default parallel `cargo test` — that is a genuine
/// conflict between "this test needs exclusive access to shared server state" and "the rest of the
/// suite assumes the shared server is always in its normal (noeviction) posture," not a bug in the
/// assertion itself (verified: run alone, or with `--test-threads=1`, it passes every time). Run
/// explicitly and alone: `VALKEY_URL=... cargo test -p busbar-store-valkey -- --ignored
/// connect_refuses_to_start_under_an_eviction_policy`.
#[test]
#[ignore]
fn connect_refuses_to_start_under_an_eviction_policy() {
    let Some(_baseline) = live_store() else {
        return;
    };
    let url = std::env::var("VALKEY_URL").unwrap();
    let mut conn = redis::Client::open(url.as_str())
        .unwrap()
        .get_connection()
        .unwrap();
    let _: () = redis::cmd("CONFIG")
        .arg("SET")
        .arg("maxmemory-policy")
        .arg("allkeys-lru")
        .query(&mut conn)
        .unwrap();

    let result = ValkeyStore::connect(&url);

    // ALWAYS restore, regardless of the assertion below, so a failure doesn't poison later tests.
    let _: () = redis::cmd("CONFIG")
        .arg("SET")
        .arg("maxmemory-policy")
        .arg("noeviction")
        .query(&mut conn)
        .unwrap();

    assert!(
        result.is_err(),
        "connect() must refuse to start under allkeys-lru — an eviction policy can silently drop \
         a denylist entry or a metering row with no error anywhere"
    );
}

// ── migrate() / with_conn retry: guards on two predicates in `store-valkey/src/lib.rs` ─────────
//
// The logic these pin is correct; what was missing was anything that would fail if it broke. Both
// predicates are silent in normal operation and catastrophic when wrong:
//   - `migrate()`'s `version >= SCHEMA_VERSION` early return. If that comparison were inverted, a
//     SECOND `connect()` against an already-migrated namespace would wipe the entire shared
//     `busbar:*` keyspace on every reconnect.
//   - `run()`'s `retry && is_connection_error(&e)` match guard. Each half must hold on its own: a
//     non-connection error under `retry: true` must NOT be retried, and a genuine connection-level
//     error must be retried and transparently recovered.

/// Pins the `version >= SCHEMA_VERSION` early return against inversion: a second
/// `connect()` (fresh `ValkeyStore`, fresh internal `migrate()` call) against a namespace already
/// at the current schema version must be a pure no-op, not a full `busbar:*` wipe.
#[test]
fn reconnecting_to_an_already_migrated_namespace_does_not_wipe_existing_data() {
    let Some(store1) = live_store() else { return };
    // By the time `store1`'s own `connect()` above returns, the schema marker is unconditionally
    // at `SCHEMA_VERSION` (every migrate() branch — fresh, already-current, or in-place upgrade —
    // ends with the marker set), so this write happens strictly after any wipe `store1`'s own
    // connect could have triggered.
    let id = uid("vk_migrate_reconnect");
    store1.put_key(&vk(&id)).unwrap();

    let url = std::env::var("VALKEY_URL").unwrap();
    let store2 = ValkeyStore::connect(&url).expect("a second connect() must succeed");
    assert!(
        store2.get_key(&id).unwrap().is_some(),
        "a second connect()/migrate() against an already-migrated namespace must not wipe \
         existing data (this test's own just-written key, and every concurrently-running test's \
         data along with it)"
    );
}

/// A deterministic NON-connection error (`WRONGTYPE`: a usage window that is not a hash) surfaces
/// through the store op in the store's words (the `"command"` context), never retried as a
/// connection failure.
#[test]
fn a_server_error_surfaces_through_the_op_in_the_stores_words() {
    let Some(store) = live_store() else { return };
    let id = uid("vk_wrongtype");
    let k = usage_key(&id, 60);
    store
        .with_conn(|c| c.set::<_, _, ()>(&k, "not-a-hash"))
        .unwrap();
    let err = store
        .get_usage(&id, 60)
        .expect_err("HGETALL against a string-valued key must fail with WRONGTYPE");
    assert!(
        err.0.contains("valkey command:") && err.0.contains("WRONGTYPE"),
        "a server error must surface via the 'command' context: {}",
        err.0
    );
    store.with_conn(|c| c.del::<_, ()>(&k)).unwrap();
}

// ── Denylist (unchanged shape, still real coverage) ─────────────────────────────────────────

#[test]
fn denylist_add_and_list_round_trips() {
    let Some(store) = live_store() else { return };
    let id = uid("vk_denied");
    store.add_denylist(&id, "compromised").unwrap();
    let list = store.list_denylist().unwrap();
    assert!(list.contains(&id));
}

/// The first denylist write wins: a repeat is a no-op that keeps the first reason.
#[test]
fn a_repeat_denylist_add_keeps_the_first_reason() {
    let Some(store) = live_store() else { return };
    let id = uid("vk_denied_twice");
    store.add_denylist(&id, "first").unwrap();
    store.add_denylist(&id, "second").unwrap();
    let reason: String = store
        .with_conn(|c| c.get(format!("{DENYLIST_PREFIX}{id}")))
        .unwrap();
    assert_eq!(reason, "first");
    let listed = store.list_denylist().unwrap();
    assert_eq!(listed.iter().filter(|s| **s == id).count(), 1);
}

// ── Audit log (unchanged shape) ──────────────────────────────────────────────────────────────

/// Serialises the tests that write the shared audit zset: `busbar:audit` is one global set keyed by
/// seq, so a `uid()` namespace cannot isolate them, and a concurrent append would push another
/// test's record out of the tail it reads back.
pub(crate) static AUDIT_SEQ_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Take `AUDIT_SEQ_LOCK`, ignoring poisoning, so one failing audit test does not convert the others
/// into spurious failures that bury the original.
pub(crate) fn audit_seq_guard() -> std::sync::MutexGuard<'static, ()> {
    AUDIT_SEQ_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// `VALKEY_URL` re-pointed at database `db`, so a refusal test owns a whole namespace and never
/// leaves a stale marker in the shared one the rest of the suite uses.
fn url_for_db(db: u32) -> String {
    let url = std::env::var("VALKEY_URL").unwrap();
    let base = url.split('?').next().unwrap();
    let (head, _) = base
        .rsplit_once('/')
        .filter(|(h, _)| h.contains("://"))
        .unwrap_or((base, ""));
    let head = if head.ends_with(':') || head.ends_with('/') {
        base.trim_end_matches('/')
    } else {
        head
    };
    match url.split_once('?') {
        Some((_, q)) => format!("{head}/{db}?{q}"),
        None => format!("{head}/{db}"),
    }
}

/// The database number a url selects (`/<db>` before any query; 0 when it names none).
fn db_of_url(url: &str) -> u32 {
    let base = url.split('?').next().unwrap_or(url);
    let rest = base.split_once("://").map_or(base, |(_, r)| r);
    rest.split_once('/')
        .and_then(|(_, db)| db.parse().ok())
        .unwrap_or(0)
}

/// Refuse to flush `db` when it is the database `VALKEY_URL` itself selects (the shared one every
/// other test uses).
fn assert_private_db(db: u32) {
    let shared = db_of_url(&std::env::var("VALKEY_URL").unwrap());
    assert_ne!(
        db, shared,
        "refusing to FLUSHDB the shared database {shared}"
    );
}

#[test]
fn db_of_url_reads_the_selected_database() {
    assert_eq!(db_of_url("redis://127.0.0.1:6379/0"), 0);
    assert_eq!(db_of_url("redis://u:p@h:6379/13?x=1"), 13);
    assert_eq!(db_of_url("redis://h:6379"), 0);
}

#[test]
#[should_panic(expected = "refusing to FLUSHDB")]
fn the_shared_database_is_never_flushed() {
    let Some(_) = live_store() else {
        panic!("refusing to FLUSHDB (no live store)");
    };
    assert_private_db(db_of_url(&std::env::var("VALKEY_URL").unwrap()));
}

/// An independent upstream client on database `db`, emptied first.
fn fresh_db_client(db: u32) -> redis::Connection {
    assert_private_db(db);
    let mut c = redis::Client::open(url_for_db(db).as_str())
        .and_then(|c| c.get_connection())
        .unwrap();
    redis::cmd("FLUSHDB").query::<()>(&mut c).unwrap();
    c
}

/// A namespace marked NEWER than this build is REFUSED at open, and left as found: an older build
/// on a newer keyspace would not know what the newer schema did to it.
#[test]
fn a_namespace_newer_than_this_build_is_refused() {
    let Some(_) = live_store() else { return };
    let mut up = fresh_db_client(11);
    let newer = SCHEMA_VERSION + 1;
    redis::cmd("SET")
        .arg("busbar:schema")
        .arg(newer)
        .query::<()>(&mut up)
        .unwrap();
    let err = match ValkeyStore::connect(&url_for_db(11)) {
        Ok(_) => panic!("connect() must refuse a namespace marked v{newer}"),
        Err(e) => e.to_string(),
    };
    assert!(
        err.contains(&format!(
            "schema v{newer} is newer than this build (v{SCHEMA_VERSION}); refusing to open"
        )),
        "{err}"
    );
    let marker: i64 = redis::cmd("GET")
        .arg("busbar:schema")
        .query(&mut up)
        .unwrap();
    assert_eq!(marker, newer, "the marker must not be rewritten");
    redis::cmd("FLUSHDB").query::<()>(&mut up).unwrap();
}

/// A namespace marked OLDER than v6 is REFUSED, never wiped: `migrate()` has no in-place path for
/// it, and the old wipe also destroyed a live v6/v7 namespace whose marker had merely been lost.
/// Seeds a refund-shaped usage row (`billable_requests == 0`, `requests > 0`), forces a v5 marker
/// and requires `connect()` to error, say nothing was changed, and leave the row and marker alone.
#[test]
#[ignore]
fn a_pre_v6_namespace_is_refused_not_wiped_and_keeps_refund_shaped_data() {
    let Some(_) = live_store() else { return };
    let mut up = fresh_db_client(13);
    let bucket = "vk_migrate_v6_refund_shaped";
    let row_key = format!("busbar:usage:{bucket}:1700000000");
    redis::cmd("SET")
        .arg(&row_key)
        .arg("{\"requests\":3,\"billable_requests\":0,\"models\":[]}")
        .query::<()>(&mut up)
        .unwrap();
    redis::cmd("SET")
        .arg("busbar:schema")
        .arg(5i64)
        .query::<()>(&mut up)
        .unwrap();

    let err = match ValkeyStore::connect(&url_for_db(13)) {
        Ok(_) => panic!("connect() must refuse a namespace marked v5"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("busbar:schema"), "names the marker: {err}");
    assert!(
        err.contains("= 5") || err.contains("is 5"),
        "names the version: {err}"
    );
    assert!(
        err.contains("NOTHING was changed"),
        "says nothing changed: {err}"
    );

    let still: Option<String> = redis::cmd("GET").arg(&row_key).query(&mut up).unwrap();
    assert!(still.is_some(), "the usage row must survive the refusal");
    let marker: i64 = redis::cmd("GET")
        .arg("busbar:schema")
        .query(&mut up)
        .unwrap();
    assert_eq!(marker, 5, "the marker must not be rewritten");
    redis::cmd("FLUSHDB").query::<()>(&mut up).unwrap();
}

/// A namespace holding `busbar:*` keys but NO schema marker (operator DEL, partial restore) is
/// refused and every seeded key survives -- the old code read it as v0 and wiped it.
#[test]
#[ignore]
fn a_namespace_with_keys_but_no_marker_refuses_to_connect_and_keeps_every_key() {
    let Some(_) = live_store() else { return };
    let mut up = fresh_db_client(12);
    let seeded = [
        "busbar:key:vk_no_marker",
        "busbar:usage:vk_no_marker:1700000000",
        "busbar:keys",
        "busbar:cred:vk_SECRETID_no_marker:aws:slot",
    ];
    for k in seeded {
        redis::cmd("SET")
            .arg(k)
            .arg("x")
            .query::<()>(&mut up)
            .unwrap();
    }

    let err = match ValkeyStore::connect(&url_for_db(12)) {
        Ok(_) => panic!("connect() must refuse a keyed namespace with no marker"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("missing"), "says the marker is missing: {err}");
    assert!(
        err.contains("NOTHING was changed"),
        "says nothing changed: {err}"
    );
    let sample = err
        .split_once("holds other `busbar:*` keys (e.g. ")
        .and_then(|(_, rest)| rest.split_once("); "))
        .map(|(sample, _)| sample)
        .unwrap_or_else(|| panic!("names a sample of key prefixes: {err}"));
    assert!(
        (1..=3).contains(&sample.split(", ").count()),
        "at most 3 sample prefixes: {err}"
    );
    assert!(!err.contains("4 other"), "no total count: {err}");

    assert!(
        !err.contains("SECRETID"),
        "no id may leak into the error: {err}"
    );
    for k in seeded {
        let n: i64 = redis::cmd("EXISTS").arg(k).query(&mut up).unwrap();
        assert_eq!(n, 1, "{k} must survive the refusal");
    }
    let marker: Option<i64> = redis::cmd("GET")
        .arg("busbar:schema")
        .query(&mut up)
        .unwrap();
    assert_eq!(
        marker, None,
        "no marker may be written over a namespace we refused"
    );
    redis::cmd("FLUSHDB").query::<()>(&mut up).unwrap();
}

/// The `RecordStore` contract conformance suite, this crate's own copy (`src/tests/store_conformance.rs`
/// — see its header for provenance): every ruling the suite offers, wired against the live Valkey.
///
/// Fixtures are namespaced per process AND per check, and cleaned first. Per-process because this
/// runs against a SHARED live Valkey that is not flushed between tests; per-check because these run
/// in parallel and the cleanup clears every id in the namespace it is given, so one shared namespace
/// would have each check deleting the others' rows mid-run.
#[path = "tests/store_conformance.rs"]
mod store_conformance;

/// The store v3 slots (`StoreSlots`): the durable `op_id` dedupe, the plane-record append and the
/// kernel's records, and the v9 upgrade.
mod slots_tests;

/// A proxy that holds one client mid-op, for deterministic interleavings.
mod interleave;

mod conformance {
    use super::store_conformance::conf;
    use super::{live_store, Raw, ValkeyStore};

    fn ns(check: &str) -> String {
        format!("vk_c{}{}", std::process::id(), check)
    }

    /// Remove every row this suite is about to write, so a rerun (or a crashed prior run that left
    /// state behind) starts from the same place as a first run.
    fn reset(store: &ValkeyStore, ns: &str, seq: u64) {
        for id in conf::key_ids(ns) {
            let _ = store.purge_key_for_test(&id);
        }
        for id in conf::credential_ids(ns) {
            let _ = store.purge_credential_for_test(&id);
        }
        if seq != 0 {
            let _ = store.purge_audit_seq_for_test(seq);
        }
    }

    fn setup(check: &str, seq: u64) -> Option<(ValkeyStore, String)> {
        let store = live_store()?;
        let ns = ns(check);
        reset(&store, &ns, seq);
        Some((store, ns))
    }

    #[test]
    fn put_key_does_not_resurrect_a_tombstone() {
        let Some((store, ns)) = setup("put", 0) else {
            return;
        };
        conf::assert_put_key_does_not_resurrect_a_tombstone(&store, &ns);
    }

    #[test]
    fn delete_key_unknown_id_is_an_error() {
        let Some((store, ns)) = setup("del", 0) else {
            return;
        };
        conf::assert_delete_key_unknown_id_is_an_error(&store, &ns);
    }

    #[test]
    fn revoke_credential_unknown_id_is_an_error() {
        let Some((store, ns)) = setup("rev", 0) else {
            return;
        };
        conf::assert_revoke_credential_unknown_id_is_an_error(&store, &ns);
    }

    #[test]
    fn put_credential_requires_a_live_key() {
        let Some((store, ns)) = setup("own", 0) else {
            return;
        };
        conf::assert_put_credential_requires_a_live_key(&store, &ns);
    }

    #[test]
    fn put_key_with_credential_is_atomic() {
        let Some((store, ns)) = setup("mint", 0) else {
            return;
        };
        conf::assert_put_key_with_credential_is_atomic(&store, &ns);
    }

    #[test]
    fn plane_task_upsert_get_list() {
        let Some((store, ns)) = setup("ptask", 0) else {
            return;
        };
        conf::assert_plane_task_upsert_get_list(&store, &ns);
    }

    #[test]
    fn plane_event_chain_is_ordered_by_seq() {
        let Some((store, ns)) = setup("pchain", 0) else {
            return;
        };
        conf::assert_plane_event_chain_is_ordered_by_seq(&store, &ns);
    }

    #[test]
    fn plane_call_parents_enumerated() {
        let Some((store, ns)) = setup("pcall", 0) else {
            return;
        };
        conf::assert_plane_call_parents_enumerated(&store, &ns);
    }

    #[test]
    fn plane_demotion_upsert_list_delete() {
        let Some((store, ns)) = setup("pdem", 0) else {
            return;
        };
        conf::assert_plane_demotion_upsert_list_delete(&store, &ns);
    }

    #[test]
    fn plane_purge_honours_the_cutoff() {
        let _serialised = super::purge_guard();
        let Some((store, ns)) = setup("pcut", 0) else {
            return;
        };
        conf::assert_plane_purge_honours_the_cutoff(&store, &ns);
    }

    #[test]
    fn plane_purge_task_keeps_active_rows() {
        let _serialised = super::purge_guard();
        let Some((store, ns)) = setup("pkeep", 0) else {
            return;
        };
        conf::assert_plane_purge_task_keeps_active_rows(&store, &ns);
    }

    #[test]
    fn plane_token_is_single_use() {
        let Some((store, ns)) = setup("ptok", 0) else {
            return;
        };
        conf::assert_plane_token_is_single_use(&store, &ns);
    }

    /// The kind-wide purge has no namespace of its own, so two runs sharing one live Valkey each
    /// sweep the other's old rows too; the suite's windows are built to stay correct under that.
    /// Two concurrent runs against the SAME server must both complete.
    #[test]
    fn plane_purges_survive_two_interleaved_runs() {
        let _serialised = super::purge_guard();
        let Some(store) = live_store() else { return };
        let a = ns("ilvA");
        let b = ns("ilvB");
        std::thread::scope(|scope| {
            let x = scope.spawn(|| conf::assert_plane_purge_honours_the_cutoff(&store, &a));
            let y = scope.spawn(|| conf::assert_plane_purge_honours_the_cutoff(&store, &b));
            x.join().expect("run A must not panic");
            y.join().expect("run B must not panic");
        });
        std::thread::scope(|scope| {
            let x = scope.spawn(|| conf::assert_plane_purge_task_keeps_active_rows(&store, &a));
            let y = scope.spawn(|| conf::assert_plane_purge_task_keeps_active_rows(&store, &b));
            x.join().expect("run A must not panic");
            y.join().expect("run B must not panic");
        });
    }
}

/// An undecodable credential row FAILS the hydration delta, naming the row's key and never echoing
/// its value: skipping it silently would leave a credential missing with nothing said. The corrupt
/// row is planted in a database of its own, since the delta is a global scan.
#[test]
fn a_corrupt_credential_row_fails_the_delta_naming_its_key() {
    let Some(_) = live_store() else { return };
    let mut up = fresh_db_client(CORRUPT_ROW_DB);
    let store = ValkeyStore::connect(&url_for_db(CORRUPT_ROW_DB)).expect("connect");
    let key_id = uid("vk_delta_bad");
    store
        .put_key_with_credential(&vk(&key_id), &cred(&key_id, &uid("AKIA_DELTA_BAD"), 0))
        .unwrap();
    let row = cred_row_key(&key_id, "sigv4", 0);
    redis::cmd("SET")
        .arg(&row)
        .arg("CANARY-not-json")
        .query::<()>(&mut up)
        .unwrap();

    let e = store
        .list_credentials_since(0)
        .expect_err("one undecodable row fails the delta")
        .to_string();
    assert!(e.contains(&row), "names the row's key: {e}");
    assert!(!e.contains("CANARY"), "never echoes the value: {e}");
    redis::cmd("FLUSHDB").query::<()>(&mut up).unwrap();
}

/// The database the corrupt-row test owns.
const CORRUPT_ROW_DB: u32 = 7;

/// A refused transaction must not silently swallow the NEXT write on the same connection.
///
/// `redis::transaction` issues WATCH, runs the closure, and UNWATCHes only on the success path — a
/// closure returning `Err` skips it. This store keeps ONE connection behind a mutex and reuses it,
/// so the stale WATCH survives into the next operation. Every plain `pipe().atomic()...query(c)`
/// write here types its reply as `()`, and `FromRedisValue for ()` accepts the `Nil` that a dirtied
/// WATCH makes EXEC return — so the write is discarded and the call still reports `Ok(())`.
///
/// `add_denylist` is the sharp end: an operator revokes a leaked signed token, the store says it
/// worked, and the token keeps authenticating. This drives the exact sequence — a refused
/// `put_key` over a tombstone (which WATCHes the key's row), then another client dirties that key,
/// then a revocation on the original store which MUST land.
#[test]
fn a_refused_transaction_does_not_swallow_the_next_write() {
    let Some(store) = live_store() else { return };
    let id = uid("vk_watch");
    store.put_key(&vk(&id)).unwrap();
    store.delete_key(&id).unwrap();

    // A live write over the tombstone: refused, and the refusal is the path that used to leak the
    // WATCH on the key's row.
    store
        .put_key(&vk(&id))
        .expect_err("a live write over a tombstone must be refused");

    // Another client writes the watched key, dirtying it.
    store
        .with_conn(|c| {
            let row = format!("{KEY_PREFIX}{id}");
            let raw: String = c.get(&row)?;
            c.set::<_, _, ()>(&row, raw)
        })
        .unwrap();

    // The revocation must actually land. Before the fix this returned Ok and wrote nothing.
    let sub = format!("sub_leaked_{id}");
    store.add_denylist(&sub, "token leaked").unwrap();
    let denied = store.list_denylist().unwrap();
    assert!(
        denied.iter().any(|d| d == &sub),
        "add_denylist reported Ok but the subject is not denied -- a revoked token would still \
         authenticate"
    );

    store.purge_key_for_test(&id).unwrap();
}

// ── THE PLANE-RECORD VOCABULARY THESE TESTS SPEAK ─────────────────────────────────────────────
//
// busbar 1.6.0 collapsed the protocol-named durable methods (`put_task`, `append_mcp_call`,
// `put_mcp_demotion`, `redeem_ask_state`, …) onto eight kind-tagged verbs over an opaque body. Every
// property this file pinned on the old methods is still a property of the store, so the tests keep
// their names for the rows and reach the store through the verbs, with the sidecar each 1.6.0 plane
// writes (busbar-a2a `TaskRow::to_plane_record` / `TaskEventRow::to_plane_record`, the MCP plane's
// call and demotion records, the kernel's `ask` token kind). The bodies are opaque to the store: the
// row types below exist only so an assertion can read a field back.

use crate::legacy::rows::{Demotion as DemotionRow, Task as TaskRow, TaskEvent as TaskEventRow};
use busbar_contract::records::{PlaneRecord, PlaneSelector};

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq)]
struct CallRow {
    principal: String,
    seq: u64,
    ts: u64,
    server: String,
    tool: String,
    outcome: String,
    reason: String,
    tool_digest: String,
    pin_generation: u64,
    request_id: String,
    prev_hash: String,
    hash: String,
}

fn body<T: serde::Serialize>(row: &T) -> Vec<u8> {
    serde_json::to_vec(row).expect("encode a test row")
}

fn row<T: serde::de::DeserializeOwned>(body: &[u8]) -> T {
    serde_json::from_slice(body).expect("a body this suite wrote decodes as the row it wrote")
}

const TERMINAL: [&str; 4] = ["completed", "failed", "canceled", "rejected"];

/// The typed names, over the neutral verbs, for any `RecordStore`.
trait Vocab: RecordStore {
    fn put_task(&self, t: &TaskRow) -> RecordStoreResult<()> {
        self.upsert_plane_record(
            PlaneRecord {
                kind: "task".into(),
                id: t.task_id.clone(),
                parent: None,
                seq: 0,
                ts: t.updated_at,
                disposition: if TERMINAL.contains(&t.state.as_str()) {
                    PlaneDisposition::Terminal
                } else {
                    PlaneDisposition::Active
                },
                body: body(t),
            }
            .view(),
        )
    }
    fn get_task(&self, id: &str) -> RecordStoreResult<Option<TaskRow>> {
        Ok(self.get_plane_record("task", id)?.map(|b| row(&b)))
    }
    fn list_tasks(&self) -> RecordStoreResult<Vec<TaskRow>> {
        Ok(self
            .list_plane_records("task", &PlaneSelector::All)?
            .iter()
            .map(|b| row(b))
            .collect())
    }
    fn purge_tasks_before(&self, before: u64) -> RecordStoreResult<u64> {
        self.purge_plane_records(
            "task",
            before,
            busbar_contract::records::Retention::TerminalOnly,
        )
    }
    fn append_task_event(&self, e: &TaskEventRow) -> RecordStoreResult<()> {
        self.append_plane_record(
            PlaneRecord {
                kind: "task_event".into(),
                id: e.task_id.clone(),
                parent: Some(e.task_id.clone()),
                seq: e.seq,
                ts: e.ts,
                disposition: PlaneDisposition::Active,
                body: body(e),
            }
            .view(),
        )
    }
    fn list_task_events(&self, task_id: &str) -> RecordStoreResult<Vec<TaskEventRow>> {
        Ok(self
            .list_plane_records("task_event", &PlaneSelector::Parent(task_id.into()))?
            .iter()
            .map(|b| row(b))
            .collect())
    }
    fn append_mcp_call(&self, r: &CallRow) -> RecordStoreResult<()> {
        self.append_plane_record(
            PlaneRecord {
                kind: "call".into(),
                id: r.principal.clone(),
                parent: Some(r.principal.clone()),
                seq: r.seq,
                ts: r.ts,
                disposition: PlaneDisposition::Active,
                body: body(r),
            }
            .view(),
        )
    }
    fn list_mcp_calls(&self, principal: &str) -> RecordStoreResult<Vec<CallRow>> {
        Ok(self
            .list_plane_records("call", &PlaneSelector::Parent(principal.into()))?
            .iter()
            .map(|b| row(b))
            .collect())
    }
    fn list_mcp_call_principals(&self) -> RecordStoreResult<Vec<String>> {
        self.list_plane_record_parents("call")
    }
    fn purge_mcp_calls_before(&self, before: u64) -> RecordStoreResult<u64> {
        self.purge_plane_records_before("call", before)
    }
    fn put_mcp_demotion(&self, d: &DemotionRow) -> RecordStoreResult<()> {
        self.upsert_plane_record(
            PlaneRecord {
                kind: "demotion".into(),
                id: d.server.clone(),
                parent: None,
                seq: 0,
                ts: d.recorded_at,
                disposition: PlaneDisposition::Active,
                body: body(d),
            }
            .view(),
        )
    }
    fn list_mcp_demotions(&self) -> RecordStoreResult<Vec<DemotionRow>> {
        Ok(self
            .list_plane_records("demotion", &PlaneSelector::All)?
            .iter()
            .map(|b| row(b))
            .collect())
    }
    fn clear_mcp_demotion(&self, server: &str) -> RecordStoreResult<()> {
        self.delete_plane_record("demotion", server)
    }
    fn redeem_ask_state(&self, nonce: &str, expires_at: u64, now: u64) -> RecordStoreResult<bool> {
        self.redeem_plane_token("ask", nonce, expires_at, now)
    }
}

impl Vocab for ValkeyStore {}

/// Serialises EVERY test that purges a plane kind. `purge_plane_records_before(kind, before)` has no
/// namespace: against the SHARED live Valkey one test's sweep deletes another's rows whenever their
/// timestamps sit under the same cutoff, so a per-test `uid()` isolates nothing here. The ported
/// retention tests sweep up to ~1_000_001_000 and the conformance suite's own purge checks sweep
/// below 100_000 with rows just above it, so each can take the other's rows. One lock for all of them,
/// rather than disjoint bands, because a band picked today is inside SOME other purge's cutoff the
/// moment a third retention test is added.
static PURGE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn purge_guard() -> std::sync::MutexGuard<'static, ()> {
    PURGE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

// ── THE DURABLE MCP TOOL-CALL LOG (kind `call`) ────────────────────────────────────────────────
//
// The property under test is not "the write returned Ok" — the trait's default `append_plane_record`
// returns `Ok(())` and keeps nothing, so a write's return value is worthless as evidence of
// durability. The only honest way to know a deployment has durable call evidence is to READ IT
// BACK, and the only honest way to know it survives a deploy is to read it back on a NEW
// CONNECTION after the writing store is gone.

fn sample_call(principal: &str, seq: u64, ts: u64, prev_hash: &str, hash: &str) -> CallRow {
    CallRow {
        principal: principal.to_string(),
        seq,
        ts,
        server: "srv".to_string(),
        tool: "srv_read_file".to_string(),
        outcome: "dispatched".to_string(),
        reason: String::new(),
        tool_digest: format!("sha256:tool{seq}"),
        pin_generation: 3,
        request_id: format!("req-{seq}"),
        prev_hash: prev_hash.to_string(),
        hash: hash.to_string(),
    }
}

/// THE TEST THAT MATTERS. A round-trip on one live handle cannot distinguish a backend that wrote
/// to the server from one holding a HashMap behind the same trait. So this DROPS the store —
/// closing its connection entirely — then connects a genuinely new one and verifies the
/// per-principal hash chain still links from what the server hands back.
#[test]
fn an_mcp_call_chain_survives_dropping_the_store_and_reconnecting() {
    let Some(store) = live_store() else { return };
    let p = uid("vk_mcp_restart");
    // Appended out of order: the read must come back in chain order regardless.
    store
        .append_mcp_call(&sample_call(&p, 2, 2_000_000_200, "h1", "h2"))
        .unwrap();
    store
        .append_mcp_call(&sample_call(&p, 1, 2_000_000_100, "", "h1"))
        .unwrap();
    store
        .append_mcp_call(&sample_call(&p, 3, 2_000_000_300, "h2", "h3"))
        .unwrap();
    drop(store);

    let Some(reopened) = live_store() else { return };
    let got = reopened.list_mcp_calls(&p).unwrap();
    assert_eq!(
        got.len(),
        3,
        "the call log must survive a reconnect; got {} records back, which is the \
         accept-and-keep-nothing behaviour this backend exists to replace",
        got.len()
    );
    assert_eq!(got[0].prev_hash, "", "seq 1 opens the chain");
    for w in got.windows(2) {
        assert_eq!(
            w[1].prev_hash, w[0].hash,
            "the per-principal chain must still link after a reconnect: seq {} carries prev_hash \
             {:?} but seq {} persisted hash {:?}",
            w[1].seq, w[1].prev_hash, w[0].seq, w[0].hash
        );
    }
    assert_eq!(got.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![1, 2, 3]);
    assert_eq!(got[2].tool_digest, "sha256:tool3");
    assert_eq!(got[2].request_id, "req-3");
    assert_eq!(got[1].tool, "srv_read_file");
    assert_eq!(got[1].pin_generation, 3);
}

/// The boot enumeration: a restart has to resume a chain for a principal this process has not yet
/// seen, so the store must be able to name every principal holding records — exactly once.
#[test]
fn mcp_call_principals_are_enumerable_after_a_reconnect() {
    let Some(store) = live_store() else { return };
    let a = uid("vk_mcp_enum_a");
    let b = uid("vk_mcp_enum_b");
    store
        .append_mcp_call(&sample_call(&a, 1, 2_000_000_100, "", "a1"))
        .unwrap();
    store
        .append_mcp_call(&sample_call(&b, 1, 2_000_000_100, "", "b1"))
        .unwrap();
    store
        .append_mcp_call(&sample_call(&a, 2, 2_000_000_101, "a1", "a2"))
        .unwrap();
    drop(store);

    let Some(reopened) = live_store() else { return };
    let principals = reopened.list_mcp_call_principals().unwrap();
    for want in [&a, &b] {
        assert_eq!(
            principals.iter().filter(|p| *p == want).count(),
            1,
            "{want} must be enumerable after a reconnect, exactly once"
        );
    }
    assert_eq!(reopened.list_mcp_calls(&a).unwrap().len(), 2);
    assert_eq!(reopened.list_mcp_calls(&b).unwrap().len(), 1);
    assert!(
        reopened
            .list_mcp_calls(&uid("vk_mcp_absent"))
            .unwrap()
            .is_empty(),
        "a principal with no records reads back empty, not an error"
    );
}

/// Retention must ACTUALLY DELETE and report a real count — a purge that returns a number it did
/// not perform is worse than one that reports nothing purged. It must also retire the principal
/// from the boot enumeration once its chain is empty.
#[test]
fn purge_mcp_calls_before_deletes_and_returns_a_real_count() {
    let _serialised = purge_guard();
    let Some(store) = live_store() else { return };
    let p = uid("vk_mcp_purge");
    store
        .append_mcp_call(&sample_call(&p, 1, 1_000_000_100, "", "h1"))
        .unwrap();
    store
        .append_mcp_call(&sample_call(&p, 2, 1_000_000_200, "h1", "h2"))
        .unwrap();
    store
        .append_mcp_call(&sample_call(&p, 3, 1_000_000_300, "h2", "h3"))
        .unwrap();

    let purged = store.purge_mcp_calls_before(1_000_000_200).unwrap();
    assert!(
        purged >= 1,
        "purge must report rows it actually removed; got {purged}"
    );
    assert_eq!(
        store
            .list_mcp_calls(&p)
            .unwrap()
            .iter()
            .map(|r| r.seq)
            .collect::<Vec<_>>(),
        vec![2, 3],
        "rows at or after the cutoff must remain — `before` is strictly less-than, so the row \
         exactly at the cutoff is kept"
    );
    assert!(store.list_mcp_call_principals().unwrap().contains(&p));

    let rest = store.purge_mcp_calls_before(1_000_001_000).unwrap();
    assert!(
        rest >= 2,
        "the remaining two rows must actually be removed; got {rest}"
    );
    assert!(store.list_mcp_calls(&p).unwrap().is_empty());
    assert!(
        !store.list_mcp_call_principals().unwrap().contains(&p),
        "a principal whose chain is now empty must leave the boot enumeration, or a restart keeps \
         resuming a chain with nothing in it"
    );
}

/// A record arriving on a `(principal, seq)` that already has one is settled the way the contract
/// settles it: IDENTICAL is the retry and succeeds; DIFFERENT is a forked or tampered log and is an
/// error. Overwriting would destroy the second case instead of reporting it.
#[test]
fn a_replayed_mcp_call_is_idempotent_but_a_forked_one_is_refused() {
    let Some(store) = live_store() else { return };
    let p = uid("vk_mcp_replay");

    let rec = sample_call(&p, 1, 2_000_000_100, "", "h1");
    store.append_mcp_call(&rec).unwrap();
    store
        .append_mcp_call(&rec)
        .expect("an identical replay is the at-least-once retry and must succeed");
    assert_eq!(
        store.list_mcp_calls(&p).unwrap().len(),
        1,
        "a replay must not duplicate the row"
    );

    let forked = sample_call(&p, 1, 2_000_000_100, "", "h2-second-writer");
    let err = store
        .append_mcp_call(&forked)
        .expect_err("a different record at an occupied (principal, seq) is a fork and must error");
    assert!(
        !format!("{err}").contains("h2-second-writer"),
        "the error must not echo stored content back"
    );
    assert_eq!(
        store.list_mcp_calls(&p).unwrap()[0].hash,
        "h1",
        "the refused fork must not have overwritten the record already on record"
    );

    // A differing payload under an identical sidecar is a fork too, not a silent accept.
    let mut tampered = sample_call(&p, 1, 2_000_000_100, "", "h1");
    tampered.tool = "srv_other_tool".to_string();
    store
        .append_mcp_call(&tampered)
        .expect_err("a payload that differs under an identical sidecar is a fork and must error");
    // And a differing SIDECAR under an identical payload (a different ts at the same position).
    let mut moved = PlaneRecord {
        kind: "call".into(),
        id: p.clone(),
        parent: Some(p.clone()),
        seq: 1,
        ts: 2_000_000_101,
        disposition: PlaneDisposition::Active,
        body: body(&rec),
    };
    store
        .append_plane_record(moved.view())
        .expect_err("a record whose ts differs at an occupied position is a fork");
    moved.ts = 2_000_000_100;
    store
        .append_plane_record(moved.view())
        .expect("the same sidecar and body is the identical replay");
}

/// A busbar key id is caller-visible and may itself contain a colon, so retention must still find
/// and retire a principal whose id does — a separator that can occur in the data is a parser that
/// silently mis-splits, and the failure would surface as a purge that quietly removed nothing.
#[test]
fn retention_still_finds_a_principal_whose_id_contains_the_separator_characters() {
    let _serialised = purge_guard();
    let Some(store) = live_store() else { return };
    let p = format!("{}:with:colons", uid("vk_mcp_sep"));
    store
        .append_mcp_call(&sample_call(&p, 1, 1_000_000_100, "", "h1"))
        .unwrap();
    assert_eq!(store.list_mcp_calls(&p).unwrap().len(), 1);
    let purged = store.purge_mcp_calls_before(1_000_000_200).unwrap();
    assert!(
        purged >= 1,
        "the colon-bearing principal's record must actually be purged"
    );
    assert!(
        store.list_mcp_calls(&p).unwrap().is_empty(),
        "a principal id containing the key-prefix separator must still purge correctly"
    );
    assert!(!store.list_mcp_call_principals().unwrap().contains(&p));
}

// ── THE DURABLE A2A TASK STORE (kinds `task` and `task_event`) ──────────────────────────────────
//
// A2A is async by design: a task spans turns, can sit interrupted waiting on a human, and can
// outlive the process that started it. So the property under test is never "the upsert returned
// Ok" — the trait's defaults keep nothing and answer every read empty. The tests that can DROP the
// store and reconnect do so; the rest assert counts those defaults could never produce.

/// Timestamps are BANDED. The task purge is GLOBAL by `(disposition, ts)`, so every task this file
/// writes BELOW the band top belongs to the purge tests (which hold [`purge_guard`]); every other
/// task test writes ABOVE it.
const TASK_PURGE_BAND_TOP: u64 = 1_000_100_000;
const TASK_LIVE_TS: u64 = 2_000_000_000;

fn sample_task(task_id: &str, state: &str, updated_at: u64) -> TaskRow {
    TaskRow {
        task_id: task_id.to_string(),
        context_id: format!("ctx-{task_id}"),
        principal: "vk_a".to_string(),
        direction: "inbound".to_string(),
        state: state.to_string(),
        agent_id: "planner".to_string(),
        artifact_cursor: 4,
        push_callback: "https://caller.example/push".to_string(),
        created_at: TASK_LIVE_TS,
        updated_at,
    }
}

fn sample_event(task_id: &str, seq: u64, kind: &str, prev_hash: &str, hash: &str) -> TaskEventRow {
    TaskEventRow {
        task_id: task_id.to_string(),
        seq,
        ts: TASK_LIVE_TS + seq,
        kind: kind.to_string(),
        context_id: format!("ctx-{task_id}"),
        principal: "vk_a".to_string(),
        agent_id: "planner".to_string(),
        state: "working".to_string(),
        request_id: format!("req-{seq}"),
        prev_hash: prev_hash.to_string(),
        hash: hash.to_string(),
    }
}

/// Each test owns its own task ids and clears them first — the task row AND its chain.
fn reset_tasks(store: &ValkeyStore, task_ids: &[&str]) {
    for id in task_ids {
        store.delete_plane_record("task", id).expect("clear task");
        store
            .delete_plane_record("task_event", id)
            .expect("clear chain");
    }
}

/// Own the whole low band: a previous run's (or the conformance suite's) leftovers would otherwise be
/// counted by the exact-count assertions the purge tests make. Caller holds [`purge_guard`].
///
/// Reads the retention index itself, never the bodies: retention sweeps by the SIDECAR `ts`, and a
/// body's own `updated_at` need not agree with it (the conformance suite's task bodies all say
/// 1_700_000_100 while their sidecars sit in this band) — clearing by the body would leave exactly
/// the rows the sweep then counts.
fn clear_purge_band(store: &ValkeyStore) {
    let byts = format!("busbar:plane:{}:byts", hex(b"task"));
    let fields: Vec<String> = store
        .with_conn(|c| c.zrangebyscore(&byts, "-inf", format!("({TASK_PURGE_BAND_TOP}")))
        .expect("read the purge band");
    let ids: Vec<&str> = fields
        .iter()
        .filter_map(|f| f.split_once(':').map(|(_, id)| id))
        .collect();
    reset_tasks(store, &ids);
}

/// THE TEST THAT MATTERS: an in-flight task, read back off the server on a NEW connection after the
/// writing store is gone.
#[test]
fn an_in_flight_task_survives_dropping_the_store_and_reconnecting() {
    let Some(store) = live_store() else { return };
    let (t1, t2) = ("t_vk_restart_1", "t_vk_restart_2");
    reset_tasks(&store, &[t1, t2]);
    store
        .put_task(&sample_task(t1, "working", TASK_LIVE_TS + 200))
        .unwrap();
    let mut interrupted = sample_task(t1, "input-required", TASK_LIVE_TS + 300);
    interrupted.artifact_cursor = 11;
    store.put_task(&interrupted).unwrap();
    store
        .put_task(&sample_task(t2, "submitted", TASK_LIVE_TS + 210))
        .unwrap();
    drop(store);

    let reopened = live_store().expect("reconnect");
    let got = reopened
        .get_task(t1)
        .unwrap()
        .expect("an in-flight task must survive a restart");
    assert_eq!(
        got, interrupted,
        "every field must round-trip, and the row read back must be the SECOND write"
    );
    let ids = reopened
        .list_tasks()
        .unwrap()
        .into_iter()
        .filter(|t| t.task_id == t1 || t.task_id == t2)
        .map(|t| t.task_id)
        .collect::<Vec<_>>();
    assert_eq!(
        ids,
        vec![t1, t2],
        "the upsert replaces by id, never appends — and the listing is deterministic (by id)"
    );
    assert!(
        reopened
            .get_task("t_vk_nonexistent_task")
            .unwrap()
            .is_none(),
        "an unknown task id reads back None, not an error"
    );
    reset_tasks(&reopened, &[t1, t2]);
}

/// The listing is deliberately UNFILTERED: the boot rehydrate wants the active rows, retention the
/// terminal ones and the scoped listing one principal's.
#[test]
fn list_tasks_returns_every_row_including_terminal_ones_after_a_reconnect() {
    let Some(store) = live_store() else { return };
    let ids = [
        "t_vk_list_a_working",
        "t_vk_list_b_interrupted",
        "t_vk_list_c_completed",
        "t_vk_list_d_failed",
    ];
    reset_tasks(&store, &ids);
    for (id, state) in ids
        .iter()
        .zip(["working", "input-required", "completed", "failed"])
    {
        store
            .put_task(&sample_task(id, state, TASK_LIVE_TS + 200))
            .unwrap();
    }
    drop(store);

    let reopened = live_store().expect("reconnect");
    let mine = reopened
        .list_tasks()
        .unwrap()
        .into_iter()
        .filter(|t| ids.contains(&t.task_id.as_str()))
        .map(|t| t.task_id)
        .collect::<Vec<_>>();
    assert_eq!(
        mine,
        ids.to_vec(),
        "terminal rows are returned too, every row survives a reconnect, and the order is \
         deterministic"
    );
    reset_tasks(&reopened, &ids);
}

/// The per-task provenance chain, read back after a reconnect. Never calls `put_task`: an event and
/// the first task upsert are independent write-throughs with no ordering between them.
#[test]
fn a_task_event_chain_survives_a_reconnect_and_still_links() {
    let Some(store) = live_store() else { return };
    let (t1, t2) = ("t_vk_chain_1", "t_vk_chain_2");
    reset_tasks(&store, &[t1, t2]);
    store
        .append_task_event(&sample_event(t1, 1, "task.submitted", "", "e1"))
        .unwrap();
    store
        .append_task_event(&sample_event(t1, 2, "task.working", "e1", "e2"))
        .unwrap();
    store
        .append_task_event(&sample_event(t1, 3, "task.interrupted", "e2", "e3"))
        .unwrap();
    store
        .append_task_event(&sample_event(t2, 1, "task.submitted", "", "f1"))
        .unwrap();
    drop(store);

    let reopened = live_store().expect("reconnect");
    let got = reopened.list_task_events(t1).unwrap();
    assert_eq!(
        got.len(),
        3,
        "the provenance chain must survive a reconnect"
    );
    assert_eq!(
        got.iter().map(|e| e.seq).collect::<Vec<_>>(),
        vec![1, 2, 3],
        "oldest-first by seq, which is the order the chain verifier reads"
    );
    assert_eq!(got[0].prev_hash, "", "seq 1 opens the chain");
    for w in got.windows(2) {
        assert_eq!(
            w[1].prev_hash, w[0].hash,
            "the per-task chain must still link"
        );
    }
    assert_eq!(got[2].kind, "task.interrupted");
    assert_eq!(got[2].request_id, "req-3");
    assert_eq!(got[1].context_id, format!("ctx-{t1}"));
    assert_eq!(got[1].ts, TASK_LIVE_TS + 2);
    assert_eq!(reopened.list_task_events(t2).unwrap().len(), 1);
    assert!(
        reopened
            .list_task_events("t_vk_unknown_chain")
            .unwrap()
            .is_empty(),
        "a task with no events reads back empty, not an error"
    );
    // A task's chain and the task row share the identity; the chain listing names only children.
    reopened
        .put_task(&sample_task(t1, "working", TASK_LIVE_TS + 9))
        .unwrap();
    assert_eq!(reopened.list_task_events(t1).unwrap().len(), 3);
    assert_eq!(
        reopened
            .list_plane_record_parents("task_event")
            .unwrap()
            .iter()
            .filter(|p| *p == t1)
            .count(),
        1
    );
    reset_tasks(&reopened, &[t1, t2]);
}

/// A replayed `(task_id, seq)`: the IDENTICAL event is the at-least-once retry and is success with
/// no duplicate; a DIFFERENT event at that seq is REFUSED as a fork. This one changed on purpose in
/// 1.6.0: the v6 typed method upserted a corrected event, and 1.6.0 has ONE append verb for every
/// chain kind, whose contract is the fork refusal (the same change store-sqlite made).
#[test]
fn a_replayed_task_event_is_idempotent_and_a_different_one_is_a_fork() {
    let Some(store) = live_store() else { return };
    let t = "t_vk_replay_event";
    reset_tasks(&store, &[t]);

    let e = sample_event(t, 1, "task.submitted", "", "e1");
    store.append_task_event(&e).unwrap();
    store
        .append_task_event(&e)
        .expect("an identical replay must succeed, not be rejected as a fork");
    assert_eq!(store.list_task_events(t).unwrap().len(), 1);

    let mut corrected = sample_event(t, 1, "task.submitted", "", "e1-corrected");
    corrected.state = "submitted".to_string();
    store
        .append_task_event(&corrected)
        .expect_err("a different event at an occupied seq is a fork");
    let got = store.list_task_events(t).unwrap();
    assert_eq!(got.len(), 1, "a refused fork appends nothing");
    assert_eq!(got[0].hash, "e1", "and overwrites nothing");
    reset_tasks(&store, &[t]);
}

/// Retention drops TERMINAL rows only, strictly older than the cutoff, and returns a count it
/// actually performed. The terminal/active split is the helper's typed disposition (the store never
/// reads the state text), so the odd state names only vary the Active rows.
#[test]
fn purge_tasks_before_drops_only_terminal_rows_and_returns_a_real_count() {
    let _guard = purge_guard();
    let Some(store) = live_store() else { return };
    clear_purge_band(&store);

    let old = 1_000_000_100;
    for state in ["completed", "failed", "canceled", "rejected"] {
        store
            .put_task(&sample_task(&format!("t_vk_purge_old_{state}"), state, old))
            .unwrap();
    }
    for state in [
        "input-required",
        "auth-required",
        "working",
        "submitted",
        "unrecognised-state",
        "Completed",
    ] {
        store
            .put_task(&sample_task(&format!("t_vk_purge_old_{state}"), state, old))
            .unwrap();
    }
    store
        .put_task(&sample_task(
            "t_vk_purge_at_cutoff",
            "completed",
            1_000_000_200,
        ))
        .unwrap();
    store
        .put_task(&sample_task("t_vk_purge_newer", "completed", 1_000_000_300))
        .unwrap();

    let purged = store.purge_tasks_before(1_000_000_200).unwrap();
    assert_eq!(
        purged, 4,
        "only the four TERMINAL rows strictly older than the cutoff go, and the count must be one \
         actually performed"
    );
    let mut left = store
        .list_tasks()
        .unwrap()
        .into_iter()
        .filter(|t| t.updated_at < TASK_PURGE_BAND_TOP)
        .map(|t| t.task_id)
        .collect::<Vec<_>>();
    left.sort();
    assert_eq!(
        left,
        vec![
            "t_vk_purge_at_cutoff",
            "t_vk_purge_newer",
            "t_vk_purge_old_Completed",
            "t_vk_purge_old_auth-required",
            "t_vk_purge_old_input-required",
            "t_vk_purge_old_submitted",
            "t_vk_purge_old_unrecognised-state",
            "t_vk_purge_old_working",
        ],
        "a task the helper stored as Active (its disposition, not its state text, is what the \
         store reads) is never dropped by retention, and a row exactly at the cutoff is kept"
    );
    assert_eq!(
        store.purge_tasks_before(1_000_000_200).unwrap(),
        0,
        "re-running the same purge removes nothing"
    );
    clear_purge_band(&store);
}

/// Deleting a task takes its provenance chain with it, and no other task's.
#[test]
fn deleting_a_task_takes_its_provenance_chain_with_it_and_no_other() {
    let Some(store) = live_store() else { return };
    let (gone, stays) = ("t_vk_del_cascade_gone", "t_vk_del_cascade_stays");
    reset_tasks(&store, &[gone, stays]);
    for t in [gone, stays] {
        store
            .put_task(&sample_task(t, "working", 4_000_000_100))
            .unwrap();
        store
            .append_task_event(&sample_event(t, 1, "task.submitted", "", &format!("{t}1")))
            .unwrap();
    }
    store.delete_plane_record("task", gone).unwrap();
    assert!(store.get_task(gone).unwrap().is_none());
    assert!(
        store.list_task_events(gone).unwrap().is_empty(),
        "the deleted task's events go with it"
    );
    let parents = store.list_plane_record_parents("task_event").unwrap();
    assert!(!parents.contains(&gone.to_string()));
    assert_eq!(
        store.list_task_events(stays).unwrap().len(),
        1,
        "another task's chain is untouched"
    );
    reset_tasks(&store, &[gone, stays]);
}

/// A purged task takes ITS provenance chain with it, and no other task's.
#[test]
fn purging_a_task_takes_its_provenance_chain_with_it_and_no_other() {
    let _guard = purge_guard();
    let Some(store) = live_store() else { return };
    clear_purge_band(&store);

    let (gone, stays) = ("t_vk_cascade_gone", "t_vk_cascade_stays");
    reset_tasks(&store, &[gone, stays]);
    store
        .put_task(&sample_task(gone, "completed", 1_000_000_100))
        .unwrap();
    store
        .put_task(&sample_task(stays, "working", 1_000_000_100))
        .unwrap();
    store
        .append_task_event(&sample_event(gone, 1, "task.submitted", "", "g1"))
        .unwrap();
    store
        .append_task_event(&sample_event(gone, 2, "task.completed", "g1", "g2"))
        .unwrap();
    store
        .append_task_event(&sample_event(stays, 1, "task.submitted", "", "s1"))
        .unwrap();

    assert_eq!(
        store.purge_tasks_before(1_000_000_200).unwrap(),
        1,
        "exactly the one terminal task in this band is swept"
    );
    assert!(
        store.list_task_events(gone).unwrap().is_empty(),
        "the purged task's events go with it"
    );
    assert!(
        !store
            .list_plane_record_parents("task_event")
            .unwrap()
            .contains(&gone.to_string()),
        "and its chain leaves the parent enumeration"
    );
    assert_eq!(
        store.list_task_events(stays).unwrap().len(),
        1,
        "another task's chain must be untouched by that purge"
    );
    reset_tasks(&store, &[gone, stays]);
    clear_purge_band(&store);
}

/// Two task ids differing ONLY IN CASE are two tasks, and the same for two chains.
#[test]
fn task_ids_differing_only_in_case_are_distinct_tasks() {
    let Some(store) = live_store() else { return };
    let (lower, upper) = ("t_vk_case_fold", "T_VK_CASE_FOLD");
    reset_tasks(&store, &[lower, upper]);
    store
        .put_task(&sample_task(lower, "working", TASK_LIVE_TS + 400))
        .unwrap();
    store
        .put_task(&sample_task(upper, "completed", TASK_LIVE_TS + 400))
        .unwrap();
    assert_eq!(store.get_task(lower).unwrap().unwrap().state, "working");
    assert_eq!(store.get_task(upper).unwrap().unwrap().state, "completed");
    store
        .append_task_event(&sample_event(lower, 1, "task.submitted", "", "l1"))
        .unwrap();
    store
        .append_task_event(&sample_event(upper, 1, "task.submitted", "", "u1"))
        .unwrap();
    assert_eq!(store.list_task_events(lower).unwrap()[0].hash, "l1");
    assert_eq!(store.list_task_events(upper).unwrap()[0].hash, "u1");
    reset_tasks(&store, &[lower, upper]);
}

/// A task id is a protocol-supplied opaque string, COLONS INCLUDED. The adversarial spellings: an id
/// that renders like another kind's key segment, and ids that differ only in where a colon falls.
#[test]
fn a_task_id_containing_the_key_separator_cannot_alias_another_tasks_chain() {
    let Some(store) = live_store() else { return };
    let victim = "t_vk_sep_victim";
    let attacker = "idx:t_vk_sep_victim";
    let (c1, c2) = ("t_vk_sep:a:b", "t_vk_sep:a");
    reset_tasks(&store, &[victim, attacker, c1, c2]);
    for (id, state) in [
        (victim, "working"),
        (attacker, "completed"),
        (c1, "failed"),
        (c2, "submitted"),
    ] {
        store
            .put_task(&sample_task(id, state, TASK_LIVE_TS + 500))
            .unwrap();
    }
    store
        .append_task_event(&sample_event(victim, 1, "task.submitted", "", "v1"))
        .unwrap();
    store
        .append_task_event(&sample_event(attacker, 1, "task.submitted", "", "a1"))
        .unwrap();
    assert_eq!(store.get_task(victim).unwrap().unwrap().state, "working");
    assert_eq!(
        store.get_task(attacker).unwrap().unwrap().state,
        "completed"
    );
    assert_eq!(store.get_task(c1).unwrap().unwrap().state, "failed");
    assert_eq!(store.get_task(c2).unwrap().unwrap().state, "submitted");
    assert_eq!(store.list_task_events(victim).unwrap()[0].hash, "v1");
    assert_eq!(store.list_task_events(attacker).unwrap()[0].hash, "a1");
    reset_tasks(&store, &[victim, attacker, c1, c2]);
}

/// A `u64` a signed column cannot hold is refused before any write, naming the method and field.
#[test]
fn a_u64_a_signed_column_cannot_hold_is_refused() {
    let Some(store) = live_store() else { return };
    let big = i64::MAX as u64 + 1;
    let kind = uid("k_unstorable");
    let rec = |seq: u64, ts: u64| PlaneRecord {
        kind: kind.clone(),
        id: "r1".into(),
        parent: Some("p1".into()),
        seq,
        ts,
        disposition: PlaneDisposition::Active,
        body: b"b".to_vec(),
    };
    for (field, r) in [("seq", rec(big, 1)), ("ts", rec(1, big))] {
        let e = store.append_plane_record(r.view()).unwrap_err().to_string();
        assert!(
            e.contains(&format!(
                "append_plane_record: {field} {big} exceeds the storable range"
            )),
            "{e}"
        );
        let e = store.upsert_plane_record(r.view()).unwrap_err().to_string();
        assert!(
            e.contains(&format!(
                "upsert_plane_record: {field} {big} exceeds the storable range"
            )),
            "{e}"
        );
    }
    assert!(store.get_plane_record(&kind, "r1").unwrap().is_none());
    assert!(store
        .list_plane_records(&kind, &PlaneSelector::All)
        .unwrap()
        .is_empty());

    let mut m = MeteringDelta {
        key_id: uid("vk_unstorable"),
        bucket: unique_bucket(20260803),
        model: "m".to_string(),
        provider: "p".to_string(),
        tokens_input: 1,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 0,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
        priced_from_ms: big,
        usage_units: Default::default(),
    };
    let e = store.add_metering(&m).unwrap_err().to_string();
    assert!(
        e.contains(&format!(
            "add_metering_batch: priced_from_ms {big} exceeds the storable range"
        )),
        "{e}"
    );
    m.priced_from_ms = 0;
    assert!(store.list_metering(m.bucket).unwrap().is_empty());
}

/// Every `u64` field of both rows round-trips at the full range the sidecar can hold (`i64::MAX`;
/// beyond it the write is refused, see `a_u64_a_signed_column_cannot_hold_is_refused`), `u64::MAX`
/// in the opaque body included, and ordering reads the exact `seq`.
#[test]
fn the_task_store_round_trips_the_full_u64_range() {
    let Some(store) = live_store() else { return };
    let t = "t_vk_full_range";
    reset_tasks(&store, &[t]);

    const TOP: u64 = i64::MAX as u64;
    let mut task = sample_task(t, "working", TOP);
    task.artifact_cursor = u64::MAX;
    task.created_at = u64::MAX;
    store.put_task(&task).unwrap();
    let got = store.get_task(t).unwrap().expect("the task must read back");
    assert_eq!(got.artifact_cursor, u64::MAX, "the cursor must not wrap");
    assert_eq!(got.updated_at, TOP);

    let mut event = sample_event(t, 1, "task.submitted", "", "e1");
    event.seq = TOP;
    event.ts = TOP;
    store.append_task_event(&event).unwrap();
    // A second event one below: past 2^53 the ZSET score cannot tell them apart, the order must
    // still be exact.
    let mut before = sample_event(t, 1, "task.working", "", "e0");
    before.seq = TOP - 1;
    before.ts = TOP;
    store.append_task_event(&before).unwrap();
    let events = store.list_task_events(t).unwrap();
    assert_eq!(
        events.iter().map(|e| e.seq).collect::<Vec<_>>(),
        vec![TOP - 1, TOP]
    );
    assert_eq!(events[1].ts, TOP);
    reset_tasks(&store, &[t]);
}

// ── THE DURABLE MCP DEMOTION RECORD AND THE SPENT-APPROVAL LEDGER ────────────────────────────
//
// Both are security state. The trait defaults keep no demotion and answer `false` to every
// redemption; what a backend that dropped either would cost is a quarantined upstream that gets the
// operator's approval back at the next restart, and a single-use human approval a second node of the
// fleet redeems again. Valkey is the backend a fleet reaches for FIRST.

/// THE LIVE STORE, OR A FAILURE — these cases must never skip. See the doc above.
fn require_live_store() -> ValkeyStore {
    let url = std::env::var("VALKEY_URL").unwrap_or_else(|_| {
        panic!(
            "VALKEY_URL is unset. These cases are the ONLY coverage of the durable MCP demotion \
             record and the spent-approval ledger on this backend; point this at a live Valkey, \
             e.g. redis://127.0.0.1:6379/0"
        )
    });
    ValkeyStore::connect(&url).expect("connect to the live Valkey")
}

/// Per-process namespacing: every test in this file shares ONE Valkey.
fn trust_ns(tag: &str) -> String {
    format!("{}_{}", tag, std::process::id())
}

const TRUST_NOW: u64 = 2_000_000_000;

fn demotion(server: &str, reason: &str, recorded_at: u64) -> DemotionRow {
    DemotionRow {
        server: server.to_string(),
        reason: reason.to_string(),
        recorded_at,
    }
}

/// Drop exactly this suite's own keys — never a blanket wipe.
fn reset_trust_state(store: &ValkeyStore, servers: &[&str], nonces: &[&str]) {
    for s in servers {
        store
            .clear_mcp_demotion(s)
            .expect("clear this test's own demotion");
    }
    for n in nonces {
        store
            .with_conn(|c| c.del::<_, ()>(plane::token_key("ask", n)))
            .expect("clear this test's own ledger entry");
    }
}

/// A DEMOTION OUTLIVES THE PROCESS THAT RECORDED IT, upserted to the latest reason, and a cleared
/// one stays cleared.
#[test]
fn a_demotion_survives_dropping_the_store_and_reconnecting() {
    let url = std::env::var("VALKEY_URL").unwrap_or_else(|_| {
        panic!("VALKEY_URL is unset; see require_live_store for why this must not skip")
    });
    let (a, b, c) = (
        trust_ns("srv_payments"),
        trust_ns("srv_search"),
        trust_ns("srv_mail"),
    );
    {
        let store = ValkeyStore::connect(&url).expect("connect");
        reset_trust_state(&store, &[&a, &b, &c], &[]);
        store
            .put_mcp_demotion(&demotion(&a, "tool-drift", TRUST_NOW))
            .unwrap();
        store
            .put_mcp_demotion(&demotion(&a, "digest-mismatch", TRUST_NOW + 10))
            .unwrap();
        store
            .put_mcp_demotion(&demotion(&b, "tool-drift", TRUST_NOW + 20))
            .unwrap();
        store
            .put_mcp_demotion(&demotion(&c, "tool-drift", TRUST_NOW + 30))
            .unwrap();
        store.clear_mcp_demotion(&c).unwrap();
        store
            .clear_mcp_demotion(&trust_ns("srv_never_demoted"))
            .expect("clearing a record that is not there is a no-op, not an error");
    }

    let reopened = ValkeyStore::connect(&url).expect("reconnect");
    let mut mine = reopened
        .list_mcp_demotions()
        .unwrap()
        .into_iter()
        .filter(|r| r.server == a || r.server == b || r.server == c)
        .collect::<Vec<_>>();
    mine.sort_by(|x, y| x.server.cmp(&y.server));
    let mut expect = vec![
        demotion(&a, "digest-mismatch", TRUST_NOW + 10),
        demotion(&b, "tool-drift", TRUST_NOW + 20),
    ];
    expect.sort_by(|x, y| x.server.cmp(&y.server));
    assert_eq!(
        mine, expect,
        "the boot read must put every recorded quarantine back in force, upserted to the LATEST \
         reason and WITHOUT the one a later agreeing observation cleared"
    );
    reset_trust_state(&reopened, &[&a, &b, &c], &[]);
}

/// Two registration ids that differ only in where a colon falls are two upstreams.
#[test]
fn server_ids_containing_separators_are_not_confusable() {
    let store = require_live_store();
    let (a, b) = (format!("{}:x", trust_ns("srv_sep")), trust_ns("srv_sep:x"));
    reset_trust_state(&store, &[&a, &b], &[]);
    store
        .put_mcp_demotion(&demotion(&a, "tool-drift", TRUST_NOW))
        .unwrap();
    store
        .put_mcp_demotion(&demotion(&b, "digest-mismatch", TRUST_NOW + 1))
        .unwrap();
    let mine = store
        .list_mcp_demotions()
        .unwrap()
        .into_iter()
        .filter(|r| r.server == a || r.server == b)
        .count();
    assert_eq!(
        mine, 2,
        "two ids that differ only in a colon's position are two upstreams"
    );
    reset_trust_state(&store, &[&a, &b], &[]);
}

/// THE SPENT-APPROVAL LEDGER ACROSS A RESTART, with the control that keeps it from being a blanket
/// refusal.
#[test]
fn a_reconnected_store_refuses_a_second_redemption_of_the_same_approval() {
    let url = std::env::var("VALKEY_URL")
        .unwrap_or_else(|_| panic!("VALKEY_URL is unset; this case must not skip"));
    let (spent, fresh) = (trust_ns("nonce_restart"), trust_ns("nonce_restart_other"));
    {
        let store = ValkeyStore::connect(&url).expect("connect");
        reset_trust_state(&store, &[], &[&spent, &fresh]);
        assert!(store
            .redeem_ask_state(&spent, TRUST_NOW + 900, TRUST_NOW)
            .unwrap());
    }
    let reopened = ValkeyStore::connect(&url).expect("reconnect");
    assert!(
        !reopened
            .redeem_ask_state(&spent, TRUST_NOW + 900, TRUST_NOW + 1)
            .unwrap(),
        "a restart handed a spent approval back"
    );
    assert!(
        reopened
            .redeem_ask_state(&fresh, TRUST_NOW + 900, TRUST_NOW + 2)
            .unwrap(),
        "a different approval is not the one that was spent"
    );
    // A token of ANOTHER kind with the same spelling is another token.
    assert!(reopened
        .redeem_plane_token("approval", &spent, TRUST_NOW + 900, TRUST_NOW + 3)
        .unwrap());
    let _ = reopened.with_conn(|c| c.del::<_, ()>(plane::token_key("approval", &spent)));
    reset_trust_state(&reopened, &[], &[&spent, &fresh]);
}

/// TWO CONNECTIONS ARE TWO NODES OF A FLEET.
#[test]
fn a_second_node_cannot_redeem_an_approval_the_first_already_spent() {
    let url = std::env::var("VALKEY_URL")
        .unwrap_or_else(|_| panic!("VALKEY_URL is unset; this case must not skip"));
    let nonce = trust_ns("nonce_fleet");
    let node_a = ValkeyStore::connect(&url).expect("node A connects");
    let node_b = ValkeyStore::connect(&url).expect("node B connects");
    reset_trust_state(&node_a, &[], &[&nonce]);
    assert!(node_a
        .redeem_ask_state(&nonce, TRUST_NOW + 900, TRUST_NOW)
        .unwrap());
    assert!(
        !node_b
            .redeem_ask_state(&nonce, TRUST_NOW + 900, TRUST_NOW)
            .unwrap(),
        "a second node redeemed an approval the first already spent"
    );
    reset_trust_state(&node_a, &[], &[&nonce]);
}

/// CONCURRENT REDEMPTION IS THE ATTACK: eight independent connections race through a barrier;
/// exactly one may win.
#[test]
fn exactly_one_of_many_racing_nodes_wins_the_redemption() {
    let url = std::env::var("VALKEY_URL")
        .unwrap_or_else(|_| panic!("VALKEY_URL is unset; this case must not skip"));
    let nonce = trust_ns("nonce_race");
    let cleanup = ValkeyStore::connect(&url).expect("connect");
    reset_trust_state(&cleanup, &[], &[&nonce]);
    drop(cleanup);

    let n = 8usize;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(n));
    let winners: usize = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..n)
            .map(|_| {
                let url = url.clone();
                let nonce = nonce.clone();
                let barrier = std::sync::Arc::clone(&barrier);
                scope.spawn(move || {
                    let node = ValkeyStore::connect(&url).expect("a racing node connects");
                    barrier.wait();
                    node.redeem_ask_state(&nonce, TRUST_NOW + 900, TRUST_NOW)
                        .expect("redeem") as usize
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).sum()
    });
    assert_eq!(
        winners, 1,
        "exactly one redemption may be the first; {winners} were"
    );
    let cleanup = ValkeyStore::connect(&url).expect("connect");
    reset_trust_state(&cleanup, &[], &[&nonce]);
}

/// THE LEDGER IS BOUNDED BY THE GRANT'S OWN LIFE, via the server's TTL.
#[test]
fn a_redeemed_entry_carries_a_ttl_bounded_by_the_approvals_own_life() {
    let store = require_live_store();
    let (short, long) = (trust_ns("nonce_ttl_short"), trust_ns("nonce_ttl_long"));
    reset_trust_state(&store, &[], &[&short, &long]);
    assert!(store
        .redeem_ask_state(&short, TRUST_NOW + 30, TRUST_NOW)
        .unwrap());
    assert!(store
        .redeem_ask_state(&long, TRUST_NOW + 10_000, TRUST_NOW)
        .unwrap());
    let ttl = |nonce: &str| -> i64 {
        store
            .with_conn(|c| c.ttl::<_, i64>(plane::token_key("ask", nonce)))
            .expect("TTL")
    };
    // The TTL is cleanup only: never shorter than the grant's life (the judgment is the stored
    // `expires_at` against the caller's `now`), and bounded by it plus a skew allowance.
    assert!(
        (31..=30 + 3_600).contains(&ttl(&short)),
        "got {}",
        ttl(&short)
    );
    assert!(
        (10_001..=10_000 + 3_600).contains(&ttl(&long)),
        "got {}",
        ttl(&long)
    );
    assert!(
        ttl(&long) > ttl(&short),
        "the TTL tracks the grant's remaining life"
    );
    reset_trust_state(&store, &[], &[&short, &long]);
}

/// A grant that outlives the ledger's TTL cap is recorded with NO expiry: capping it would let the
/// grant redeem again once the entry lapsed.
#[test]
fn a_grant_beyond_the_ttl_cap_is_recorded_without_expiry() {
    let store = require_live_store();
    let nonce = trust_ns("nonce_ttl_forever");
    reset_trust_state(&store, &[], &[&nonce]);
    let eleven_years = 11 * 365 * 86_400;
    assert!(store
        .redeem_ask_state(&nonce, TRUST_NOW + eleven_years, TRUST_NOW)
        .unwrap());
    let ttl: i64 = store
        .with_conn(|c| c.ttl::<_, i64>(plane::token_key("ask", &nonce)))
        .expect("TTL");
    assert_eq!(ttl, -1, "the entry must not expire");
    assert!(!store
        .redeem_ask_state(&nonce, TRUST_NOW + eleven_years, TRUST_NOW)
        .unwrap());
    reset_trust_state(&store, &[], &[&nonce]);
}

/// A stored entry is spent while its `expires_at` is at or after the CALLER'S `now`; only an entry
/// with `expires_at < now` is lapsed and redeems afresh (the server's clock plays no part).
#[test]
fn a_spent_entry_is_judged_against_the_callers_now() {
    let store = require_live_store();
    let nonce = trust_ns("nonce_judged");
    reset_trust_state(&store, &[], &[&nonce]);
    let exp = TRUST_NOW + 100;
    assert!(store.redeem_ask_state(&nonce, exp, TRUST_NOW).unwrap());
    assert!(!store.redeem_ask_state(&nonce, exp, TRUST_NOW + 50).unwrap());
    assert!(
        !store.redeem_ask_state(&nonce, exp, exp).unwrap(),
        "an entry whose expires_at equals now is still spent"
    );
    assert!(
        store.redeem_ask_state(&nonce, exp + 500, exp + 1).unwrap(),
        "an entry with expires_at < now is lapsed and redeems afresh"
    );
    assert!(
        !store.redeem_ask_state(&nonce, exp + 500, exp + 2).unwrap(),
        "and that fresh redemption is spent in turn"
    );
    reset_trust_state(&store, &[], &[&nonce]);
}

/// AN ALREADY-LAPSED APPROVAL IS STILL ANSWERED HONESTLY, with a bounded record.
#[test]
fn a_lapsed_approval_still_gets_a_truthful_answer_and_a_bounded_record() {
    let store = require_live_store();
    let nonce = trust_ns("nonce_lapsed");
    reset_trust_state(&store, &[], &[&nonce]);
    assert!(store
        .redeem_ask_state(&nonce, TRUST_NOW, TRUST_NOW + 60)
        .unwrap());
    let ttl: i64 = store
        .with_conn(|c| c.ttl::<_, i64>(plane::token_key("ask", &nonce)))
        .expect("TTL");
    assert!((2..=1 + 3_600).contains(&ttl), "got {ttl}");
    reset_trust_state(&store, &[], &[&nonce]);
}

/// THE FULL STORABLE RANGE (up to `i64::MAX`) round-trips for the demotion record too.
#[test]
fn the_demotion_record_round_trips_the_full_storable_range() {
    let store = require_live_store();
    let server = trust_ns("srv_range");
    reset_trust_state(&store, &[&server], &[]);
    store
        .put_mcp_demotion(&demotion(&server, "tool-drift", i64::MAX as u64))
        .unwrap();
    assert_eq!(
        store
            .list_mcp_demotions()
            .unwrap()
            .into_iter()
            .find(|r| r.server == server)
            .expect("the record must be there")
            .recorded_at,
        i64::MAX as u64
    );
    reset_trust_state(&store, &[&server], &[]);
}

/// `plane_token_live` — MULTI-USE, SPENDS NOTHING, and FAIL-CLOSED: live while the record is present,
/// Active and `now` has not passed `expires_at`; dead on each of the three failing, and asking twice
/// answers the same twice.
#[test]
fn plane_token_live_is_present_active_and_unexpired() {
    let store = require_live_store();
    let tok = trust_ns("push_tok");
    store.delete_plane_record("task", &tok).unwrap();
    assert!(
        !store
            .plane_token_live("task", &tok, TRUST_NOW + 10, TRUST_NOW)
            .unwrap(),
        "no record holds no capability"
    );
    let mut t = sample_task(&tok, "working", TASK_LIVE_TS + 1);
    store.put_task(&t).unwrap();
    for _ in 0..2 {
        assert!(store
            .plane_token_live("task", &tok, TRUST_NOW + 10, TRUST_NOW)
            .unwrap());
    }
    assert!(
        store
            .plane_token_live("task", &tok, TRUST_NOW + 10, TRUST_NOW + 10)
            .unwrap(),
        "`now` AT the deadline has not passed it"
    );
    assert!(
        !store
            .plane_token_live("task", &tok, TRUST_NOW + 10, TRUST_NOW + 11)
            .unwrap(),
        "a lapsed token is dead"
    );
    t.state = "completed".into();
    store.put_task(&t).unwrap();
    assert!(
        !store
            .plane_token_live("task", &tok, TRUST_NOW + 10, TRUST_NOW)
            .unwrap(),
        "a terminal record names finished work"
    );
    store.delete_plane_record("task", &tok).unwrap();
}

// ── 1.6.0 SHAPES: usage units, metering identity, key fields ──────────────────────────────────

/// Open (non-reserved) usage units round-trip beside the reserved four, per model, whatever
/// characters the unit and the model carry; and every counter is FLOORED at 0 as a refund lands,
/// so a refund larger than the counter never leaves a debt the next accrual pays back.
#[test]
fn usage_carries_open_units_and_floors_each_counter_at_zero() {
    use busbar_contract::records::{ModelTokensDelta, UNIT_INPUT, UNIT_OUTPUT};
    let Some(store) = live_store() else { return };
    let bucket = uid("vk_units");
    let delta = |model: &str, units: &[(&str, i64)], requests: i64| UsageDelta {
        requests,
        billable_requests: requests,
        models: vec![ModelTokensDelta {
            model: model.into(),
            usage_units: units.iter().map(|(u, n)| (u.to_string(), *n)).collect(),
        }],
    };
    store
        .add_usage(
            &bucket,
            1000,
            &delta(
                "m:1",
                &[(UNIT_INPUT, 10), (UNIT_OUTPUT, 4), ("tool:calls", 3)],
                2,
            ),
        )
        .unwrap();
    store
        .add_usage(
            &bucket,
            1000,
            &delta("m:1", &[(UNIT_INPUT, -25), ("tool:calls", 1)], -5),
        )
        .unwrap();
    store
        .add_usage(&bucket, 1000, &delta("m:1", &[(UNIT_INPUT, 3)], 1))
        .unwrap();
    let got = store.get_usage(&bucket, 1000).unwrap();
    assert_eq!(got.requests, 1, "2, then floored at 0, then +1");
    assert_eq!(got.models.len(), 1);
    let m = &got.models[0];
    assert_eq!(m.model, "m:1");
    assert_eq!(m.tier(UNIT_INPUT), 3, "10 - 25 floors at 0, then +3");
    assert_eq!(m.tier(UNIT_OUTPUT), 4);
    assert_eq!(m.usage_units.get("tool:calls"), Some(&4));

    // `put_usage` is an absolute set of the same shape, and reads back as itself.
    let mut ledger = got.clone();
    ledger.models[0].usage_units.insert("bytes".into(), 7);
    store.put_usage(&bucket, 2000, &ledger).unwrap();
    assert_eq!(store.get_usage(&bucket, 2000).unwrap(), ledger);
}

/// A v6 build's unfloored HINCRBY could leave a counter NEGATIVE. It always read as 0; the next add
/// must land on that 0, not pay the old debt back.
#[test]
fn a_legacy_negative_counter_is_added_to_as_the_zero_it_always_read_as() {
    let Some(store) = live_store() else { return };
    let bucket = uid("vk_negative");
    let k = usage_key(&bucket, 1000);
    store
        .with_conn(|c| c.hset::<_, _, _, ()>(&k, "requests", -7))
        .unwrap();
    assert_eq!(store.get_usage(&bucket, 1000).unwrap().requests, 0);
    store
        .add_usage(
            &bucket,
            1000,
            &UsageDelta {
                requests: 2,
                billable_requests: 0,
                models: vec![],
            },
        )
        .unwrap();
    assert_eq!(store.get_usage(&bucket, 1000).unwrap().requests, 2);
}

/// `priced_from_ms` joins the metering cell's identity (a rate-card edit SPLITS the day's cell), an
/// undated cell keeps the v6 row key so v6 and v7 writes of it are one cell, and open classes
/// accumulate beside the token columns.
#[test]
fn metering_splits_a_cell_at_a_price_change_and_carries_open_classes() {
    let Some(store) = live_store() else { return };
    let bucket = unique_bucket(20260926);
    let key_id = uid("vk_priced");
    let d = |priced_from_ms: u64, class_n: u64| MeteringDelta {
        key_id: key_id.clone(),
        bucket,
        model: "m".into(),
        provider: "p".into(),
        tokens_input: 1,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
        priced_from_ms,
        usage_units: [("tool_calls".to_string(), class_n)].into_iter().collect(),
    };
    store.add_metering(&d(0, 2)).unwrap();
    store.add_metering(&d(0, 3)).unwrap();
    store.add_metering(&d(1_700_000_000_000, 5)).unwrap();
    let mut rows = store.list_metering(bucket).unwrap();
    rows.sort_by_key(|r| r.priced_from_ms);
    assert_eq!(rows.len(), 2, "a price change splits the cell: {rows:?}");
    assert_eq!(rows[0].priced_from_ms, 0);
    assert_eq!(rows[0].requests, 2);
    assert_eq!(rows[0].usage_units.get("tool_calls"), Some(&5));
    assert_eq!(rows[1].priced_from_ms, 1_700_000_000_000);
    assert_eq!(rows[1].usage_units.get("tool_calls"), Some(&5));
    assert_eq!(
        metering_row(bucket, &key_id, "m", "p", 0),
        format!("busbar:metering:{bucket}:{key_id}|m|p"),
        "an undated cell keeps the v6 row key"
    );
}

/// The 1.6.0 key fields round-trip, and a NON-POOL scope grant comes back as the kind it was granted
/// — never as a pool grant (which would lose the grant AND widen pool access).
#[test]
fn a_key_round_trips_its_attribution_and_every_scope_kind() {
    use busbar_contract::records::ScopeRef;
    let Some(store) = live_store() else { return };
    let id = uid("vk_scopes");
    let key = VirtualKey {
        allowed_scopes: Some(vec![
            ScopeRef::pool("fast"),
            ScopeRef {
                kind: "mcp_server".into(),
                value: "github".into(),
            },
        ]),
        idp_subject: Some("alice@example".into()),
        binding_mode: Some("user-bound".into()),
        minted_by: Some("vk_admin".into()),
        ..vk(&id)
    };
    store.put_key(&key).unwrap();
    let back = store.get_key(&id).unwrap().unwrap();
    assert!(back.scope_allowed("mcp_server", "github"));
    assert!(
        !back.scope_allowed("pool", "github"),
        "the MCP grant must not become a pool grant"
    );
    assert!(back.scope_allowed("pool", "fast"));
    assert_eq!(back.idp_subject.as_deref(), Some("alice@example"));
    assert_eq!(back.binding_mode.as_deref(), Some("user-bound"));
    assert_eq!(back.minted_by.as_deref(), Some("vk_admin"));
}

/// `idp_provider` is persisted with the row and read back.
#[test]
fn a_key_round_trips_its_idp_provider() {
    let Some(store) = live_store() else { return };
    let id = uid("vk_idp");
    let key = VirtualKey {
        idp_provider: Some("github".into()),
        ..vk(&id)
    };
    store.put_key(&key).unwrap();
    let back = store.get_key(&id).unwrap().unwrap();
    assert_eq!(back.idp_provider.as_deref(), Some("github"));
}

// ── THE v6 -> v7 UPGRADE, IN PLACE ────────────────────────────────────────────────────────────

/// A v6 namespace's typed task / task-event / demotion / spent-approval keys, written the way v6
/// wrote them, come back through the 1.6.0 verbs after a connect — as the bodies the planes decode,
/// with the sidecar the planes write (a replay of a migrated event is the identical append, not a
/// fork) — and the typed keys are gone. Everything else in the namespace (keys, usage, the v6 call
/// log) is untouched. Safe beside the rest of the suite: the upgrade only reads and removes v6 keys
/// and appends into empty positions.
#[test]
fn v6_namespace_upgrades_in_place_to_v7() {
    use crate::legacy::{
        ASK_STATE_PREFIX, MCP_DEMOTIONS_HASH, TASKS_BY_UPDATED, TASKS_INDEX, TASK_EVENTS_PREFIX,
        TASK_ROW_PREFIX,
    };
    let Some(store) = live_store() else { return };
    let t = uid("t_v6_live");
    let done = uid("t_v6_done");
    let server = uid("srv_v6");
    let nonce = uid("nonce_v6");
    let key_id = uid("vk_v6");
    let call_key = format!("busbar:mcp:calls:{}", uid("vk_v6_calls"));
    store.put_key(&vk(&key_id)).unwrap();

    // v6's own writes, byte for byte the shapes v6 serialised.
    let live = sample_task(&t, "input-required", TASK_LIVE_TS + 7);
    let finished = sample_task(&done, "completed", TASK_LIVE_TS + 8);
    let e1 = sample_event(&t, 1, "task.submitted", "", "x1");
    let e2 = sample_event(&t, 2, "task.working", "x1", "x2");
    let dem = demotion(&server, "tool-drift", TRUST_NOW);
    store
        .with_conn(|c| {
            let mut p = redis::pipe();
            for task in [&live, &finished] {
                p.set(
                    format!("{TASK_ROW_PREFIX}{}", task.task_id),
                    serde_json::to_string(task).unwrap(),
                )
                .sadd(TASKS_INDEX, &task.task_id)
                .zadd(TASKS_BY_UPDATED, &task.task_id, task.updated_at);
            }
            for e in [&e1, &e2] {
                p.zadd(
                    format!("{TASK_EVENTS_PREFIX}{t}"),
                    serde_json::to_string(e).unwrap(),
                    e.seq,
                );
            }
            p.hset(
                MCP_DEMOTIONS_HASH,
                &server,
                serde_json::to_string(&dem).unwrap(),
            );
            p.cmd("SET")
                .arg(format!("{ASK_STATE_PREFIX}{nonce}"))
                .arg(TRUST_NOW + 900)
                .arg("EX")
                .arg(600);
            p.zadd(&call_key, "{\"v6\":\"call\"}", 1);
            p.set(SCHEMA_KEY, 6);
            p.query::<()>(c)
        })
        .unwrap();

    let url = std::env::var("VALKEY_URL").unwrap();
    let upgraded = ValkeyStore::connect(&url).expect("a v6 namespace upgrades on connect");

    assert_eq!(upgraded.get_task(&t).unwrap(), Some(live.clone()));
    assert_eq!(upgraded.get_task(&done).unwrap(), Some(finished.clone()));
    assert!(
        upgraded.plane_token_live("task", &t, u64::MAX, 0).unwrap(),
        "the interrupted task migrates ACTIVE"
    );
    assert!(
        !upgraded
            .plane_token_live("task", &done, u64::MAX, 0)
            .unwrap(),
        "the completed task migrates TERMINAL"
    );
    assert_eq!(
        upgraded.list_task_events(&t).unwrap(),
        vec![e1.clone(), e2.clone()]
    );
    upgraded
        .append_task_event(&e2)
        .expect("the engine replaying a migrated event is the identical append, not a fork");
    assert!(upgraded.list_mcp_demotions().unwrap().contains(&dem));
    assert!(
        !upgraded
            .redeem_ask_state(&nonce, TRUST_NOW + 900, TRUST_NOW)
            .unwrap(),
        "a v6 spent approval stays spent across the upgrade"
    );
    let ttl: i64 = upgraded
        .with_conn(|c| c.ttl(plane::token_key("ask", &nonce)))
        .unwrap();
    assert!(
        (601..=600 + 3_600).contains(&ttl),
        "the spent entry keeps at least its own remaining life: {ttl}"
    );

    // The typed keys are gone; everything else is where it was.
    let left: Vec<String> = upgraded
        .with_conn(|c| {
            let mut v = Vec::new();
            for k in [
                format!("{TASK_ROW_PREFIX}{t}"),
                format!("{TASK_ROW_PREFIX}{done}"),
                format!("{TASK_EVENTS_PREFIX}{t}"),
                format!("{ASK_STATE_PREFIX}{nonce}"),
            ] {
                if c.exists::<_, bool>(&k)? {
                    v.push(k);
                }
            }
            Ok(v)
        })
        .unwrap();
    assert!(left.is_empty(), "v6 typed keys left behind: {left:?}");
    assert!(!upgraded
        .with_conn(|c| c.hexists::<_, _, bool>(MCP_DEMOTIONS_HASH, &server))
        .unwrap());
    assert!(
        upgraded
            .with_conn(|c| c.exists::<_, bool>(&call_key))
            .unwrap(),
        "the v6 call log is left in place, unread — no evidence is destroyed"
    );
    assert!(
        upgraded.get_key(&key_id).unwrap().is_some(),
        "keys are untouched"
    );
    let marker: i64 = upgraded.with_conn(|c| c.get(SCHEMA_KEY)).unwrap();
    assert_eq!(marker, SCHEMA_VERSION);

    // Idempotent: a second pass over an already-upgraded namespace changes nothing (the marker set
    // back to v6, the next open's connect step runs the upgrade again).
    upgraded
        .with_conn(|c| c.set::<_, _, ()>(SCHEMA_KEY, 6i64))
        .unwrap();
    let upgraded = ValkeyStore::connect(&url).expect("a second upgrade pass on open");
    assert_eq!(
        upgraded.list_task_events(&t).unwrap(),
        vec![e1.clone(), e2.clone()]
    );

    // Crash-safe: a v6 row RESURFACING beside its already-migrated v7 record (the upgrade died
    // after the copy and before the delete, or an old node wrote it back) must not clobber the v7
    // record: the copy is append-if-absent, and the stale v6 key is still removed.
    let stale = sample_task(&t, "working", TASK_LIVE_TS + 1);
    assert_ne!(stale, live);
    upgraded
        .with_conn(|c| {
            let mut p = redis::pipe();
            p.set(
                format!("{TASK_ROW_PREFIX}{t}"),
                serde_json::to_string(&stale).unwrap(),
            )
            .sadd(TASKS_INDEX, &t)
            .zadd(TASKS_BY_UPDATED, &t, stale.updated_at)
            .set(SCHEMA_KEY, 6);
            p.query::<()>(c)
        })
        .unwrap();
    let upgraded = ValkeyStore::connect(&url).expect("a re-seeded v6 row upgrades on open");
    assert_eq!(
        upgraded.get_task(&t).unwrap(),
        Some(live.clone()),
        "the v7 record must not be overwritten by a stale v6 row"
    );
    assert!(
        !upgraded
            .with_conn(|c| c.exists::<_, bool>(format!("{TASK_ROW_PREFIX}{t}")))
            .unwrap(),
        "the stale v6 row is removed"
    );
    assert_eq!(upgraded.list_task_events(&t).unwrap(), vec![e1, e2]);

    reset_tasks(&upgraded, &[&t, &done]);
    reset_trust_state(&upgraded, &[&server], &[&nonce]);
    let _ = upgraded.with_conn(|c| c.del::<_, ()>(&call_key));
}

// ── THE CONNECTION, through the host's connector (ARCHITECT rulings 2026-10-03 12:10Z) ─────────
//
// Each test puts an in-test PROXY in front of the live server (`VALKEY_URL`): a TCP, unix-socket or
// TLS front, forwarding every connection to the server's own address. The proxy counts the
// connections the store makes and can drop them all, which is how the store's kept connection,
// its reconnect-and-retry, its unix-socket URLs and its `rediss://` are seen from outside.

/// The front a proxy listens on.
enum Front {
    Tcp,
    Unix(std::path::PathBuf),
    Tls(Arc<rustls::ServerConfig>),
}

/// A proxy in front of the live server.
struct Proxy {
    /// Where the front listens: `127.0.0.1:port`, or the socket path.
    at: String,
    accepted: Arc<std::sync::atomic::AtomicUsize>,
    /// Every front connection's socket, to drop them all.
    live: Arc<std::sync::Mutex<Vec<Shut>>>,
}

enum Shut {
    Tcp(std::net::TcpStream),
    Unix(std::os::unix::net::UnixStream),
}

/// The live server's `host:port`, database and userinfo, as `VALKEY_URL` names them.
fn live_parts() -> (String, i64, String) {
    let url = std::env::var("VALKEY_URL").expect("VALKEY_URL");
    let u = url::Url::parse(&url).expect("VALKEY_URL parses");
    let addr = format!(
        "{}:{}",
        u.host_str().expect("a host"),
        u.port().unwrap_or(6379)
    );
    let db = u.path().trim_matches('/').parse().unwrap_or(0);
    let userinfo = match (u.username(), u.password()) {
        ("", None) => String::new(),
        (user, Some(p)) => format!("{user}:{p}@"),
        (user, None) => format!("{user}@"),
    };
    (addr, db, userinfo)
}

/// Copy `from` to `to` until either ends.
fn pump(mut from: impl std::io::Read, mut to: impl std::io::Write) {
    let mut buf = [0_u8; 16 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() || to.flush().is_err() {
                    return;
                }
            }
        }
    }
}

impl Proxy {
    fn start(front: Front) -> Self {
        let (backend, _, _) = live_parts();
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let live = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (count, held) = (accepted.clone(), live.clone());
        let at = match front {
            Front::Unix(path) => {
                let _ = std::fs::remove_file(&path);
                let l = std::os::unix::net::UnixListener::bind(&path).expect("bind the socket");
                std::thread::spawn(move || {
                    for s in l.incoming() {
                        let Ok(s) = s else { return };
                        count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        held.lock()
                            .unwrap()
                            .push(Shut::Unix(s.try_clone().unwrap()));
                        let b = std::net::TcpStream::connect(&backend).expect("the live server");
                        let (s2, b2) = (s.try_clone().unwrap(), b.try_clone().unwrap());
                        std::thread::spawn(move || pump(s, b));
                        std::thread::spawn(move || pump(b2, s2));
                    }
                });
                path.display().to_string()
            }
            Front::Tcp | Front::Tls(_) => {
                let tls = match front {
                    Front::Tls(c) => Some(c),
                    _ => None,
                };
                let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
                let at = l.local_addr().unwrap().to_string();
                std::thread::spawn(move || {
                    for s in l.incoming() {
                        let Ok(s) = s else { return };
                        count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        held.lock().unwrap().push(Shut::Tcp(s.try_clone().unwrap()));
                        let b = std::net::TcpStream::connect(&backend).expect("the live server");
                        match &tls {
                            None => {
                                let (s2, b2) = (s.try_clone().unwrap(), b.try_clone().unwrap());
                                std::thread::spawn(move || pump(s, b));
                                std::thread::spawn(move || pump(b2, s2));
                            }
                            Some(config) => {
                                let conn = rustls::ServerConnection::new(config.clone()).unwrap();
                                std::thread::spawn(move || tls_pump(conn, s, b));
                            }
                        }
                    }
                });
                at
            }
        };
        Self { at, accepted, live }
    }

    /// How many connections the store made.
    fn accepted(&self) -> usize {
        self.accepted.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Drop every connection the store holds (a server going away under it).
    fn drop_all(&self) {
        for s in self.live.lock().unwrap().drain(..) {
            match s {
                Shut::Tcp(t) => {
                    let _ = t.shutdown(std::net::Shutdown::Both);
                }
                Shut::Unix(u) => {
                    let _ = u.shutdown(std::net::Shutdown::Both);
                }
            }
        }
    }
}

/// TLS-terminate `front` and forward the plaintext to `back` (one TLS stream, two directions).
fn tls_pump(conn: rustls::ServerConnection, front: std::net::TcpStream, back: std::net::TcpStream) {
    use std::io::{Read, Write};
    front
        .set_read_timeout(Some(std::time::Duration::from_millis(5)))
        .unwrap();
    let tls = Arc::new(std::sync::Mutex::new(rustls::StreamOwned::new(conn, front)));
    let (t2, mut b2) = (tls.clone(), back.try_clone().unwrap());
    std::thread::spawn(move || {
        let mut buf = [0_u8; 16 * 1024];
        loop {
            match b2.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    let mut t = t2.lock().unwrap();
                    if t.write_all(&buf[..n]).is_err() || t.flush().is_err() {
                        return;
                    }
                }
            }
        }
    });
    let mut back = back;
    let mut buf = [0_u8; 16 * 1024];
    loop {
        let got = tls.lock().unwrap().read(&mut buf);
        match got {
            Ok(0) => return,
            Ok(n) => {
                if back.write_all(&buf[..n]).is_err() {
                    return;
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(_) => return,
        }
    }
}

/// The store's door opened on `settings` on a dispatcher of its own, over the connection table
/// `table` builds; the table too, to read what it was asked.
fn open_on(
    settings: &str,
    table: impl FnOnce(&Dispatcher) -> TcpConns,
) -> (Result<LoadedStore, String>, Arc<TcpConns>) {
    open_on_dispatcher(
        Arc::new(Dispatcher::new(DispatchConfig::default())),
        settings,
        table,
    )
}

/// [`open_on`] on the dispatcher `d`.
fn open_on_dispatcher(
    d: Arc<Dispatcher>,
    settings: &str,
    table: impl FnOnce(&Dispatcher) -> TcpConns,
) -> (Result<LoadedStore, String>, Arc<TcpConns>) {
    let t = Arc::new(table(&d));
    let conns: Arc<dyn busbar_contract::conn::DeclaredConns> = t.clone();
    let row = LinkedRow::of(crate::door).expect("the door");
    let p = load_linked::<Store>(
        &row,
        Bind {
            instance: Arc::from("store-valkey-test"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: busbar_plugin_loader::dispatch::ConnTable::Host(conns),
        },
    )
    .expect("the door loads");
    (LoadedStore::open(p, d, settings.as_bytes(), mint), t)
}

fn plain(d: &Dispatcher) -> TcpConns {
    TcpConns::new(d.conn_waker())
}

/// A table whose TLS trusts no root: a verifying handshake refuses every certificate, and only an
/// operator-infrastructure need's verify-off (`#insecure`) secures a stream.
fn trusting_nothing(d: &Dispatcher) -> TcpConns {
    TcpConns::with_tls(d.conn_waker(), Arc::new(TestTls::default()))
}

/// THE TEST TABLE'S TLS (the loader's `SecureDial`; TLS itself is the connector's, which the
/// loader's test table cannot name): rustls trusting exactly the roots a test hands it, or, on
/// `verify_off`, checking no certificate, only the handshake's signature. As the loader's own test
/// table secured a stream before TLS left it (busbar 0db7ee2ea0 `TcpConns::with_roots`).
#[derive(Default)]
struct TestTls {
    roots: Option<Vec<u8>>,
}

impl TestTls {
    fn trusting(ca_der: &[u8]) -> Self {
        Self {
            roots: Some(ca_der.to_vec()),
        }
    }

    fn config(&self, verify_off: bool) -> Arc<rustls::ClientConfig> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("the default protocol versions");
        let config = if verify_off {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
                .with_no_client_auth()
        } else {
            let mut roots = rustls::RootCertStore::empty();
            if let Some(ca) = &self.roots {
                roots
                    .add(rustls_pki_types::CertificateDer::from(ca.clone()))
                    .expect("the test CA is a root certificate");
            }
            builder.with_root_certificates(roots).with_no_client_auth()
        };
        Arc::new(config)
    }
}

impl busbar_test_kit::tcp_conns::SecureDial for TestTls {
    fn secure(
        &self,
        server: &str,
        verify_off: bool,
        mut tcp: std::net::TcpStream,
    ) -> std::io::Result<Box<dyn busbar_test_kit::tcp_conns::SecuredSock>> {
        let invalid = |e: String| std::io::Error::new(std::io::ErrorKind::InvalidInput, e);
        let name = rustls_pki_types::ServerName::try_from(server.to_owned())
            .map_err(|e| invalid(e.to_string()))?;
        let mut tls = rustls::ClientConnection::new(self.config(verify_off), name)
            .map_err(|e| invalid(e.to_string()))?;
        while tls.is_handshaking() {
            tls.complete_io(&mut tcp)?;
        }
        Ok(Box::new(TestTlsStream(rustls::StreamOwned::new(tls, tcp))))
    }
}

/// A stream [`TestTls`] secured.
struct TestTlsStream(rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>);

impl std::io::Read for TestTlsStream {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(b)
    }
}

impl std::io::Write for TestTlsStream {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.write(b)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl busbar_test_kit::tcp_conns::SecuredSock for TestTlsStream {
    fn tcp(&self) -> &std::net::TcpStream {
        self.0.get_ref()
    }
    fn close(&mut self) {
        self.0.conn.send_close_notify();
        let _ = std::io::Write::flush(&mut self.0);
        let _ = self.0.sock.shutdown(std::net::Shutdown::Both);
    }
}

/// A verifier that checks no certificate, only the handshake's signature (`#insecure`).
#[derive(Debug)]
struct AnyCertificate(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _: &rustls_pki_types::CertificateDer<'_>,
        _: &[rustls_pki_types::CertificateDer<'_>],
        _: &rustls_pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn settings_for(url: &str) -> String {
    serde_json::json!({ "url": url }).to_string()
}

/// STORE-KEEP: the store keeps ONE connection across ops (1.5.5's one mutex-guarded connection):
/// its open and every later op are one connection, one handshake.
#[test]
fn the_store_keeps_one_connection_across_ops() {
    if live_store().is_none() {
        return;
    }
    let proxy = Proxy::start(Front::Tcp);
    let (_, db, userinfo) = live_parts();
    let (store, _) = open_on(
        &settings_for(&format!("redis://{userinfo}{}/{db}", proxy.at)),
        plain,
    );
    let store = store.expect("opens through the proxy");
    let id = uid("vk_kept");
    store.put_key(&vk(&id)).unwrap();
    assert!(store.get_key(&id).unwrap().is_some());
    store.list_denylist().unwrap();
    assert_eq!(
        proxy.accepted(),
        1,
        "the open and every op share one kept connection"
    );
    let _ = store.purge_key_for_test(&id);
}

/// VALKEY-RETRY, 1.5.5's own pin: a genuine connection-level error (the server dropping the
/// store's connection out from under it, the real-world case `with_conn`'s reconnect-and-retry
/// exists for) is transparently recovered on a fresh connection, not surfaced to the caller.
#[test]
fn with_conn_transparently_reconnects_after_the_connection_is_dropped() {
    if live_store().is_none() {
        return;
    }
    let proxy = Proxy::start(Front::Tcp);
    let (_, db, userinfo) = live_parts();
    let (store, _) = open_on(
        &settings_for(&format!("redis://{userinfo}{}/{db}", proxy.at)),
        plain,
    );
    let store = store.expect("opens");
    let before = uid("vk_before_drop");
    store.put_key(&vk(&before)).unwrap();
    proxy.drop_all();
    std::thread::sleep(std::time::Duration::from_millis(20));
    let id = uid("vk_after_drop");
    store.put_key(&vk(&id)).expect(
        "a connection-level error (a dropped connection) must trigger transparent \
         reconnect-and-retry, not surface as a caller-visible failure",
    );
    assert!(store.get_key(&id).unwrap().is_some());
    assert_eq!(
        proxy.accepted(),
        2,
        "one fresh connection for the retry, then kept"
    );
    let _ = store.purge_key_for_test(&before);
    let _ = store.purge_key_for_test(&id);
}

/// VALKEY-RETRY's other half: a write 1.5.5 never replayed (`with_conn_no_retry`: the plane
/// writes, a token redemption) fails on a dropped connection, and the next op dials fresh.
#[test]
fn a_no_retry_write_on_a_dropped_connection_fails_and_the_next_op_dials_fresh() {
    if live_store().is_none() {
        return;
    }
    let proxy = Proxy::start(Front::Tcp);
    let (_, db, userinfo) = live_parts();
    let (store, _) = open_on(
        &settings_for(&format!("redis://{userinfo}{}/{db}", proxy.at)),
        plain,
    );
    let store = store.expect("opens");
    store.list_denylist().unwrap();
    proxy.drop_all();
    std::thread::sleep(std::time::Duration::from_millis(20));
    let token = uid("tok_noretry");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let err = store
        .redeem_plane_token("ask", &token, now + 60, now)
        .expect_err("a redemption is never replayed on a fresh connection");
    assert!(err.0.contains("valkey command:"), "{err:?}");
    store.list_denylist().expect("the next op dials fresh");
    assert_eq!(proxy.accepted(), 2);
}

/// VALKEY-UNIX: every unix-socket URL form 1.5.5's driver read reaches the server over a
/// unix-domain socket through the host's connector (`unix:<path>`).
#[test]
fn a_unix_socket_url_reaches_the_server() {
    if live_store().is_none() {
        return;
    }
    let (_, db, _) = live_parts();
    let dir = std::env::temp_dir().join(format!("vk-unix-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for (n, scheme) in ["redis+unix", "unix", "valkey+unix"].iter().enumerate() {
        let path = dir.join(format!("s{n}.sock"));
        let proxy = Proxy::start(Front::Unix(path.clone()));
        let (store, _) = open_on(
            &settings_for(&format!("{scheme}://{}?db={db}", proxy.at)),
            plain,
        );
        let store = store.unwrap_or_else(|e| panic!("{scheme}: {e}"));
        let id = uid("vk_unix");
        store.put_key(&vk(&id)).unwrap();
        assert!(store.get_key(&id).unwrap().is_some());
        assert_eq!(proxy.accepted(), 1);
        let _ = store.purge_key_for_test(&id);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// VALKEY-TIMEOUT: `connect_timeout_ms` (default 10 s, 1.5.5's) is every dial's timeout, as the
/// host's table is asked; a zero timeout refuses the load as 1.5.5's driver refused it.
#[test]
fn connect_timeout_ms_is_the_dial_timeout() {
    if live_store().is_none() {
        return;
    }
    let url = std::env::var("VALKEY_URL").unwrap();
    let (store, table) = open_on(
        &serde_json::json!({ "url": url, "connect_timeout_ms": 1234 }).to_string(),
        plain,
    );
    store.expect("opens").list_denylist().unwrap();
    assert_eq!(table.dial_timeouts(), vec![1234]);
    let (store, table) = open_on(&settings_for(&url), plain);
    store.expect("opens").list_denylist().unwrap();
    assert_eq!(table.dial_timeouts(), vec![10_000]);
    let (store, _) = open_on(
        &serde_json::json!({ "url": url, "connect_timeout_ms": 0 }).to_string(),
        plain,
    );
    assert_eq!(
        store.expect_err("a zero timeout refuses the load"),
        "plugin 'busbar-store-valkey' open failed: invalid valkey plugin config: \
         `connect_timeout_ms` must be a positive integer (milliseconds), got a number"
    );
}

/// A CA and a server certificate it signed for `127.0.0.1` (the proxy's address; an IP SAN): the
/// server config, and the CA (DER).
fn tls_server() -> (Arc<rustls::ServerConfig>, Vec<u8>) {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::from_params(&ca_params, ca_key);
    let key = rcgen::KeyPair::generate().unwrap();
    let leaf = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()])
        .unwrap()
        .signed_by(&key, &issuer)
        .unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![leaf.der().clone()],
        rustls_pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
    )
    .unwrap();
    (Arc::new(config), ca.der().to_vec())
}

/// TLS: a `rediss://` URL is secured from its first byte through the host's connector (the test
/// table's TLS standing in for the connector's TLS wrap, trusting a test CA), and the kept
/// connection stays secure; without the CA the load fails in the store's words.
#[test]
fn a_rediss_url_is_secured_through_the_hosts_connector() {
    if live_store().is_none() {
        return;
    }
    let (config, ca) = tls_server();
    let proxy = Proxy::start(Front::Tls(config));
    let port = proxy.at.rsplit_once(':').unwrap().1.to_string();
    let (_, db, userinfo) = live_parts();
    let url = format!("rediss://{userinfo}127.0.0.1:{port}/{db}");
    let (store, _) = open_on(&settings_for(&url), |d| {
        TcpConns::with_tls(d.conn_waker(), Arc::new(TestTls::trusting(&ca)))
    });
    let store = store.expect("opens over TLS");
    let id = uid("vk_tls");
    store.put_key(&vk(&id)).unwrap();
    assert!(store.get_key(&id).unwrap().is_some());
    assert_eq!(proxy.accepted(), 1, "one secured connection, kept");
    let _ = store.purge_key_for_test(&id);

    let (untrusted, _) = open_on(&settings_for(&url), plain);
    let err = untrusted.expect_err("no TLS without trust");
    assert!(
        err.starts_with(
            "plugin 'busbar-store-valkey' open failed: valkey store: failed to connect: "
        ) && !err.contains("valkey connect:"),
        "{err}"
    );
}

/// Host services offering the clock alone (the dispatcher's own timebase), refusing the rest: the
/// host clock a wire's bound runs on. Every other service answers as busbar's shared test double
/// (`busbar_contract::services::double`) answers an unserved one: REFUSED, at once.
struct ClockOnly;

impl busbar_contract::services::double::ServicesDouble for ClockOnly {
    fn now(&self) -> busbar_contract::services::Reading {
        busbar_contract::services::Reading {
            wall_ns: 0,
            mono_ns: busbar_plugin_loader::dispatch::now_ns(),
        }
    }
}

/// VALKEY-TIMEOUT over the whole span 1.5.5's `get_connection_with_timeout` bounded: a server that
/// accepts the dial and never answers the handshake's `AUTH` (or `SELECT`) refuses the load within
/// `connect_timeout_ms`, in the store's words, rather than at the op's deadline.
#[test]
fn connect_timeout_ms_bounds_the_handshake_after_the_dial() {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let at = l.local_addr().unwrap().to_string();
    // Accept and hold every connection, saying nothing.
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for s in l.incoming() {
            held.push(s);
        }
    });
    for url in [format!("redis://:pw@{at}/0"), format!("redis://{at}/3")] {
        let d = Arc::new(Dispatcher::with_services(
            DispatchConfig::default(),
            Arc::new(ClockOnly),
        ));
        let t = std::time::Instant::now();
        let (store, _) = open_on_dispatcher(
            d,
            &serde_json::json!({ "url": url, "connect_timeout_ms": 300 }).to_string(),
            plain,
        );
        let err = store.expect_err("the handshake never answers");
        assert!(
            t.elapsed() < std::time::Duration::from_secs(5),
            "{url}: bounded by connect_timeout_ms, not the op's deadline: {:?}",
            t.elapsed()
        );
        assert!(
            err.starts_with(
                "plugin 'busbar-store-valkey' open failed: valkey store: failed to connect: "
            ) && !err.contains("valkey connect:")
                && err.contains("deadline passed"),
            "{url}: {err}"
        );
        assert!(!err.contains("pw"), "the password is scrubbed: {err}");
    }
}

/// A SELF-SIGNED `127.0.0.1` certificate (no CA anyone trusts): the server config.
fn self_signed_tls_server() -> Arc<rustls::ServerConfig> {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        rustls_pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
    )
    .unwrap();
    Arc::new(config)
}

/// `#insecure` (ARCHITECT ruling 2026-10-03 on Q-L16-4): a server whose certificate is
/// self-signed refuses the load over `rediss://` in the store's words, and is accepted over
/// `rediss://…#insecure`, its certificate unverified as 1.5.5's driver left it; the kept
/// connection carries the ops.
#[test]
fn rediss_insecure_skips_certificate_verification() {
    if live_store().is_none() {
        return;
    }
    let proxy = Proxy::start(Front::Tls(self_signed_tls_server()));
    let port = proxy.at.rsplit_once(':').unwrap().1.to_string();
    let (_, db, userinfo) = live_parts();
    let verified = format!("rediss://{userinfo}127.0.0.1:{port}/{db}");
    let (refused, _) = open_on(&settings_for(&verified), trusting_nothing);
    let err = refused.expect_err("a self-signed certificate is not trusted");
    assert!(
        err.starts_with(
            "plugin 'busbar-store-valkey' open failed: valkey store: failed to connect: "
        ) && !err.contains("valkey connect:"),
        "{err}"
    );
    let (store, _) = open_on(
        &settings_for(&format!("{verified}#insecure")),
        trusting_nothing,
    );
    let store = store.expect("#insecure accepts the self-signed certificate");
    let id = uid("vk_insecure");
    store.put_key(&vk(&id)).unwrap();
    assert!(store.get_key(&id).unwrap().is_some());
    assert_eq!(
        proxy.accepted(),
        2,
        "the refused dial, then one kept connection"
    );
    let _ = store.purge_key_for_test(&id);
}

// MIGRATION CONFORMANCE (busbar 1.6.0 #33 / M5): keys the PUBLISHED 1.5.5 binary wrote through the
// published store-valkey v1.0.7 plugin read back through this build's `migrate`. The fixture in
// `tests/fixtures/1.5.5/` was RECORDED by busbar's `scripts/store-migration-fixture.sh` driving the
// v1.5.5 binary and the v1.0.7 plugin against valkey/valkey:8@sha256:495e4fec... (the image plugin-ci
// runs); the binary, plugin and image digests and every file's sha256 are in its `MANIFEST.tsv`.
// `keys.json` (= `rows.json`) is every key 1.5.5 wrote: `{key: {type, value, has_ttl}}`, hashes as
// field -> value maps, zsets as [[member, score], ...]. Destructive (it clears `busbar:*`), so
// `#[ignore]`d like the other namespace-wiping tests and run by plugin-ci's `--ignored` pass.
const FIXTURE_KEYS_1_5_5: &str = include_str!("../tests/fixtures/1.5.5/keys.json");

/// A TTL comfortably longer than any test run, as 1.5.5 gave its metering rows.
const FIXTURE_TTL_SECS: u64 = 31 * 24 * 3600;

fn fixture_keys() -> serde_json::Map<String, serde_json::Value> {
    serde_json::from_str::<serde_json::Value>(FIXTURE_KEYS_1_5_5)
        .unwrap()
        .as_object()
        .unwrap_or_else(|| panic!("keys.json is an object"))
        .clone()
}

fn fx_text(v: &serde_json::Value) -> String {
    v.as_str()
        .unwrap_or_else(|| panic!("{v} is not a string"))
        .to_string()
}

fn fx_num(v: &serde_json::Value) -> u64 {
    fx_text(v)
        .parse()
        .unwrap_or_else(|_| panic!("{v} is not an unsigned integer"))
}

/// Clear `busbar:*`, then write every key of `keys.json` with the crate's own test client.
fn replay_1_5_5(store: &ValkeyStore) {
    store
        .with_conn(|c| {
            let existing: Vec<String> = redis::cmd("KEYS").arg("busbar:*").query(c)?;
            for k in &existing {
                redis::cmd("DEL").arg(k).query::<()>(c)?;
            }
            for (key, row) in fixture_keys() {
                let value = &row["value"];
                match row["type"].as_str().unwrap() {
                    "string" => redis::cmd("SET")
                        .arg(&key)
                        .arg(fx_text(value))
                        .query::<()>(c)?,
                    "hash" => {
                        for (f, v) in value.as_object().unwrap() {
                            redis::cmd("HSET")
                                .arg(&key)
                                .arg(f)
                                .arg(fx_text(v))
                                .query::<()>(c)?;
                        }
                    }
                    "set" => {
                        for m in value.as_array().unwrap() {
                            redis::cmd("SADD")
                                .arg(&key)
                                .arg(fx_text(m))
                                .query::<()>(c)?;
                        }
                    }
                    "zset" => {
                        for pair in value.as_array().unwrap() {
                            let score: f64 = fx_text(&pair[1]).parse().unwrap();
                            redis::cmd("ZADD")
                                .arg(&key)
                                .arg(score)
                                .arg(fx_text(&pair[0]))
                                .query::<()>(c)?;
                        }
                    }
                    "list" => {
                        for m in value.as_array().unwrap() {
                            redis::cmd("RPUSH")
                                .arg(&key)
                                .arg(fx_text(m))
                                .query::<()>(c)?;
                        }
                    }
                    other => panic!("{key}: unknown fixture type {other}"),
                }
                if row["has_ttl"].as_bool().unwrap() {
                    redis::cmd("EXPIRE")
                        .arg(&key)
                        .arg(FIXTURE_TTL_SECS)
                        .query::<()>(c)?;
                }
            }
            Ok(())
        })
        .unwrap();
}

fn schema_marker(store: &ValkeyStore) -> i64 {
    store.with_conn(|c| c.get("busbar:schema")).unwrap()
}

/// The 1.6.0 surface read back, against values derived from `keys.json` here and now.
fn assert_1_5_5_keys_read_back(store: &ValkeyStore) {
    let fx = fixture_keys();

    // METERING: every `busbar:metering:<bucket>:<key>|<model>|<provider>` hash, per bucket, and no extra.
    let mut buckets = std::collections::BTreeSet::new();
    for key in fx.keys() {
        if let Some(rest) = key.strip_prefix("busbar:metering:") {
            buckets.insert(rest.split(':').next().unwrap().parse::<u64>().unwrap());
        }
    }
    assert!(!buckets.is_empty(), "the fixture carries metering rows");
    let mut seen = 0;
    for bucket in &buckets {
        let prefix = format!("busbar:metering:{bucket}:");
        let want: Vec<&serde_json::Value> = fx
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(_, v)| &v["value"])
            .collect();
        let got = store.list_metering(*bucket).unwrap();
        assert_eq!(got.len(), want.len(), "metering rows in bucket {bucket}");
        for w in want {
            let row = got
                .iter()
                .find(|g| {
                    g.key_id == fx_text(&w["key_id"])
                        && g.model == fx_text(&w["model"])
                        && g.provider == fx_text(&w["provider"])
                })
                .unwrap_or_else(|| panic!("metering row missing after migrate: {w}"));
            assert_eq!(row.requests, fx_num(&w["requests"]), "{w}");
            assert_eq!(
                row.billable_requests,
                fx_num(&w["billable_requests"]),
                "{w}"
            );
            assert_eq!(row.key_group_at_use, fx_text(&w["key_group_at_use"]), "{w}");
            assert_eq!(row.pricing_version, fx_text(&w["pricing_version"]), "{w}");
            assert_eq!(row.tokens_input, fx_num(&w["tokens_input"]), "{w}");
            assert_eq!(row.tokens_output, fx_num(&w["tokens_output"]), "{w}");
            assert_eq!(
                row.tokens_cache_read,
                fx_num(&w["tokens_cache_read"]),
                "{w}"
            );
            assert_eq!(
                row.tokens_cache_write,
                fx_num(&w["tokens_cache_write"]),
                "{w}"
            );
            seen += 1;
        }
    }
    assert!(seen > 0);

    // USAGE WINDOWS: `busbar:usage:<bucket>:<window_start>` — the counts and each model's tokens.
    let mut windows = 0;
    for (key, row) in &fx {
        let Some(rest) = key.strip_prefix("busbar:usage:") else {
            continue;
        };
        let (bucket, start) = rest.rsplit_once(':').unwrap();
        let start: u64 = start.parse().unwrap();
        let mut requests = 0;
        let mut billable = 0;
        let mut models: std::collections::BTreeMap<
            String,
            std::collections::BTreeMap<String, u64>,
        > = Default::default();
        for (field, v) in row["value"].as_object().unwrap() {
            match field.as_str() {
                "requests" => requests = fx_num(v),
                "billable_requests" => billable = fx_num(v),
                _ => {
                    let (model, unit) = field.strip_prefix("m:").unwrap().rsplit_once(':').unwrap();
                    models
                        .entry(model.to_string())
                        .or_default()
                        .insert(unit.to_string(), fx_num(v));
                }
            }
        }
        let got = store.get_usage(bucket, start).unwrap();
        assert_eq!(got.requests, requests, "{key}");
        assert_eq!(got.billable_requests, billable, "{key}");
        let have: std::collections::BTreeMap<String, std::collections::BTreeMap<String, u64>> = got
            .models
            .iter()
            .map(|m| (m.model.clone(), m.usage_units.clone()))
            .collect();
        assert_eq!(have, models, "per-model tokens of {key}");
        windows += 1;
    }
    assert!(windows > 0, "the fixture carries usage windows");

    // KEYS: name, group, enabled; and no extra key.
    let mut key_rows = 0;
    for (key, row) in &fx {
        let Some(id) = key.strip_prefix("busbar:key:") else {
            continue;
        };
        let want: serde_json::Value = serde_json::from_str(&fx_text(&row["value"])).unwrap();
        let got = store
            .get_key(id)
            .unwrap()
            .unwrap_or_else(|| panic!("key missing after migrate: {id}"));
        assert_eq!(got.name, fx_text(&want["name"]), "{id}");
        assert_eq!(got.group.as_deref(), want["group"].as_str(), "{id}");
        assert_eq!(got.enabled, want["enabled"].as_bool().unwrap(), "{id}");
        key_rows += 1;
    }
    assert!(key_rows > 0, "the fixture carries keys");
    assert_eq!(store.list_keys().unwrap().len(), key_rows);

    // AUDIT: the hash chain, verbatim and in order (the zset's own order).
    let want: Vec<serde_json::Value> = fx["busbar:audit"]["value"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| serde_json::from_str(&fx_text(&pair[0])).unwrap())
        .collect();
    assert!(!want.is_empty(), "the fixture carries audit rows");
    let got = store.list_audit().unwrap();
    assert_eq!(got.len(), want.len());
    for (g, w) in got.iter().zip(&want) {
        assert_eq!(g.seq, w["seq"].as_u64().unwrap(), "{w}");
        assert_eq!(g.ts, w["ts"].as_u64().unwrap(), "{w}");
        assert_eq!(g.action, fx_text(&w["action"]), "{w}");
        assert_eq!(g.resource, fx_text(&w["resource"]), "{w}");
        assert_eq!(g.outcome, fx_text(&w["outcome"]), "{w}");
        assert_eq!(g.principal, fx_text(&w["principal"]), "{w}");
        assert_eq!(g.prev_hash, fx_text(&w["prev_hash"]), "{w}");
        assert_eq!(g.hash, fx_text(&w["hash"]), "{w}");
    }
}

/// Every read the assertions above make, as text, so two opens compare whole.
fn read_everything_1_5_5(store: &ValkeyStore) -> Vec<String> {
    let mut out = vec![
        format!("{:?}", store.list_keys().unwrap()),
        format!("{:?}", store.list_audit().unwrap()),
    ];
    for key in fixture_keys().keys() {
        if let Some(rest) = key.strip_prefix("busbar:metering:") {
            if let Ok(bucket) = rest.parse::<u64>() {
                out.push(format!("{:?}", store.list_metering(bucket).unwrap()));
            }
        } else if let Some(rest) = key.strip_prefix("busbar:usage:") {
            let (bucket, start) = rest.rsplit_once(':').unwrap();
            out.push(format!(
                "{:?}",
                store.get_usage(bucket, start.parse().unwrap()).unwrap()
            ));
        }
    }
    out
}

/// Keys written by the 1.5.5 binary read back through this build's migrate, field for field.
#[test]
#[ignore]
fn the_1_5_5_binarys_rows_read_back_through_migrate() {
    let Some(setup) = live_store() else { return };
    replay_1_5_5(&setup);
    assert_eq!(schema_marker(&setup), 6, "the replayed marker is 1.5.5's");
    let url = std::env::var("VALKEY_URL").unwrap();
    let store = ValkeyStore::connect(&url).expect("this build opens the 1.5.5 keyspace");
    assert_eq!(schema_marker(&store), SCHEMA_VERSION);
    assert_1_5_5_keys_read_back(&store);

    // The revision counter carries over: a key written after the migrate is stamped past every
    // revision the 1.5.5 rows hold, so a hydrating reader at that watermark sees it.
    let revision = fx_num(&fixture_keys()["busbar:revision"]["value"]);
    let counter: u64 = store
        .with_conn(|c| redis::cmd("GET").arg(REVISION_KEY).query(c))
        .unwrap();
    assert_eq!(
        counter, revision,
        "migrate leaves the revision counter alone"
    );
    let id = uid("vk_after_1_5_5");
    store.put_key(&vk(&id)).unwrap();
    assert!(store.get_key(&id).unwrap().unwrap().revision > revision);
    assert!(store
        .list_keys_since(revision)
        .unwrap()
        .iter()
        .any(|k| k.id == id));
}

/// A second open over the migrated 1.5.5 keyspace changes nothing.
#[test]
#[ignore]
fn migrate_over_the_1_5_5_rows_is_idempotent() {
    let Some(setup) = live_store() else { return };
    replay_1_5_5(&setup);
    let url = std::env::var("VALKEY_URL").unwrap();
    let first = {
        let store = ValkeyStore::connect(&url).expect("first open");
        assert_eq!(schema_marker(&store), SCHEMA_VERSION);
        assert_1_5_5_keys_read_back(&store);
        read_everything_1_5_5(&store)
    };
    let store = ValkeyStore::connect(&url).expect("second open");
    assert_eq!(schema_marker(&store), SCHEMA_VERSION);
    assert_1_5_5_keys_read_back(&store);
    assert_eq!(read_everything_1_5_5(&store), first);
}

#[test]
fn audit_list_and_tail_are_ordered_oldest_first() {
    let _serialised = audit_seq_guard();
    let Some(store) = live_store() else { return };
    // The audit zset is shared: seed seqs above everything present, so this test owns the top of
    // the range and the tail it asserts cannot be pushed out by a sibling.
    let top = store
        .list_audit()
        .unwrap()
        .iter()
        .map(|r| r.seq)
        .max()
        .unwrap_or(0)
        .saturating_add(1_000);
    let seqs = [top, top + 1, top + 2];
    for seq in seqs {
        store.seed_audit_for_test(&audit_row(seq)).unwrap();
    }
    let all: Vec<u64> = store
        .list_audit()
        .unwrap()
        .into_iter()
        .map(|r| r.seq)
        .filter(|q| seqs.contains(q))
        .collect();
    assert_eq!(all, seqs, "oldest first");
    let tail: Vec<u64> = store
        .list_audit_tail(2)
        .unwrap()
        .into_iter()
        .map(|r| r.seq)
        .collect();
    for seq in seqs {
        let _ = store.purge_audit_seq_for_test(seq);
    }
    assert_eq!(tail, vec![top + 1, top + 2], "the newest two, oldest first");
}

fn audit_row(seq: u64) -> AuditRecord {
    AuditRecord {
        seq,
        ts: 1000,
        action: "key.mint".to_string(),
        resource: format!("key:vk_{seq}"),
        outcome: "applied".to_string(),
        principal: "admin".to_string(),
        prev_hash: String::new(),
        hash: format!("h{seq}"),
    }
}

/// `list_audit_tail(0)` is the contract's empty tail, not the whole chain.
#[test]
fn list_audit_tail_zero_is_empty() {
    let _serialised = audit_seq_guard();
    let Some(store) = live_store() else { return };
    let top = store
        .list_audit()
        .unwrap()
        .iter()
        .map(|r| r.seq)
        .max()
        .unwrap_or(0)
        + 1_000;
    store.seed_audit_for_test(&audit_row(top)).unwrap();
    let tail = store.list_audit_tail(0).unwrap();
    let _ = store.purge_audit_seq_for_test(top);
    assert!(tail.is_empty(), "limit 0 must be empty, got {}", tail.len());
}

/// The URL password never reaches `Debug` output.
#[test]
fn debug_output_redacts_the_url_password() {
    let url = "redis://user:s3cr3t@host:6379/0";
    let store =
        crate::ValkeyStore::from_settings(format!(r#"{{"url":"{url}"}}"#).as_bytes()).unwrap();
    let t = parse_url(url).unwrap();
    for out in [format!("{store:?}"), format!("{t:?}")] {
        assert!(!out.contains("s3cr3t"), "password leaked: {out}");
        assert!(out.contains("<redacted>"), "no redaction marker: {out}");
    }
}

/// `put_key_with_credential` into a slot holding a DIFFERENT LIVE credential is refused, and the
/// live credential's pointers still resolve to it.
#[test]
fn put_key_with_credential_refuses_an_occupied_live_slot() {
    let Some(store) = live_store() else { return };
    let key_id = uid("vk_kwc_occ");
    let p1 = uid("AKIA_KWC_OCC1");
    let p2 = uid("AKIA_KWC_OCC2");
    let key = vk(&key_id);
    let c1 = cred(&key_id, &p1, 0);
    let c2 = cred(&key_id, &p2, 0);
    store.put_key_with_credential(&key, &c1).unwrap();
    let err = store.put_key_with_credential(&key, &c2);
    assert!(
        err.is_err(),
        "minting into an occupied LIVE slot must fail: {err:?}"
    );
    let live = store
        .lookup_credential_secret("sigv4", &p1)
        .unwrap()
        .expect("C1 must still resolve");
    assert_eq!(live.meta.id, c1.meta.id);
    assert!(store
        .lookup_credential_secret("sigv4", &p2)
        .unwrap()
        .is_none());
}

/// After the occupant is revoked, the slot can be re-minted and the old public_id stops resolving.
#[test]
fn put_key_with_credential_reclaims_a_revoked_slot_and_drops_old_pointers() {
    let Some(store) = live_store() else { return };
    let key_id = uid("vk_kwc_recl");
    let p1 = uid("AKIA_KWC_RECL1");
    let p2 = uid("AKIA_KWC_RECL2");
    let key = vk(&key_id);
    let c1 = cred(&key_id, &p1, 0);
    let c2 = cred(&key_id, &p2, 0);
    store.put_key_with_credential(&key, &c1).unwrap();
    store.revoke_credential(&c1.meta.id, "rotated").unwrap();
    store.put_key_with_credential(&key, &c2).unwrap();
    assert!(store
        .lookup_credential_secret("sigv4", &p1)
        .unwrap()
        .is_none());
    assert_eq!(
        store
            .lookup_credential_secret("sigv4", &p2)
            .unwrap()
            .expect("C2 resolves")
            .meta
            .id,
        c2.meta.id
    );
    // C1's old id pointer is gone: revoking it must not touch C2.
    let _ = store.revoke_credential(&c1.meta.id, "late retry");
    assert!(
        store
            .lookup_credential_secret("sigv4", &p2)
            .unwrap()
            .expect("C2 resolves")
            .meta
            .revoked_at
            .is_none(),
        "revoking C1's old id must leave C2 un-revoked"
    );
}

/// A replayed mint of a REVOKED credential must not un-revoke it.
#[test]
fn put_key_with_credential_never_remints_a_revoked_credential() {
    let Some(store) = live_store() else { return };
    let key_id = uid("vk_kwc_unrev");
    let p1 = uid("AKIA_KWC_UNREV");
    let key = vk(&key_id);
    let c1 = cred(&key_id, &p1, 0);
    store.put_key_with_credential(&key, &c1).unwrap();
    store.revoke_credential(&c1.meta.id, "rotated").unwrap();
    let again = store.put_key_with_credential(&key, &c1);
    assert!(
        again.is_err(),
        "re-minting a revoked credential must fail: {again:?}"
    );
    let row = store.lookup_credential_secret("sigv4", &p1).unwrap();
    assert!(
        row.is_none_or(|r| r.meta.revoked_at.is_some()),
        "the credential must stay revoked"
    );
}

/// A RESP parse error leaves the bad bytes buffered on the kept connection, so the connection must
/// be discarded: the op AFTER the malformed reply succeeds (on a fresh connection) instead of
/// failing on the same buffered bytes forever.
#[test]
fn a_malformed_reply_discards_the_kept_connection() {
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicBool, Ordering};
    if live_store().is_none() {
        return;
    }
    let (backend, db, userinfo) = live_parts();
    let poison = Arc::new(AtomicBool::new(false));
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let at = l.local_addr().unwrap().to_string();
    let flag = poison.clone();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(s) = s else { return };
            let b = std::net::TcpStream::connect(&backend).expect("the live server");
            let (s2, b2) = (s.try_clone().unwrap(), b.try_clone().unwrap());
            std::thread::spawn(move || pump(s, b));
            let flag = flag.clone();
            std::thread::spawn(move || {
                let (mut from, mut to) = (b2, s2);
                let mut buf = [0_u8; 16 * 1024];
                loop {
                    match from.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if flag.swap(false, Ordering::SeqCst) {
                                // The malformed reply now; the REAL reply late, as a slow
                                // (not gone) server would deliver it.
                                if to.write_all(b"!bad\r\n").is_err() {
                                    return;
                                }
                                let (mut late, stale) =
                                    (to.try_clone().unwrap(), buf[..n].to_vec());
                                std::thread::spawn(move || {
                                    std::thread::sleep(std::time::Duration::from_millis(300));
                                    let _ = late.write_all(&stale);
                                });
                                continue;
                            }
                            if to.write_all(&buf[..n]).is_err() || to.flush().is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    let (store, _) = open_on(
        &settings_for(&format!("redis://{userinfo}{at}/{db}")),
        plain,
    );
    let store = store.expect("opens through the proxy");
    let id = uid("vk_malformed");
    store.put_key(&vk(&id)).unwrap();
    poison.store(true, Ordering::SeqCst);
    assert!(
        store.list_denylist().is_err(),
        "the malformed reply is refused"
    );
    // The late real reply to the refused op lands on the old connection after this wait; it must
    // not be read as the reply to a LATER op.
    std::thread::sleep(std::time::Duration::from_millis(500));
    let got = store.get_key(&id);
    assert!(
        matches!(&got, Ok(Some(k)) if k.id == id),
        "the op after a malformed reply must not run on the poisoned kept connection: {got:?}"
    );
    let _ = store.purge_key_for_test(&id);
}

/// A replayed `put_credential` of a REVOKED credential must not un-revoke it.
#[test]
fn put_credential_never_remints_a_revoked_credential() {
    let Some(store) = live_store() else { return };
    let key_id = uid("vk_pc_unrev");
    let p1 = uid("AKIA_PC_UNREV");
    store.put_key(&vk(&key_id)).unwrap();
    let c1 = cred(&key_id, &p1, 0);
    store.put_credential(&c1).unwrap();
    store.revoke_credential(&c1.meta.id, "rotated").unwrap();
    let again = store.put_credential(&c1);
    assert!(
        again.is_err(),
        "re-minting a revoked credential must fail: {again:?}"
    );
    let row = store.lookup_credential_secret("sigv4", &p1).unwrap();
    assert!(
        row.is_none_or(|r| r.meta.revoked_at.is_some()),
        "the credential must stay revoked"
    );
}

// ── settings: the sibling-aligned parse (unknown key, connect_timeout_ms type, url shape) ────────

fn settings_err(json: &str) -> String {
    crate::ValkeyStore::from_settings(json.as_bytes())
        .expect_err(&format!("{json} must be refused"))
}

#[test]
fn settings_refuse_an_unknown_top_level_key() {
    let e = settings_err(r#"{"url":"redis://127.0.0.1:6379/0","urll":"x"}"#);
    assert_eq!(
        e,
        "invalid valkey plugin config: unknown setting `urll` (accepted: url, connect_timeout_ms)"
    );
}

#[test]
fn settings_refuse_a_connect_timeout_that_is_not_a_positive_integer() {
    for (bad, got) in [
        ("\"5000\"", "a string"),
        ("1.5", "a number"),
        ("-3", "a number"),
        ("0", "a number"),
        ("true", "a boolean"),
        ("[]", "an array"),
        ("{}", "an object"),
    ] {
        let e = settings_err(&format!(
            r#"{{"url":"redis://127.0.0.1:6379/0","connect_timeout_ms":{bad}}}"#
        ));
        assert_eq!(
            e,
            format!(
                "invalid valkey plugin config: `connect_timeout_ms` must be a positive integer \
                 (milliseconds), got {got}"
            ),
            "{bad}"
        );
    }
    crate::ValkeyStore::from_settings(
        br#"{"url":"redis://127.0.0.1:6379/0","connect_timeout_ms":250}"#,
    )
    .expect("a positive integer is accepted");
}

/// A `null` optional setting means the setting is absent.
#[test]
fn a_null_optional_setting_means_absent() {
    crate::ValkeyStore::from_settings(
        br#"{"url":"redis://127.0.0.1:6379/0","connect_timeout_ms":null}"#,
    )
    .expect("a null connect_timeout_ms is the default");
}

#[test]
fn settings_refuse_a_url_that_is_not_a_non_empty_string() {
    for (bad, want) in [
        ("5", "`url` must be a non-empty string, got a number"),
        ("\"\"", "`url` must be a non-empty string"),
        ("[]", "`url` must be a non-empty string, got an array"),
    ] {
        let e = settings_err(&format!(r#"{{"url":{bad}}}"#));
        assert_eq!(e, format!("invalid valkey plugin config: {want}"), "{bad}");
    }
}

/// A missing (or null) `url` and a settings document that is no object are refused in the one
/// grammar: `invalid valkey plugin config: ...`, naming the JSON type, never the value.
#[test]
fn every_settings_refusal_starts_with_the_one_prefix() {
    for json in ["{}", r#"{"url":null}"#] {
        assert_eq!(
            settings_err(json),
            "invalid valkey plugin config: `url` is required (a redis:// connection string)"
        );
    }
    for (json, got) in [
        ("[]", "an array"),
        ("\"redis://h\"", "a string"),
        ("5", "a number"),
        ("true", "a boolean"),
        ("null", "null"),
    ] {
        assert_eq!(
            settings_err(json),
            format!("invalid valkey plugin config: expected a JSON object, got {got}"),
            "{json}"
        );
    }
    assert!(settings_err("{not json").starts_with("invalid valkey plugin config: "));
}

#[test]
fn a_url_parse_refusal_is_not_worded_as_a_failed_connect() {
    let e = settings_err(r#"{"url":"http://127.0.0.1:6379/0"}"#);
    assert!(e.starts_with("invalid valkey plugin config: url: "), "{e}");
    assert!(
        !e.contains("failed to connect"),
        "nothing was connected: {e}"
    );
}

// ── redaction: the unix-socket query form ─────────────────────────────────────────────────────

#[test]
fn the_unix_socket_query_password_never_reaches_an_error_or_a_debug() {
    for (url, secret) in [
        ("valkey+unix:///run/v.sock?pass=hunter2xyz", "hunter2xyz"),
        (
            "valkey+unix:///run/v.sock?db=1&password=hunter2xyz",
            "hunter2xyz",
        ),
        ("unix:///run/v.sock?user=al&pass=p%40ssw0rd", "p%40ssw0rd"),
    ] {
        assert!(url_password(url).is_some(), "{url}: password extracted");
        let leaked = scrub(
            format!("could not reach {url}"),
            url_password(url).as_deref(),
        );
        assert!(
            !leaked.contains(secret) && !leaked.contains("p@ssw0rd"),
            "{url}: {leaked}"
        );
        // `password=` is not a parameter the unix form reads, so that URL is refused: its refusal
        // must not carry the secret either. The others parse, and their Debug never shows it.
        let shown = match parse_url(url) {
            Ok(t) => format!("{t:?}"),
            Err(e) => e.to_string(),
        };
        assert!(
            !shown.contains(secret) && !shown.contains("p@ssw0rd"),
            "{shown}"
        );
    }
    // An error built from a bad unix URL carrying the secret never contains it.
    let e = crate::ValkeyStore::from_settings(
        br#"{"url":"valkey+unix:///run/v.sock?pass=hunter2xyz&db=notanumber"}"#,
    )
    .expect_err("a bad db is refused");
    assert!(!e.contains("hunter2xyz"), "{e}");
}

// ── not-found / refusal wording ──────────────────────────────────────────────────────────────

#[test]
fn unknown_id_refusals_name_the_id_in_the_canonical_form() {
    let Some(store) = live_store() else { return };
    let id = uid("vk_never_existed");
    let e = store.delete_key(&id).unwrap_err().to_string();
    assert!(e.contains(&format!("delete_key: unknown id '{id}'")), "{e}");
    assert!(!e.contains("- Client"), "{e}");
}

/// An id that spells the delete's internal retry text is just an unknown id: it answers the refusal
/// (it never loops). The call runs on a thread so a regression fails by timeout, not by hanging.
#[test]
fn an_unknown_id_spelling_the_retry_sentinel_is_refused_not_retried() {
    if live_store().is_none() {
        return;
    }
    let id = uid("__internal_delete_key_retry__");
    let want = id.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let store = live_store().expect("live");
        let _ = tx.send(store.delete_key(&id).unwrap_err().to_string());
    });
    let e = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("delete_key answered instead of retrying forever");
    assert!(
        e.contains(&format!("delete_key: unknown id '{want}'")),
        "{e}"
    );
}

/// Two writers interleaved at the revision read: the one that allocates first but commits last must
/// still stamp the HIGHER revision (else a cursor reader that already passed the other's stamp skips
/// its row forever). The first writer is held after its revision command, the second runs to completion.
#[test]
fn a_writer_overtaken_between_its_revision_read_and_commit_restamps_above_the_winner() {
    if live_store().is_none() {
        return;
    }
    let url = std::env::var("VALKEY_URL").unwrap();
    let gate = interleave::gate(&url, false, |c| {
        interleave::contains(c, b"busbar:revision") && !interleave::contains(c, b"WATCH")
    });
    let (a, b) = (uid("vk_rev_a"), uid("vk_rev_b"));
    let slow = ValkeyStore::connect(&gate.url).expect("connect through the gate");
    let fast = live_store().unwrap();
    let a_id = a.clone();
    let writer = std::thread::spawn(move || slow.put_key(&vk(&a_id)));
    gate.held
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the first writer reached its revision command");
    fast.put_key(&vk(&b)).unwrap();
    gate.release.send(()).unwrap();
    writer.join().unwrap().unwrap();
    let rev = |id: &str| fast.get_key(id).unwrap().unwrap().revision;
    assert!(rev(&a) > rev(&b), "a={} b={}", rev(&a), rev(&b));
    let mut r = redis::Client::open(url.as_str())
        .unwrap()
        .get_connection()
        .unwrap();
    let score =
        |id: &str, r: &mut redis::Connection| -> f64 { r.zscore("busbar:keys:byrev", id).unwrap() };
    assert!(score(&a, &mut r) > score(&b, &mut r));
}

/// A handshake the server REFUSES (AUTH) must not leave its connection kept: the next op would skip
/// the handshake and run unauthenticated on db 0. The user's password is rotated away, its
/// connections killed, one op fails to re-authenticate, the password is restored, and the next op
/// must land in the store's own database.
#[test]
fn a_refused_handshake_does_not_leave_a_connection_kept() {
    if live_store().is_none() {
        return;
    }
    let url = std::env::var("VALKEY_URL").unwrap();
    let addr = interleave::upstream_addr(&url);
    let user = uid("hs_user");
    let (pw1, pw2) = ("pw-one", "pw-two");
    let mut admin = redis::Client::open(url.as_str())
        .unwrap()
        .get_connection()
        .unwrap();
    let acl = |admin: &mut redis::Connection, pw: &str| {
        let _: () = redis::cmd("ACL")
            .arg("SETUSER")
            .arg(&user)
            .arg(&["on", "resetpass", "~*", "&*", "+@all"][..])
            .arg(format!(">{pw}"))
            .query(admin)
            .unwrap();
    };
    acl(&mut admin, pw1);
    let store = ValkeyStore::connect(&format!("redis://{user}:{pw1}@{addr}/10")).unwrap();
    store.put_key(&vk(&uid("vk_hs_a"))).unwrap();
    acl(&mut admin, pw2);
    let _: i64 = redis::cmd("CLIENT")
        .arg(&["KILL", "USER", user.as_str()][..])
        .query(&mut admin)
        .unwrap();
    store
        .put_key(&vk(&uid("vk_hs_b")))
        .expect_err("the re-authentication is refused");
    acl(&mut admin, pw1);
    let id = uid("vk_hs_c");
    let landed = store.put_key(&vk(&id));
    let row = format!("busbar:key:{id}");
    let in_db0: bool = admin.exists(&row).unwrap();
    let _: () = redis::cmd("ACL")
        .arg(&["DELUSER", user.as_str()][..])
        .query(&mut admin)
        .unwrap();
    if in_db0 {
        let _: () = admin.del(&row).unwrap();
    }
    landed.expect("the next op re-handshakes and succeeds");
    assert!(
        !in_db0,
        "the op ran on db 0, on a connection that skipped its handshake"
    );
}

/// `list_metering` reads one snapshot: a write landing after it has read the bucket's row set is
/// either wholly in the answer or wholly out of it (never a new count on a row set that predates it).
#[test]
fn list_metering_is_one_snapshot() {
    let Some(direct) = live_store() else { return };
    let url = std::env::var("VALKEY_URL").unwrap();
    let bucket = unique_bucket(20260802);
    let delta = |model: &str, requests: u64| MeteringDelta {
        key_id: uid("vk_snapshot"),
        bucket,
        model: model.to_string(),
        provider: "p".to_string(),
        tokens_input: 0,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests,
        billable_requests: 0,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
        priced_from_ms: 0,
        usage_units: Default::default(),
    };
    let mut a = delta("a", 1);
    a.key_id = "vk_snapshot".to_string();
    let mut b = delta("b", 5);
    b.key_id = "vk_snapshot".to_string();
    direct.add_metering(&a).unwrap();

    let set = metering_set(bucket);
    let gate = interleave::gate(&url, false, move |c| {
        interleave::contains(c, set.as_bytes())
    });
    let store = ValkeyStore::connect(&gate.url).unwrap();
    let reader = std::thread::spawn(move || store.list_metering(bucket));
    gate.held
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the read is held after it asked for the bucket's rows");
    direct.add_metering(&a).unwrap();
    direct.add_metering(&b).unwrap();
    gate.release.send(()).unwrap();
    let mut rows: Vec<(String, u64)> = reader
        .join()
        .unwrap()
        .unwrap()
        .into_iter()
        .map(|r| (r.model, r.requests))
        .collect();
    rows.sort();
    let before = vec![("a".to_string(), 1)];
    let after = vec![("a".to_string(), 2), ("b".to_string(), 5)];
    assert!(rows == before || rows == after, "a torn read: {rows:?}");
}

/// A write that decides nothing to write does not `EXEC`: a replayed credential put, a repeat
/// revoke and a repeat delete leave the transaction without contending on `busbar:revision`.
#[test]
fn no_op_paths_do_not_exec() {
    let Some(direct) = live_store() else { return };
    let url = std::env::var("VALKEY_URL").unwrap();
    let execs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = execs.clone();
    let proxied = interleave::tamper(
        &url,
        |c| interleave::contains(c, b"EXEC"),
        move || {
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        },
    );
    let store = ValkeyStore::connect(&proxied).unwrap();

    let (kid, gone, revoked) = (uid("vk_noop"), uid("vk_noop_gone"), uid("vk_noop_rev"));
    let c = cred(&kid, &uid("AKIA_NOOP"), 0);
    direct.put_key_with_credential(&vk(&kid), &c).unwrap();
    direct.put_key(&vk(&gone)).unwrap();
    direct.delete_key(&gone).unwrap();
    let r = cred(&revoked, &uid("AKIA_NOOP_REV"), 0);
    direct.put_key_with_credential(&vk(&revoked), &r).unwrap();
    direct.revoke_credential(&r.meta.id, "first").unwrap();

    execs.store(0, std::sync::atomic::Ordering::SeqCst);
    store.put_credential(&c).expect("a replay is Ok");
    store
        .put_key_with_credential(&vk(&kid), &c)
        .expect("a replay is Ok");
    store.revoke_credential(&r.meta.id, "again").unwrap();
    store.delete_key(&gone).unwrap();
    assert_eq!(
        execs.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a no-op path sent an EXEC"
    );
}

/// One op in flight must not block the next: the store keeps several connections, one per op.
#[test]
fn a_held_op_does_not_block_a_second_op_on_the_same_store() {
    if live_store().is_none() {
        return;
    }
    let url = std::env::var("VALKEY_URL").unwrap();
    let (a, b) = (uid("vk_pool_a"), uid("vk_pool_b"));
    let direct = live_store().unwrap();
    direct.put_key(&vk(&a)).unwrap();
    direct.put_key(&vk(&b)).unwrap();
    let held_row = format!("busbar:key:{a}");
    let gate = interleave::gate(&url, true, move |c| {
        interleave::contains(c, b"GET") && interleave::contains(c, held_row.as_bytes())
    });
    let store = Arc::new(ValkeyStore::connect(&gate.url).unwrap());
    let first = store.clone();
    let id = a.clone();
    let holder = std::thread::spawn(move || first.get_key(&id));
    gate.held
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the first op is held mid-flight");
    let (tx, rx) = std::sync::mpsc::channel();
    let second = store.clone();
    std::thread::spawn(move || {
        let _ = tx.send(second.get_key(&b));
    });
    let got = rx.recv_timeout(std::time::Duration::from_secs(5));
    gate.release.send(()).unwrap();
    holder.join().unwrap().unwrap();
    got.expect("the second op ran while the first was held")
        .unwrap();
}

/// `delete_key` leaves the key's own usage windows and every other bucket's whose id starts with
/// `<id>:` (a group bucket, an era bucket) alone: the ledger is billing evidence.
#[test]
fn delete_key_leaves_its_own_and_other_buckets_usage_windows() {
    let Some(store) = live_store() else { return };
    let id = uid("vk_usage_scope");
    store.put_key(&vk(&id)).unwrap();
    let mut r = redis::Client::open(std::env::var("VALKEY_URL").unwrap())
        .unwrap()
        .get_connection()
        .unwrap();
    let windows = [
        format!("busbar:usage:{id}:60"),
        format!("busbar:usage:{id}:x@1:60"),
        format!("busbar:usage:{id}:e:ab12"),
    ];
    for k in &windows {
        let _: () = r.hset(k, "requests", 1).unwrap();
    }
    store.delete_key(&id).unwrap();
    let left: Vec<bool> = windows.iter().map(|k| r.exists(k).unwrap()).collect();
    let _: () = r.del(&windows[..]).unwrap();
    assert_eq!(left, vec![true; 3], "delete_key touched a usage window");
}

/// `delete_key` takes the key's credential pointers out of the credential revision index too: a
/// destroyed row must not stay in `busbar:creds:byrev` for ever (the key's own tombstone is what
/// tells hydrators to evict).
#[test]
fn delete_key_removes_its_credentials_from_the_revision_index() {
    let Some(store) = live_store() else { return };
    let key_id = uid("vk_byrev");
    store.put_key(&vk(&key_id)).unwrap();
    let c0 = cred(&key_id, &uid("AKIA_BYREV"), 0);
    store.put_credential(&c0).unwrap();
    let member = format!("{key_id}:{}:{}", c0.meta.kind, c0.meta.slot);
    let mut r = redis::Client::open(std::env::var("VALKEY_URL").unwrap())
        .unwrap()
        .get_connection()
        .unwrap();
    let before: Option<f64> = r.zscore("busbar:creds:byrev", &member).unwrap();
    assert!(before.is_some(), "the credential was indexed by revision");
    store.delete_key(&key_id).unwrap();
    let after: Option<f64> = r.zscore("busbar:creds:byrev", &member).unwrap();
    assert!(after.is_none(), "the destroyed credential stays indexed");
}

/// Two revokes of one credential racing: the one that commits first stands. The slower one read the
/// live row, was overtaken, and must NOT overwrite the first's reason and time.
#[test]
fn a_revoke_overtaken_before_commit_does_not_overwrite_the_first_reason() {
    if live_store().is_none() {
        return;
    }
    let url = std::env::var("VALKEY_URL").unwrap();
    let key_id = uid("vk_revoke_race");
    let c0 = cred(&key_id, &uid("AKIA_REVOKE_RACE"), 0);
    let direct = live_store().unwrap();
    direct.put_key(&vk(&key_id)).unwrap();
    direct.put_credential(&c0).unwrap();
    let row = format!("busbar:cred:{key_id}:{}:{}", c0.meta.kind, c0.meta.slot);
    let gate = interleave::gate(&url, false, move |c| {
        interleave::contains(c, b"GET")
            && interleave::contains(c, row.as_bytes())
            && !interleave::contains(c, b"WATCH")
    });
    let slow = ValkeyStore::connect(&gate.url).unwrap();
    let id = c0.meta.id.clone();
    let writer = std::thread::spawn(move || slow.revoke_credential(&id, "slow"));
    gate.held
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the slow revoke has read the live row");
    direct.revoke_credential(&c0.meta.id, "fast").unwrap();
    gate.release.send(()).unwrap();
    writer.join().unwrap().unwrap();
    let metas = direct.list_credentials(&key_id).unwrap();
    assert_eq!(metas[0].revoke_reason.as_deref(), Some("fast"), "{metas:?}");
}

/// A transaction whose watched key moves on EVERY attempt gives up with an error after a bounded
/// number of tries instead of spinning for ever. The proxy bumps the revision counter ahead of each
/// `EXEC`; the call runs on a thread so a regression fails by timeout.
#[test]
fn a_transaction_that_always_aborts_ends_with_an_error() {
    if live_store().is_none() {
        return;
    }
    // A database of its own: the bumps would abort every other test's transaction in db 0.
    let mut up = fresh_db_client(7);
    let url = url_for_db(7);
    let bump_url = url.clone();
    let proxied = interleave::tamper(
        &url,
        |c| interleave::contains(c, b"EXEC"),
        move || {
            let mut r = redis::Client::open(bump_url.as_str())
                .unwrap()
                .get_connection()
                .unwrap();
            let _: i64 = redis::cmd("INCR")
                .arg("busbar:revision")
                .query(&mut r)
                .unwrap();
        },
    );
    let id = uid("vk_always_abort");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let store = ValkeyStore::connect(&proxied).unwrap();
        let _ = tx.send(store.put_key(&vk(&id)).unwrap_err().to_string());
    });
    let e = rx
        .recv_timeout(std::time::Duration::from_secs(20))
        .expect("put_key gave up instead of retrying for ever");
    redis::cmd("FLUSHDB").query::<()>(&mut up).unwrap();
    assert!(e.contains("aborted"), "{e}");
}

/// Putting a credential again is a replay only when it is the SAME credential: one with the stored
/// id but different content is refused, never answered as a success that wrote nothing.
#[test]
fn re_putting_a_credential_id_with_different_content_is_refused() {
    let Some(store) = live_store() else { return };
    let key_id = uid("vk_replay");
    store.put_key(&vk(&key_id)).unwrap();
    let c0 = cred(&key_id, &uid("AKIA_REPLAY"), 0);
    store.put_credential(&c0).unwrap();
    store
        .put_credential(&c0)
        .expect("an identical re-put replays");
    let mut other = c0.clone();
    other.meta.public_id = uid("AKIA_OTHER");
    let e = store.put_credential(&other).unwrap_err().to_string();
    assert!(
        e.contains(&format!(
            "put_credential: credential '{}' already exists with different content",
            c0.meta.id
        )),
        "{e}"
    );
    let mut third = c0.clone();
    third.secret = "v1:plain:changed".into();
    let e = store
        .put_key_with_credential(&vk(&key_id), &third)
        .unwrap_err()
        .to_string();
    assert!(e.contains("already exists with different content"), "{e}");
}

#[test]
fn put_refusals_carry_the_reason_without_the_kind_suffix() {
    let Some(store) = live_store() else { return };
    let id = uid("vk_tomb_wording");
    store.put_key(&vk(&id)).unwrap();
    store.delete_key(&id).unwrap();
    let e = store.put_key(&vk(&id)).unwrap_err().to_string();
    assert!(e.contains(&format!("put_key: '{id}' is tombstoned")), "{e}");
    assert!(!e.contains("- Client"), "{e}");
}

/// A unix-socket URL's `?pass=` is the scrub secret too: an error string that echoes the URL (or
/// the password, raw or decoded) carries no credential bytes.
#[test]
fn unix_url_query_password_is_scrubbed_from_errors() {
    for url in [
        "redis+unix:///run/v.sock?db=2&pass=CANARY-vk-p4ss",
        "unix:///run/v.sock?user=al&pass=CANARY-vk-p4ss",
        "valkey+unix:///run/v.sock?pass=CANARY%2Dvk%2Dp4ss&db=1",
    ] {
        let secret = url_password(url);
        for leak in [
            format!("valkey connect: cannot reach {url}"),
            "valkey connect: AUTH CANARY-vk-p4ss refused".to_string(),
        ] {
            let out = scrub(leak, secret.as_deref());
            assert!(!out.contains("CANARY"), "{url}: password leaked: {out}");
        }
    }
    // A query value's `+` is a space in the form encoding the unix URL reads.
    let url = "valkey+unix:///run/v.sock?pass=CANARY+vk+p4ss";
    let out = scrub(
        "valkey connect: AUTH CANARY vk p4ss refused".to_string(),
        url_password(url).as_deref(),
    );
    assert!(!out.contains("CANARY"), "a `+` password leaked: {out}");
    // The userinfo form is unchanged; a unix URL without `pass=` has no secret.
    assert_eq!(url_password("redis://u:p@host:6379").as_deref(), Some("p"));
    assert_eq!(url_password("redis+unix:///run/v.sock?db=2"), None);
    // `password=` is not a parameter the unix form reads (it is refused at parse), yet a value an
    // operator wrote under that name is still treated as a secret and never echoed.
    assert_eq!(
        url_password("redis+unix:///run/v.sock?password=x").as_deref(),
        Some("x")
    );
}

/// A URL parameter the store does not read is REFUSED, never silently ignored; its name is withheld
/// when the URL carries a password (an unencoded one can split at `?`).
#[test]
fn an_unknown_url_parameter_is_refused_not_ignored() {
    for url in [
        "redis://127.0.0.1:6379/0?timeout=5",
        "valkey+unix:///run/v.sock?db=1&password=x",
        "redis://u:12?abc@127.0.0.1:6379/0",
    ] {
        assert!(parse_url(url).is_err(), "{url} must be refused");
    }
    let e = parse_url("redis://127.0.0.1:6379/0?timeout=5")
        .unwrap_err()
        .to_string();
    assert!(e.contains("timeout") && e.contains("not supported"), "{e}");
    let e = parse_url("redis://u:12?abc@127.0.0.1:6379/0")
        .unwrap_err()
        .to_string();
    assert!(!e.contains("abc"), "the password tail leaked: {e}");
    for ok in [
        "redis://127.0.0.1:6379/0?protocol=resp2",
        "valkey+unix:///run/v.sock?db=1&user=al&pass=x",
    ] {
        parse_url(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
    }
}

/// UPSERT IS BY `(kind, id)` (the contract's `RecordStore::upsert_plane_record` /
/// `get_plane_record`), with or without a parent: an upserted record that names a parent reads back
/// by its own id, a second id under the same parent is a second record (never an overwrite), the
/// parent-scoped listing and the parent enumeration still see both, and a delete or a purge keeps
/// both exact.
#[test]
fn a_parented_upserted_record_reads_back_by_its_own_id() {
    let Some(store) = live_store() else { return };
    let kind = "vk_parented_task";
    let child = |id: &str, ts: u64, body: &[u8]| busbar_contract::records::PlaneRecord {
        kind: kind.to_string(),
        id: id.to_string(),
        parent: Some("vk_ctx".to_string()),
        seq: 0,
        ts,
        disposition: PlaneDisposition::Active,
        body: body.to_vec(),
    };
    for id in ["vk_c1", "vk_c2", "vk_ctx"] {
        store.delete_plane_record(kind, id).unwrap();
    }
    store.purge_plane_records_before(kind, u64::MAX).unwrap();

    store
        .upsert_plane_record(child("vk_c1", 10, b"one").view())
        .unwrap();
    store
        .upsert_plane_record(child("vk_c2", 10, b"two").view())
        .unwrap();
    assert_eq!(
        store.get_plane_record(kind, "vk_c1").unwrap(),
        Some(b"one".to_vec())
    );
    assert_eq!(
        store.get_plane_record(kind, "vk_c2").unwrap(),
        Some(b"two".to_vec())
    );
    let parent = busbar_contract::records::PlaneSelector::Parent("vk_ctx".into());
    let mut listed = store.list_plane_records(kind, &parent).unwrap();
    listed.sort();
    assert_eq!(listed, vec![b"one".to_vec(), b"two".to_vec()]);
    assert_eq!(
        store.list_plane_record_parents(kind).unwrap(),
        vec!["vk_ctx".to_string()]
    );
    // A record whose own id is the parent's name, under another parent, is not the parent's child.
    let mut other = child("vk_ctx", 10, b"other");
    other.parent = Some("vk_elsewhere".to_string());
    store.upsert_plane_record(other.view()).unwrap();
    let mut listed = store.list_plane_records(kind, &parent).unwrap();
    listed.sort();
    assert_eq!(listed, vec![b"one".to_vec(), b"two".to_vec()]);
    store.delete_plane_record(kind, "vk_ctx").unwrap();
    assert_eq!(
        store.get_plane_record(kind, "vk_c1").unwrap(),
        Some(b"one".to_vec())
    );

    // A second upsert of one id replaces it; deleting it by id removes it alone.
    store
        .upsert_plane_record(child("vk_c1", 10, b"one'").view())
        .unwrap();
    assert_eq!(
        store.get_plane_record(kind, "vk_c1").unwrap(),
        Some(b"one'".to_vec())
    );
    store.delete_plane_record(kind, "vk_c1").unwrap();
    assert_eq!(store.get_plane_record(kind, "vk_c1").unwrap(), None);
    assert_eq!(
        store.list_plane_records(kind, &parent).unwrap(),
        vec![b"two".to_vec()]
    );
    assert_eq!(
        store.list_plane_record_parents(kind).unwrap(),
        vec!["vk_ctx".to_string()]
    );

    // A purge takes the last child out of the parent's listing and enumeration too.
    assert_eq!(store.purge_plane_records_before(kind, 11).unwrap(), 1);
    assert_eq!(store.get_plane_record(kind, "vk_c2").unwrap(), None);
    assert!(store.list_plane_records(kind, &parent).unwrap().is_empty());
    assert!(store.list_plane_record_parents(kind).unwrap().is_empty());
}

/// Redemption stores decimal strings, not signed columns. Permanent node claims and clocks
/// past i64::MAX must retain exact one-use and expiry-boundary semantics.
#[test]
fn token_redemption_keeps_the_full_u64_range_exact() {
    let Some(store) = live_store() else { return };
    for expiry in [i64::MAX as u64 + 1, u64::MAX - 1, u64::MAX] {
        let token = uid("tok_full_u64");
        assert!(store
            .redeem_plane_token("node-id", &token, expiry, expiry - 1)
            .unwrap());
        assert!(!store
            .redeem_plane_token("node-id", &token, expiry, expiry)
            .unwrap());
        if let Some(after) = expiry.checked_add(1) {
            assert!(store
                .redeem_plane_token("node-id", &token, u64::MAX, after)
                .unwrap());
            assert!(!store
                .redeem_plane_token("node-id", &token, u64::MAX, after)
                .unwrap());
        }
    }
}

/// Existing revoked credentials are repaired on upgrade, and the repair reaches hydrated caches.
#[test]
fn a_v9_upgrade_scrubs_revoked_credentials_and_publishes_the_repairs_once() {
    let Some(_) = live_store() else { return };
    let mut raw = fresh_db_client(5);
    let url = url_for_db(5);
    let store = ValkeyStore::connect(&url).unwrap();
    let mut before = Vec::new();
    for index in 0..4 {
        let key_id = uid("vk_revoked_upgrade");
        let public_id = uid("AKIA_UPGRADE");
        let offered = cred(&key_id, &public_id, 0);
        store
            .put_key_with_credential(&vk(&key_id), &offered)
            .unwrap();
        let row_key = cred_row_key(&key_id, "sigv4", 0);
        let text: String = raw.get(&row_key).unwrap();
        let mut row: CredentialSecret = serde_json::from_str(&text).unwrap();
        if index < 3 {
            row.meta.revoked_at = Some(1234);
            row.meta.revoke_reason = Some("legacy revoke".into());
        }
        if index == 1 || index == 2 {
            row.secret.clear();
        }
        if index == 2 {
            row.meta.secret_form = SecretForm::None;
        }
        let text = cred_to_json(&row).unwrap();
        raw.set::<_, _, ()>(&row_key, &text).unwrap();
        before.push((row_key, row, text));
    }
    let watermark = before
        .iter()
        .map(|(_, row, _)| row.meta.revision)
        .max()
        .unwrap();
    raw.set::<_, _, ()>(SCHEMA_KEY, 9).unwrap();
    drop(store);
    let reopened = ValkeyStore::connect(&url).expect("the supported old namespace upgrades");
    let mut repaired_bytes = Vec::new();
    for (index, (key, old, old_text)) in before.iter().enumerate() {
        let text: String = raw.get(key).unwrap();
        let row: CredentialSecret = serde_json::from_str(&text).unwrap();
        if index < 2 {
            assert_eq!(
                row.secret, "",
                "persisted revoked material must be destroyed"
            );
            assert_eq!(row.meta.secret_form, SecretForm::None);
            assert!(
                row.meta.revision > watermark,
                "hydrators must observe the repair"
            );
            let mut expected = old.meta.clone();
            expected.secret_form = SecretForm::None;
            expected.revision = row.meta.revision;
            assert_eq!(
                row.meta, expected,
                "original revocation metadata is retained"
            );
            let score: u64 = raw.zscore(CREDS_BYREV, slot_pointer(&row.meta)).unwrap();
            assert_eq!(score, row.meta.revision);
        } else {
            assert_eq!(
                &text, old_text,
                "clean revoked and live rows remain byte-identical"
            );
        }
        repaired_bytes.push(text);
    }
    let delta = reopened.list_credentials_since(watermark).unwrap();
    for (_, row, _) in before.iter().take(2) {
        let repaired = delta
            .iter()
            .find(|candidate| candidate.meta.id == row.meta.id)
            .expect("repair is hydrated");
        assert!(repaired.secret.is_empty());
        assert_eq!(repaired.meta.secret_form, SecretForm::None);
    }
    let marker: i64 = raw.get(SCHEMA_KEY).unwrap();
    assert_eq!(
        marker, 10,
        "the completed repair advances the schema marker"
    );
    let revision: u64 = raw.get(REVISION_KEY).unwrap();
    drop(reopened);
    // A crash after data repair but before the marker write must be safe to replay.
    raw.set::<_, _, ()>(SCHEMA_KEY, 9).unwrap();
    let direct = ValkeyStore::connect(&url).unwrap();
    let marker: i64 = raw.get(SCHEMA_KEY).unwrap();
    assert_eq!(marker, 10);
    let after_revision: u64 = raw.get(REVISION_KEY).unwrap();
    assert_eq!(
        after_revision, revision,
        "replay does not allocate another revision"
    );
    for ((key, _, _), expected) in before.iter().zip(repaired_bytes) {
        let actual: String = raw.get(key).unwrap();
        assert_eq!(
            actual, expected,
            "a completed repair never gains another revision"
        );
    }

    // A concurrent remint wins over a repair's old snapshot; the WATCH retry must reread it.
    let key_id = uid("vk_repair_remint");
    let old = cred(&key_id, &uid("AKIA_OLD"), 0);
    direct.put_key_with_credential(&vk(&key_id), &old).unwrap();
    direct.revoke_credential(&old.meta.id, "rotated").unwrap();
    let row_key = cred_row_key(&key_id, "sigv4", 0);
    let text: String = raw.get(&row_key).unwrap();
    let mut dirty: CredentialSecret = serde_json::from_str(&text).unwrap();
    dirty.secret = "legacy retained material".into();
    dirty.meta.secret_form = SecretForm::Recoverable;
    raw.set::<_, _, ()>(&row_key, cred_to_json(&dirty).unwrap())
        .unwrap();
    raw.set::<_, _, ()>(SCHEMA_KEY, 9).unwrap();
    let gate = interleave::gate(&url, true, |chunk| {
        interleave::contains(chunk, b"$4\r\nEXEC\r\n")
    });
    let gate_url = gate.url.clone();
    let migrating = std::thread::spawn(move || ValkeyStore::connect(&gate_url));
    gate.held
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("repair reached EXEC after reading the revoked row");
    let replacement = cred(&key_id, &uid("AKIA_NEW"), 0);
    direct.put_credential(&replacement).unwrap();
    let minted: String = raw.get(&row_key).unwrap();
    let new_id_key = cred_id_key(&replacement.meta.id);
    let new_public_key = cred_pub_key("sigv4", &replacement.meta.public_id);
    let id_pointer: String = raw.get(&new_id_key).unwrap();
    let public_pointer: String = raw.get(&new_public_key).unwrap();
    gate.release.send(()).unwrap();
    let upgraded = migrating
        .join()
        .unwrap()
        .expect("the repair retries the changed slot");
    let after: String = raw.get(&row_key).unwrap();
    assert_eq!(
        after, minted,
        "the live replacement is never scrubbed or reverted"
    );
    assert_eq!(raw.get::<_, String>(&new_id_key).unwrap(), id_pointer);
    assert_eq!(
        raw.get::<_, String>(&new_public_key).unwrap(),
        public_pointer
    );
    assert!(!raw.exists::<_, bool>(cred_id_key(&old.meta.id)).unwrap());
    assert!(!raw
        .exists::<_, bool>(cred_pub_key("sigv4", &old.meta.public_id))
        .unwrap());
    let found = upgraded
        .lookup_credential_secret("sigv4", &replacement.meta.public_id)
        .unwrap()
        .unwrap();
    assert_eq!(found.meta.id, replacement.meta.id);
    assert!(found.meta.revoked_at.is_none());
    assert_eq!(found.secret, replacement.secret);
}
