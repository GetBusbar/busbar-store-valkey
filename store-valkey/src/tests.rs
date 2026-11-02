#[path = "../../test-support/valkey_io.rs"]
mod valkey_io;
// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::sdk::store::column::clamp;
use busbar_contract::records::{MeteringDelta, PlaneDisposition, RecordStore, SecretForm};
#[allow(unused_imports)]
use redis::Commands;
use std::sync::OnceLock;

#[path = "tests/credential_auth.rs"]
mod credential_auth;
#[path = "tests/credential_rewrap.rs"]
mod credential_rewrap;
#[path = "../../test-support/database.rs"]
pub(crate) mod database;

use busbar_contract::abi::store::OpId;
use busbar_plugin_loader::dispatch::kinds::store::Store;
use busbar_plugin_loader::dispatch::{
    load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink,
};
use busbar_plugin_loader::store_v3::LoadedStore;
#[path = "tests/socket_observer.rs"]
mod socket_observer;
use socket_observer::ValkeyWireObserver;

/// THE STORE UNDER TEST is the store as the host opens it: its door through the loader
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
        let conns: Arc<dyn busbar_contract::conn::DeclaredConns> = valkey_io::host(
            d.conn_waker(),
            busbar_contract::transport::EgressTrust::default(),
        );
        (d, conns)
    })
}

/// The node's `op_id` allocator for the bridge's writes: a node half no earlier run used (the
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

impl Raw for database::Database {
    fn with_conn<T>(
        &self,
        f: impl FnOnce(&mut redis::Connection) -> redis::RedisResult<T>,
    ) -> RecordStoreResult<T> {
        let mut c = self
            .connection()
            .map_err(|_| RecordStoreError("private test connection failed".into()))?;
        f(&mut c).map_err(|_| RecordStoreError("private test command failed".into()))
    }
}

/// Test convenience preserves borrowed-string callers; production settings capture in the SDK.
fn parse_url(input: &str) -> resp::RedisResult<Target> {
    let url = busbar_contract::abi::sdk::cred::ValkeyUrl(
        busbar_contract::abi::sdk::cred::CredUrl::parse_valkey(input).map_err(url_refused)?,
    );
    parse_target(&url)
}
fn captured_url(input: &str) -> ValkeyUrl {
    ValkeyUrl(busbar_contract::abi::sdk::cred::CredUrl::parse_valkey(input).unwrap())
}
fn assert_auth(target: &Target, user: Option<&str>, password: &str) {
    let (got_user, got_password) = target.auth.as_ref().expect("AUTH configured");
    assert_eq!(got_user.as_deref(), user);
    let expected: Cred =
        busbar_contract::abi::sdk::cred::settings(&serde_json::to_vec(password).unwrap()).unwrap();
    assert!(got_password == &expected, "sealed password differs");
}

#[test]
fn password_capture_and_redaction_preserve_raw_and_decoded_forms() {
    for (url, decoded, raw) in [
        ("redis://:s3cr3t@host:6379/0", "s3cr3t", "s3cr3t"),
        ("rediss://user:p%40ss@host:6380", "p@ss", "p%40ss"),
    ] {
        let captured = captured_url(url);
        assert!(captured.password().is_some());
        for leak in [
            format!("connection refused for {url}"),
            format!("AUTH {decoded} refused"),
        ] {
            let scrubbed = captured.redact_echo(&leak);
            assert!(
                !scrubbed.contains(raw) && !scrubbed.contains(decoded),
                "{scrubbed}"
            );
            assert!(scrubbed.contains("<redacted>"));
        }
    }
    for url in ["redis://host:6379", "redis://user@host:6379", "not a url"] {
        assert!(captured_url(url).password().is_none());
    }
    assert_eq!(captured_url("redis://h").redact_echo("plain"), "plain");
    assert_eq!(percent_decode_utf8("p%40ss").as_deref(), Some("p@ss"));
    assert_eq!(percent_decode_utf8("bad%zz").as_deref(), Some("bad%zz"));
}

#[test]
fn tls_url_scheme_is_accepted() {
    let t = parse_url("rediss://:pw@localhost:6380/0").expect("a rediss URL parses");
    assert!(t.tls);
    assert_eq!(t.addr, "localhost:6380");
    assert_auth(&t, None, "pw");
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
#[test]
fn urls_parse_as_the_upstream_driver_read_them() {
    let t = parse_url("redis://alice:p%40ss@db.internal:7000/3").unwrap();
    assert_eq!(
        (t.addr.as_str(), t.host.as_str(), t.tls, t.db),
        ("db.internal:7000", "db.internal", false, 3)
    );
    assert_auth(&t, Some("alice"), "p@ss");
    let t = parse_url("valkey://[::1]/").unwrap();
    assert_eq!(
        (t.addr.as_str(), t.host.as_str(), t.db),
        ("[::1]:6379", "::1", 0)
    );
    assert!(parse_url("redis://h").unwrap().auth.is_none());
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

    let t = parse_url("rediss://h:6380/#insecure").unwrap();
    assert!(t.tls && t.insecure);
    assert!(!parse_url("rediss://h:6380/").unwrap().insecure);
    assert_eq!(
        parse_url("rediss://h/#other").unwrap_err().to_string(),
        "only #insecure is supported as URL fragment - InvalidClientConfig"
    );
}

/// The unix-socket URLs 1.5.5's driver read (VALKEY-UNIX): the path is the connector's
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
        assert!(t.auth.is_none());
    }
    let t = parse_url("redis+unix:///run/v.sock?db=2&user=%25al&pass=%26%3F+x").unwrap();
    assert_eq!(t.db, 2);
    assert_auth(&t, Some("%al"), "&? x");
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
fn unique_bucket(base: u64) -> u64 {
    base * 1_000_000_000 + unique_suffix()
}

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

    assert!(delta.iter().any(|k| k.id == b), "{b} must be in the delta");
    assert!(
        !delta.iter().any(|k| k.id == a),
        "{a} was created BEFORE the watermark and must not reappear"
    );
}

/// A row at revision 0 (never stamped) is returned by every delta, and `since = 0` returns every
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

    let _ = store.purge_key_for_test("vk_live");
    let _ = store.purge_key_for_test("vk_dead");
    store.put_key(&vk("vk_live")).unwrap();
    store.put_key(&vk("vk_dead")).unwrap();
    store.delete_key("vk_dead").unwrap();
    let all = store.list_keys().unwrap();

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

#[test]
fn delete_key_tombstones_not_removes() {
    let Some(store) = live_store() else { return };

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
#[test]
fn delete_key_destroys_credential_secret_material() {
    let Some(store) = live_store() else { return };

    let _ = store.purge_key_for_test("vk_cred");
    let key = vk("vk_cred");
    let c = cred("vk_cred", "AKIA_LIVE", 0);
    store.put_key_with_credential(&key, &c).unwrap();

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

    let raw_after: Option<String> = store
        .with_conn(|conn| conn.get(cred_row_key("vk_cred", "sigv4", 0)))
        .unwrap();
    assert!(
        raw_after.is_none(),
        "credential row must be hard-deleted, not merely blanked"
    );

    assert!(store
        .lookup_credential_secret("sigv4", "AKIA_LIVE")
        .unwrap()
        .is_none());
    assert!(store.list_credentials("vk_cred").unwrap().is_empty());
}

/// HARDEST INVARIANT #2: the credential-id and public_id reverse-lookup pointers are cleaned up
#[test]
fn delete_key_cleans_up_reverse_lookup_pointers() {
    let Some(store) = live_store() else { return };

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
    let id = uid("vk_usage");
    store.put_key(&vk(&id)).unwrap();
    store
        .add_usage(
            &id,
            1000,
            &UsageDelta {
                requests: 1,
                billable_requests: 1,
                models: vec![],
            },
        )
        .unwrap();
    let before = store.get_usage(&id, 1000).unwrap();
    assert_eq!(before.requests, 1);
    store.delete_key(&id).unwrap();
    let after = store.get_usage(&id, 1000).unwrap();
    assert_eq!(
        after.requests, 1,
        "delete_key destroys credentials only: the usage ledger is billing evidence and stays"
    );
}

/// `delete_key` touches no usage window of any key, however the id is spelled (it once swept
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

#[test]
fn put_credential_rejects_a_live_slot_but_allows_reclaiming_a_revoked_one() {
    let Some(store) = live_store() else { return };

    let vk_id = uid("vk_slot");
    let key = vk(&vk_id);
    let c0 = cred(&vk_id, &uid("AKIA_0"), 0);
    store.put_key_with_credential(&key, &c0).unwrap();

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
    let Some(store) = live_store() else { return };
    let key_id = uid("vk_reclaim");
    let key = vk(&key_id);

    let mut c0 = cred(&key_id, &uid("AKIA_OLD"), 0);
    c0.meta.id = uid("cred_old");
    store.put_key_with_credential(&key, &c0).unwrap();
    store.revoke_credential(&c0.meta.id, "rotated").unwrap();

    let mut c1 = cred(&key_id, &uid("AKIA_NEW"), 0);
    c1.meta.id = uid("cred_new");
    store.put_credential(&c1).unwrap();

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
    for rendered in [serde_json::to_string(&metas).unwrap(), format!("{metas:?}")] {
        assert!(
            !rendered.contains(&c.secret),
            "metadata output must not carry the stored secret"
        );
    }
}

#[test]
fn list_credentials_since_carries_the_secret_for_hydration() {
    let Some(store) = live_store() else { return };
    let key_id = uid("vk_hydrate");
    let public_id = uid("AKIA_HYDRATE");
    let key = vk(&key_id);
    let c = cred(&key_id, &public_id, 0);
    store.put_key_with_credential(&key, &c).unwrap();

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
#[test]
fn put_credential_replayed_with_the_same_credential_id_is_a_retry_safe_no_op() {
    let Some(store) = live_store() else { return };
    let key_id = uid("vk_replay");
    let public_id = uid("AKIA_REPLAY");
    let key = vk(&key_id);
    let c = cred(&key_id, &public_id, 0);
    store.put_key_with_credential(&key, &c).unwrap();

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
#[test]
fn delete_key_fails_loud_on_a_corrupt_credential_row_instead_of_orphaning_pointers() {
    let Some(store) = live_store() else { return };
    let key_id = uid("vk_corrupt");
    let public_id = uid("AKIA_CORRUPT");
    let key = vk(&key_id);
    let c = cred(&key_id, &public_id, 0);
    store.put_key_with_credential(&key, &c).unwrap();

    store
        .with_conn(|conn| {
            conn.zrem::<_, _, ()>(CREDS_BYREV, format!("{key_id}:sigv4:0"))?;
            conn.set::<_, _, ()>(cred_row_key(&key_id, "sigv4", 0), "not json")
        })
        .unwrap();

    let result = store.delete_key(&key_id);

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
            priced_from_ms: 1_780_000_000_123,
            usage_units: std::collections::BTreeMap::from([("audio_seconds".into(), 7)]),
        })
        .unwrap();
    let rows = store.list_metering(bucket).unwrap();
    assert_eq!(rows.len(), 1);
    let r = &rows[0];
    assert_eq!(r.key_id, key_id);
    assert_eq!(r.model, "claude");
    assert_eq!(r.provider, "anthropic");
    assert_eq!(r.tokens_input, 10);
    assert_eq!(r.tokens_output, 5);
    assert_eq!(r.tokens_cache_read, 2);
    assert_eq!(r.requests, 1);
    assert_eq!(r.priced_from_ms, 1_780_000_000_123);
    assert_eq!(
        r.usage_units,
        std::collections::BTreeMap::from([("audio_seconds".into(), 7)])
    );
    assert_eq!(
        r.tokens_cache_write, 3,
        "renamed from tokens_cache_creation"
    );
    assert_eq!(r.billable_requests, 1);
    assert_eq!(r.key_group_at_use, "growth");
    assert_eq!(r.pricing_version, "2026-07");
}

#[test]
fn metering_keeps_each_historical_attribution_with_its_own_counts() {
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
    assert_eq!(rows.len(), 2, "each attribution owns its counts");
    for expected in [&base, &second] {
        let row = rows
            .iter()
            .find(|row| {
                row.key_id == expected.key_id
                    && row.model == expected.model
                    && row.provider == expected.provider
                    && row.priced_from_ms == expected.priced_from_ms
                    && row.key_group_at_use == expected.key_group_at_use
                    && row.pricing_version == expected.pricing_version
            })
            .expect("the exact historical attribution survives");
        assert_eq!(row.requests, expected.requests);
        assert_eq!(row.billable_requests, expected.billable_requests);
        assert_eq!(row.tokens_input, expected.tokens_input);
        assert_eq!(row.tokens_output, expected.tokens_output);
    }
}

#[test]
fn metering_row_identity_does_not_collide_across_a_delimiter_character() {
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

/// HARDEST INVARIANT #4: `connect()` refuses to start when `maxmemory-policy` is not
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

    let _: () = redis::cmd("CONFIG")
        .arg("SET")
        .arg("maxmemory-policy")
        .arg("noeviction")
        .query(&mut conn)
        .unwrap();

    let error = result.expect_err("connect must refuse an eviction policy");
    assert!(
        error.contains("maxmemory-policy")
            && error.contains("allkeys-lru")
            && error.contains("noeviction"),
        "{error}"
    );
}

/// Pins the `version >= SCHEMA_VERSION` early return against inversion: a second
#[test]
fn reconnecting_to_an_already_migrated_namespace_does_not_wipe_existing_data() {
    let Some(store1) = live_store() else { return };

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

/// Serialises the tests that write the shared audit zset: `busbar:audit` is one global set keyed by
pub(crate) static AUDIT_SEQ_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Take `AUDIT_SEQ_LOCK`, ignoring poisoning, so one failing audit test does not convert the others
pub(crate) fn audit_seq_guard() -> std::sync::MutexGuard<'static, ()> {
    AUDIT_SEQ_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// `VALKEY_URL` re-pointed at database `db`, so a refusal test owns a whole namespace and never
pub(crate) fn url_for_db(db: u32) -> String {
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
fn the_shared_database_is_never_flushed() {
    let Some(_) = live_store() else { return };
    let shared = db_of_url(&std::env::var("VALKEY_URL").unwrap());
    let refused = std::panic::catch_unwind(|| assert_private_db(shared))
        .expect_err("the actual shared-database guard must refuse");
    let text = refused
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| refused.downcast_ref::<&str>().copied())
        .unwrap_or("");
    assert!(text.contains("refusing to FLUSHDB"), "{text}");
}

/// An independent upstream client on database `db`, emptied first.
pub(crate) fn fresh_db_client(db: u32) -> (database::Database, redis::Connection) {
    assert_private_db(db);
    let held = database::Database::take(&url_for_db(db));
    let c = held.connection().expect("connect to private test database");
    (held, c)
}

/// A namespace marked NEWER than this build is REFUSED at open, and left as found: an older build
#[test]
fn a_namespace_newer_than_this_build_is_refused() {
    let Some(_) = live_store() else { return };
    let (_database, mut up) = fresh_db_client(11);
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
#[test]
#[ignore]
fn a_pre_v6_namespace_is_refused_not_wiped_and_keeps_refund_shaped_data() {
    let Some(_) = live_store() else { return };
    let (_database, mut up) = fresh_db_client(13);
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
#[test]
#[ignore]
fn a_namespace_with_keys_but_no_marker_refuses_to_connect_and_keeps_every_key() {
    let Some(_) = live_store() else { return };
    let (_database, mut up) = fresh_db_client(12);
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
#[path = "tests/store_conformance.rs"]
mod store_conformance;

/// The store v3 slots (`StoreSlots`): the durable `op_id` dedupe, the plane-record append and the
mod slots_tests;

#[path = "tests/delta_reader.rs"]
mod delta_reader;
/// A proxy that holds one client mid-op, for deterministic interleavings.
mod interleave;

mod conformance {
    use super::store_conformance::conf;
    use super::{live_store, Raw, ValkeyStore};

    fn ns(check: &str) -> String {
        format!("vk_c{}{}", std::process::id(), check)
    }

    /// Remove every row this suite is about to write, so a rerun (or a crashed prior run that left
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
#[test]
fn a_corrupt_credential_row_fails_the_delta_naming_its_key() {
    let Some(_) = live_store() else { return };
    let (_database, mut up) = fresh_db_client(CORRUPT_ROW_DB);
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
#[test]
fn a_refused_transaction_does_not_swallow_the_next_write() {
    let Some(store) = live_store() else { return };
    let id = uid("vk_watch");
    store.put_key(&vk(&id)).unwrap();
    store.delete_key(&id).unwrap();

    store
        .put_key(&vk(&id))
        .expect_err("a live write over a tombstone must be refused");

    store
        .with_conn(|c| {
            let row = format!("{KEY_PREFIX}{id}");
            let raw: String = c.get(&row)?;
            c.set::<_, _, ()>(&row, raw)
        })
        .unwrap();

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
static PURGE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn purge_guard() -> std::sync::MutexGuard<'static, ()> {
    PURGE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

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
#[test]
fn an_mcp_call_chain_survives_dropping_the_store_and_reconnecting() {
    let Some(store) = live_store() else { return };
    let p = uid("vk_mcp_restart");

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
#[test]
fn purge_mcp_calls_before_deletes_and_returns_a_real_count() {
    let Some(_) = live_store() else { return };

    let (_database, _raw) = fresh_db_client(8);
    let store = ValkeyStore::connect(&url_for_db(8)).unwrap();
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
    assert_eq!(purged, 1, "purge must count only the row actually removed");
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
    assert_eq!(rest, 2, "the remaining two rows must actually be removed");
    assert!(store.list_mcp_calls(&p).unwrap().is_empty());
    assert!(
        !store.list_mcp_call_principals().unwrap().contains(&p),
        "a principal whose chain is now empty must leave the boot enumeration, or a restart keeps \
         resuming a chain with nothing in it"
    );
}

/// A record arriving on a `(principal, seq)` that already has one is settled the way the contract
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

    let mut tampered = sample_call(&p, 1, 2_000_000_100, "", "h1");
    tampered.tool = "srv_other_tool".to_string();
    store
        .append_mcp_call(&tampered)
        .expect_err("a payload that differs under an identical sidecar is a fork and must error");

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
#[test]
fn retention_still_finds_a_principal_whose_id_contains_the_separator_characters() {
    let Some(_) = live_store() else { return };

    let (_database, _raw) = fresh_db_client(8);
    let store = ValkeyStore::connect(&url_for_db(8)).unwrap();
    let p = format!("{}:with:colons", uid("vk_mcp_sep"));
    store
        .append_mcp_call(&sample_call(&p, 1, 1_000_000_100, "", "h1"))
        .unwrap();
    assert_eq!(store.list_mcp_calls(&p).unwrap().len(), 1);
    let purged = store.purge_mcp_calls_before(1_000_000_200).unwrap();
    assert_eq!(purged, 1, "count the colon-bearing principal's record");
    assert!(
        store.list_mcp_calls(&p).unwrap().is_empty(),
        "a principal id containing the key-prefix separator must still purge correctly"
    );
    assert!(!store.list_mcp_call_principals().unwrap().contains(&p));
}

/// Timestamps are BANDED. The task purge is GLOBAL by `(disposition, ts)`, so every task this file
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

/// Signed-range sequence and price instants refuse before writing; timestamps retain all u64 bits.
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
    let r = rec(big, 1);
    let e = store.append_plane_record(r.view()).unwrap_err().to_string();
    assert!(
        e.contains(&format!(
            "append_plane_record: seq {big} exceeds the storable range"
        )),
        "{e}"
    );
    let e = store.upsert_plane_record(r.view()).unwrap_err().to_string();
    assert!(
        e.contains(&format!(
            "upsert_plane_record: seq {big} exceeds the storable range"
        )),
        "{e}"
    );
    assert!(store.get_plane_record(&kind, "r1").unwrap().is_none());
    assert!(store
        .list_plane_records(&kind, &PlaneSelector::All)
        .unwrap()
        .is_empty());

    let dated = rec(1, u64::MAX);
    store.append_plane_record(dated.view()).unwrap();
    store.upsert_plane_record(dated.view()).unwrap();
    assert_eq!(
        store.get_plane_record(&kind, "r1").unwrap(),
        Some(b"b".to_vec())
    );
    assert_eq!(
        store.purge_plane_records_before(&kind, u64::MAX).unwrap(),
        0
    );
    store.delete_plane_record(&kind, "r1").unwrap();
    store.delete_plane_record(&kind, "p1").unwrap();

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

/// Sequence ordering stays exact through i64::MAX, and u64::MAX survives in opaque body fields.
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
#[test]
fn a_reconnected_store_refuses_a_second_redemption_of_the_same_approval() {
    let url = std::env::var("VALKEY_URL")
        .unwrap_or_else(|_| panic!("VALKEY_URL is unset; this case must not skip"));
    let (spent, fresh) = (trust_ns("nonce_restart"), trust_ns("nonce_restart_other"));
    let now;
    {
        let store = ValkeyStore::connect(&url).expect("connect");
        now = token_test_now(&store);
        reset_trust_state(&store, &[], &[&spent, &fresh]);
        assert!(store.redeem_ask_state(&spent, now + 900, now).unwrap());
    }
    let reopened = ValkeyStore::connect(&url).expect("reconnect");
    assert!(
        !reopened
            .redeem_ask_state(&spent, now + 900, now + 1)
            .unwrap(),
        "a restart handed a spent approval back"
    );
    assert!(
        reopened
            .redeem_ask_state(&fresh, now + 900, now + 2)
            .unwrap(),
        "a different approval is not the one that was spent"
    );

    assert!(reopened
        .redeem_plane_token("approval", &spent, now + 900, now + 3)
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
    let now = token_test_now(&node_a);
    reset_trust_state(&node_a, &[], &[&nonce]);
    assert!(node_a.redeem_ask_state(&nonce, now + 900, now).unwrap());
    assert!(
        !node_b.redeem_ask_state(&nonce, now + 900, now).unwrap(),
        "a second node redeemed an approval the first already spent"
    );
    reset_trust_state(&node_a, &[], &[&nonce]);
}

/// CONCURRENT REDEMPTION IS THE ATTACK: eight independent connections race through a barrier;
#[test]
fn exactly_one_of_many_racing_nodes_wins_the_redemption() {
    let url = std::env::var("VALKEY_URL")
        .unwrap_or_else(|_| panic!("VALKEY_URL is unset; this case must not skip"));
    let nonce = trust_ns("nonce_race");
    let cleanup = ValkeyStore::connect(&url).expect("connect");
    reset_trust_state(&cleanup, &[], &[&nonce]);
    let now = token_test_now(&cleanup);
    drop(cleanup);

    let n = 8usize;

    let nodes: Vec<_> = (0..n)
        .map(|_| ValkeyStore::connect(&url).expect("a racing node connects"))
        .collect();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(n));
    let winners: usize = std::thread::scope(|scope| {
        let handles: Vec<_> = nodes
            .into_iter()
            .map(|node| {
                let nonce = nonce.clone();
                let barrier = std::sync::Arc::clone(&barrier);
                scope.spawn(move || {
                    barrier.wait();
                    node.redeem_ask_state(&nonce, now + 900, now)
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
    const SHORT_LIFE: u64 = 30;
    const LONG_LIFE: u64 = 10_000;
    let store = require_live_store();
    let now = token_test_now(&store);
    let (short, long) = (trust_ns("nonce_ttl_short"), trust_ns("nonce_ttl_long"));
    for (nonce, life) in [(&short, SHORT_LIFE), (&long, LONG_LIFE)] {
        let expires = now + life;
        assert!(store.redeem_ask_state(nonce, expires, 0).unwrap());
        let cleanup: u64 = store
            .with_conn(|c| {
                redis::cmd("EXPIRETIME")
                    .arg(plane::token_key(crate::legacy::KIND_ASK, nonce))
                    .query(c)
            })
            .unwrap();
        assert_eq!(
            cleanup,
            expires + 1,
            "cleanup is the first second strictly after absolute expiry"
        );
    }
    reset_trust_state(&store, &[], &[&short, &long]);
}

/// A grant that outlives the ledger's TTL cap is recorded with NO expiry: capping it would let the
#[test]
fn a_grant_beyond_the_ttl_cap_is_recorded_without_expiry() {
    let store = require_live_store();
    let now = token_test_now(&store);
    let nonce = trust_ns("nonce_ttl_forever");
    reset_trust_state(&store, &[], &[&nonce]);
    let eleven_years = 11 * 365 * 86_400;
    assert!(store
        .redeem_ask_state(&nonce, now + eleven_years, now)
        .unwrap());
    let ttl: i64 = store
        .with_conn(|c| c.ttl::<_, i64>(plane::token_key("ask", &nonce)))
        .expect("TTL");
    assert_eq!(ttl, -1, "the entry must not expire");
    assert!(!store
        .redeem_ask_state(&nonce, now + eleven_years, now)
        .unwrap());
    reset_trust_state(&store, &[], &[&nonce]);
}

/// A live spent entry survives arbitrary caller clocks; only shared-clock expiry permits reuse.
#[test]
fn a_spent_entry_is_judged_against_the_shared_clock() {
    const LIVE_LIFE: u64 = 900;
    let store = require_live_store();
    let nonce = trust_ns("nonce_judged");
    let expires = token_test_now(&store) + LIVE_LIFE;
    assert!(store.redeem_ask_state(&nonce, expires, 0).unwrap());
    for caller_now in [0, expires, u64::MAX] {
        assert!(!store
            .redeem_ask_state(&nonce, u64::MAX, caller_now)
            .unwrap());
    }
    let key = plane::token_key(crate::legacy::KIND_ASK, &nonce);
    let stored: String = store.with_conn(|c| c.get(&key)).unwrap();
    assert_eq!(stored, expires.to_string());
    let _: () = store.with_conn(|c| c.set(&key, 0)).unwrap();
    assert!(
        store.redeem_ask_state(&nonce, expires, 0).unwrap(),
        "a preexisting expired receipt can be reclaimed"
    );
    assert!(!store.redeem_ask_state(&nonce, expires, u64::MAX).unwrap());
    reset_trust_state(&store, &[], &[&nonce]);
}

/// An already-lapsed candidate cannot claim a token and leaves no receipt.
#[test]
fn a_lapsed_approval_is_refused_without_a_redemption_record() {
    let store = require_live_store();
    let nonce = trust_ns("nonce_lapsed");
    let expires = token_test_now(&store) - 1;
    assert!(!store.redeem_ask_state(&nonce, expires, 0).unwrap());
    let value: Option<String> = store
        .with_conn(|c| c.get(plane::token_key(crate::legacy::KIND_ASK, &nonce)))
        .unwrap();
    assert_eq!(value, None);
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

/// Open (non-reserved) usage units round-trip beside the reserved four, per model, whatever
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

    let mut ledger = got.clone();
    ledger.models[0].usage_units.insert("bytes".into(), 7);
    store.put_usage(&bucket, 2000, &ledger).unwrap();
    assert_eq!(store.get_usage(&bucket, 2000).unwrap(), ledger);
}

/// A v6 build's unfloored HINCRBY could leave a counter NEGATIVE. It always read as 0; the next add
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

/// A v6 namespace's typed task / task-event / demotion / spent-approval keys, written the way v6
#[test]
fn v6_namespace_upgrades_in_place_to_v7() {
    use crate::legacy::{
        ASK_STATE_PREFIX, MCP_DEMOTIONS_HASH, TASKS_BY_UPDATED, TASKS_INDEX, TASK_EVENTS_PREFIX,
        TASK_ROW_PREFIX,
    };
    let Some(_) = live_store() else { return };
    let (database, _raw) = fresh_db_client(6);
    let url = url_for_db(6);
    let store = ValkeyStore::connect(&url).unwrap();
    let t = uid("t_v6_live");
    let done = uid("t_v6_done");
    let server = uid("srv_v6");
    let nonce = uid("nonce_v6");
    let token_expires = token_test_now(&store) + 900;
    let key_id = uid("vk_v6");
    let call_key = format!("busbar:mcp:calls:{}", uid("vk_v6_calls"));
    store.put_key(&vk(&key_id)).unwrap();

    let live = sample_task(&t, "input-required", TASK_LIVE_TS + 7);
    let finished = sample_task(&done, "completed", TASK_LIVE_TS + 8);
    let e1 = sample_event(&t, 1, "task.submitted", "", "x1");
    let e2 = sample_event(&t, 2, "task.working", "x1", "x2");
    let dem = demotion(&server, "tool-drift", TRUST_NOW);
    database
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
                .arg(token_expires)
                .arg("EX")
                .arg(600);
            p.zadd(&call_key, "{\"v6\":\"call\"}", 1);
            p.set(SCHEMA_KEY, 6);
            p.query::<()>(c)
        })
        .unwrap();

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
            .redeem_ask_state(&nonce, token_expires, u64::MAX)
            .unwrap(),
        "a v6 spent approval stays spent across the upgrade"
    );
    let cleanup: u64 = database
        .with_conn(|c| {
            redis::cmd("EXPIRETIME")
                .arg(plane::token_key(crate::legacy::KIND_ASK, &nonce))
                .query(c)
        })
        .unwrap();
    assert_eq!(
        cleanup,
        token_expires + 1,
        "imported receipt survives its absolute validity boundary"
    );

    let left: Vec<String> = database
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
    assert!(!database
        .with_conn(|c| c.hexists::<_, _, bool>(MCP_DEMOTIONS_HASH, &server))
        .unwrap());
    assert!(
        database
            .with_conn(|c| c.exists::<_, bool>(&call_key))
            .unwrap(),
        "the v6 call log is left in place, unread — no evidence is destroyed"
    );
    assert!(
        upgraded.get_key(&key_id).unwrap().is_some(),
        "keys are untouched"
    );
    let marker: i64 = database.with_conn(|c| c.get(SCHEMA_KEY)).unwrap();
    assert_eq!(marker, SCHEMA_VERSION);

    database
        .with_conn(|c| c.set::<_, _, ()>(SCHEMA_KEY, 6i64))
        .unwrap();
    let upgraded = ValkeyStore::connect(&url).expect("a second upgrade pass on open");
    assert_eq!(
        upgraded.list_task_events(&t).unwrap(),
        vec![e1.clone(), e2.clone()]
    );

    let stale = sample_task(&t, "working", TASK_LIVE_TS + 1);
    assert_ne!(stale, live);
    database
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
        !database
            .with_conn(|c| c.exists::<_, bool>(format!("{TASK_ROW_PREFIX}{t}")))
            .unwrap(),
        "the stale v6 row is removed"
    );
    assert_eq!(upgraded.list_task_events(&t).unwrap(), vec![e1, e2]);
}

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
fn open_on(
    settings: &str,
    table: impl FnOnce(&Dispatcher) -> ValkeyWireObserver,
) -> (Result<LoadedStore, String>, Arc<ValkeyWireObserver>) {
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
    table: impl FnOnce(&Dispatcher) -> ValkeyWireObserver,
) -> (Result<LoadedStore, String>, Arc<ValkeyWireObserver>) {
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

fn plain(d: &Dispatcher) -> ValkeyWireObserver {
    ValkeyWireObserver::new(d.conn_waker())
}

/// A table whose TLS trusts no root: a verifying handshake refuses every certificate, and only an
fn trusting_nothing(d: &Dispatcher) -> ValkeyWireObserver {
    ValkeyWireObserver::with_tls(d.conn_waker(), Arc::new(TestTls::default()))
}

/// The concrete Valkey wire observer's TLS: rustls trusting exactly the roots a test hands it, or, on
/// `verify_off`, checking no certificate, only the handshake's signature. As the loader's own test
/// table secured a stream before TLS left it (busbar 0db7ee2ea0 `ValkeyWireObserver::with_roots`).
#[derive(Default)]
struct TestTls {
    roots: Option<Vec<u8>>,
    last_handshake_error: std::sync::Mutex<Option<String>>,
}

impl TestTls {
    fn trusting(ca_der: &[u8]) -> Self {
        Self {
            roots: Some(ca_der.to_vec()),
            ..Default::default()
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

impl TestTls {
    fn secure(
        &self,
        server: &str,
        verify_off: bool,
        mut tcp: std::net::TcpStream,
    ) -> std::io::Result<Box<TestTlsStream>> {
        *self.last_handshake_error.lock().unwrap() = None;
        let invalid = |e: String| std::io::Error::new(std::io::ErrorKind::InvalidInput, e);
        let name = rustls_pki_types::ServerName::try_from(server.to_owned())
            .map_err(|e| invalid(e.to_string()))?;
        let mut tls = rustls::ClientConnection::new(self.config(verify_off), name)
            .map_err(|e| invalid(e.to_string()))?;
        while tls.is_handshaking() {
            tls.complete_io(&mut tcp).inspect_err(|error| {
                *self.last_handshake_error.lock().unwrap() = Some(error.to_string());
            })?;
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

impl TestTlsStream {
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
        ValkeyWireObserver::with_tls(d.conn_waker(), Arc::new(TestTls::trusting(&ca)))
    });
    let store = store.expect("opens over TLS");
    let id = uid("vk_tls");
    store.put_key(&vk(&id)).unwrap();
    assert!(store.get_key(&id).unwrap().is_some());
    assert_eq!(proxy.accepted(), 1, "one secured connection, kept");
    let _ = store.purge_key_for_test(&id);

    let untrusted_tls = Arc::new(TestTls::default());
    let (untrusted, _) = open_on(&settings_for(&url), |d| {
        ValkeyWireObserver::with_tls(d.conn_waker(), untrusted_tls.clone())
    });
    let err = untrusted.expect_err("the TLS certificate must be trusted");
    let tls_error = untrusted_tls.last_handshake_error.lock().unwrap().clone();
    assert!(
        tls_error
            .as_deref()
            .is_some_and(|error| error.contains("UnknownIssuer")),
        "the refusal must be certificate verification: {tls_error:?}; host refusal: {err}"
    );
    assert!(
        err.starts_with(
            "plugin 'busbar-store-valkey' open failed: valkey store: failed to connect: "
        ) && !err.contains("valkey connect:"),
        "{err}"
    );
}

/// Host services offering the clock alone (the dispatcher's own timebase), refusing the rest: the
struct ClockOnly;

use busbar_contract::services::{
    Caller, DiskDest, HookAsk, Later, NestAsk, Ran, Reading, RecordsList, Snapshot, Stored,
    TrustKeyRef, UNSERVED,
};

fn refused() -> Ran {
    Ran::Now(Stored::refused(UNSERVED))
}

impl busbar_contract::services::HostServices for ClockOnly {
    fn now(&self) -> Reading {
        Reading {
            wall_ns: 0,
            mono_ns: busbar_plugin_loader::dispatch::now_ns(),
        }
    }

    fn dest_judge(&self, _dest: &str, _class: u32, _flags: u32, _later: Option<Later>) -> Ran {
        refused()
    }

    fn records_get(&self, _caller: &Caller, _kind: &str, _key: &[u8], _later: Later) -> Ran {
        refused()
    }

    fn records_list(&self, _caller: &Caller, _list: RecordsList, _later: Later) -> Ran {
        refused()
    }

    fn records_claim(
        &self,
        _caller: &Caller,
        _kind: &str,
        _key: &[u8],
        _ttl_ms: u64,
        _later: Later,
    ) -> Ran {
        refused()
    }

    fn sign(&self, _caller: &Caller, _data: &[u8]) -> Stored {
        Stored::refused(UNSERVED)
    }

    fn trust_sight(
        &self,
        _caller: &Caller,
        _counterparty: &str,
        _hash: &str,
        _later: Later,
    ) -> Ran {
        refused()
    }

    fn trust_unreached(&self, _caller: &Caller, _counterparty: &str) -> Stored {
        Stored::refused(UNSERVED)
    }

    fn trust_sight_item(
        &self,
        _caller: &Caller,
        _counterparty: &str,
        _item: &str,
        _digest: &str,
    ) -> Stored {
        Stored::refused(UNSERVED)
    }

    fn trust_decide(
        &self,
        _caller: &Caller,
        _key: TrustKeyRef<'_>,
        _expected: Option<&str>,
        _approve: bool,
    ) -> Stored {
        Stored::refused(UNSERVED)
    }

    fn trust_state(&self, _caller: &Caller, _counterparty: &str) -> Stored {
        Stored::refused(UNSERVED)
    }

    fn trust_serves(
        &self,
        _caller: &Caller,
        _counterparty: &str,
        _item: Option<&str>,
        _digest: Option<&str>,
    ) -> Stored {
        Stored::refused(UNSERVED)
    }

    fn trust_due(&self, _caller: &Caller) -> Stored {
        Stored::refused(UNSERVED)
    }

    fn trust_verify(
        &self,
        _caller: &Caller,
        _counterparty: &str,
        _payload: &[u8],
        _signatures: &[u8],
    ) -> Stored {
        Stored::refused(UNSERVED)
    }

    fn entitlement_check(&self, _caller: &Caller, _unit: Option<u64>, _target: &str) -> Stored {
        Stored::refused(UNSERVED)
    }

    fn session_emit(&self, _caller: &Caller, _session: u64, _bytes: &[u8]) -> Stored {
        Stored::refused(UNSERVED)
    }

    fn ticket_mint(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _ttl_secs: u64,
        _record: &[u8],
    ) -> Stored {
        Stored::refused(UNSERVED)
    }

    fn ticket_take(&self, _caller: &Caller, _unit: Option<u64>) -> Stored {
        Stored::refused(UNSERVED)
    }

    fn random_fill(&self, _len: u64) -> Stored {
        Stored::refused(UNSERVED)
    }

    fn records_secret(&self, _kind: &str, _id: &str, _later: Later) -> Ran {
        refused()
    }

    fn unit_nest(&self, _caller: &Caller, _unit: Option<u64>, _ask: NestAsk, _later: Later) -> Ran {
        refused()
    }

    fn work_open(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _kind: &str,
        _record: &[u8],
        _later: Later,
    ) -> Ran {
        refused()
    }

    fn work_find(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _reference: &[u8],
        _later: Later,
    ) -> Ran {
        refused()
    }

    fn work_settle(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _handle: u64,
        _record: &[u8],
        _later: Later,
    ) -> Ran {
        refused()
    }

    fn work_resume(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _handle: u64,
        _later: Later,
    ) -> Ran {
        refused()
    }

    fn disk_append(&self, _dest: &DiskDest, _bytes: Vec<u8>, _later: Later) -> Ran {
        refused()
    }

    fn verify_lookup(&self, _caller: &Caller, _key: &[u8], _later: Later) -> Ran {
        refused()
    }

    fn verify_store(&self, _caller: &Caller, _key: &[u8], _entry: &[u8], _ttl_ms: u64) -> Stored {
        Stored::refused(UNSERVED)
    }

    fn content_scan(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _content: &[u8],
        _later: Later,
    ) -> Ran {
        refused()
    }

    fn hook_call(&self, _caller: &Caller, _unit: Option<u64>, _ask: HookAsk, _later: Later) -> Ran {
        refused()
    }

    fn snapshot_read(&self, _caller: &Caller, _scope: u32) -> Snapshot {
        Snapshot::Refused(UNSERVED)
    }
}

/// VALKEY-TIMEOUT over the whole span 1.5.5's `get_connection_with_timeout` bounded: a server that
#[test]
fn connect_timeout_ms_bounds_the_handshake_after_the_dial() {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let at = l.local_addr().unwrap().to_string();

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

/// `#insecure` disables certificate verification for a TLS connection.
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

const FIXTURE_KEYS_1_5_5: &str = include_str!("../tests/fixtures/1.5.5/keys.json");

/// A TTL comfortably longer than any test run, as 1.5.5 gave its metering rows.
const FIXTURE_TTL_SECS: u64 = 31 * 24 * 3600;

fn recorded_1_5_5_token_spend(
    model: &str,
    input: u64,
    output: u64,
    cache_read: u64,
    cache_write: u64,
) -> u64 {
    assert!(
        matches!(model, "m-chat" | "m-cache" | "m-chat-down"),
        "recorded model {model}"
    );
    assert_eq!(
        cache_write, 0,
        "the recorded script emits no cache-creation usage"
    );
    if model != "m-cache" {
        assert_eq!(
            cache_read, 0,
            "only m-cache has a cache-read price in the recorder"
        );
    }
    input * 100_000 + output * 200_000 + cache_read * 10_000
}

fn recorded_1_5_5_breakdown(rows: &[&MeteringRow]) -> serde_json::Value {
    let mut input = 0;
    let mut output = 0;
    let mut cache_read = 0;
    let mut cache_write = 0;
    let mut requests = 0;
    let mut spend = 0;
    for row in rows {
        input += row.tokens_input;
        output += row.tokens_output;
        cache_read += row.tokens_cache_read;
        cache_write += row.tokens_cache_write;
        requests += row.requests;
        spend += recorded_1_5_5_token_spend(
            &row.model,
            row.tokens_input,
            row.tokens_output,
            row.tokens_cache_read,
            row.tokens_cache_write,
        ) + row.billable_requests * 30_000;
    }
    serde_json::json!({
        "requests": requests, "spend_micros": spend, "tokens_input": input,
        "tokens_output": output, "tokens_cache_read": cache_read,
        "tokens_cache_creation": cache_write,
    })
}

/// Compare the loaded store's reads with all three frozen 1.5.5 HTTP response bodies. Only the
fn assert_recorded_1_5_5_readback(store: &ValkeyStore) {
    use serde_json::{json, Value};
    use std::collections::BTreeMap;
    let expected: Value =
        serde_json::from_str(include_str!("../tests/fixtures/1.5.5/readback/usage.json")).unwrap();
    let start = expected["window"]["start"]
        .as_u64()
        .expect("recorded integer UTC start");
    let end = expected["window"]["end"]
        .as_u64()
        .expect("recorded integer UTC end");
    assert_eq!(start % 86_400, 0, "metering is a pinned UTC-day bucket");
    assert_eq!(end, start + 86_400);
    let rows = store.list_metering(start).unwrap();
    assert!(store.list_metering(start - 86_400).unwrap().is_empty());
    assert!(
        store.list_metering(end).unwrap().is_empty(),
        "the end boundary is the next bucket"
    );
    let mut models: BTreeMap<(&str, &str), Vec<&MeteringRow>> = BTreeMap::new();
    let mut keys: BTreeMap<&str, Vec<&MeteringRow>> = BTreeMap::new();
    for row in &rows {
        models
            .entry((&row.model, &row.provider))
            .or_default()
            .push(row);
        keys.entry(&row.key_id).or_default().push(row);
    }
    let by_model: Vec<Value> = models
        .into_iter()
        .map(|((model, provider), rows)| {
            let mut view = recorded_1_5_5_breakdown(&rows);
            view["model"] = json!(model);
            view["provider"] = json!(provider);
            view
        })
        .collect();
    let mut by_key: Vec<Value> = keys
        .into_iter()
        .map(|(id, rows)| {
            let key = store.get_key(id).unwrap().expect("metering key reads back");
            let mut view = recorded_1_5_5_breakdown(&rows);
            view["id"] = json!(key.id);
            view["name"] = json!(key.name);
            view
        })
        .collect();

    by_key.sort_by(|a, b| {
        b["spend_micros"]
            .as_u64()
            .unwrap()
            .cmp(&a["spend_micros"].as_u64().unwrap())
            .then_with(|| a["id"].as_str().unwrap().cmp(b["id"].as_str().unwrap()))
    });
    let actual = json!({
        "window": {"start": start, "end": end}, "currency": "USD",
        "total": recorded_1_5_5_breakdown(&rows.iter().collect::<Vec<_>>()),
        "by_model": by_model, "by_key": by_key, "by_key_truncated": false,
    });
    assert_eq!(
        actual, expected,
        "the whole recorded usage response, including JSON field types"
    );

    for recorded in [
        include_str!("../tests/fixtures/1.5.5/readback/key-fixture-grouped.json"),
        include_str!("../tests/fixtures/1.5.5/readback/key-fixture-ungrouped.json"),
    ] {
        let expected: Value = serde_json::from_str(recorded).unwrap();
        let id = expected["id"].as_str().expect("recorded string key ID");
        assert_eq!(
            expected["window_start"].as_u64(),
            Some(0),
            "key attribution is all-time"
        );
        let key = store
            .get_key(id)
            .unwrap()
            .expect("the recorded key is loaded");
        let ledger = store.get_usage(id, 0).unwrap();
        assert_eq!(
            store.get_usage(id, start).unwrap(),
            UsageLedger::default(),
            "day metering must not be mistaken for the key's all-time attribution"
        );
        let spend = ledger
            .models
            .iter()
            .map(|model| {
                recorded_1_5_5_token_spend(
                    &model.model,
                    model.tier("input"),
                    model.tier("output"),
                    model.tier("cache_read"),
                    model.tier("cache_write"),
                )
            })
            .sum::<u64>()
            + ledger.billable_requests * 30_000;
        let actual = json!({
            "id": &key.id, "group": &key.group, "budget_period": "total", "window_start": 0,
            "requests": ledger.requests, "tokens": ledger.total_tokens(), "spend_cents": spend / 10_000,
            // The recorder config gives the group only a budget; it has no requests/tokens rate cap.
            "rate_headroom": Option::<f64>::None,
        });
        assert_eq!(
            actual, expected,
            "the complete recorded key usage response for {id}"
        );
        if let Some(group) = key.group.as_deref() {
            assert_eq!(store.get_usage(&format!("group:{group}@day"), start).unwrap(), ledger,
                "the group's daily budget and the key's all-time attribution preserve the same recorded usage");
        }
    }
}

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

/// Write `keys.json` through the raw endpoint of an already-emptied, guarded private database.
fn replay_1_5_5(database: &database::Database) {
    database
        .with_conn(|c| {
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

fn schema_marker(database: &database::Database) -> i64 {
    database.with_conn(|c| c.get("busbar:schema")).unwrap()
}

/// The 1.6.0 surface read back, against values derived from `keys.json` here and now.
fn assert_1_5_5_keys_read_back(store: &ValkeyStore) {
    let fx = fixture_keys();

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
    assert_recorded_1_5_5_readback(store);
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
fn the_1_5_5_binarys_rows_read_back_through_migrate() {
    let url = url_for_db(6);
    let database = database::Database::take(&url);
    replay_1_5_5(&database);
    assert_eq!(
        schema_marker(&database),
        6,
        "the replayed marker is 1.5.5's"
    );
    let store = ValkeyStore::connect(&url).expect("this build opens the 1.5.5 keyspace");
    assert_eq!(schema_marker(&database), SCHEMA_VERSION);
    assert_1_5_5_keys_read_back(&store);

    let revision = fx_num(&fixture_keys()["busbar:revision"]["value"]);
    let counter: u64 = database
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
fn migrate_over_the_1_5_5_rows_is_idempotent() {
    let url = url_for_db(6);
    let database = database::Database::take(&url);
    replay_1_5_5(&database);
    let first = {
        let store = ValkeyStore::connect(&url).expect("first open");
        assert_eq!(schema_marker(&database), SCHEMA_VERSION);
        assert_1_5_5_keys_read_back(&store);
        read_everything_1_5_5(&store)
    };
    let store = ValkeyStore::connect(&url).expect("second open");
    assert_eq!(schema_marker(&database), SCHEMA_VERSION);
    assert_1_5_5_keys_read_back(&store);
    assert_eq!(read_everything_1_5_5(&store), first);
}

#[test]
fn audit_list_and_tail_are_ordered_oldest_first() {
    let _serialised = audit_seq_guard();
    let Some(store) = live_store() else { return };

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
        let captured = captured_url(url);
        let leaked = captured.redact_echo(&format!("could not reach {url}"));
        assert!(
            !leaked.contains(secret) && !leaked.contains("p@ssw0rd"),
            "{url}: {leaked}"
        );

        let shown = match parse_url(url) {
            Ok(t) => format!("{t:?}"),
            Err(e) => e.to_string(),
        };
        assert!(
            !shown.contains(secret) && !shown.contains("p@ssw0rd"),
            "{shown}"
        );
    }

    let e = crate::ValkeyStore::from_settings(
        br#"{"url":"valkey+unix:///run/v.sock?pass=hunter2xyz&db=notanumber"}"#,
    )
    .expect_err("a bad db is refused");
    assert!(!e.contains("hunter2xyz"), "{e}");
}

#[test]
fn unknown_id_refusals_name_the_id_in_the_canonical_form() {
    let Some(store) = live_store() else { return };
    let id = uid("vk_never_existed");
    let e = store.delete_key(&id).unwrap_err().to_string();
    assert!(e.contains(&format!("delete_key: unknown id '{id}'")), "{e}");
    assert!(!e.contains("- Client"), "{e}");
}

/// An id that spells the delete's internal retry text is just an unknown id: it answers the refusal
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
    let writer = gate.spawn(move || slow.put_key(&vk(&a_id)));
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
#[test]
fn a_refused_handshake_does_not_leave_a_connection_kept() {
    if live_store().is_none() {
        return;
    }
    let url = std::env::var("VALKEY_URL").unwrap();
    let target_db = if db_of_url(&url) == 10 { 9 } else { 10 };
    let (_database, mut target) = fresh_db_client(target_db);
    let mut db0 = redis::Client::open(url_for_db(0))
        .unwrap()
        .get_connection()
        .unwrap();
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
    let store = ValkeyStore::connect(&format!("redis://{user}:{pw1}@{addr}/{target_db}")).unwrap();
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
    let in_db0: bool = db0.exists(&row).unwrap();
    let in_target: bool = target.exists(&row).unwrap();
    let _: () = redis::cmd("ACL")
        .arg(&["DELUSER", user.as_str()][..])
        .query(&mut admin)
        .unwrap();
    if in_db0 {
        let _: () = db0.del(&row).unwrap();
    }
    landed.expect("the next op re-handshakes and succeeds");
    assert!(
        in_target,
        "the selected database must contain the successful write"
    );
    assert!(
        !in_db0,
        "the op ran on db 0, on a connection that skipped its handshake"
    );
}

/// `list_metering` reads one snapshot: a write landing after it has read the bucket's row set is
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
    let reader = gate.spawn(move || store.list_metering(bucket));
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
    let store = ValkeyStore::connect(&proxied.url).unwrap();

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
    let holder = gate.spawn(move || first.get_key(&id));
    gate.held
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the first op is held mid-flight");
    let (tx, rx) = std::sync::mpsc::channel();
    let second = store.clone();
    let second_worker = gate.spawn(move || {
        let _ = tx.send(second.get_key(&b));
    });
    let got = rx.recv_timeout(std::time::Duration::from_secs(5));
    gate.release.send(()).unwrap();
    holder.join().unwrap().unwrap();
    second_worker.join().unwrap();
    got.expect("the second op ran while the first was held")
        .unwrap();
}

/// `delete_key` leaves the key's own usage windows and every other bucket's whose id starts with
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
    let writer = gate.spawn(move || slow.revoke_credential(&id, "slow"));
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
#[test]
fn a_transaction_that_always_aborts_ends_with_an_error() {
    if live_store().is_none() {
        return;
    }

    let (database, _up) = fresh_db_client(7);
    let url = url_for_db(7);
    let timeout = std::time::Duration::from_secs(10);
    let bump = redis::Client::open(url.as_str())
        .unwrap()
        .get_connection_with_timeout(timeout)
        .unwrap();
    bump.set_read_timeout(Some(timeout)).unwrap();
    bump.set_write_timeout(Some(timeout)).unwrap();
    let bump = std::sync::Mutex::new(bump);
    let proxied = interleave::tamper(
        &url,
        |c| interleave::contains(c, b"EXEC"),
        move || {
            let mut r = bump.lock().unwrap();
            let _: i64 = redis::cmd("INCR")
                .arg("busbar:revision")
                .query(&mut *r)
                .unwrap();
        },
    );
    let id = uid("vk_always_abort");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _database = database;
        let proxied = proxied;
        let store = ValkeyStore::connect(&proxied.url).unwrap();
        let _ = tx.send(store.put_key(&vk(&id)).unwrap_err().to_string());
    });
    let e = rx
        .recv_timeout(std::time::Duration::from_secs(20))
        .expect("put_key gave up instead of retrying for ever");
    assert!(e.contains("aborted"), "{e}");
}

/// Putting a credential again is a replay only when it is the SAME credential: one with the stored
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
#[test]
fn unix_url_query_password_is_scrubbed_from_errors() {
    for url in [
        "redis+unix:///run/v.sock?db=2&pass=CANARY-vk-p4ss",
        "unix:///run/v.sock?user=al&pass=CANARY-vk-p4ss",
        "valkey+unix:///run/v.sock?pass=CANARY%2Dvk%2Dp4ss&db=1",
    ] {
        let secret = captured_url(url);
        for leak in [
            format!("valkey connect: cannot reach {url}"),
            "valkey connect: AUTH CANARY-vk-p4ss refused".to_string(),
        ] {
            let out = secret.redact_echo(&leak);
            assert!(!out.contains("CANARY"), "{url}: password leaked: {out}");
        }
    }

    let url = "valkey+unix:///run/v.sock?pass=CANARY+vk+p4ss";
    let out = captured_url(url).redact_echo("valkey connect: AUTH CANARY vk p4ss refused");
    assert!(!out.contains("CANARY"), "a `+` password leaked: {out}");

    assert!(captured_url("redis://u:p@host:6379").password().is_some());
    assert!(captured_url("redis+unix:///run/v.sock?db=2")
        .password()
        .is_none());

    assert!(!captured_url("redis+unix:///run/v.sock?password=x")
        .redact_echo("AUTH x refused")
        .contains(" x "));
}

/// A URL parameter the store does not read is REFUSED, never silently ignored; its name is withheld
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

    assert_eq!(store.purge_plane_records_before(kind, 11).unwrap(), 1);
    assert_eq!(store.get_plane_record(kind, "vk_c2").unwrap(), None);
    assert!(store.list_plane_records(kind, &parent).unwrap().is_empty());
    assert!(store.list_plane_record_parents(kind).unwrap().is_empty());
}

/// Redemption stores decimal strings, not signed columns. Permanent node claims and clocks
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
            assert!(!store
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
    let (_database, mut raw) = fresh_db_client(5);
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
        marker, SCHEMA_VERSION,
        "the completed repair advances the schema marker"
    );
    let revision: u64 = raw.get(REVISION_KEY).unwrap();
    drop(reopened);

    raw.set::<_, _, ()>(SCHEMA_KEY, 9).unwrap();
    let direct = ValkeyStore::connect(&url).unwrap();
    let marker: i64 = raw.get(SCHEMA_KEY).unwrap();
    assert_eq!(marker, SCHEMA_VERSION);
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
    let migrating = gate.spawn(move || ValkeyStore::connect(&gate_url));
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

    let malformed = r#"{"meta":"migration-private-marker","secret":"migration-private-marker"}"#;
    raw.set::<_, _, ()>(&row_key, malformed).unwrap();
    raw.set::<_, _, ()>(SCHEMA_KEY, 9).unwrap();
    let error = match ValkeyStore::connect(&url) {
        Ok(_) => panic!("an undecodable indexed credential refuses migration"),
        Err(error) => error,
    };
    assert!(!error.to_string().contains("migration-private-marker"));
    assert_eq!(raw.get::<_, i64>(SCHEMA_KEY).unwrap(), 9);
    assert_eq!(raw.get::<_, String>(&row_key).unwrap(), malformed);
}

#[test]
fn usage_cleanup_preserves_full_width_boundaries_billing_and_other_namespaces() {
    use busbar_contract::store_calls::StoreCalls;
    if live_store().is_none() {
        return;
    }
    let (_database, mut raw) = fresh_db_client(8);
    let url = url_for_db(8);
    let store = ValkeyStore::connect(&url).unwrap();
    let ledger = UsageLedger {
        requests: 3,
        billable_requests: 2,
        models: ["alpha", "beta"]
            .into_iter()
            .map(|model| ModelTokens {
                model: model.to_owned(),
                usage_units: [
                    (RESERVED_UNITS[0].to_owned(), 5),
                    ("audio_seconds".to_owned(), 7),
                ]
                .into_iter()
                .collect(),
            })
            .collect(),
    };
    for bucket in ["first", "tenant:second"] {
        for window in [0, 9, 10, i64::MAX as u64 + 1, u64::MAX] {
            store.put_usage(bucket, window, &ledger).unwrap();
        }
    }
    let malformed = [
        "busbar:usage:first:+9",
        "busbar:usage:first:09",
        "busbar:usage:first:18446744073709551616",
        "busbar:usage:first:not-a-window",
        "other:usage:first:9",
    ];
    for key in malformed {
        redis::cmd("SET")
            .arg(key)
            .arg("untouched")
            .query::<()>(&mut raw)
            .unwrap();
    }
    let billed = metering_row(9, "billed", "alpha", "provider", 0);
    redis::cmd("HSET")
        .arg(&billed)
        .arg("requests")
        .arg(17)
        .arg(format!("{METERING_UNIT_PREFIX}audio_seconds"))
        .arg(19)
        .query::<()>(&mut raw)
        .unwrap();
    let billing: std::collections::HashMap<String, String> = raw.hgetall(&billed).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let purge = |before| runtime.block_on(StoreCalls::purge_usage_before(&store, before));
    assert_eq!(purge(0).unwrap(), 0);
    assert_eq!(
        purge(10).unwrap(),
        2,
        "count complete window hashes, never their fields"
    );
    assert_eq!(purge(10).unwrap(), 0);
    for bucket in ["first", "tenant:second"] {
        assert_eq!(store.get_usage(bucket, 9).unwrap(), UsageLedger::default());
        assert_eq!(store.get_usage(bucket, 0).unwrap(), ledger);
        assert_eq!(store.get_usage(bucket, 10).unwrap(), ledger);
    }
    assert_eq!(purge(i64::MAX as u64 + 1).unwrap(), 2);
    assert_eq!(
        store
            .get_usage("tenant:second", i64::MAX as u64 + 1)
            .unwrap(),
        ledger,
        "the full-width exact cutoff survives"
    );
    assert_eq!(purge(u64::MAX).unwrap(), 2);
    assert_eq!(purge(u64::MAX).unwrap(), 0);
    for key in malformed {
        assert_eq!(raw.get::<_, String>(key).unwrap(), "untouched", "{key}");
    }
    assert_eq!(
        raw.hgetall::<_, std::collections::HashMap<String, String>>(&billed)
            .unwrap(),
        billing
    );
    let reopened = ValkeyStore::connect(&url).unwrap();
    assert_eq!(reopened.get_usage("first", 0).unwrap(), ledger);
    assert_eq!(reopened.get_usage("first", u64::MAX).unwrap(), ledger);
    assert_eq!(
        reopened.get_usage("first", i64::MAX as u64 + 1).unwrap(),
        UsageLedger::default()
    );
    redis::cmd("FLUSHDB").query::<()>(&mut raw).unwrap();
}

struct UsageServerResult {
    commands: Vec<Vec<String>>,
    applied: Vec<String>,
}

fn usage_scan_server(
    lose_delete_reply: bool,
) -> (String, std::thread::JoinHandle<UsageServerResult>) {
    use std::io::Write;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("redis://{}/0", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let mut parser = redis::Parser::new();
        let mut commands = Vec::new();
        let mut applied = Vec::new();
        let mut live_keys = std::collections::HashSet::from([
            "busbar:usage:first:9".to_owned(),
            "busbar:usage:third:7".to_owned(),
        ]);
        let (mut pages, mut deletions) = (0, 0);
        loop {
            let value = match parser.parse_value(&mut stream) {
                Ok(value) => value,
                Err(_) => return UsageServerResult { commands, applied },
            };
            let redis::Value::Array(fields) = value else {
                panic!("a command is an array")
            };
            let fields: Vec<String> = fields
                .into_iter()
                .map(|field| match field {
                    redis::Value::BulkString(bytes) => String::from_utf8(bytes).unwrap(),
                    redis::Value::SimpleString(value) => value,
                    other => panic!("a command field is text: {other:?}"),
                })
                .collect();
            let command = fields[0].as_str();
            let response = match command {
                "GET" => {
                    assert_eq!(fields[1], SCHEMA_KEY);
                    format!(
                        "${}\r\n{}\r\n",
                        SCHEMA_VERSION.to_string().len(),
                        SCHEMA_VERSION
                    )
                    .into_bytes()
                }
                "CONFIG" => b"*2\r\n$16\r\nmaxmemory-policy\r\n$10\r\nnoeviction\r\n".to_vec(),
                "AUTH" | "SELECT" => b"+OK\r\n".to_vec(),
                "PING" => b"+PONG\r\n".to_vec(),
                "SCAN" => {
                    let (cursor, keys): (&str, &[&str]) = match pages {
                        0 => {
                            assert_eq!(fields[1], "0");
                            ("7", &[])
                        }
                        1 => {
                            assert_eq!(fields[1], "7");
                            (
                                "9",
                                &[
                                    "busbar:usage:first:9",
                                    "busbar:usage:first:9",
                                    "busbar:usage:tenant:second:8",
                                    "busbar:usage:first:0",
                                    "busbar:usage:first:10",
                                    "busbar:usage:first:+9",
                                ],
                            )
                        }
                        2 => {
                            assert_eq!(fields[1], "9");
                            ("0", &["busbar:usage:first:9", "busbar:usage:third:7"])
                        }
                        _ => panic!("the scan ended"),
                    };
                    pages += 1;
                    let mut response =
                        format!("*2\r\n${}\r\n{cursor}\r\n*{}\r\n", cursor.len(), keys.len())
                            .into_bytes();
                    for key in keys {
                        response
                            .extend_from_slice(format!("${}\r\n{key}\r\n", key.len()).as_bytes());
                    }
                    commands.push(fields.clone());
                    response
                }
                "DEL" => {
                    commands.push(fields.clone());
                    deletions += 1;
                    let before = applied.len();
                    for key in &fields[1..] {
                        if live_keys.remove(key) {
                            applied.push(key.clone());
                        }
                    }
                    let removed = applied.len() - before;
                    if lose_delete_reply {
                        stream.shutdown(std::net::Shutdown::Both).unwrap();
                        return UsageServerResult { commands, applied };
                    }
                    format!(":{removed}\r\n").into_bytes()
                }
                other => panic!("unexpected command: {other}"),
            };
            stream.write_all(&response).unwrap();
            if deletions == 2 {
                return UsageServerResult { commands, applied };
            }
        }
    });
    (url, server)
}

#[test]
fn usage_cleanup_continues_empty_scan_pages_deduplicates_and_counts_delete_replies() {
    use busbar_contract::store_calls::StoreCalls;
    let (url, server) = usage_scan_server(false);
    let (store, _) = open_on(&settings_for(&url), plain);
    let store = store.unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let removed = runtime.block_on(StoreCalls::purge_usage_before(&store, 10));
    let UsageServerResult { commands, applied } = server.join().unwrap();
    assert_eq!(
        removed.unwrap(),
        2,
        "count actual DEL replies, not discovered keys"
    );
    assert_eq!(applied, ["busbar:usage:first:9", "busbar:usage:third:7"]);
    let scans: Vec<_> = commands
        .iter()
        .filter(|c| c[0] == "SCAN")
        .map(|c| c[1].as_str())
        .collect();
    assert_eq!(
        scans,
        ["0", "7", "9"],
        "an empty nonterminal page must continue"
    );
    let deleted: Vec<_> = commands
        .iter()
        .filter(|c| c[0] == "DEL")
        .map(|c| c[1..].to_vec())
        .collect();
    assert_eq!(
        deleted,
        [
            vec![
                "busbar:usage:first:9".to_owned(),
                "busbar:usage:tenant:second:8".to_owned()
            ],
            vec!["busbar:usage:third:7".to_owned()],
        ],
        "duplicates, zero, equality and malformed keys must not be deleted"
    );
}

#[test]
fn usage_cleanup_never_reconnects_and_replays_a_delete_whose_reply_was_lost() {
    use busbar_contract::store_calls::StoreCalls;
    let (url, server) = usage_scan_server(true);
    let (store, table) = open_on(&settings_for(&url), plain);
    let store = store.unwrap();
    let dials = table.dial_timeouts().len();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let removed = runtime.block_on(StoreCalls::purge_usage_before(&store, 10));
    let UsageServerResult { commands, applied } = server.join().unwrap();
    assert!(
        removed.is_err(),
        "an applied delete with a lost reply must fail without a false count"
    );
    assert_eq!(
        applied,
        ["busbar:usage:first:9"],
        "the backend deleted before dropping its reply"
    );
    assert_eq!(commands.iter().filter(|c| c[0] == "DEL").count(), 1);
    assert_eq!(
        table.dial_timeouts().len(),
        dials,
        "no reconnect/replay after the ambiguous delete"
    );
}

#[test]
fn paired_mint_replay_refuses_a_changed_or_missing_owner_without_writing() {
    let Some(store) = live_store() else { return };
    let owner = uid("vk_pair_replay");
    let public = uid("vk_pair_public");
    let key = vk(&owner);
    let credential = cred(&owner, &public, 0);
    store.put_key_with_credential(&key, &credential).unwrap();
    let before = store.get_key(&owner).unwrap().unwrap();
    let secret = store
        .lookup_credential_secret("sigv4", &public)
        .unwrap()
        .unwrap();
    let mut changed = key.clone();
    changed.enabled = !changed.enabled;
    assert!(store
        .put_key_with_credential(&changed, &credential)
        .is_err());
    assert_eq!(store.get_key(&owner).unwrap().unwrap(), before);
    assert!(
        store
            .lookup_credential_secret("sigv4", &public)
            .unwrap()
            .unwrap()
            == secret
    );
    store.put_key_with_credential(&key, &credential).unwrap();
    assert_eq!(store.get_key(&owner).unwrap().unwrap(), before);
    assert!(
        store
            .lookup_credential_secret("sigv4", &public)
            .unwrap()
            .unwrap()
            == secret
    );
    store
        .with_conn(|c| c.del::<_, ()>(format!("{KEY_PREFIX}{owner}")))
        .unwrap();
    assert!(store.put_key_with_credential(&key, &credential).is_err());
    assert!(store.get_key(&owner).unwrap().is_none());
    assert!(
        store
            .lookup_credential_secret("sigv4", &public)
            .unwrap()
            .unwrap()
            == secret
    );
}

/// Revision exhaustion refuses the entire write, including a two-stamp key/credential pair.
#[test]
fn invalid_or_exhausted_revision_counters_never_reuse_or_partially_reserve_stamps() {
    let Some(_) = live_store() else { return };
    let (_database, mut raw) = fresh_db_client(5);
    let store = ValkeyStore::connect(&url_for_db(5)).unwrap();
    for (counter, paired) in [(-1, false), (i64::MAX, false), (i64::MAX - 1, true)] {
        raw.set::<_, _, ()>(REVISION_KEY, counter).unwrap();
        let id = uid("vk_revision_refusal");
        let offered = cred(&id, &uid("AKIA_REVISION_REFUSAL"), 0);
        let result = if paired {
            store.put_key_with_credential(&vk(&id), &offered)
        } else {
            store.put_key(&vk(&id))
        };
        let error = result.expect_err("an invalid reservation must fail before any write");
        assert!(error.0.contains("busbar:revision"), "{error}");
        assert_eq!(raw.get::<_, i64>(REVISION_KEY).unwrap(), counter);
        assert!(store.get_key(&id).unwrap().is_none());
        assert!(!raw
            .exists::<_, bool>(cred_id_key(&offered.meta.id))
            .unwrap());
        assert!(!raw.sismember::<_, _, bool>(KEYS_INDEX, &id).unwrap());
    }
    for paired in [false, true] {
        let count = if paired { 2 } else { 1 };
        raw.set::<_, _, ()>(REVISION_KEY, i64::MAX - count).unwrap();
        let id = uid("vk_revision_last");
        let offered = cred(&id, &uid("AKIA_REVISION_LAST"), 0);
        if paired {
            store.put_key_with_credential(&vk(&id), &offered).unwrap();
        } else {
            store.put_key(&vk(&id)).unwrap();
        }
        let key = store.get_key(&id).unwrap().unwrap();
        assert_eq!(key.revision, (i64::MAX - count + 1) as u64);
        if paired {
            assert_eq!(
                store.list_credentials(&id).unwrap()[0].revision,
                i64::MAX as u64
            );
        }
        assert_eq!(raw.get::<_, i64>(REVISION_KEY).unwrap(), i64::MAX);
        let before: String = raw.get(format!("{KEY_PREFIX}{id}")).unwrap();
        assert!(store.put_key(&vk(&id)).is_err());
        assert_eq!(
            raw.get::<_, String>(format!("{KEY_PREFIX}{id}")).unwrap(),
            before
        );
        assert_eq!(raw.get::<_, i64>(REVISION_KEY).unwrap(), i64::MAX);
    }
}

#[test]
fn revoke_refuses_dangling_foreign_or_incoherent_rows_without_mutation() {
    let Some(_) = live_store() else { return };
    let (_database, mut raw) = fresh_db_client(5);
    let store = ValkeyStore::connect(&url_for_db(5)).unwrap();
    let owner = uid("vk_revoke_corruption");
    let offered = cred(&owner, &uid("AKIA_REVOKE_CORRUPTION"), 0);
    store
        .put_key_with_credential(&vk(&owner), &offered)
        .unwrap();
    let row_key = cred_row_key(&owner, &offered.meta.kind, offered.meta.slot);
    let original: String = raw.get(&row_key).unwrap();
    let revision: i64 = raw.get(REVISION_KEY).unwrap();
    let foreign_id = uid("vk_foreign_credential");
    raw.set::<_, _, ()>(cred_id_key(&foreign_id), slot_pointer(&offered.meta))
        .unwrap();
    for (id, replacement) in [
        (foreign_id.as_str(), Some(original.clone())),
        (offered.meta.id.as_str(), None),
        (
            offered.meta.id.as_str(),
            Some(r#"{"meta":"RevokePrivateCanary","secret":"RevokePrivateCanary"}"#.to_owned()),
        ),
    ] {
        match &replacement {
            Some(value) => raw.set::<_, _, ()>(&row_key, value).unwrap(),
            None => {
                raw.del::<_, ()>(&row_key).unwrap();
            }
        }
        let error = store
            .revoke_credential(id, "requested")
            .expect_err("a corrupt target cannot confirm a revocation")
            .0;
        assert!(
            error.contains("revoke_credential") && error.contains(&row_key),
            "{error}"
        );
        assert!(!error.contains("RevokePrivateCanary"), "{error}");
        assert_eq!(raw.get::<_, Option<String>>(&row_key).unwrap(), replacement);
        assert_eq!(raw.get::<_, i64>(REVISION_KEY).unwrap(), revision);
    }

    let mut incoherent: CredentialSecret = serde_json::from_str(&original).unwrap();
    incoherent.meta.slot += 1;
    let replacement = serde_json::to_string(&incoherent).unwrap();
    raw.set::<_, _, ()>(&row_key, &replacement).unwrap();
    assert!(store
        .revoke_credential(&offered.meta.id, "requested")
        .is_err());
    assert_eq!(raw.get::<_, String>(&row_key).unwrap(), replacement);
    assert_eq!(raw.get::<_, i64>(REVISION_KEY).unwrap(), revision);

    raw.set::<_, _, ()>(&row_key, original).unwrap();
    store
        .revoke_credential(&offered.meta.id, "requested")
        .unwrap();
    let revoked: String = raw.get(&row_key).unwrap();
    let revision: i64 = raw.get(REVISION_KEY).unwrap();
    store.revoke_credential(&offered.meta.id, "again").unwrap();
    assert_eq!(raw.get::<_, String>(&row_key).unwrap(), revoked);
    assert_eq!(raw.get::<_, i64>(REVISION_KEY).unwrap(), revision);
}

#[test]
fn a_failed_legacy_upgrade_reports_safe_context_and_truthful_partial_progress() {
    use crate::legacy::{TASK_EVENTS_PREFIX, TASK_ROW_PREFIX};
    let Some(_) = live_store() else { return };
    let (_database, mut raw) = fresh_db_client(6);
    let url = url_for_db(6);
    drop(ValkeyStore::connect(&url).unwrap());
    let id = uid("vk_bad_v6");
    let event = sample_event(&id, 1, "task.submitted", "", "h1");
    let events_key = format!("{TASK_EVENTS_PREFIX}{id}");
    raw.zadd::<_, _, _, ()>(&events_key, serde_json::to_string(&event).unwrap(), 1)
        .unwrap();
    let task_key = format!("{TASK_ROW_PREFIX}{id}");
    let mut task = serde_json::to_value(sample_task(&id, "working", TASK_LIVE_TS)).unwrap();
    task["artifact_cursor"] = serde_json::json!("LegacyPrivateCanary");
    let malformed = task.to_string();
    raw.set::<_, _, ()>(&task_key, &malformed).unwrap();
    raw.set::<_, _, ()>(SCHEMA_KEY, 6).unwrap();
    let error = ValkeyStore::connect(&url).expect_err("a malformed v6 task refuses the upgrade");
    assert!(
        error.contains("task") && error.contains(&task_key),
        "{error}"
    );
    assert!(!error.contains("LegacyPrivateCanary"), "{error}");
    assert!(error.contains("unprocessed v6 keys remain"), "{error}");
    assert_eq!(raw.get::<_, String>(&task_key).unwrap(), malformed);
    assert!(
        !raw.exists::<_, bool>(&events_key).unwrap(),
        "the earlier event phase already completed"
    );
    assert_eq!(raw.get::<_, i64>(SCHEMA_KEY).unwrap(), 6);
    task["artifact_cursor"] = serde_json::json!(0);
    raw.set::<_, _, ()>(&task_key, task.to_string()).unwrap();
    let repaired = ValkeyStore::connect(&url).unwrap();
    assert_eq!(repaired.list_task_events(&id).unwrap(), vec![event]);
    assert!(repaired.get_task(&id).unwrap().is_some());
}

/// A bounded, joined RESP peer: exercise malformed transaction replies and a lost script reply
fn malformed_reply_peer(exec: Option<&'static [u8]>) -> (String, std::thread::JoinHandle<usize>) {
    use std::io::Write;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("redis://{}/0", listener.local_addr().unwrap());
    let peer = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut accepted = 0;
        loop {
            let (mut stream, _) = match listener.accept() {
                Ok(stream) => stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        return accepted;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    continue;
                }
                Err(e) => panic!("accept mock RESP client: {e}"),
            };
            accepted += 1;
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut parser = redis::Parser::new();
            let mut queued = false;
            loop {
                let redis::Value::Array(fields) = (match parser.parse_value(&mut stream) {
                    Ok(value) => value,
                    Err(_) => break,
                }) else {
                    panic!("command is an array")
                };
                let fields: Vec<String> = fields
                    .into_iter()
                    .map(|value| match value {
                        redis::Value::BulkString(bytes) => String::from_utf8(bytes).unwrap(),
                        other => panic!("command field is bulk text: {other:?}"),
                    })
                    .collect();
                let command = fields[0].as_str();
                let mut done = false;
                let response = match command {
                    "AUTH" | "SELECT" | "WATCH" | "UNWATCH" => b"+OK\r\n".to_vec(),
                    "PING" => b"+PONG\r\n".to_vec(),
                    "CONFIG" => b"*2\r\n$16\r\nmaxmemory-policy\r\n$10\r\nnoeviction\r\n".to_vec(),
                    "MULTI" => {
                        queued = true;
                        b"+OK\r\n".to_vec()
                    }
                    "EXEC" => {
                        queued = false;
                        exec.expect("transaction peer").to_vec()
                    }
                    _ if queued => b"+QUEUED\r\n".to_vec(),
                    "GET" if fields[1] == SCHEMA_KEY => {
                        format!(":{SCHEMA_VERSION}\r\n").into_bytes()
                    }
                    "GET" if fields[1] == REVISION_KEY => b":0\r\n".to_vec(),
                    "GET" => {
                        done = fields[1].ends_with("reply_probe");
                        b"$-1\r\n".to_vec()
                    }
                    "SCRIPT" if exec.is_none() => {
                        b"$40\r\n0000000000000000000000000000000000000000\r\n".to_vec()
                    }
                    "EVALSHA" | "EVAL" if exec.is_none() => {
                        if accepted == 1 {
                            stream.shutdown(std::net::Shutdown::Both).unwrap();
                            break;
                        }
                        done = true;
                        b":0\r\n".to_vec()
                    }
                    other => panic!("unexpected command {other}"),
                };
                stream.write_all(&response).unwrap();
                if done {
                    return accepted;
                }
            }
        }
    });
    (url, peer)
}

#[test]
fn exec_must_confirm_every_queued_command_and_discard_malformed_reply_connections() {
    for exec in [
        b"*0\r\n".as_slice(),
        b"*9\r\n:1\r\n:1\r\n:1\r\n:1\r\n:1\r\n:1\r\n:1\r\n:1\r\n:1\r\n",
        b":1\r\n",
    ] {
        let (url, peer) = malformed_reply_peer(Some(exec));
        let store = ValkeyStore::connect(&url).unwrap();
        let result = store.put_key(&vk("malformed_exec"));
        let probe = store.get_key("reply_probe");
        drop(store);
        let accepted = peer.join().unwrap();
        let error = result.expect_err("an EXEC reply must confirm the complete command list");
        assert!(error.0.contains("EXEC reply"), "{error}");
        assert!(probe.unwrap().is_none());
        assert_eq!(
            accepted, 2,
            "the malformed reply connection cannot serve another operation"
        );
    }
}

#[test]
fn eof_after_a_nonreplayable_script_discards_the_connection_before_the_next_write() {
    let (url, peer) = malformed_reply_peer(None);
    let store = ValkeyStore::connect(&url).unwrap();
    let record = PlaneRecord {
        kind: "eof_control".into(),
        id: "row".into(),
        parent: None,
        seq: 0,
        ts: 1,
        disposition: PlaneDisposition::Active,
        body: b"body".to_vec(),
    };
    let first = store.upsert_plane_record(record.view());
    let second = store.upsert_plane_record(record.view());
    drop(store);
    let accepted = peer.join().unwrap();
    assert!(first.is_err(), "a lost script reply must not be replayed");
    assert!(
        second.is_ok(),
        "the next write must use a fresh connection: {second:?}"
    );
    assert_eq!(accepted, 2);
}

fn legacy_approval_peer(
    unexpected_key: Option<&'static str>,
    ttl: i64,
) -> (String, std::thread::JoinHandle<Option<Vec<String>>>) {
    use std::io::Write;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("redis://{}/0", listener.local_addr().unwrap());
    let peer = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(stream) => break stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        return None;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(e) => panic!("accept legacy fixture client: {e}"),
            }
        };
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut parser = redis::Parser::new();
        let mut transaction = false;
        let mut target = None;
        loop {
            let redis::Value::Array(fields) = (match parser.parse_value(&mut stream) {
                Ok(value) => value,
                Err(_) => return target,
            }) else {
                panic!("command is an array")
            };
            let fields: Vec<String> = fields
                .into_iter()
                .map(|value| match value {
                    redis::Value::BulkString(bytes) => String::from_utf8(bytes).unwrap(),
                    other => panic!("command field is text: {other:?}"),
                })
                .collect();
            let response = match fields[0].as_str() {
                "AUTH" | "SELECT" => b"+OK\r\n".to_vec(),
                "PING" => b"+PONG\r\n".to_vec(),
                "CONFIG" => b"*2\r\n$16\r\nmaxmemory-policy\r\n$10\r\nnoeviction\r\n".to_vec(),
                "MULTI" => {
                    transaction = true;
                    b"+OK\r\n".to_vec()
                }
                "EXEC" => {
                    transaction = false;

                    if ttl == -2 {
                        b"*2\r\n$-1\r\n:-2\r\n".to_vec()
                    } else {
                        format!("*2\r\n$10\r\n2000000900\r\n:{ttl}\r\n").into_bytes()
                    }
                }
                _ if transaction => b"+QUEUED\r\n".to_vec(),
                "GET" if fields[1] == SCHEMA_KEY => b":6\r\n".to_vec(),
                "GET" => b"$10\r\n2000000900\r\n".to_vec(),
                "TTL" => format!(":{ttl}\r\n").into_bytes(),
                "SCAN" => {
                    if fields.iter().any(|field| field == "busbar:askstate:*") {
                        let key = unexpected_key.unwrap_or("busbar:askstate:spent");
                        format!("*2\r\n$1\r\n0\r\n*1\r\n${}\r\n{key}\r\n", key.len()).into_bytes()
                    } else {
                        b"*2\r\n$1\r\n0\r\n*0\r\n".to_vec()
                    }
                }
                "HGETALL" | "ZRANGE" => b"*0\r\n".to_vec(),
                "DEL" => b":1\r\n".to_vec(),
                "SET" => {
                    if fields[1] != SCHEMA_KEY {
                        target = Some(fields);
                    }
                    b"+OK\r\n".to_vec()
                }
                other => panic!("unexpected migration command: {other}"),
            };
            if stream.write_all(&response).is_err() {
                return target;
            }
        }
    });
    (url, peer)
}

#[test]
fn legacy_approval_migration_keeps_absolute_expiry_and_never_makes_a_finite_entry_permanent() {
    let Some(_) = live_store() else { return };
    let (_database, mut raw) = fresh_db_client(TOKEN_CLOCK_DATABASE);
    let url = url_for_db(TOKEN_CLOCK_DATABASE);
    let store = ValkeyStore::connect(&url).unwrap();
    let before = token_test_now(&store);
    let expires = before + 900;
    let source = |token: &str| format!("{}{}", legacy::ASK_STATE_PREFIX, token);
    let target = |token: &str| plane::token_key(legacy::KIND_ASK, token);

    raw.set_ex::<_, _, ()>(source("short-cleanup"), expires, 60)
        .unwrap();
    raw.set::<_, _, ()>(source("no-cleanup"), expires).unwrap();
    raw.set_ex::<_, _, ()>(source("wide-expiry"), u64::MAX, 60)
        .unwrap();
    raw.set_ex::<_, _, ()>(source("finite-fallback"), "not-an-expiry", 600)
        .unwrap();
    raw.set::<_, _, ()>(source("permanent-fallback"), "not-an-expiry")
        .unwrap();
    raw.set::<_, _, ()>(source("existing"), expires).unwrap();
    raw.set::<_, _, ()>(target("existing"), u64::MAX).unwrap();
    raw.set::<_, _, ()>(source("missing"), expires).unwrap();
    redis::cmd("EXPIREAT")
        .arg(source("missing"))
        .arg(1)
        .query::<()>(&mut raw)
        .unwrap();
    raw.set::<_, _, ()>(source("expired"), before - 1).unwrap();
    raw.set::<_, _, ()>(SCHEMA_KEY, 6).unwrap();
    drop(store);

    let upgraded = ValkeyStore::connect(&url).expect("the real migration scripts run on Valkey");
    let after = token_test_now(&upgraded);
    for token in ["short-cleanup", "no-cleanup"] {
        assert_eq!(raw.get::<_, u64>(target(token)).unwrap(), expires);
        let cleanup: u64 = redis::cmd("EXPIRETIME")
            .arg(target(token))
            .query(&mut raw)
            .unwrap();
        assert_eq!(
            cleanup,
            expires + 1,
            "the old TTL cannot shorten or unbound {token}"
        );
        assert!(!upgraded.redeem_ask_state(token, expires, u64::MAX).unwrap());
    }
    let fallback: u64 = raw.get(target("finite-fallback")).unwrap();
    assert!(fallback > before && fallback <= after + 600);
    let cleanup: u64 = redis::cmd("EXPIRETIME")
        .arg(target("finite-fallback"))
        .query(&mut raw)
        .unwrap();
    assert_eq!(
        cleanup,
        fallback + 1,
        "a malformed finite source stays bounded"
    );
    for (token, expected) in [
        ("wide-expiry", u64::MAX),
        ("permanent-fallback", i64::MAX as u64),
        ("existing", u64::MAX),
    ] {
        assert_eq!(raw.get::<_, u64>(target(token)).unwrap(), expected);
        assert_eq!(raw.ttl::<_, i64>(target(token)).unwrap(), -1);
        assert!(!upgraded.redeem_ask_state(token, u64::MAX, 0).unwrap());
    }
    for token in [
        "short-cleanup",
        "no-cleanup",
        "wide-expiry",
        "finite-fallback",
        "permanent-fallback",
        "existing",
        "missing",
        "expired",
    ] {
        assert!(
            !raw.exists::<_, bool>(source(token)).unwrap(),
            "source {token} retired"
        );
    }
    for token in ["missing", "expired"] {
        assert!(!raw.exists::<_, bool>(target(token)).unwrap());
    }
    assert!(!upgraded.redeem_ask_state("expired", before - 1, 0).unwrap());
    assert!(upgraded.redeem_ask_state("missing", expires, 0).unwrap());
    assert_eq!(raw.get::<_, i64>(SCHEMA_KEY).unwrap(), SCHEMA_VERSION);
    drop(upgraded);
    let reopened = ValkeyStore::connect(&url).unwrap();
    for token in ["short-cleanup", "no-cleanup", "missing"] {
        assert!(!reopened.redeem_ask_state(token, expires, 0).unwrap());
    }
}

#[test]
fn legacy_approval_refuses_unexpected_scan_keys_without_panicking() {
    for key in ["x", "éééééééééé"] {
        let (url, peer) = legacy_approval_peer(Some(key), 1);
        let opened = std::panic::catch_unwind(|| ValkeyStore::connect(&url));
        let target = peer.join().unwrap();
        let error = opened
            .expect("an unexpected SCAN key must not unwind the plugin")
            .expect_err("an unexpected SCAN key refuses migration");
        assert!(
            error.contains("ask-state key") && error.contains("namespace"),
            "{error}"
        );
        assert!(target.is_none());
    }
}

#[test]
fn malformed_plane_index_members_do_not_block_deleting_or_purging_valid_records() {
    let Some(_) = live_store() else { return };
    let (_database, mut raw) = fresh_db_client(8);
    let store = ValkeyStore::connect(&url_for_db(8)).unwrap();
    for purge in [false, true] {
        let kind = if purge {
            "corrupt_purge_control"
        } else {
            "corrupt_delete_control"
        };
        let record = PlaneRecord {
            kind: kind.into(),
            id: "valid".into(),
            parent: None,
            seq: 0,
            ts: 1,
            disposition: PlaneDisposition::Terminal,
            body: b"valid body".to_vec(),
        };
        store.upsert_plane_record(record.view()).unwrap();
        let prefix = format!("busbar:plane:{}:", hex(kind.as_bytes()));
        let rec = format!("{prefix}rec");
        let body = format!("{prefix}body");
        let byts = format!("{prefix}byts");
        let idx = format!("{prefix}idx:{}", hex(b"valid"));
        let side: String = raw.hget(&rec, "0:valid").unwrap();
        raw.hset::<_, _, _, ()>(&rec, "malformed", &side).unwrap();
        raw.hset::<_, _, _, ()>(&body, "malformed", "corrupt body")
            .unwrap();
        raw.zadd::<_, _, _, ()>(&byts, "malformed", 1).unwrap();
        raw.zadd::<_, _, _, ()>(&idx, "malformed", 0).unwrap();
        if purge {
            assert_eq!(
                store
                    .purge_plane_records(kind, 2, busbar_contract::records::Retention::Age)
                    .unwrap(),
                1
            );
            assert_eq!(
                store
                    .purge_plane_records(kind, 2, busbar_contract::records::Retention::Age)
                    .unwrap(),
                0
            );
        } else {
            store.delete_plane_record(kind, "valid").unwrap();
        }
        assert!(store.get_plane_record(kind, "valid").unwrap().is_none());
        assert_eq!(raw.hget::<_, _, String>(&rec, "malformed").unwrap(), side);
        assert_eq!(
            raw.hget::<_, _, String>(&body, "malformed").unwrap(),
            "corrupt body"
        );
        assert!(raw
            .zscore::<_, _, Option<f64>>(&byts, "malformed")
            .unwrap()
            .is_some());
    }
}

#[test]
fn new_writes_cannot_persist_secret_material_on_an_already_revoked_credential() {
    let Some(_) = live_store() else { return };
    let (_database, mut raw) = fresh_db_client(5);
    let store = ValkeyStore::connect(&url_for_db(5)).unwrap();
    for paired in [false, true] {
        let owner = uid("vk_revoked_input");
        if !paired {
            store.put_key(&vk(&owner)).unwrap();
        }
        let mut offered = cred(&owner, &uid("AKIA_REVOKED_INPUT"), 0);
        offered.meta.revoked_at = Some(1);
        let secret_canary = offered.secret.clone();
        let revision: Option<i64> = raw.get(REVISION_KEY).unwrap();
        for retain_bytes in [true, false] {
            if !retain_bytes {
                offered.secret.clear();
            }
            let result = if paired {
                store.put_key_with_credential(&vk(&owner), &offered)
            } else {
                store.put_credential(&offered)
            };
            let error = result
                .expect_err("a revoked credential cannot retain a secret or a live secret form")
                .0;
            assert!(
                error.contains("revoked credential") && !error.contains(&secret_canary),
                "{error}"
            );
            assert_eq!(raw.get::<_, Option<i64>>(REVISION_KEY).unwrap(), revision);
            assert!(!raw
                .exists::<_, bool>(cred_id_key(&offered.meta.id))
                .unwrap());
            assert_eq!(store.get_key(&owner).unwrap().is_some(), !paired);
        }
        offered.meta.secret_form = SecretForm::None;
        if paired {
            store
                .put_key_with_credential(&vk(&owner), &offered)
                .unwrap();
        } else {
            store.put_credential(&offered).unwrap();
        }
        let stored: String = raw
            .get(cred_row_key(&owner, &offered.meta.kind, offered.meta.slot))
            .unwrap();
        let stored: CredentialSecret = serde_json::from_str(&stored).unwrap();
        assert!(stored.secret.is_empty());
        assert_eq!(stored.meta.secret_form, SecretForm::None);
        assert!(stored.meta.revoked_at.is_some());
    }
}

#[test]
fn corrupt_hydration_index_members_and_plane_sidecars_refuse_without_echoing_content() {
    let Some(_) = live_store() else { return };
    let (_database, mut raw) = fresh_db_client(8);
    let store = ValkeyStore::connect(&url_for_db(8)).unwrap();
    raw.zadd::<_, _, _, ()>(CREDS_BYREV, "CorruptPrivateCanary", 0)
        .unwrap();
    let error = store.list_credentials_since(0).unwrap_err().0;
    assert!(
        error.contains("list_credentials_since") && !error.contains("CorruptPrivateCanary"),
        "{error}"
    );
    raw.zrem::<_, _, ()>(CREDS_BYREV, "CorruptPrivateCanary")
        .unwrap();
    assert!(store.list_credentials_since(0).unwrap().is_empty());
    let record = PlaneRecord {
        kind: "corrupt_read".into(),
        id: "event".into(),
        parent: Some("chain".into()),
        seq: 1,
        ts: 1,
        disposition: PlaneDisposition::Active,
        body: b"valid body".to_vec(),
    };
    store.append_plane_record(record.view()).unwrap();
    let prefix = format!("busbar:plane:{}:", hex(b"corrupt_read"));
    let rec = format!("{prefix}rec");
    let body = format!("{prefix}body");
    raw.hset::<_, _, _, ()>(&body, "CorruptPrivateCanary", "private body")
        .unwrap();
    let error = store
        .list_plane_records("corrupt_read", &PlaneSelector::All)
        .unwrap_err()
        .0;
    assert!(
        error.contains("list_plane_records") && !error.contains("CorruptPrivateCanary"),
        "{error}"
    );
    raw.hdel::<_, _, ()>(&body, "CorruptPrivateCanary").unwrap();
    let side: String = raw.hget(&rec, "1:chain").unwrap();
    let selector = PlaneSelector::Parent("chain".into());
    for malformed in [
        "1aCorruptPrivateCanary",
        "1a{\"parent\":7}",
        "1a{\"parent\":null}",
    ] {
        raw.hset::<_, _, _, ()>(&rec, "1:chain", malformed).unwrap();
        let error = store
            .list_plane_records("corrupt_read", &selector)
            .unwrap_err()
            .0;
        assert!(
            error.contains("list_plane_records") && !error.contains("CorruptPrivateCanary"),
            "{error}"
        );
    }
    raw.hset::<_, _, _, ()>(&rec, "1:chain", &side).unwrap();
    raw.hdel::<_, _, ()>(&body, "1:chain").unwrap();
    assert!(store.list_plane_records("corrupt_read", &selector).is_err());
    raw.hdel::<_, _, ()>(&rec, "1:chain").unwrap();
    assert!(
        store
            .list_plane_records("corrupt_read", &selector)
            .unwrap()
            .is_empty(),
        "an index snapshot followed by a complete concurrent deletion still skips the absent row"
    );
    store.append_plane_record(record.view()).unwrap();
    assert_eq!(
        store.list_plane_records("corrupt_read", &selector).unwrap(),
        vec![b"valid body".to_vec()]
    );
}

#[test]
fn shared_clock_ignores_caller_skew_and_refuses_expired_grants_without_mutation() {
    const TOKEN_KIND: &str = "shared-clock-regression";
    const PAST_EPOCH: u64 = 1;
    let Some(store) = live_store() else { return };
    let live = uid("clock-live");
    let expired = uid("clock-expired");
    assert!(store
        .redeem_plane_token(TOKEN_KIND, &live, u64::MAX, PAST_EPOCH)
        .unwrap());
    assert!(!store
        .redeem_plane_token(TOKEN_KIND, &live, u64::MAX, u64::MAX)
        .unwrap());
    assert!(!store
        .redeem_plane_token(TOKEN_KIND, &expired, PAST_EPOCH, 0)
        .unwrap());
    let absent: Option<String> = store
        .with_conn(|c| c.get(plane::token_key(TOKEN_KIND, &expired)))
        .unwrap();
    assert_eq!(absent, None, "expired input leaves no receipt");
    drop(store);
    let store = ValkeyStore::connect(&std::env::var("VALKEY_URL").unwrap()).unwrap();
    assert!(!store
        .redeem_plane_token(TOKEN_KIND, &live, u64::MAX, 0)
        .unwrap());
    let stored: String = store
        .with_conn(|c| c.get(plane::token_key(TOKEN_KIND, &live)))
        .unwrap();
    assert_eq!(stored, u64::MAX.to_string());
    let _: () = store
        .with_conn(|c| c.del(plane::token_key(TOKEN_KIND, &live)))
        .unwrap();
}

#[test]
fn shared_clock_keeps_exact_large_stored_expiries_and_reclaims_only_lapsed_rows() {
    const TOKEN_KIND: &str = "shared-clock-seeded";
    const EXACT_EXPIRY: u64 = (1_u64 << 53) + 1;
    let Some(store) = live_store() else { return };
    let future = uid("clock-future");
    let lapsed = uid("clock-lapsed");
    let _: () = store
        .with_conn(|c| c.set(plane::token_key(TOKEN_KIND, &future), EXACT_EXPIRY))
        .unwrap();
    let _: () = store
        .with_conn(|c| c.set(plane::token_key(TOKEN_KIND, &lapsed), 0))
        .unwrap();
    assert!(!store
        .redeem_plane_token(TOKEN_KIND, &future, u64::MAX, u64::MAX)
        .unwrap());
    assert!(store
        .redeem_plane_token(TOKEN_KIND, &lapsed, u64::MAX, 0)
        .unwrap());
    let stored: String = store
        .with_conn(|c| c.get(plane::token_key(TOKEN_KIND, &future)))
        .unwrap();
    assert_eq!(stored, EXACT_EXPIRY.to_string());
    for token in [&future, &lapsed] {
        let _: () = store
            .with_conn(|c| c.del(plane::token_key(TOKEN_KIND, token)))
            .unwrap();
    }
}

/// TIME is the shared authority used by the token script, independent of the test process clock.
fn token_test_now(store: &ValkeyStore) -> u64 {
    let (seconds, _micros): (u64, u64) = store.with_conn(|c| redis::cmd("TIME").query(c)).unwrap();
    seconds
}

#[test]
fn caller_clock_token_ttls_are_repaired_before_reopening_the_store() {
    const TOKEN_KIND: &str = "clock-upgrade";
    const LIVE_LIFE: u64 = 900;
    const EARLY_CLEANUP: u64 = 60;
    const CALLER_CLOCK_SCHEMA: i64 = 11;
    let Some(_) = live_store() else { return };
    let (database, _raw) = fresh_db_client(TOKEN_CLOCK_DATABASE);
    let url = url_for_db(TOKEN_CLOCK_DATABASE);
    let store = ValkeyStore::connect(&url).unwrap();
    let expires = token_test_now(&store) + LIVE_LIFE;
    let normal = plane::token_key(TOKEN_KIND, "normal");
    let forever = plane::token_key(TOKEN_KIND, "forever");
    database
        .with_conn(|c| {
            redis::pipe()
                .set_ex(&normal, expires, EARLY_CLEANUP)
                .set_ex(&forever, u64::MAX, EARLY_CLEANUP)
                .set(SCHEMA_KEY, CALLER_CLOCK_SCHEMA)
                .query::<()>(c)
        })
        .unwrap();
    drop(store);
    let store = ValkeyStore::connect(&url).unwrap();
    for caller in [0, u64::MAX] {
        assert!(!store
            .redeem_plane_token(TOKEN_KIND, "normal", expires, caller)
            .unwrap());
        assert!(!store
            .redeem_plane_token(TOKEN_KIND, "forever", u64::MAX, caller)
            .unwrap());
    }
    let cleanup: u64 = database
        .with_conn(|c| redis::cmd("EXPIRETIME").arg(&normal).query(c))
        .unwrap();
    assert_eq!(cleanup, expires + 1);
    let ttl: i64 = database.with_conn(|c| c.ttl(&forever)).unwrap();
    const NO_EXPIRY: i64 = -1;
    assert_eq!(ttl, NO_EXPIRY);
    let stored: String = database.with_conn(|c| c.get(&forever)).unwrap();
    assert_eq!(stored, u64::MAX.to_string());
    drop(store);
    let store = ValkeyStore::connect(&url).unwrap();
    assert!(!store
        .redeem_plane_token(TOKEN_KIND, "normal", expires, 0)
        .unwrap());
}

#[test]
fn ticket_expiry_records_survive_a_fast_purge_caller() {
    use busbar_contract::records::Retention;
    let Some(_) = live_store() else { return };
    let (_database, _raw) = fresh_db_client(TOKEN_CLOCK_DATABASE);
    let store = ValkeyStore::connect(&url_for_db(TOKEN_CLOCK_DATABASE)).unwrap();
    let now = token_test_now(&store);
    let live = uid("live-ticket");
    let expired = uid("expired-ticket");

    const TICKET_KIND: &str = "ticket";
    const OTHER_KIND: &str = "ordinary-retention-regression";
    const FUTURE_OFFSET: u64 = 900;
    let future = now + FUTURE_OFFSET;
    let row = |kind: &str, id: &str, ts| PlaneRecord {
        kind: kind.into(),
        id: id.into(),
        parent: None,
        seq: 0,
        ts,
        disposition: if kind == TICKET_KIND {
            PlaneDisposition::Terminal
        } else {
            PlaneDisposition::Active
        },
        body: id.as_bytes().to_vec(),
    };
    for (kind, id, ts) in [
        (TICKET_KIND, live.as_str(), future),
        (TICKET_KIND, expired.as_str(), 0),
        (OTHER_KIND, live.as_str(), future),
    ] {
        store.upsert_plane_record(row(kind, id, ts).view()).unwrap();
    }
    assert_eq!(
        store
            .purge_plane_records(TICKET_KIND, 0, Retention::Age)
            .unwrap(),
        0,
        "an exact cutoff retains equality"
    );
    assert_eq!(
        store
            .purge_plane_records(TICKET_KIND, u64::MAX, Retention::Age)
            .unwrap(),
        1
    );
    assert_eq!(
        store.get_plane_record(TICKET_KIND, &live).unwrap(),
        Some(live.as_bytes().to_vec())
    );
    assert_eq!(store.get_plane_record(TICKET_KIND, &expired).unwrap(), None);
    assert_eq!(
        store
            .purge_plane_records(OTHER_KIND, u64::MAX, Retention::Age)
            .unwrap(),
        1,
        "ordinary record age policy is unchanged"
    );
    store.delete_plane_record(TICKET_KIND, &live).unwrap();
}

#[test]
fn ticket_preflight_uses_the_shared_clock_and_matching_terminal_deadline_without_spending() {
    let Some(store) = live_store() else { return };
    let now = token_test_now(&store);
    let token = uid("preflight-ticket");

    const TICKET_KIND: &str = "ticket";
    const LIVE_LIFE: u64 = 900;
    let expires = now + LIVE_LIFE;
    let record = |ts, disposition| PlaneRecord {
        kind: TICKET_KIND.into(),
        id: token.clone(),
        parent: None,
        seq: 0,
        ts,
        disposition,
        body: b"ticket-preflight".to_vec(),
    };
    store
        .upsert_plane_record(record(expires, PlaneDisposition::Terminal).view())
        .unwrap();
    for caller in [u64::MAX, 0, u64::MAX] {
        assert!(
            store
                .plane_token_live(TICKET_KIND, &token, expires, caller)
                .unwrap(),
            "shared clock validates a live terminal ticket"
        );
    }
    assert!(
        !store
            .plane_token_live(TICKET_KIND, &token, expires + 1, 0)
            .unwrap(),
        "a different signed deadline must not match"
    );
    store
        .upsert_plane_record(record(expires, PlaneDisposition::Active).view())
        .unwrap();
    assert!(
        !store
            .plane_token_live(TICKET_KIND, &token, expires, 0)
            .unwrap(),
        "ticket records are terminal"
    );
    let expired = now - 1;
    store
        .upsert_plane_record(record(expired, PlaneDisposition::Terminal).view())
        .unwrap();
    assert!(
        !store
            .plane_token_live(TICKET_KIND, &token, expired, 0)
            .unwrap(),
        "slow callers cannot keep expired tickets live"
    );
    store
        .upsert_plane_record(record(expires, PlaneDisposition::Terminal).view())
        .unwrap();
    assert!(store
        .plane_token_live(TICKET_KIND, &token, expires, 0)
        .unwrap());
    store.delete_plane_record(TICKET_KIND, &token).unwrap();
    assert!(!store
        .plane_token_live(TICKET_KIND, &token, expires, 0)
        .unwrap());

    let receipt: Option<String> = store
        .with_conn(|c| c.get(plane::token_key(TICKET_KIND, &token)))
        .unwrap();
    assert_eq!(receipt, None, "preflight is non-consuming");
}

/// Existing isolated database lease used by the shared-clock fixtures.
pub(crate) const TOKEN_CLOCK_DATABASE: u32 = 6;
