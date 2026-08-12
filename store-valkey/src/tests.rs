// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_api::{McpCallRecord, SecretForm, TaskEventRow, TaskRow};

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
    assert!(redis::Client::open("rediss://:pw@localhost:6380/0").is_ok());
}

#[test]
fn glob_escaping_covers_every_metacharacter() {
    assert_eq!(escape_glob("*"), "\\*");
    assert_eq!(escape_glob("a?b"), "a\\?b");
    assert_eq!(escape_glob("[x]"), "\\[x\\]");
    assert_eq!(escape_glob("back\\slash"), "back\\\\slash");
    assert_eq!(escape_glob("plain-id-123"), "plain-id-123");
}

/// End-to-end against a REAL Valkey, gated on `VALKEY_URL` (a docker service in CI). Skips
/// cleanly when unset LOCALLY; under `CI` a missing URL is a HARD FAILURE, never a silent skip.
fn live_store() -> Option<ValkeyStore> {
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
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    (std::process::id() as u64) * 1_000_000 + n
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
    store.put_key(&vk("vk_1")).unwrap();
    let back = store.get_key("vk_1").unwrap().expect("key exists");
    assert_eq!(back.id, "vk_1");
    assert!(back.deleted_at.is_none());
    assert!(back.revision > 0, "put_key must stamp a nonzero revision");
}

#[test]
fn list_keys_since_only_returns_keys_past_the_watermark() {
    let Some(store) = live_store() else { return };
    store.put_key(&vk("vk_a")).unwrap();
    let watermark = store.get_key("vk_a").unwrap().unwrap().revision;
    store.put_key(&vk("vk_b")).unwrap();
    let delta = store.list_keys_since(watermark).unwrap();
    // Tests run in parallel against one shared instance, so `delta` may legitimately also contain
    // OTHER tests' concurrently-created keys past this watermark — assert on presence/absence of
    // THIS test's own ids, not an exact global count.
    assert!(
        delta.iter().any(|k| k.id == "vk_b"),
        "vk_b must be in the delta"
    );
    assert!(
        !delta.iter().any(|k| k.id == "vk_a"),
        "vk_a was created BEFORE the watermark and must not reappear"
    );
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
fn delete_key_removes_usage_windows() {
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
        after.requests, 0,
        "usage windows must be cleaned up on delete"
    );
}

/// Regression guard for the historical glob-injection finding: a key id containing glob
/// metacharacters must not make `delete_key`'s usage-window cleanup match ANOTHER key's windows.
#[test]
fn delete_key_does_not_glob_match_other_keys_usage() {
    let Some(store) = live_store() else { return };
    let evil = uid("vk_evil_*");
    let victim = uid("vk_evil_victim");
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
    // The victim's usage must survive — an unescaped glob would have matched "vk_evil_victim"
    // as well as the literal "vk_evil_*" pattern.
    let victim_usage = store.get_usage(&victim, 1000).unwrap();
    assert_eq!(
        victim_usage.requests, 1,
        "an unescaped '*' in the deleted key's id must not sweep another key's usage windows"
    );
}

// ── scrub_key ────────────────────────────────────────────────────────────────────────────────

#[test]
fn scrub_key_requires_tombstone_first() {
    let Some(store) = live_store() else { return };
    store.put_key(&vk("vk_live_scrub")).unwrap();
    assert!(
        store.scrub_key("vk_live_scrub").is_err(),
        "scrubbing a live (non-tombstoned) key must error"
    );
}

#[test]
fn scrub_key_nulls_name_and_labels_after_tombstone() {
    let Some(store) = live_store() else { return };
    // This suite runs against a SHARED, PERSISTENT Valkey that is not flushed between runs, and
    // this test uses a FIXED id. It used to be self-healing only because `put_key` resurrected
    // whatever tombstone a prior run had left on that id; now that `put_key` refuses to clear a
    // tombstone, the fixture has to be removed explicitly.
    let _ = store.purge_key_for_test("vk_scrub");
    let mut key = vk("vk_scrub");
    key.labels.insert("team".to_string(), "growth".to_string());
    store.put_key(&key).unwrap();
    store.delete_key("vk_scrub").unwrap();
    store.scrub_key("vk_scrub").unwrap();
    let row = store.get_key("vk_scrub").unwrap().unwrap();
    assert_eq!(row.name, "");
    assert!(row.labels.is_empty());
    assert!(
        row.deleted_at.is_some(),
        "scrub must not un-tombstone the key"
    );
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
    assert!(
        store.put_credential(&c0b).is_err(),
        "minting into a slot holding a LIVE credential must be rejected"
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
    assert!(
        store.put_credential(&c1).is_err(),
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
    assert_eq!(
        resolved.secret, "",
        "secret material must be destroyed on revoke"
    );

    // Idempotent: revoking again must not error or clobber the original revoked_at reason.
    assert!(store.revoke_credential(&c.meta.id, "again").is_ok());
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

/// HARDEST INVARIANT #3: put_key_with_credential is atomic — a failure partway (simulated here by
/// pre-occupying the credential slot with a LIVE row before the atomic mint attempt) must leave
/// NEITHER the key nor the credential in a half-written state distinguishable from "never
/// attempted". Since redis::transaction's WATCH/EXEC either commits both writes or neither, we
/// prove this indirectly: after a forced conflict, the key must not exist at all (the whole
/// transaction body ran and failed before either SET landed, because the conflict check happens
/// before any command is queued in this implementation's slot-occupancy path)... this crate's
/// put_key_with_credential does not pre-check occupancy (new mints use a fresh id/slot), so
/// instead we prove atomicity the direct way: kill the connection mid-flight is not testable here,
/// so we assert the STRUCTURAL guarantee — both the key row and credential row appear together or
/// neither does, verified on the success path.
#[test]
fn put_key_with_credential_writes_both_or_neither() {
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

/// `delete_key`'s credential-row cleanup silently swallows a decode failure on a single
/// credential row (`if let Ok(Some(raw)) = c.get(...)`  / nested `if let Ok(cred) = ...`):
/// if a row is corrupt, its `cred:pub:*`/`cred:id:*` reverse-lookup pointers are never cleaned up,
/// yet the row itself is still deleted and the surrounding `delete_key` call still reports success
/// — silently violating the trait's own "destroy every credential row + pointers" contract while
/// claiming to have done so. This directly contradicts this same file's stated philosophy
/// elsewhere (`list_metering`: "a malformed value must not silently ... under-report"). The
/// correct behavior is to fail the whole (atomic) delete_key call loudly, matching every other
/// decode path in this crate, rather than reporting success while leaving a dangling pointer that
/// permanently blocks that public_id from ever being reused.
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
    store
        .with_conn(|conn| conn.del::<_, ()>(cred_row_key(&key_id, "sigv4", 0)))
        .unwrap();
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
    // at `SCHEMA_VERSION` (every migrate() branch — fresh, already-current, or wipe-then-mark —
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

/// Pins the `retry && is_connection_error(&e)` guard against a constant-true or `||` form. A
/// deterministic NON-connection error (`WRONGTYPE`, from issuing `LPUSH` against a string-valued
/// key) under `with_conn` (`retry: true`) must surface directly via the `"command"` error context, never
/// silently retry — a retry would issue the exact same doomed command again and report it via the
/// `"retry after reconnect"` context instead, which is what this test would see if the guard ever
/// stopped checking `is_connection_error` at all.
#[test]
fn with_conn_does_not_retry_a_non_connection_error() {
    let Some(store) = live_store() else { return };
    let id = uid("vk_wrongtype");
    let k = format!("busbar:test:wrongtype:{id}");
    store
        .with_conn(|c| c.set::<_, _, ()>(&k, "not-a-list"))
        .unwrap();

    let err = store
        .with_conn(|c| redis::cmd("LPUSH").arg(&k).arg("x").query::<i64>(c))
        .expect_err("LPUSH against a string-valued key must fail with WRONGTYPE");
    assert!(
        err.0.contains("valkey command:"),
        "a non-connection (WRONGTYPE) error must surface via the 'command' context, never \
         trigger the reconnect-and-retry path meant only for connection-level errors: {}",
        err.0
    );

    store.with_conn(|c| c.del::<_, ()>(&k)).unwrap();
}

/// Pins the retry half of the guard: a genuine connection-level error (the server killing our
/// connection out from under us, the real-world case `with_conn`'s reconnect-and-retry exists for)
/// must be transparently recovered, not surfaced to the caller.
#[test]
fn with_conn_transparently_reconnects_after_the_connection_is_dropped() {
    let Some(store) = live_store() else { return };
    let url = std::env::var("VALKEY_URL").unwrap();

    let my_id: i64 = store
        .with_conn(|c| redis::cmd("CLIENT").arg("ID").query(c))
        .unwrap();
    let mut killer = redis::Client::open(url.as_str())
        .unwrap()
        .get_connection()
        .unwrap();
    let _: () = redis::cmd("CLIENT")
        .arg("KILL")
        .arg("ID")
        .arg(my_id)
        .query(&mut killer)
        .expect("kill this store's own connection from an independent connection");

    let id = uid("vk_after_kill");
    store.put_key(&vk(&id)).expect(
        "a connection-level error (a killed connection) must trigger transparent \
         reconnect-and-retry, not surface as a caller-visible failure",
    );
    assert!(store.get_key(&id).unwrap().is_some());
}

// ── Denylist (unchanged shape, still real coverage) ─────────────────────────────────────────

#[test]
fn denylist_add_and_list_round_trips() {
    let Some(store) = live_store() else { return };
    store.add_denylist("vk_denied", "compromised").unwrap();
    let list = store.list_denylist().unwrap();
    assert!(list.contains(&"vk_denied".to_string()));
}

// ── Audit log (unchanged shape) ──────────────────────────────────────────────────────────────

/// Serialises every test that writes the SHARED, fleet-wide audit zset.
///
/// `busbar:audit` is one global sorted set keyed by seq, so unlike every other fixture in this file
/// it cannot be isolated by a `uid()` namespace. `audit_append_and_list_are_ordered_oldest_first`
/// takes `max(seq) + 1_000` and then requires that record to still be in `list_audit_tail(2)`; the
/// two sibling tests below write FIXED seqs in the 910/930-million range, so whichever of them lands
/// between that read and the tail read pushes the record out and fails an assertion about ORDERING
/// with something that is really a concurrency artifact. Pre-existing on dev — surfaced here because
/// this suite now runs more tests against one shared server, not because retention changed anything.
static AUDIT_SEQ_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Take `AUDIT_SEQ_LOCK`, ignoring poisoning, so one failing audit test does not convert the others
/// into spurious failures that bury the original.
fn audit_seq_guard() -> std::sync::MutexGuard<'static, ()> {
    AUDIT_SEQ_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[test]
fn audit_append_and_list_are_ordered_oldest_first() {
    let _serialised = audit_seq_guard();
    let Some(store) = live_store() else { return };
    // The audit zset is SHARED and persistent, and this test used to be the only writer of low
    // seqs, so it could assume it owned the whole thing. It never really did: it only looked that
    // way because `append_audit` OVERWROTE by score, so rerunning it replaced seqs 1..3 in place
    // rather than adding to them. Now that a duplicate seq is compared instead of overwritten, the
    // fixture is cleared first and the assertions filter to the seqs this test actually wrote.
    for seq in 1..=3u64 {
        let _ = store.purge_audit_seq_for_test(seq);
    }
    for seq in 1..=3u64 {
        store
            .append_audit(&AuditRecord {
                seq,
                ts: 1000 + seq,
                action: "key.mint".to_string(),
                resource: format!("key:vk_{seq}"),
                outcome: "applied".to_string(),
                principal: "admin".to_string(),
                prev_hash: String::new(),
                hash: format!("h{seq}"),
            })
            .unwrap();
    }
    let all: Vec<_> = store
        .list_audit()
        .unwrap()
        .into_iter()
        .filter(|r| (1..=3).contains(&r.seq))
        .collect();
    assert_eq!(all.len(), 3);
    assert_eq!(all[0].seq, 1, "oldest first");
    assert_eq!(all[2].seq, 3);

    // The tail is the highest seqs in the WHOLE shared zset, which this test does not own and
    // cannot pin to 2 and 3 (it only used to look that way because `append_audit` overwrote by
    // score, so nothing but this test's own low seqs ever accumulated).
    //
    // Nor can it be checked against a SEPARATELY fetched `list_audit()`: sibling tests append
    // concurrently, so a record landing between the two calls makes them disagree through no fault
    // of `list_audit_tail`. An earlier version of this assertion did exactly that and flaked about
    // one run in eight. Assert instead the two things that hold no matter who else is writing: the
    // tail is oldest-first within itself, and it comes from the newest end rather than the head.
    // WHICH END the tail comes from has to be asserted, and can be, race-free.
    //
    // Two earlier versions of this were wrong in opposite directions. `all(seq >= 3)` was FALSE
    // whenever the zset held only this test's own 1,2,3 and passed on a sibling's litter. Dropping
    // the claim entirely then left assertions that a BROKEN implementation satisfies: returning the
    // OLDEST entries still yields two records in ascending order, so `list_audit_tail` could have
    // been reading the wrong end of the log with nothing anywhere noticing.
    //
    // The race-free version: append a record whose seq is higher than anything else present, then
    // require it in the tail. Sibling writers can only push it out by writing an even HIGHER seq,
    // and this test owns the top of the range by construction, so there is nothing to race.
    let top = store
        .list_audit()
        .unwrap()
        .iter()
        .map(|r| r.seq)
        .max()
        .unwrap_or(0)
        .saturating_add(1_000);
    store
        .append_audit(&AuditRecord {
            seq: top,
            ts: 1000,
            action: "key.mint".to_string(),
            resource: "key:vk_top".to_string(),
            outcome: "applied".to_string(),
            principal: "admin".to_string(),
            prev_hash: String::new(),
            hash: format!("h{top}"),
        })
        .unwrap();
    let tail = store.list_audit_tail(2).unwrap();
    assert_eq!(tail.len(), 2);
    assert!(
        tail[0].seq < tail[1].seq,
        "the tail is oldest-first WITHIN the tail: {tail:?}"
    );
    assert!(
        tail.iter().any(|r| r.seq == top),
        "the newest record must be IN the tail -- without this, an implementation returning the \
         OLDEST entries passes: {tail:?}"
    );
    let _ = store.purge_audit_seq_for_test(top);
}

/// The v5->v6 SCHEMA_VERSION bump exists to close a real billing bug: `GovState::hydrate_budgets`
/// (busbarAI core) cannot infer "legacy pre-split row" from `billable_requests == 0 && requests >
/// 0` alone, because that is ALSO the shape of a bucket that was legitimately fully refunded
/// (`refund_bucket` decrements `billable_requests`, never `requests`), so a restart could silently
/// re-bill correctly-refunded fees. The one-time cutover therefore lives here, at a real schema-
/// version boundary (see `SCHEMA_VERSION`'s doc comment for the full rationale): any pre-v6
/// namespace is wiped on the next `connect()`, exactly like every prior bump this crate has done,
/// so `hydrate_budgets` can trust `billable_requests` unconditionally from v6 onward with no more
/// value-based guessing. `#[ignore]`d for the same reason as `wipes_the_entire_namespace_destructively`:
/// this seeds real usage data shaped like the refund-collision case, then forces a v5 marker and a
/// fresh `connect()` (destructively wiping the shared `busbar:*` namespace), so it must run alone.
#[test]
#[ignore]
fn migrate_v5_to_v6_wipes_a_namespace_with_refund_shaped_data() {
    let Some(store) = live_store() else { return };
    // Seed data shaped exactly like the ambiguous case: billable_requests == 0, requests > 0 (a
    // legitimately-refunded window, or an unmigrated legacy row).
    let bucket = "vk_migrate_v6_refund_shaped";
    let ledger = busbar_api::UsageLedger {
        requests: 3,
        billable_requests: 0,
        models: vec![],
    };
    store.put_usage(bucket, 1_700_000_000, &ledger).unwrap();
    assert_eq!(
        store.get_usage(bucket, 1_700_000_000).unwrap().requests,
        3,
        "precondition: the seeded row is really there before we force the version back"
    );

    // Force the marker back to v5, simulating a namespace that predates this bump (the real thing
    // migrate() checks: `version < SCHEMA_VERSION`).
    store
        .with_conn(|c| c.set::<_, _, ()>("busbar:schema", 5i64))
        .unwrap();

    let url = std::env::var("VALKEY_URL").unwrap();
    let store2 = ValkeyStore::connect(&url).expect("connect() must succeed and run migrate()");

    assert_eq!(
        store2.get_usage(bucket, 1_700_000_000).unwrap(),
        busbar_api::UsageLedger::default(),
        "a namespace at v5 (pre-v6) must be wiped by the v6 bump, including any refund-shaped \
         usage row - there is no real customer data to preserve at this bump (1.5.0 unreleased)"
    );
    let marker: i64 = store2.with_conn(|c| c.get("busbar:schema")).unwrap();
    assert_eq!(
        marker, 6,
        "the marker must land on the current SCHEMA_VERSION after migrate()"
    );
}

/// A destructive full-namespace wipe of a REAL Valkey, gated on the SAME `VALKEY_URL` as
/// every other live test above. `#[ignore]`d so a bare `cargo test` never touches a shared dev
/// instance by accident.
#[test]
#[ignore]
fn wipes_the_entire_namespace_destructively() {
    let Some(store) = live_store() else { return };
    store.put_key(&vk("vk_wipe_me")).unwrap();
    store
        .with_conn(|c| {
            let existing: Vec<String> = c
                .scan_match::<_, String>("busbar:*")?
                .collect::<Result<Vec<String>, _>>()?;
            let mut pipe = redis::pipe();
            pipe.atomic();
            for k in &existing {
                pipe.del(k).ignore();
            }
            pipe.query::<()>(c)
        })
        .unwrap();
    assert!(store.get_key("vk_wipe_me").unwrap().is_none());
}

/// The shared `Store` contract conformance suite (`busbar-plugin-testkit`) — the four behaviours the
/// fleet used to settle differently per backend. Kept in the testkit rather than written out here so
/// a future ruling reaches every backend at once instead of being hand-copied and drifting again.
///
/// Fixtures are namespaced per process AND per check, and cleaned first. Per-process because this
/// runs against a SHARED live Valkey that is not flushed between tests; per-check because these run
/// in parallel and the cleanup clears every id in the namespace it is given, so one shared namespace
/// would have each check deleting the others' rows mid-run.
mod conformance {
    use super::{live_store, ValkeyStore};
    use busbar_plugin_testkit::store_conformance as conf;

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
    fn append_audit_duplicate_seq_is_ok_when_identical_and_an_error_when_different() {
        let _serialised = super::audit_seq_guard();
        let seq = 910_000_000u64 + (std::process::id() as u64 % 1_000_000);
        let Some((store, _ns)) = setup("aud", seq) else {
            return;
        };
        conf::assert_append_audit_duplicate_seq(&store, seq);
        // Clean up AFTER as well as before: this writes into the fleet-wide audit zset, and leaving
        // the row behind makes every later run of the suite share a slightly dirtier instance.
        let _ = store.purge_audit_seq_for_test(seq);
    }
}

/// One undecodable credential row must not break the hydration delta for EVERY key.
///
/// `list_credentials_since` is a global scan of every credential in the store, so propagating a
/// decode failure meant a single corrupt row made the engine hydrate NO credentials at all — a
/// store-wide authentication outage caused by one bad row. Skipping it degrades that to exactly one
/// credential missing, and skipping is the fail-CLOSED direction: a row that cannot be decoded
/// cannot authenticate anyone, so omitting it denies access rather than granting it.
///
/// Found because a sibling test plants a corrupt row on purpose and this suite shares one live
/// instance, so the failure surfaced as an unrelated test flaking roughly half the time.
#[test]
fn one_corrupt_credential_row_does_not_break_the_whole_hydration_delta() {
    let Some(store) = live_store() else { return };

    // A healthy credential that MUST still come back.
    let good_key = uid("vk_delta_good");
    let good_pub = uid("AKIA_DELTA_GOOD");
    let good = cred(&good_key, &good_pub, 0);
    store
        .put_key_with_credential(&vk(&good_key), &good)
        .unwrap();

    // A corrupt one, left INDEXED so the scan actually reaches it — that is the whole point.
    let bad_key = uid("vk_delta_bad");
    let bad_pub = uid("AKIA_DELTA_BAD");
    store
        .put_key_with_credential(&vk(&bad_key), &cred(&bad_key, &bad_pub, 0))
        .unwrap();
    store
        .with_conn(|conn| conn.set::<_, _, ()>(cred_row_key(&bad_key, "sigv4", 0), "not json"))
        .unwrap();

    let delta = store
        .list_credentials_since(0)
        .expect("one undecodable row must not fail the entire delta");
    assert!(
        delta.iter().any(|c| c.meta.public_id == good_pub),
        "the healthy credential must still hydrate"
    );
    assert!(
        !delta.iter().any(|c| c.meta.public_id == bad_pub),
        "the corrupt credential must be absent, not partially decoded"
    );

    // Leave nothing behind for the other tests sharing this instance.
    store
        .with_conn(|conn| conn.del::<_, ()>(cred_row_key(&bad_key, "sigv4", 0)))
        .unwrap();
    let _ = store.purge_key_for_test(&bad_key);
    let _ = store.purge_key_for_test(&good_key);
}

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
/// `append_audit` (which WATCHes the fleet-wide audit zset), then another client dirties that key,
/// then a revocation on the original store which MUST land.
#[test]
fn a_refused_transaction_does_not_swallow_the_next_write() {
    let _serialised = audit_seq_guard();
    let Some(store) = live_store() else { return };
    let Some(other) = live_store() else { return };
    let seq = 930_000_000u64 + (std::process::id() as u64 % 1_000_000);
    let _ = store.purge_audit_seq_for_test(seq);

    let rec = AuditRecord {
        seq,
        ts: 1_700_000_000,
        action: "key.mint".to_string(),
        resource: "key:vk_watch".to_string(),
        outcome: "applied".to_string(),
        principal: "admin".to_string(),
        prev_hash: String::new(),
        hash: "h-watch".to_string(),
    };
    store.append_audit(&rec).unwrap();

    // A DIFFERENT record on the same seq: refused, and the refusal is the path that used to leak
    // the WATCH on `busbar:audit`.
    let mut forked = rec.clone();
    forked.action = "key.delete".to_string();
    store
        .append_audit(&forked)
        .expect_err("a forked record must be refused");

    // Another client writes the watched key, dirtying it.
    let mut moved = rec.clone();
    moved.seq = seq + 1;
    other.append_audit(&moved).unwrap();

    // The revocation must actually land. Before the fix this returned Ok and wrote nothing.
    let sub = format!("sub_leaked_{seq}");
    store.add_denylist(&sub, "token leaked").unwrap();
    let denied = store.list_denylist().unwrap();
    assert!(
        denied.iter().any(|d| d == &sub),
        "add_denylist reported Ok but the subject is not denied -- a revoked token would still \
         authenticate"
    );

    let _ = store.purge_audit_seq_for_test(seq);
    let _ = store.purge_audit_seq_for_test(seq + 1);
}

// ── THE DURABLE MCP TOOL-CALL LOG ────────────────────────────────────────────────────────────
//
// The property under test is not "the write returned Ok" — the trait's default `append_mcp_call`
// returns `Ok(())` and keeps nothing, so a write's return value is worthless as evidence of
// durability. The only honest way to know a deployment has durable call evidence is to READ IT
// BACK, and the only honest way to know it survives a deploy is to read it back on a NEW
// CONNECTION after the writing store is gone.

fn sample_call(principal: &str, seq: u64, ts: u64, prev_hash: &str, hash: &str) -> McpCallRecord {
    McpCallRecord {
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
    // Per-invocation-unique principal: this suite shares ONE Valkey and isolates by key namespace.
    let p = uid("vk_mcp_restart");
    store
        .append_mcp_call(&sample_call(&p, 1, 2_000_000_100, "", "h1"))
        .unwrap();
    store
        .append_mcp_call(&sample_call(&p, 2, 2_000_000_200, "h1", "h2"))
        .unwrap();
    store
        .append_mcp_call(&sample_call(&p, 3, 2_000_000_300, "h2", "h3"))
        .unwrap();
    drop(store);

    // A genuinely new connection — nothing carried over in this process.
    let Some(reopened) = live_store() else { return };
    let got = reopened.list_mcp_calls(&p).unwrap();

    assert_eq!(
        got.len(),
        3,
        "the call log must survive a reconnect; got {} records back, which is the \
         accept-and-keep-nothing behaviour this backend exists to replace",
        got.len()
    );
    assert_eq!(
        got[0].prev_hash, "",
        "seq 1 opens the chain with an empty prev_hash"
    );
    for w in got.windows(2) {
        assert_eq!(
            w[1].prev_hash, w[0].hash,
            "the per-principal chain must still link after a reconnect: seq {} carries prev_hash \
             {:?} but seq {} persisted hash {:?}",
            w[1].seq, w[1].prev_hash, w[0].seq, w[0].hash
        );
    }
    // The per-principal set is scored by seq, so the read comes back in chain order.
    assert_eq!(got.iter().map(|r| r.seq).collect::<Vec<_>>(), vec![1, 2, 3]);
    assert_eq!(got[2].tool_digest, "sha256:tool3");
    assert_eq!(got[2].request_id, "req-3");
    assert_eq!(got[1].tool, "srv_read_file");
    assert_eq!(got[1].pin_generation, 3);
}

/// The boot enumeration: a restart has to resume a chain for a principal this process has not yet
/// seen, so the store must be able to name every principal holding records.
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
    // The chain scope is the principal: a scoped read returns only its own.
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

/// Serialises the tests that call `purge_mcp_calls_before`.
///
/// Retention is GLOBAL BY TIMESTAMP, not scoped to a principal, so a per-principal `uid()` namespace
/// — which isolates every other test in this file — isolates nothing here: one test's purge deletes
/// another's rows out from under it if their ts bands overlap, and both retention tests deliberately
/// write in the same 1_000_000_1xx band because that is what their cutoffs are about. Observed, not
/// theorised: `retention_still_finds_a_principal_whose_id_contains_the_separator_characters` failed
/// roughly two runs in three, at "must actually be purged" (its row already deleted by the sibling's
/// `purge_mcp_calls_before(1_000_001_000)`) or one line earlier at the read-back — a red that looks
/// exactly like a broken retention index while retention is in fact fine.
///
/// A lock rather than disjoint ts bands: any band this test picked would still be inside SOME other
/// purge's cutoff the moment a third retention test is added, and the failure would come back
/// looking like a product bug again.
static MCP_RETENTION_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Take `MCP_RETENTION_LOCK`, ignoring poisoning: a panic in one retention test must not convert
/// every other one into a spurious failure that buries the original.
fn mcp_retention_guard() -> std::sync::MutexGuard<'static, ()> {
    MCP_RETENTION_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Retention must ACTUALLY DELETE and report a real count — a purge that returns a number it did
/// not perform is worse than one that reports nothing purged. It must also retire the principal
/// from the boot enumeration once its chain is empty.
#[test]
fn purge_mcp_calls_before_deletes_and_returns_a_real_count() {
    let _serialised = mcp_retention_guard();
    let Some(store) = live_store() else { return };
    let p = uid("vk_mcp_purge");
    // Retention is GLOBAL by ts, so this test cannot assert an exact global count against a shared
    // server; it asserts what it OWNS — its own principal's survivors and its own disappearance
    // from the enumeration — and that the reported count covers its own rows.
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
/// settles it: BYTE-IDENTICAL is the retry and succeeds; DIFFERENT is a forked or tampered log and
/// is an error. Overwriting would destroy the second case instead of reporting it.
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

    let forked = sample_call(&p, 1, 2_000_000_100, "", "DIFFERENT");
    let err = store
        .append_mcp_call(&forked)
        .expect_err("a different record at an occupied (principal, seq) is a fork and must error");
    assert!(
        !format!("{err}").contains("DIFFERENT"),
        "the error must not echo stored content back"
    );
    assert_eq!(
        store.list_mcp_calls(&p).unwrap()[0].hash,
        "h1",
        "the refused fork must not have overwritten the record already on record"
    );

    // A differing non-indexed payload under an identical digest is a fork too, not a silent accept.
    let mut tampered = sample_call(&p, 1, 2_000_000_100, "", "h1");
    tampered.tool = "srv_other_tool".to_string();
    store
        .append_mcp_call(&tampered)
        .expect_err("a payload that differs under an identical digest is a fork and must error");
}

/// A busbar key id is caller-visible and may itself contain a colon, so the retention index must
/// still split correctly when it does — a separator that can occur in the data is a parser that
/// silently mis-splits, and the failure would surface as a purge that quietly removed nothing.
#[test]
fn retention_still_finds_a_principal_whose_id_contains_the_separator_characters() {
    let _serialised = mcp_retention_guard();
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
}

// ── THE DURABLE A2A TASK STORE ────────────────────────────────────────────────────────────────
//
// A2A is async by design: a task spans turns, can sit interrupted waiting on a human, and can
// outlive the process that started it. So the property under test is never "put_task returned Ok" —
// the trait's default `put_task` returns `Ok(())` and keeps nothing, `get_task` answers `None` for
// everything and `list_tasks` answers empty, which is a backend that accepts every in-flight task
// and loses all of them on restart while reporting success. The tests that can DROP the store and
// reconnect do so; the rest assert counts those defaults could never produce.

/// Timestamps are BANDED. `purge_tasks_before` is GLOBAL by `(state, updated_at)` and cannot be
/// scoped to a task or a principal, so against the SHARED live instance a purge test's cutoff would
/// delete every other test's terminal rows if the timestamps overlapped. Everything below the top of
/// this band belongs to the purge tests; every other task test writes ABOVE it.
const TASK_PURGE_BAND_TOP: u64 = 1_000_100_000;
const TASK_LIVE_TS: u64 = 2_000_000_000;

/// The two purge tests share the low band and both assert EXACT counts, so they must not run at the
/// same time as each other. One lock held by the handful of tests that care keeps the rest of the
/// suite parallel — the same discipline the file's other unscoped-retention tests use.
static TASK_PURGE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn lock_task_purge() -> std::sync::MutexGuard<'static, ()> {
    TASK_PURGE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

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

/// The live instance is SHARED across tests, so each test owns its own task ids and clears them
/// first — the isolation-by-unique-id discipline this whole file relies on.
fn reset_tasks(store: &ValkeyStore, task_ids: &[&str]) {
    for id in task_ids {
        store
            .with_conn(|c| {
                redis::pipe()
                    .atomic()
                    .del(task_row_key(id))
                    .ignore()
                    .del(task_events_key(id))
                    .ignore()
                    .srem(TASKS_INDEX, *id)
                    .ignore()
                    .zrem(TASKS_BY_UPDATED, *id)
                    .ignore()
                    .query::<()>(c)
            })
            .expect("clear this test's own task");
    }
}

/// Own the whole low band: a previous run's leftovers would otherwise be counted by the exact-count
/// assertions the purge tests make.
fn clear_purge_band(store: &ValkeyStore) {
    let ids: Vec<String> = store
        .with_conn(|c| c.zrangebyscore(TASKS_BY_UPDATED, "-inf", format!("({TASK_PURGE_BAND_TOP}")))
        .expect("read the purge band");
    let refs = ids.iter().map(String::as_str).collect::<Vec<_>>();
    reset_tasks(store, &refs);
}

/// THE TEST THAT MATTERS. A round-trip on one live handle cannot distinguish a backend that wrote to
/// the server from one holding a HashMap behind the same trait — nor from the trait default, which
/// answers `Ok(())` to the write and keeps nothing. So this DROPS the store, closing its connection
/// entirely, then connects a genuinely new one and reads the task back off the server.
#[test]
fn an_in_flight_task_survives_dropping_the_store_and_reconnecting() {
    let Some(store) = live_store() else { return };
    let (t1, t2) = ("t_vk_restart_1", "t_vk_restart_2");
    reset_tasks(&store, &[t1, t2]);
    store
        .put_task(&sample_task(t1, "working", TASK_LIVE_TS + 200))
        .unwrap();
    // The state transition the durability actually exists for: a live task becoming an interrupted
    // one — an interrupted task waiting on a human is what a restart has to find.
    let mut interrupted = sample_task(t1, "input-required", TASK_LIVE_TS + 300);
    interrupted.artifact_cursor = 11;
    store.put_task(&interrupted).unwrap();
    store
        .put_task(&sample_task(t2, "submitted", TASK_LIVE_TS + 210))
        .unwrap();
    drop(store);

    let reopened = live_store().expect("reconnect");
    let got = reopened.get_task(t1).unwrap().expect(
        "an in-flight task must survive a restart; got None back after reconnecting, which is the \
         accept-and-keep-nothing shape of the trait default this backend exists to replace",
    );
    assert_eq!(
        got, interrupted,
        "every field must round-trip, and the row read back must be the SECOND write"
    );

    // UPSERT, not append: two writes for one task_id leave ONE row, and the enumeration names it
    // exactly once.
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
        "put_task upserts by task_id; a second write for the same id must replace, never append — \
         and list_tasks is sorted by task_id"
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

/// `list_tasks` is deliberately UNFILTERED. The boot rehydrate wants the active rows, the retention
/// sweep wants the terminal ones and the scoped listing wants one principal's; a store that
/// pre-filtered for any one of those would break the other two.
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
        "list_tasks is unfiltered: terminal rows are returned too, every row survives a reconnect, \
         and the order is deterministic (a SET has none of its own)"
    );
    reset_tasks(&reopened, &ids);
}

/// The per-task provenance chain, read back off the server after a reconnect. Per-TASK rather than
/// one global chain, so the scope of a read is one task and the links have to hold within it.
///
/// Note what this test does NOT do: it never calls `put_task`. That is deliberate. A `task.submitted`
/// event and the first `put_task` are two independent write-throughs and the contract states no
/// ordering between them, so appending an event for a task with no row yet has to WORK.
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
    // A second task's chain is independent — it must not leak into the first one's read.
    store
        .append_task_event(&sample_event(t2, 1, "task.submitted", "", "f1"))
        .unwrap();
    drop(store);

    let reopened = live_store().expect("reconnect");
    let got = reopened.list_task_events(t1).unwrap();
    assert_eq!(
        got.len(),
        3,
        "the provenance chain must survive a reconnect; got {} event(s) back, which is the \
         accept-and-keep-nothing default this backend exists to replace",
        got.len()
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
            "the per-task chain must still link after a reconnect: seq {} carries prev_hash {:?} \
             but seq {} persisted hash {:?}",
            w[1].seq, w[1].prev_hash, w[0].seq, w[0].hash
        );
    }
    // Every field round-trips, including the join key that is deliberately NOT chained.
    assert_eq!(got[2].kind, "task.interrupted");
    assert_eq!(got[2].request_id, "req-3");
    assert_eq!(got[1].context_id, format!("ctx-{t1}"));
    assert_eq!(got[1].principal, "vk_a");
    assert_eq!(got[1].agent_id, "planner");
    assert_eq!(got[1].state, "working");
    assert_eq!(got[1].ts, TASK_LIVE_TS + 2);
    // The scope of a read is one task.
    assert_eq!(reopened.list_task_events(t2).unwrap().len(), 1);
    assert!(
        reopened
            .list_task_events("t_vk_unknown_chain")
            .unwrap()
            .is_empty(),
        "a task with no events reads back empty, not an error"
    );
    reset_tasks(&reopened, &[t1, t2]);
}

/// A replayed `(task_id, seq)` UPSERTS. This is where the task-event contract genuinely DIFFERS from
/// `append_mcp_call`'s, and a backend that copied the call log's fork check would be wrong in a way
/// that looks right: the contract says a store "must upsert on that pair — the write-through is
/// idempotent on replay, and rejecting or duplicating a replayed `seq` breaks the chain the engine
/// will verify on read".
///
/// The CORRECTED case is the one that pins the implementation. On a ZSET scored by `seq`, a rewritten
/// event is a DIFFERENT member string at the SAME score, which a bare `ZADD` adds ALONGSIDE the old
/// one — two events at one seq, which is exactly the duplication the contract rules out.
#[test]
fn a_replayed_task_event_upserts_rather_than_duplicating_or_erroring() {
    let Some(store) = live_store() else { return };
    let t = "t_vk_replay_event";
    reset_tasks(&store, &[t]);

    let e = sample_event(t, 1, "task.submitted", "", "e1");
    store.append_task_event(&e).unwrap();
    store
        .append_task_event(&e)
        .expect("an identical replay must succeed, not be rejected as a fork");
    assert_eq!(
        store.list_task_events(t).unwrap().len(),
        1,
        "a replay must not duplicate the row"
    );

    let mut corrected = sample_event(t, 1, "task.submitted", "", "e1-corrected");
    corrected.state = "submitted".to_string();
    store.append_task_event(&corrected).unwrap();
    let got = store.list_task_events(t).unwrap();
    assert_eq!(got.len(), 1, "an upsert replaces; it does not append");
    assert_eq!(got[0].hash, "e1-corrected");
    assert_eq!(got[0].state, "submitted");
    reset_tasks(&store, &[t]);
}

/// Retention drops TERMINAL rows only, strictly older than the cutoff, and returns a count it
/// actually performed. An interrupted task waiting on a human is exactly the row that legitimately
/// sits still for a long time; compacting it is losing the work, not reclaiming space.
#[test]
fn purge_tasks_before_drops_only_terminal_rows_and_returns_a_real_count() {
    let Some(store) = live_store() else { return };
    let _guard = lock_task_purge();
    clear_purge_band(&store);

    let old = 1_000_000_100;
    for state in ["completed", "failed", "canceled", "rejected"] {
        store
            .put_task(&sample_task(&format!("t_vk_purge_old_{state}"), state, old))
            .unwrap();
    }
    // Old, and NOT terminal — never dropped, no matter how old. `unrecognised-state` stands in for a
    // token a NEWER engine emits that this build has never heard of: the terminal set is CLOSED, so
    // an unknown token is kept rather than swept. `Completed` (capital C) is NOT the terminal token
    // `completed` — this store compares in Rust on bytes, so it never case-folds, and the assertion
    // pins that it stays that way.
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
    // Terminal but at the cutoff exactly, and terminal but newer — both kept.
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
         actually performed rather than the size of the candidate list"
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
        "an active or interrupted task is never dropped by retention, an unrecognised state token \
         is never dropped at all (`Completed` is not `completed`), and `before` is strictly \
         less-than so a row exactly at the cutoff is kept"
    );
    assert_eq!(
        store.purge_tasks_before(1_000_000_200).unwrap(),
        0,
        "re-running the same purge removes nothing — and the retention index must not keep \
         re-offering rows the sweep already declined"
    );
    clear_purge_band(&store);
}

/// Retention has to bound the EVENT keyspace too. The trait offers no `purge_task_events_before`, so
/// if purging a task left its provenance behind, `busbar:task:events:*` would grow without any bound
/// the contract provides a way to apply. Dropping a task therefore drops the chain that belongs to
/// it — and drops nothing belonging to any other task.
#[test]
fn purging_a_task_takes_its_provenance_chain_with_it_and_no_other() {
    let Some(store) = live_store() else { return };
    let _guard = lock_task_purge();
    clear_purge_band(&store);

    let (gone, stays) = ("t_vk_cascade_gone", "t_vk_cascade_stays");
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
        "exactly the one terminal task in this band is swept, and the count must be one actually \
         performed — 0 here is the accept-and-keep-nothing default this backend exists to replace"
    );
    assert!(
        store.list_task_events(gone).unwrap().is_empty(),
        "the purged task's events go with it; otherwise the event keyspace grows unbounded, because \
         the contract offers no other way to purge it"
    );
    assert_eq!(
        store.list_task_events(stays).unwrap().len(),
        1,
        "another task's chain must be untouched by that purge"
    );
    reset_tasks(&store, &[gone, stays]);
    clear_purge_band(&store);
}

/// Two task ids differing ONLY IN CASE are two tasks, and the same for two chains. This is the class
/// of bug store-mysql shipped and then fixed on its audit chain, where a case-insensitive COLLATION
/// let `vk_alice` read `vk_Alice`'s rows. A key-value store has no collation to get wrong — a Valkey
/// key is compared as BYTES and this crate's terminal-state check is a Rust `==` on `&str` — so the
/// bug has no way in here. The test exists to keep it that way, because the consequence would be the
/// same one the SQL siblings face: the two ids collide on one row key and one task is silently lost.
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

    let a = store
        .get_task(lower)
        .unwrap()
        .expect("the lower-case id must still resolve");
    let b = store
        .get_task(upper)
        .unwrap()
        .expect("the upper-case id is a DIFFERENT task, not the same row");
    assert_eq!(a.task_id, lower, "an exact-match lookup must not case-fold");
    assert_eq!(b.task_id, upper);
    assert_eq!(
        a.state, "working",
        "the second write must not have upserted over the first: they are two tasks"
    );
    assert_eq!(b.state, "completed");

    store
        .append_task_event(&sample_event(lower, 1, "task.submitted", "", "l1"))
        .unwrap();
    store
        .append_task_event(&sample_event(upper, 1, "task.submitted", "", "u1"))
        .unwrap();
    assert_eq!(store.list_task_events(lower).unwrap()[0].hash, "l1");
    assert_eq!(
        store.list_task_events(upper).unwrap()[0].hash,
        "u1",
        "one task's chain must not answer for another's"
    );
    reset_tasks(&store, &[lower, upper]);
}

/// A task id is a protocol-supplied opaque string, COLONS INCLUDED, and this file already carries a
/// recorded hazard where credential keys join caller-supplied components on an unescaped `:` so two
/// distinct tuples render to one key. The task keyspace answers that structurally instead of by
/// convention: `row:` and `events:` are fixed, distinct segments and there is exactly ONE variable
/// component per key, so no id can make a row key render as some other task's events key. This is
/// the adversarial spelling of that — a task literally named `events:t_vk_sep_victim`.
#[test]
fn a_task_id_containing_the_key_separator_cannot_alias_another_tasks_chain() {
    let Some(store) = live_store() else { return };
    let victim = "t_vk_sep_victim";
    let attacker = "events:t_vk_sep_victim";
    reset_tasks(&store, &[victim, attacker]);

    store
        .put_task(&sample_task(victim, "working", TASK_LIVE_TS + 500))
        .unwrap();
    store
        .put_task(&sample_task(attacker, "completed", TASK_LIVE_TS + 500))
        .unwrap();
    store
        .append_task_event(&sample_event(victim, 1, "task.submitted", "", "v1"))
        .unwrap();
    store
        .append_task_event(&sample_event(attacker, 1, "task.submitted", "", "a1"))
        .unwrap();

    assert_ne!(
        task_row_key(attacker),
        task_events_key(victim),
        "a task id must not be able to render its ROW key as another task's EVENTS key"
    );
    assert_eq!(store.get_task(victim).unwrap().unwrap().state, "working");
    assert_eq!(
        store.get_task(attacker).unwrap().unwrap().state,
        "completed"
    );
    assert_eq!(store.list_task_events(victim).unwrap()[0].hash, "v1");
    assert_eq!(
        store.list_task_events(attacker).unwrap()[0].hash,
        "a1",
        "the two chains must stay separate however the ids are spelled"
    );
    reset_tasks(&store, &[victim, attacker]);
}

/// Every `u64` field of both rows round-trips at the FULL range, `u64::MAX` included. That is a
/// property of the JSON row shape, not an accident: the SQL siblings store into a signed `BIGINT` and
/// either need an unsigned column (store-mysql) or must REFUSE an out-of-range value outright
/// (store-sqlite, store-postgres), because a clamped `artifact_cursor` reads back as a different
/// number and then either replays delivered artifacts or skips undelivered ones with no error ever
/// reported. Here there is no ceiling to hit, so there is nothing to refuse.
#[test]
fn the_task_store_round_trips_the_full_u64_range() {
    let Some(store) = live_store() else { return };
    let t = "t_vk_full_range";
    reset_tasks(&store, &[t]);

    let mut task = sample_task(t, "working", u64::MAX);
    task.artifact_cursor = u64::MAX;
    task.created_at = u64::MAX;
    store
        .put_task(&task)
        .expect("a JSON row holds the whole u64 range; nothing here needs refusing");
    let got = store
        .get_task(t)
        .unwrap()
        .expect("the task must read back at all before its range can be checked");
    assert_eq!(got.artifact_cursor, u64::MAX, "the cursor must not wrap");
    assert_eq!(got.created_at, u64::MAX);
    assert_eq!(got.updated_at, u64::MAX);

    // Built by hand rather than via `sample_event`, whose `ts` is derived from `seq` and would
    // overflow before it ever reached the store.
    let mut event = sample_event(t, 1, "task.submitted", "", "e1");
    event.seq = u64::MAX;
    event.ts = u64::MAX;
    store.append_task_event(&event).unwrap();
    let events = store.list_task_events(t).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].seq, u64::MAX);
    assert_eq!(events[0].ts, u64::MAX);
    reset_tasks(&store, &[t]);
}
