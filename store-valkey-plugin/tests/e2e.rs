// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! End-to-end coverage of the `busbar-store-valkey-plugin` cdylib loaded over the REAL loader
//! `load_store` seam against a REAL, live Valkey (not a mock, not an in-process fake). This is the
//! exact seam the engine sees when `store: { module: valkey }` is configured: a `Box<dyn Store>`
//! indistinguishable from a compiled-in store, backed by `dlopen`'d code running the C ABI.
//!
//! Unlike a file-backed store (see busbarAI's sqlite plugin end-to-end test, which reopens the
//! same file), Valkey has no "close and reopen the same file" persistence signal to check. Instead
//! this proves persistence the way that is actually meaningful for a SHARED backend:
//!
//!   1. `dlopen` the plugin, write a key + usage ledger through it over the C ABI, then DROP it
//!      (which runs `busbar_close`, closing the plugin's own Valkey connection).
//!   2. Independently connect to the SAME Valkey instance via the plain `busbar-store-valkey`
//!      library crate — a code path that never touches the cdylib, the C ABI, or the loader at
//!      all — and confirm the data is genuinely present.
//!
//! If the plugin's `put_key`/`put_usage` over the ABI were silent no-ops (or wrote to some
//! in-process cache rather than Valkey), step 2 would come back empty even though a same-session
//! read-after-write through the plugin looked fine.
//!
//! Gated on `VALKEY_URL` (a docker `valkey:7` GitHub Actions service container in this repo's CI —
//! see `.github/workflows/ci.yml`). Skips cleanly when unset locally; under `CI` a missing
//! `VALKEY_URL` is a HARD FAILURE, never a silent skip, so the only over-the-ABI coverage of the
//! durable Valkey store path cannot quietly vanish.

use busbar_api::{McpCallRecord, ModelTokens, Store, TierTokens, UsageLedger, VirtualKey};
use busbar_plugin_loader::{load_store, plugin_library_filename};
use busbar_store_valkey::ValkeyStore;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Fixed ed25519 signing secret (64 hex = 32 bytes) for this e2e test. 1.5.1 requires an
/// explicit signing key to mint virtual keys; busbar no longer auto-generates one.
const TEST_SIGNING_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Locate the cdylib THIS `cargo test` invocation just built — never a leftover artifact.
///
/// This looks ONLY in `target/<profile>/deps/`, never `target/<profile>/`, and that distinction is
/// the whole point of this function.
///
/// `cargo` emits the lib target's cdylib into `deps/` as part of the very build graph that produces
/// this test binary (this package's lib unit is compiled with BOTH declared crate-types — see
/// `[lib] crate-type = ["cdylib", "rlib"]` in Cargo.toml), so `deps/libbusbar_store_valkey_plugin.dylib` is by construction up to
/// date with the source tree under test. Cargo only *uplifts* a copy to `target/<profile>/` for
/// `cargo build`, NEVER for `cargo test`. A lookup in `target/<profile>/` therefore reads an
/// artifact that nothing in this test's dependency graph refreshes: whatever some earlier `cargo
/// build` left there, from any commit — or nothing at all.
///
/// Both outcomes of that are lies about durability, and the second is the dangerous one:
///   * NOTHING there  -> the old code `return`ed with a "skip:" line and reported GREEN. That is how
///     `cargo test` can pass with ZERO over-the-ABI coverage of the durable store path.
///   * STALE artifact -> a cdylib built before an ABI change answers every write `Ok(())` and every
///     read empty, which is BYTE-FOR-BYTE the signature of the unrelayed-seam defect this file
///     exists to catch (that defect was real: `DynStore`'s `impl Store` overrode 24 methods, none of
///     them the task/call-log methods, so `put_task` took the accept-and-keep-nothing trait
///     default). RED on a stale artifact is indistinguishable from RED on the real bug — and an
///     artifact NEWER than a regression reports GREEN while the shipped ABI is broken. Proven, not
///     theorised: with a regressed plugin in the tree and a good cdylib in `target/debug/`, the old
///     lookup passed and this one fails.
///
/// Same hazard, and the same reasoning, as the engine's `crates/busbar/Cargo.toml` dev-dependency on
/// `busbar-store-example-plugin`: keep the cdylib in the build graph so no test can judge a stale
/// one. Here the plugin's lib IS this package, so that graph edge already exists — what was missing
/// was reading the artifact that edge actually produces.
///
/// Panics rather than skipping: a missing cdylib under `cargo test` means the build graph changed
/// shape, and the only honest report of that is a failure, not a silent pass.
/// The newest mtime across every workspace crate's `src/` — "how fresh must a cdylib be to be the
/// one this source tree describes".
///
/// Deliberately ONLY `src/**/*.rs` of each workspace member: editing a `tests/` file or a
/// `[dev-dependencies]` line recompiles the test binary but NOT the lib, so including those would
/// fail a perfectly current cdylib.
fn newest_source_mtime() -> std::time::SystemTime {
    fn walk(dir: &std::path::Path, newest: &mut std::time::SystemTime) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, newest);
            } else if p.extension().is_some_and(|x| x == "rs") {
                if let Ok(m) = e.metadata().and_then(|m| m.modified()) {
                    if m > *newest {
                        *newest = m;
                    }
                }
            }
        }
    }
    let ws_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the plugin crate always sits under the workspace root");
    let mut newest = std::time::SystemTime::UNIX_EPOCH;
    for e in std::fs::read_dir(ws_root).into_iter().flatten().flatten() {
        let src = e.path().join("src");
        if src.is_dir() {
            walk(&src, &mut newest);
        }
    }
    newest
}

fn plugin_path() -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe"); // .../target/<profile>/deps/<test>-<hash>
    let deps_dir = exe.parent().expect("the test binary always lives in deps/");
    let name = plugin_library_filename("busbar_store_valkey_plugin");
    let fresh = deps_dir.join(&name);
    assert!(
        fresh.exists(),
        "the store-valkey-plugin cdylib is not at {}, where cargo emits it for the same build that produced \
         this test binary. Refusing to fall back to target/<profile>/ (an artifact only `cargo \
         build` refreshes) or to skip: judging a stale cdylib is exactly how an unrelayed plugin \
         ABI reads as green.",
        fresh.display()
    );
    // FRESHNESS, ASSERTED — not assumed. Under `cargo test` the artifact above is rebuilt by the
    // same graph that built this binary (proven: delete it, re-run, cargo re-emits it). But this
    // test binary can also be executed DIRECTLY out of `deps/`, where nothing rebuilds anything,
    // and a stale cdylib there produces empty reads — indistinguishable from the unrelayed-ABI
    // defect. So compare it against the sources and fail with a message that says STALE ARTIFACT,
    // explicitly NOT a durability verdict.
    let built = std::fs::metadata(&fresh)
        .and_then(|m| m.modified())
        .expect("cdylib mtime");
    let newest_src = newest_source_mtime();
    assert!(
        built >= newest_src,
        "STALE ARTIFACT — THIS IS NOT A DURABILITY FAILURE. {} predates this workspace's sources, \
         so it cannot answer for the code in the tree; a pre-change cdylib returns empty for every \
         read, which reads exactly like an unrelayed plugin ABI. Run `cargo build -p {}` (or just \
         `cargo test`, which rebuilds it) and re-run.",
        fresh.display(),
        "busbar-store-valkey-plugin"
    );
    fresh
}

/// The live `VALKEY_URL`, mirroring `busbar-store-valkey`'s own `live_store()` gating discipline
/// (see busbarAI's `crates/store-valkey/src/lib.rs`): skip cleanly when unset LOCALLY, but a
/// missing `VALKEY_URL` under `CI` is a hard failure, not a silent skip — CI provisions the
/// `valkey:7` service container and must set this env var (see `.github/workflows/ci.yml`).
fn valkey_url() -> Option<String> {
    match std::env::var("VALKEY_URL") {
        Ok(url) => Some(url),
        Err(_) if std::env::var_os("CI").is_some() => {
            panic!(
                "VALKEY_URL is unset under CI: the valkey:7 service container must provision it \
                 (see .github/workflows/ci.yml). Refusing to silently skip the only over-the-ABI \
                 coverage of the durable valkey store path."
            );
        }
        Err(_) => {
            eprintln!("skip: set VALKEY_URL (a live Valkey) to run the valkey plugin e2e test");
            None
        }
    }
}

fn key(id: &str) -> VirtualKey {
    VirtualKey {
        id: id.into(),
        generation_hash: "binding:vk_e2e_dlopen:g0".into(),
        name: "e2e-dlopen-key".into(),
        allowed_scopes: Some(vec![busbar_api::ScopeRef::pool("p")]),
        enabled: true,
        created_at: 42,
        group: Some("infra".into()),
        labels: std::collections::BTreeMap::from([("env".into(), "e2e".into())]),
        expires_at: None,
        deleted_at: None,
        revision: 0,
    }
}

fn ledger() -> UsageLedger {
    UsageLedger {
        requests: 5,
        billable_requests: 5,
        models: vec![ModelTokens {
            model: "gpt-5".into(),
            tokens: TierTokens {
                input: 20,
                output: 8,
                cache_read: 0,
                cache_write: 0,
            },
        }],
    }
}

/// END-TO-END PERSISTENCE: dlopen the real valkey plugin against a REAL, live Valkey, write a key +
/// usage through it over the C ABI, drop the plugin (closing its connection via `RawPlugin`'s
/// `Drop`, which runs `busbar_close`), then verify the data actually landed in Valkey two
/// independent ways:
///   1. re-dlopen the SAME cdylib against the SAME `VALKEY_URL` — a fresh `busbar_open`/fresh
///      `DynStore` instance, proving the plugin itself doesn't just hold an in-memory cache
///      across calls.
///   2. connect to the SAME Valkey with `busbar_store_valkey::ValkeyStore::connect` directly — a
///      totally independent code path that never goes through the cdylib, the C ABI, or the
///      loader at all — proving the plugin actually wrote real Valkey keys, not just satisfying
///      its own in-process round-trip.
///
/// This is the proof that `store: valkey` operations over the ABI aren't silently no-ops.
#[test]
fn load_and_exercise_valkey_plugin_persists_to_real_valkey_across_reopen() {
    let path = plugin_path();
    let Some(url) = valkey_url() else {
        return;
    };
    let cfg = serde_json::json!({ "url": url }).to_string();

    // Isolate from any prior run against a persistent (non-CI) Valkey instance.
    //
    // A FRESH ID PER RUN, not a fixed one plus a `delete_key`: `delete_key` TOMBSTONES the row (it
    // is a soft delete by contract — see `Store::delete_key`), so `get_key` still answers with it
    // afterwards. Against a re-used Valkey that made this test pass even when the plugin's
    // `put_key` wrote NOTHING at all: every read below was satisfied by the previous run's row.
    // Proven, not theorised — a `put_key` stubbed to `Ok(())` passed this test against a re-used
    // instance and failed it against a flushed one. A per-run id makes every read here answerable
    // only by THIS run's writes.
    let direct = ValkeyStore::connect(&url).expect("connect directly to seed/clean up");
    let vk_id = format!(
        "vk_e2e_dlopen_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let vk_id = vk_id.as_str();

    let vk = key(vk_id);

    {
        let store = load_store(&path, &cfg).expect("load valkey plugin against a real Valkey");
        store.put_key(&vk).expect("put_key over the ABI");
        store
            .put_usage(vk_id, 200, &ledger())
            .expect("put_usage over the ABI");
        assert_eq!(
            store
                .get_key(vk_id)
                .expect("get_key over the ABI")
                .expect("present in the same session")
                .id,
            vk_id
        );
        // `store` (and the `RawPlugin` it wraps) drops here, running `busbar_close` and dropping
        // the plugin's own `ValkeyStore`/connection — the data must be durably in Valkey after
        // this, not just an in-process cache inside the plugin.
    }

    // (1) Re-dlopen the SAME cdylib against the SAME `VALKEY_URL`: a fresh plugin instance, fresh
    // `busbar_open`, fresh connection inside the plugin — proves the ABI round-trip isn't relying
    // on the first instance still being alive.
    let reopened = load_store(&path, &cfg).expect("re-load valkey plugin against the same URL");
    let got = reopened
        .get_key(vk_id)
        .expect("get_key after reopen")
        .expect("the key must survive a full plugin close + reopen against the same Valkey");
    assert_eq!(got.group.as_deref(), Some("infra"));
    assert_eq!(got.labels.get("env").map(String::as_str), Some("e2e"));
    let usage = reopened
        .get_usage(vk_id, 200)
        .expect("get_usage after reopen");
    assert_eq!(usage.requests, 5, "usage ledger must survive the reopen");
    let t = usage
        .tokens_for("gpt-5")
        .expect("model row survives reopen");
    assert_eq!((t.input, t.output), (20, 8));
    drop(reopened);

    // (2) Read back through a TOTALLY INDEPENDENT connection — the plain `ValkeyStore`, used
    // directly, never touching the cdylib, the C ABI, or `busbar-plugin-loader` at all. If the
    // plugin's `put_key`/`put_usage` over the ABI were silent no-ops (or wrote somewhere other
    // than the configured Valkey), this independent reader would come back empty even though the
    // reopen-via-plugin check above passed.
    let direct_key = Store::get_key(&direct, vk_id)
        .expect("get_key via the direct connection")
        .expect("the key must be physically present in Valkey, bypassing the plugin");
    assert_eq!(direct_key.name, "e2e-dlopen-key");
    assert_eq!(
        direct_key.allowed_scopes,
        Some(vec![busbar_api::ScopeRef::pool("p")])
    );
    let direct_usage =
        Store::get_usage(&direct, vk_id, 200).expect("get_usage via the direct connection");
    assert_eq!(
        direct_usage.requests, 5,
        "usage must be physically present in Valkey, not just cached in-process by the plugin"
    );

    let _ = Store::delete_key(&direct, vk_id);
}

/// END-TO-END FAILURE: an `open()` config that cannot produce a usable store — malformed JSON, a
/// config missing `url`, and a `url` Valkey itself refuses to parse — surfaces back across the C
/// ABI as a clean `Err`, never a panic or a silently-succeeded load. Needs no live Valkey: every
/// case here fails before (or instead of) actually connecting.
#[test]
fn load_and_exercise_valkey_plugin_bad_config_fails_over_abi() {
    let path = plugin_path();

    let err = load_store(&path, "{ not json")
        .err()
        .expect("malformed config JSON must fail to load, not silently succeed");
    assert!(
        err.contains("invalid valkey plugin config"),
        "the plugin's own error message should survive the ABI crossing intact: {err}"
    );

    let err = load_store(&path, "{}")
        .err()
        .expect("a config missing url must fail to load");
    assert!(
        err.contains("requires a \"url\""),
        "expected the plugin's own missing-url message, got: {err}"
    );

    let err = load_store(&path, r#"{"url":"not-a-valkey-url"}"#)
        .err()
        .expect("an unparseable valkey url must fail to load, not silently succeed");
    assert!(
        err.contains("valkey plugin: failed to connect"),
        "expected the plugin's own connect-failure context, got: {err}"
    );
}

// ── THE REAL "prod ready" bar: install over the real admin HTTP API, exercise it, verify ──────
//
// Everything above loads the plugin via `busbar_plugin_loader::load_store()` — a direct Rust
// function call no real end user ever makes. `admin_api_installs_the_valkey_plugin_and_writes_land_in_real_valkey`
// instead drives an ACTUAL `busbar` binary the way an operator (or CI's own INSTALL-AND-SERVE
// step, see busbarAI's `.github/workflows/plugin-ci.yml`) does:
//
//   1. Pack the built cdylib into a real tarball with the real `busbar-plugin-pack` tool.
//   2. Boot a real `busbar` process (admin listener up, no valkey plugin loaded yet).
//   3. POST the base64 tarball to `POST /api/v1/admin/plugins` — the real runtime-install path
//      (`crates/busbar/src/admin/v1/json/handlers.rs::install_plugin`) — and confirm 201.
//   4. `PUT /api/v1/admin/config/settings` to set `store.module` to the freshly-installed plugin,
//      persisted; `POST /api/v1/admin/restart` to apply it (store-module changes are documented
//      restart-to-apply, never a hot swap) — then actually restart the process, since busbar's own
//      restart deliberately does not self-respawn (a supervisor's job, which this test plays).
//   5. Confirm the restarted process picked up the plugin as its active store module.
//   6. Do REAL WORK through the running instance: `POST /api/v1/admin/keys` with
//      `issue_aws_credential: true` — the one and only admin-HTTP path that mints BOTH a virtual
//      key AND a credential in one call (there is no separate `/keys/{id}/credentials` endpoint;
//      confirmed by reading `crates/busbar/src/admin/v1/json/mod.rs`'s full route table).
//   7. INDEPENDENTLY verify both rows physically landed in the real Valkey two ways: (a) the typed
//      `ValkeyStore`/`Store` trait — a code path that never touches the plugin, the C ABI, the
//      loader, or the HTTP admin surface at all; and (b) a raw `redis::Client` GET of the exact
//      key bytes (`busbar:key:<id>`) — proof independent even of `busbar-store-valkey`'s own
//      encode/decode path, the strongest verification available short of `valkey-cli` itself.
//
// This is the first test of this shape in either sibling plugin repo (store-postgres's own
// `load_and_exercise_postgres_plugin_via_file_drop` uses the FILE-DROP mechanism, not the admin
// API — see that file's own module doc) — there is no existing pattern to mirror beyond CI's own
// bash INSTALL-AND-SERVE script, which this ports into a real, CI-gated Rust test.

/// RAII guard for a spawned child process: kills and reaps it on drop, including when a panic
/// unwinds partway through the test.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The sibling busbarAI checkout's root — same convention this repo's Cargo.toml path deps and
/// store-postgres's own `e2e.rs` already use.
fn busbarai_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../busbarAI")
        .canonicalize()
        .expect("sibling busbarAI checkout must exist (see Cargo.toml path deps)")
}

/// Build (once, cached by cargo) the real `busbar` and `busbar-plugin-pack` binaries from the
/// sibling busbarAI checkout — never a fixture, never a stub.
fn build_real_binaries() -> (PathBuf, PathBuf) {
    let root = busbarai_root();
    let status = Command::new("cargo")
        .args([
            "build",
            "--release",
            "-p",
            "busbar",
            "-p",
            "busbar-plugin-pack",
        ])
        .current_dir(&root)
        .status()
        .expect("run cargo build for busbar + busbar-plugin-pack");
    assert!(
        status.success(),
        "building the real busbar + busbar-plugin-pack binaries must succeed"
    );
    (
        root.join("target/release/busbar"),
        root.join("target/release/busbar-plugin-pack"),
    )
}

/// A free-at-the-moment localhost port (bind-then-drop; a TOCTOU race is possible in principle
/// but is the standard, accepted pattern for test port allocation and hasn't been a problem for
/// the sibling repos' own equivalents).
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind an ephemeral port")
        .local_addr()
        .expect("read local addr")
        .port()
}

fn poll_admin_up(admin: &str, token: &str, client: &reqwest::blocking::Client) -> bool {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if let Ok(resp) = client
            .get(format!("{admin}/plugins?type=store"))
            .bearer_auth(token)
            .send()
        {
            if resp.status().is_success() {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

/// Point at a DIFFERENT logical Valkey database (index 15, the conventional "spare" db a lot of
/// Valkey tooling reserves for tests) than [`valkey_url`]'s own `/0`, which every OTHER test in this
/// file/crate shares. A real `busbar` boot (unlike a plain `Store` call) HYDRATES every existing
/// virtual key at startup and validates its `group` against the config's own `groups:` block —
/// this test's config intentionally defines none, so ANY leftover key from another test sharing
/// db 0 (e.g. the dlopen persistence test above, which mints a key with `group: "infra"`) makes
/// boot fail outright with an unrelated "group does not exist" error. Same server, same
/// `VALKEY_URL` host/port, just an isolated `SELECT`ed database — proven the strongest fix short of
/// a second Valkey container (confirmed necessary: this test failed with exactly that pollution
/// before being pointed at its own db).
fn admin_test_valkey_url(base: &str) -> String {
    let without_path = match base.rfind('/') {
        Some(i) if base[..i].contains("://") => &base[..i],
        _ => base,
    };
    format!("{without_path}/15")
}

#[test]
fn admin_api_installs_the_valkey_plugin_and_writes_land_in_real_valkey() {
    let Some(base_url) = valkey_url() else { return };
    let url = admin_test_valkey_url(&base_url);
    let so_path = plugin_path();

    // Isolate from any prior run against a persistent (non-CI) Valkey instance.
    let direct = ValkeyStore::connect(&url).expect("connect directly to seed/clean up");

    let (busbar_bin, pack_bin) = build_real_binaries();

    let work = std::env::temp_dir().join(format!(
        "busbar-valkey-admin-e2e-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let plugins_dir = work.join("plugins");
    std::fs::create_dir_all(&plugins_dir).unwrap();

    // Pack the real cdylib into a real signed-shape tarball, exactly as CI's own SIGNOFF step
    // does — unsigned locally, same fallback CI's release jobs use without BUSBAR_SIGN_KEY.
    let tarball = work.join("store-valkey.tar.gz");
    let status = Command::new(&pack_bin)
        .args([
            "pack",
            "--lib",
            so_path.to_str().unwrap(),
            "--name",
            "busbar-store-valkey-plugin",
            "--alias",
            "valkey",
            "--kind",
            "store",
            "--version",
            "0.0.0-e2e",
            "--publisher",
            "busbar",
            "--description",
            "e2e admin-api install proof",
            "--license",
            "Apache-2.0",
            "--out",
            tarball.to_str().unwrap(),
            "--allow-unsigned",
        ])
        .status()
        .expect("run busbar-plugin-pack");
    assert!(status.success(), "packing the plugin must succeed");

    let admin_token = format!("e2e-admin-{}-{}", std::process::id(), free_port());
    let port = free_port();
    // The admin plane ALWAYS runs on its own listener, separate from `listen` (defaults to
    // loopback 127.0.0.1:8081 — see `crates/busbar/src/main.rs`'s `admin_listen`/
    // `build_split_routers_with_limits` doc comments: "production always serves admin on its OWN
    // listener ... admin and data never share a listener at runtime"). Must be configured
    // explicitly to an independently-allocated free port, both to avoid colliding with anything
    // else already bound to 8081 and so concurrent test runs never collide with each other.
    let admin_port = free_port();
    let admin = format!("http://127.0.0.1:{admin_port}/api/v1/admin");

    let providers = work.join("providers.yaml");
    let config = work.join("config.yaml");
    let overlay = work.join("overlay.json");
    std::fs::write(
        &providers,
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n  api_key_env: MOCK_KEY\n",
    )
    .unwrap();
    // No `store:` block at first boot — proves the plugin isn't already active some other way;
    // the whole point of this test is the RUNTIME install path. `admin_auth` grants Full scope
    // via a static bearer token (mirrors CI's INSTALL-AND-SERVE step exactly).
    //
    // 1.5.3 GRAMMAR: the operator token provider is DEFINED ONCE under the top-level
    // `identity-providers:` named map and REFERENCED BY BARE NAME from `auth.admin_auth:`. The old
    // INLINE form (`admin_auth: [ { admin-tokens: { token: … } } ]`) is a retired 1.x marker as of
    // 1.5.3: `config::migrate::detect_legacy_markers` flags any map-shaped `auth.chain:`/
    // `auth.admin_auth:` entry, and a non-empty marker list is a FAIL-CLOSED boot refusal in
    // `main.rs` (`legacy_config_error`) — not a warning. Writing the inline form here would kill
    // BOTH boots below at startup with a config error, long before the admin listener ever binds.
    // Shape confirmed against core's `IdentityProviderCfg` / `resolve_auth` in
    // `crates/busbar/src/config/mod.rs`, and byte-for-byte against `busbar --migrate-config`'s own
    // output for the previous inline form.
    std::fs::write(
        &config,
        format!(
            "listen: \"127.0.0.1:{port}\"\n\
             admin_listen: \"127.0.0.1:{admin_port}\"\n\
             identity-providers:\n  admin-tokens:\n    module: admin-tokens\n    token: {{ env: E2E_ADMIN_TOKEN }}\n\
             auth:\n  chain: [keys]\n  signing_key: {{ env: BUSBAR_SIGNING_KEY }}\n  admin_auth: [admin-tokens]\n\
             plugins:\n  enabled: true\n  dir: {}\n  trust:\n    allow_unsigned: true\n\
             providers:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\n\
             models:\n  test-model:\n    provider: mock\n",
            plugins_dir.display()
        ),
    )
    .unwrap();

    let client = reqwest::blocking::Client::new();

    // Both boots' stdout+stderr are captured to real files (never left as an unread pipe, which
    // risks the child stalling if it ever writes enough to fill the OS pipe buffer) so a failure
    // can quote the actual boot log rather than a bare timeout.
    let spawn = |label: &str| {
        let log = std::fs::File::create(work.join(format!("busbar-{label}.log")))
            .expect("create boot log file");
        let mut cmd = Command::new(&busbar_bin);
        cmd.env("BUSBAR_CONFIG", &config)
            .env("BUSBAR_PROVIDERS", &providers)
            .env("E2E_ADMIN_TOKEN", &admin_token)
            .env("BUSBAR_SIGNING_KEY", TEST_SIGNING_KEY)
            .env("BUSBAR_STATE_FILE", "")
            .env("BUSBAR_CONFIG_OVERLAY", &overlay)
            .stdout(Stdio::from(log.try_clone().expect("clone log fd")))
            .stderr(Stdio::from(log));
        cmd.spawn().expect("spawn a real busbar boot")
    };
    let boot_log = |label: &str| {
        std::fs::read_to_string(work.join(format!("busbar-{label}.log"))).unwrap_or_default()
    };

    // Boot #1: no valkey plugin loaded yet.
    let mut guard = ChildGuard(spawn("1"));
    assert!(
        poll_admin_up(&admin, &admin_token, &client),
        "busbar (boot #1) must come up with the admin listener responsive; log:\n{}",
        boot_log("1")
    );

    // THE REAL INSTALL: POST the signed tarball's base64 bytes to /api/v1/admin/plugins.
    let tarball_bytes = std::fs::read(&tarball).unwrap();
    use base64::Engine as _;
    let tarball_b64 = base64::engine::general_purpose::STANDARD.encode(&tarball_bytes);
    let install_resp = client
        .post(format!("{admin}/plugins"))
        .bearer_auth(&admin_token)
        .json(&serde_json::json!({
            "file": "busbar-store-valkey-plugin-0.0.0-e2e.tar.gz",
            "tarball_b64": tarball_b64,
        }))
        .send()
        .expect("POST /api/v1/admin/plugins");
    let install_status = install_resp.status();
    let install_body: serde_json::Value = install_resp.json().unwrap_or(serde_json::Value::Null);
    assert_eq!(
        install_status.as_u16(),
        201,
        "expected 201 from POST /api/v1/admin/plugins, got {install_status}: {install_body}"
    );
    assert_eq!(
        install_body.get("name").and_then(|v| v.as_str()),
        Some("busbar-store-valkey-plugin"),
        "install response must name the installed plugin: {install_body}"
    );

    // Activate it as the store module, persisted, then restart to apply (store-module changes
    // are documented restart-to-apply, never a hot swap — confirmed by reading
    // crates/busbar/src/admin/mod.rs / docs/admin-api.md).
    let settings_resp = client
        .put(format!("{admin}/config/settings"))
        .bearer_auth(&admin_token)
        .json(&serde_json::json!({
            "store": { "module": "busbar-store-valkey-plugin", "settings": { "url": url } },
            "persist": true,
        }))
        .send()
        .expect("PUT /api/v1/admin/config/settings");
    assert!(
        settings_resp.status().is_success(),
        "PUT /api/v1/admin/config/settings must succeed: {}",
        settings_resp.status()
    );

    let _ = client
        .post(format!("{admin}/restart"))
        .bearer_auth(&admin_token)
        .send();

    // busbar's restart deliberately does not self-respawn — drains and exits, expecting a
    // supervisor to relaunch it. Play that role: wait for the real exit, then boot #2.
    let exit_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(Some(_)) = guard.0.try_wait() {
            break;
        }
        if Instant::now() >= exit_deadline {
            let _ = guard.0.kill();
            let _ = guard.0.wait();
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Boot #2: same config, now with the persisted overlay naming the valkey plugin as the store
    // module — the real dlopen + Store::connect/migrate path executes here, before the listener
    // ever answers a request.
    let guard2 = ChildGuard(spawn("2"));
    assert!(
        poll_admin_up(&admin, &admin_token, &client),
        "busbar (boot #2, with the valkey plugin persisted as store.module) must come back up; \
         log:\n{}",
        boot_log("2")
    );
    assert!(
        !boot_log("2").contains("does not match any plugin"),
        "the valkey plugin persisted as store.module must resolve to the installed plugin, not \
         be rejected as unmatched: {}",
        boot_log("2")
    );

    let list_resp = client
        .get(format!("{admin}/plugins?type=store"))
        .bearer_auth(&admin_token)
        .send()
        .expect("GET /api/v1/admin/plugins?type=store");
    let list_body = list_resp.text().unwrap_or_default();
    assert!(
        list_body.contains("busbar-store-valkey-plugin"),
        "the restarted instance must list the installed valkey plugin: {list_body}"
    );

    // REAL WORK: mint a virtual key AND a credential in one admin call (the only admin-HTTP path
    // that writes a CredentialSecret row — there is no separate /keys/{id}/credentials endpoint).
    let mint_resp = client
        .post(format!("{admin}/keys"))
        .bearer_auth(&admin_token)
        .json(&serde_json::json!({
            "name": "e2e-admin-install-verify",
            "issue_aws_credential": true,
        }))
        .send()
        .expect("POST /api/v1/admin/keys");
    let mint_status = mint_resp.status();
    let mint_body: serde_json::Value = mint_resp.json().expect("mint response must be JSON");
    assert_eq!(
        mint_status.as_u16(),
        201,
        "expected 201 from POST /api/v1/admin/keys, got {mint_status}: {mint_body}"
    );
    let key_id = mint_body
        .get("id")
        .and_then(|v| v.as_str())
        .expect("mint response must carry an id")
        .to_string();
    assert!(
        key_id.starts_with("vk_"),
        "unexpected key id shape: {key_id}"
    );
    let access_key_id = mint_body
        .get("aws_access_key_id")
        .and_then(|v| v.as_str())
        .expect("issue_aws_credential:true must return aws_access_key_id")
        .to_string();

    // Confirm the API's own view sees it (same process, same request path).
    let get_resp = client
        .get(format!("{admin}/keys/{key_id}"))
        .bearer_auth(&admin_token)
        .send()
        .expect("GET /api/v1/admin/keys/{id}");
    assert!(
        get_resp.status().is_success(),
        "GET /api/v1/admin/keys/{{id}} must find the just-minted key: {}",
        get_resp.status()
    );

    // Now stop the real busbar process before independent verification, so there is no
    // possibility of racing its own connection/cache.
    drop(guard2);
    drop(guard);

    // INDEPENDENT VERIFICATION #1: the typed Store trait, via the plain busbar-store-valkey crate
    // — a code path that never touches the plugin cdylib, the C ABI, the loader, or the admin
    // HTTP surface at all.
    let vk = Store::get_key(&direct, &key_id)
        .expect("get_key via the direct connection")
        .expect("the virtual key minted through the real admin API must be physically in Valkey");
    assert_eq!(vk.id, key_id);
    assert_eq!(vk.name, "e2e-admin-install-verify");
    let creds = Store::list_credentials(&direct, &key_id)
        .expect("list_credentials via the direct connection");
    let cred = creds
        .iter()
        .find(|c| c.public_id == access_key_id)
        .expect("the sigv4 credential minted alongside the key must be physically in Valkey");
    assert_eq!(cred.kind, "sigv4");
    assert_eq!(cred.key_id, key_id);

    // INDEPENDENT VERIFICATION #2: a RAW redis::Client GET of the exact row bytes — proof
    // independent even of busbar-store-valkey's own encode/decode path.
    let mut raw = redis::Client::open(url.as_str())
        .and_then(|c| c.get_connection())
        .expect("raw valkey connection for the strongest independent check");
    let raw_key_row: Option<String> =
        redis::Commands::get(&mut raw, format!("busbar:key:{key_id}")).unwrap();
    let raw_key_row = raw_key_row.expect("busbar:key:<id> must be physically present in Valkey");
    assert!(
        raw_key_row.contains(&key_id) && raw_key_row.contains("e2e-admin-install-verify"),
        "raw Valkey row must contain the minted key's own id and name: {raw_key_row}"
    );

    let _ = Store::delete_key(&direct, &key_id);
    let _ = std::fs::remove_dir_all(&work);
}

/// THE DURABILITY PROOF FOR THE FOUR MCP CALL-LOG METHODS, OVER THE REAL PLUGIN PATH.
///
/// This repo ships `feat/durable-mcp-call-log` — `append_mcp_call`/`list_mcp_calls`/
/// `list_mcp_call_principals`/`purge_mcp_calls_before` against a real Valkey. Every existing test of
/// those four calls `ValkeyStore` DIRECTLY, in-process, and NONE of them can see the failure that
/// actually matters in production, because in production this backend is ONLY ever reached as a
/// plugin: conformance boots the in-process RAM store, so the plugin seam is the only path a real
/// deployment takes and was, until this test, the one path with zero coverage of these methods.
///
/// `busbar_api::Store` DEFAULTS all ten task/call-log methods to accept-and-keep-nothing. A plugin
/// seam that does not RELAY them silently substitutes those defaults: every `append_mcp_call`
/// returns `Ok`, every `list_mcp_calls` answers empty, and a deployment loses every tool-call record
/// while reporting success. That is not hypothetical — the ABI once carried four store methods while
/// the trait carried ten, so exactly this happened. A unit test passing while the ABI drops every
/// write is the precise shape this test exists to make impossible.
///
/// So it goes through `busbar_plugin_loader::load_store`: a REAL `dlopen` of the built cdylib, the
/// real C ABI, the real `DynStore`. It writes AT ARITY > 1 (three chained records for one principal
/// and one for a second), DROPS the handle — which runs `busbar_close` and UNLOADS the library, so
/// nothing this process still holds can answer the reads — then `dlopen`s AGAIN over the same file
/// and reads everything back. A restart is what proves durability; a single-row same-session round
/// trip would not distinguish a relayed method from a lucky trait default, and a multi-row one
/// across an unload/reload cannot be faked by either.
///
/// A third leg reads the same rows through the plain `ValkeyStore`, never touching the cdylib, the
/// C ABI or the loader — so a plugin that answered from its own in-process cache still fails here.
#[test]
fn mcp_call_log_survives_an_unload_and_reload_over_the_real_plugin_abi() {
    let path = plugin_path();
    let Some(url) = valkey_url() else {
        return;
    };
    let cfg = serde_json::json!({ "url": url }).to_string();

    // Start from an EMPTY call log. `list_mcp_call_principals` and `purge_mcp_calls_before` are
    // GLOBAL, not per-principal, so against a re-used Valkey a leftover chain from an earlier run
    // would make both of their exact assertions below meaningless. `purge_mcp_calls_before(MAX)` is
    // the store's own contract-level wipe (it also drops each emptied principal from the
    // enumeration — see `ValkeyStore::purge_mcp_calls_before`), so this needs no key-pattern
    // guesswork. No other test in this file touches the `busbar:mcp:*` namespace.
    let direct = ValkeyStore::connect(&url).expect("connect directly to clean up and verify");
    Store::purge_mcp_calls_before(&direct, u64::MAX).expect("wipe the call log before this run");

    // Per-run principal ids, for the same reason the key test uses one: a read that only THIS run's
    // writes can answer. Two of them, because one principal's chain leaking into another's is a real
    // defect class (this repo fixed a case-folding instance of it) and a single-principal test is
    // blind to it.
    let stamp = format!(
        "{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let p_main = format!("vk_abi_main_{stamp}");
    let p_other = format!("vk_abi_other_{stamp}");

    let call = |principal: &str, seq: u64, prev: &str, hash: &str| McpCallRecord {
        principal: principal.to_string(),
        seq,
        ts: 2_000 + seq,
        server: "srv".to_string(),
        tool: "srv_read_file".to_string(),
        outcome: "dispatched".to_string(),
        reason: String::new(),
        tool_digest: format!("sha256:tool{seq}"),
        pin_generation: 3,
        request_id: format!("req-{seq}"),
        prev_hash: prev.to_string(),
        hash: hash.to_string(),
    };

    {
        // BOOT 1 — a real dlopen of the cdylib; every call below crosses the C ABI.
        let store = load_store(&path, &cfg).expect("the valkey plugin must load over the real ABI");
        for (seq, prev, hash) in [(1_u64, "", "h1"), (2, "h1", "h2"), (3, "h2", "h3")] {
            store
                .append_mcp_call(&call(&p_main, seq, prev, hash))
                .expect("append_mcp_call over the ABI");
        }
        store
            .append_mcp_call(&call(&p_other, 1, "", "o1"))
            .expect("append_mcp_call over the ABI");
        // Dropping the boxed store drops the loader's `Library` handle: `busbar_close` runs and the
        // dylib is UNLOADED. Nothing this process still holds can be answering the reads below.
        drop(store);
    }

    // BOOT 2 — a second, independent dlopen over the same file, a fresh `busbar_open`, a fresh
    // connection inside the plugin.
    let store =
        load_store(&path, &cfg).expect("the valkey plugin must load again over the real ABI");

    let calls = store.list_mcp_calls(&p_main).expect("list_mcp_calls");
    assert_eq!(
        calls.iter().map(|c| c.seq).collect::<Vec<_>>(),
        vec![1, 2, 3],
        "the per-principal call chain must survive the unload/reload over the plugin ABI in chain \
         order; got {} record(s) back, which is the accept-and-keep-nothing shape of the trait \
         default an unrelayed seam substitutes",
        calls.len()
    );
    for w in calls.windows(2) {
        assert_eq!(
            w[1].prev_hash, w[0].hash,
            "the chain must still link after the reload: seq {} carries prev_hash {:?} but seq {} \
             persisted hash {:?}",
            w[1].seq, w[1].prev_hash, w[0].seq, w[0].hash
        );
    }
    // Every non-indexed field rides the `body` blob; a relay that dropped it would still satisfy a
    // seq-only check.
    assert_eq!(calls[2].tool_digest, "sha256:tool3");
    assert_eq!(calls[2].request_id, "req-3");
    assert_eq!(calls[2].tool, "srv_read_file");
    assert_eq!(calls[2].outcome, "dispatched");
    assert_eq!(calls[1].pin_generation, 3);
    assert_eq!(
        store
            .list_mcp_calls(&p_other)
            .expect("list_mcp_calls")
            .len(),
        1,
        "one principal's chain must not carry another's records"
    );

    let principals = store
        .list_mcp_call_principals()
        .expect("list_mcp_call_principals");
    assert_eq!(
        principals,
        vec![p_main.clone(), p_other.clone()],
        "the boot enumeration must name every principal holding records, exactly once each, sorted"
    );

    // Retention crosses the ABI too, COUNT AND ALL — checked for the number it ACTUALLY removed,
    // because a relay that dropped the return value would read as 0 and look like a no-op sweep.
    assert_eq!(
        store.purge_mcp_calls_before(2_002).expect("purge"),
        2,
        "both records at ts 2001 go (one per principal); the one sitting exactly at the cutoff stays"
    );
    assert_eq!(
        store.list_mcp_calls(&p_main).expect("list_mcp_calls").len(),
        2
    );
    assert!(store
        .list_mcp_calls(&p_other)
        .expect("list_mcp_calls")
        .is_empty());
    assert_eq!(
        store
            .list_mcp_call_principals()
            .expect("list_mcp_call_principals"),
        vec![p_main.clone()],
        "a principal whose chain the sweep emptied must leave the enumeration, or a boot keeps \
         resuming a chain with nothing in it"
    );
    drop(store);

    // LEG 3 — read the surviving rows through the plain `ValkeyStore`, a code path that never
    // touches the cdylib, the C ABI or the loader. A plugin answering the reads above out of its
    // own in-process state (rather than Valkey) passes both boots and fails here.
    let direct_calls =
        Store::list_mcp_calls(&direct, &p_main).expect("list_mcp_calls via the direct connection");
    assert_eq!(
        direct_calls.iter().map(|c| c.seq).collect::<Vec<_>>(),
        vec![2, 3],
        "the records must be physically present in Valkey, not just cached in-process by the plugin"
    );
    assert_eq!(direct_calls[1].hash, "h3");

    Store::purge_mcp_calls_before(&direct, u64::MAX).expect("clean up this run's records");
}

/// THE DURABILITY PROOF FOR THE SIX A2A TASK-STORE METHODS, OVER THE REAL PLUGIN PATH.
///
/// The sibling proof above does this for the MCP call log; this one exists because the task methods
/// are a SEPARATE half of the same defaulted seam and half the fleet used to be missing them.
/// `busbar_api::Store` defaults `put_task` to `Ok(())`, `get_task` to `Ok(None)` and `list_tasks` to
/// `Ok(vec![])`: a backend that does not override them ACCEPTS EVERY WRITE AND REPORTS SUCCESS while
/// keeping nothing. An operator would find "task state survives a restart" false on their own
/// deployment, which is the worst place to discover it.
///
/// The conformance suite cannot see this: it boots the in-process RAM store, where those defaults
/// ARE the honest answer and nothing looks wrong. The plugin seam is the ONLY path a real Valkey
/// deployment takes, so it is the only path worth proving on. A unit test against `ValkeyStore`
/// proves the function compiles and works in-process; it does not prove the plugin path reaches it.
///
/// So: a REAL `dlopen` of the built cdylib, the real C ABI, the real `DynStore`. Write at arity > 1
/// (two tasks, one of them UPSERTED a second time, plus two independent provenance chains), DROP the
/// handle — `busbar_close` runs and the library is unloaded, so nothing this process still holds can
/// answer the reads — then `dlopen` again and read everything back. A third leg reads the same rows
/// through the plain `ValkeyStore`, never touching the cdylib, so a plugin answering out of its own
/// in-process cache still fails.
#[test]
fn task_store_survives_an_unload_and_reload_over_the_real_plugin_abi() {
    use busbar_api::{TaskEventRow, TaskRow};

    let path = plugin_path();
    let Some(url) = valkey_url() else {
        return;
    };
    let cfg = serde_json::json!({ "url": url }).to_string();

    // Start from an EMPTY task keyspace. `purge_tasks_before` is GLOBAL and terminal-only, and the
    // count it returns is asserted exactly below, so a leftover terminal row from an earlier run
    // would make that assertion meaningless. `purge_tasks_before(MAX)` is the store's own
    // contract-level wipe of exactly that population, so this needs no key-pattern guesswork.
    let direct = ValkeyStore::connect(&url).expect("connect directly to clean up and verify");
    Store::purge_tasks_before(&direct, u64::MAX).expect("wipe terminal tasks before this run");

    let stamp = format!(
        "{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    // Per-run ids, so every read below can only be answered by THIS run's writes.
    let t_live = format!("task_abi_live_{stamp}");
    let t_done = format!("task_abi_done_{stamp}");

    // A timestamp BAND well above any plausible leftover, so the purge cutoff picked below names
    // this run's rows and nothing else.
    const BASE_TS: u64 = 4_000_000_000;

    let task = |id: &str, state: &str, updated_at: u64, cursor: u64| TaskRow {
        task_id: id.to_string(),
        context_id: format!("ctx-{id}"),
        principal: "vk_task_abi".to_string(),
        direction: "inbound".to_string(),
        state: state.to_string(),
        agent_id: "agent-7".to_string(),
        artifact_cursor: cursor,
        push_callback: "https://callback.example/hook".to_string(),
        created_at: BASE_TS,
        updated_at,
    };
    let event = |id: &str, seq: u64, kind: &str, prev: &str, hash: &str| TaskEventRow {
        task_id: id.to_string(),
        seq,
        ts: BASE_TS + seq,
        kind: kind.to_string(),
        context_id: format!("ctx-{id}"),
        principal: "vk_task_abi".to_string(),
        agent_id: "agent-7".to_string(),
        state: "working".to_string(),
        request_id: format!("req-{seq}"),
        prev_hash: prev.to_string(),
        hash: hash.to_string(),
    };

    {
        // BOOT 1 — a real dlopen of the cdylib; every call below crosses the C ABI.
        let store = load_store(&path, &cfg).expect("the valkey plugin must load over the real ABI");
        store
            .put_task(&task(&t_live, "working", BASE_TS + 100, 3))
            .expect("put_task over the ABI");
        // The SECOND write for the same id: the engine writes through on every state transition, so
        // this must REPLACE the row, never append a second one. An interrupted task waiting on a
        // human is exactly what a restart has to find.
        store
            .put_task(&task(&t_live, "input-required", BASE_TS + 200, 9))
            .expect("put_task over the ABI");
        store
            .put_task(&task(&t_done, "completed", BASE_TS + 50, 1))
            .expect("put_task over the ABI");
        // Two INDEPENDENT chains: per-task provenance that leaked across tasks is a real defect
        // class, and a single-chain test is blind to it.
        for (seq, prev, hash) in [(1_u64, "", "h1"), (2, "h1", "h2"), (3, "h2", "h3")] {
            store
                .append_task_event(&event(&t_live, seq, "task.working", prev, hash))
                .expect("append_task_event over the ABI");
        }
        store
            .append_task_event(&event(&t_done, 1, "task.completed", "", "d1"))
            .expect("append_task_event over the ABI");
        // Dropping the boxed store drops the loader's `Library` handle: `busbar_close` runs and the
        // dylib is UNLOADED. Nothing this process still holds can be answering the reads below.
        drop(store);
    }

    // BOOT 2 — a second, independent dlopen over the same file, a fresh `busbar_open`, a fresh
    // connection inside the plugin.
    let store =
        load_store(&path, &cfg).expect("the valkey plugin must load again over the real ABI");

    let got = store.get_task(&t_live).expect("get_task").expect(
        "an in-flight task must survive the unload/reload over the plugin ABI; got None back, \
         which is exactly the accept-and-keep-nothing shape of the trait default an unimplemented \
         backend (or an unrelayed seam) substitutes",
    );
    assert_eq!(
        got,
        task(&t_live, "input-required", BASE_TS + 200, 9),
        "every field must round-trip, and the row read back must be the SECOND write: put_task \
         upserts by task_id"
    );
    assert!(
        store
            .get_task(&format!("task_abi_nonexistent_{stamp}"))
            .expect("get_task on an unknown id is not an error")
            .is_none(),
        "an unknown task id reads back None, not an error"
    );

    let listed = store.list_tasks().expect("list_tasks");
    let mine = listed
        .iter()
        .filter(|t| t.task_id == t_live || t.task_id == t_done)
        .map(|t| t.task_id.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        mine,
        vec![t_done.clone(), t_live.clone()],
        "list_tasks is UNFILTERED — the terminal row is returned too — and the upserted task \
         appears exactly ONCE; got {} of this run's rows back",
        mine.len()
    );

    let events = store.list_task_events(&t_live).expect("list_task_events");
    assert_eq!(
        events.iter().map(|e| e.seq).collect::<Vec<_>>(),
        vec![1, 2, 3],
        "the per-task provenance chain must survive the reload, oldest-first by seq; got {} \
         event(s), the empty shape of the trait default",
        events.len()
    );
    for w in events.windows(2) {
        assert_eq!(
            w[1].prev_hash, w[0].hash,
            "the chain must still link after the reload: seq {} carries prev_hash {:?} but seq {} \
             persisted hash {:?}",
            w[1].seq, w[1].prev_hash, w[0].seq, w[0].hash
        );
    }
    assert_eq!(events[2].kind, "task.working");
    assert_eq!(events[2].request_id, "req-3");
    assert_eq!(
        store
            .list_task_events(&t_done)
            .expect("list_task_events")
            .len(),
        1,
        "one task's chain must not carry another's events"
    );

    // The task-event contract UPSERTS on (task_id, seq) — the engine's write-through is idempotent
    // on replay, and rejecting or duplicating a replayed seq breaks the chain it will verify.
    let mut replayed = event(&t_live, 3, "task.working", "h2", "h3");
    replayed.state = "input-required".to_string();
    store
        .append_task_event(&replayed)
        .expect("a replayed (task_id, seq) upserts rather than erroring");
    let events = store.list_task_events(&t_live).expect("list_task_events");
    assert_eq!(
        events.len(),
        3,
        "a replayed seq must not append a 4th event"
    );
    assert_eq!(events[2].state, "input-required");

    // Retention crosses the ABI too, COUNT AND ALL — checked for the number it ACTUALLY removed,
    // because a relay that dropped the return value would read as 0 and look like a no-op sweep.
    assert_eq!(
        store
            .purge_tasks_before(BASE_TS + 100)
            .expect("purge_tasks_before"),
        1,
        "only the TERMINAL row older than the cutoff goes; the interrupted task is never swept no \
         matter how old, because an interrupt waiting on a human is exactly the row that \
         legitimately sits still"
    );
    assert!(
        store.get_task(&t_done).expect("get_task").is_none(),
        "the purged task is gone"
    );
    assert!(
        store.get_task(&t_live).expect("get_task").is_some(),
        "a non-terminal task is never purged"
    );
    assert!(
        store
            .list_task_events(&t_done)
            .expect("list_task_events")
            .is_empty(),
        "the purge is the ONLY retention method the contract gives task_events, so a swept task's \
         chain must go with it or it is unbounded forever"
    );
    drop(store);

    // LEG 3 — read the surviving row through the plain `ValkeyStore`, a code path that never
    // touches the cdylib, the C ABI or the loader. A plugin answering the reads above out of its own
    // in-process state (rather than Valkey) passes both boots and fails here.
    let direct_task = Store::get_task(&direct, &t_live)
        .expect("get_task via the direct connection")
        .expect("the task must be physically present in Valkey, not just cached in-process");
    assert_eq!(direct_task.artifact_cursor, 9);
    assert_eq!(direct_task.state, "input-required");
    assert_eq!(
        Store::list_task_events(&direct, &t_live)
            .expect("list_task_events via the direct connection")
            .len(),
        3
    );

    // Clean up this run's rows through the contract: mark the survivor terminal, then sweep.
    Store::put_task(&direct, &task(&t_live, "canceled", BASE_TS + 200, 9))
        .expect("clean up this run's task");
    Store::purge_tasks_before(&direct, u64::MAX).expect("clean up this run's rows");
}

/// THE DURABILITY PROOF FOR THE FOUR TRUST-STATE METHODS, OVER THE REAL PLUGIN PATH.
///
/// Same reasoning as the task-store test above, and a sharper cost. `busbar_api::Store` defaults
/// `put_mcp_demotion`/`list_mcp_demotions`/`clear_mcp_demotion` to accept-and-keep-nothing and
/// `redeem_ask_state` to `Ok(true)` — "yes, this call is the first redemption" — so a seam that does
/// not RELAY them substitutes two security failures, both silent and both green:
///
///   * a demotion is written, reported successful and DISCARDED, so a restart hands a quarantined
///     upstream the operator's approval back; and
///   * every redeemer of one single-use approval is told it is the first, so a confirm-once tool an
///     operator gated because it moves money executes once per node and once per restart.
///
/// A Valkey deployment reaches this backend ONLY over the plugin seam, and it is the backend a
/// FLEET reaches for first — so the second-node case below is the ordinary deployment, not an
/// exotic one. A real `dlopen`, the real C ABI, the real `DynStore`; two simultaneous loads are the
/// fleet, a drop and a reload is the restart, and a third leg reads through the plain `ValkeyStore`
/// so a plugin answering out of its own in-process state still fails.
///
/// PANICS rather than skipping when no Valkey is configured. This is the only over-the-ABI coverage
/// of two properties whose unimplemented form is silently green, and a case that can skip is a case
/// that will skip on the day it matters.
#[test]
fn trust_state_survives_an_unload_and_reload_over_the_real_plugin_abi() {
    use busbar_api::McpDemotionRow;

    let path = plugin_path();
    let url = std::env::var("VALKEY_URL").unwrap_or_else(|_| {
        panic!(
            "VALKEY_URL is unset, and this case must not skip: it is the only over-the-ABI proof \
             that a demotion and a spent approval survive a restart on this backend, and both fail \
             SILENTLY when unrelayed — the trait defaults answer Ok(()) to a demotion and `true` to \
             every redemption"
        )
    });
    let cfg = serde_json::json!({ "url": url }).to_string();

    let direct = ValkeyStore::connect(&url).expect("connect directly to clean up and verify");

    let stamp = format!(
        "{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    // Per-run ids, so every read below can only be answered by THIS run's writes, and two runs
    // against one shared Valkey cannot redeem each other's approvals.
    let srv_demoted = format!("srv_abi_demoted_{stamp}");
    let srv_cleared = format!("srv_abi_cleared_{stamp}");
    let nonce_restart = format!("nonce_abi_restart_{stamp}");
    let nonce_fleet = format!("nonce_abi_fleet_{stamp}");
    let nonce_fresh = format!("nonce_abi_fresh_{stamp}");
    const NOW: u64 = 4_000_000_000;

    let demotion = |server: &str, reason: &str, at: u64| McpDemotionRow {
        server: server.to_string(),
        reason: reason.to_string(),
        recorded_at: at,
    };

    {
        // BOOT 1 — a real dlopen of the cdylib; every call below crosses the C ABI.
        let store = load_store(&path, &cfg).expect("the valkey plugin must load over the real ABI");
        store
            .put_mcp_demotion(&demotion(&srv_demoted, "tool-drift", NOW))
            .expect("put_mcp_demotion");
        // The UPSERT path crosses the ABI too: a second demotion of one upstream replaces the record.
        store
            .put_mcp_demotion(&demotion(&srv_demoted, "digest-mismatch", NOW + 10))
            .expect("put_mcp_demotion");
        store
            .put_mcp_demotion(&demotion(&srv_cleared, "tool-drift", NOW + 20))
            .expect("put_mcp_demotion");
        store
            .clear_mcp_demotion(&srv_cleared)
            .expect("a later agreeing observation clears the quarantine");
        assert!(
            store
                .redeem_ask_state(&nonce_restart, NOW + 900, NOW)
                .expect("redeem_ask_state"),
            "the FIRST redemption must be answered `true`, or nothing below is about single use"
        );
        // Dropping the boxed store runs `busbar_close` and unloads the library, so nothing this
        // process still holds can be answering the reads below.
        drop(store);
    }

    // BOOT 2 — a second, independent dlopen against the same Valkey.
    let store =
        load_store(&path, &cfg).expect("the valkey plugin must load again over the real ABI");

    let mine = store
        .list_mcp_demotions()
        .expect("list_mcp_demotions")
        .into_iter()
        .filter(|r| r.server == srv_demoted || r.server == srv_cleared)
        .collect::<Vec<_>>();
    assert_eq!(
        mine,
        vec![demotion(&srv_demoted, "digest-mismatch", NOW + 10)],
        "the boot read must put the recorded quarantine back in force — at its LATEST reason, and \
         without the one a later agreeing observation cleared. An empty answer here is the \
         accept-and-keep-nothing trait default an unrelayed seam substitutes, and it means a \
         restart hands a demoted upstream the operator's approval back"
    );

    assert!(
        !store
            .redeem_ask_state(&nonce_restart, NOW + 900, NOW + 1)
            .expect("redeem_ask_state"),
        "a restart handed a spent approval back over the plugin ABI. The approval has not lapsed — \
         outliving a restart is the point of it — so the only thing that changed is that the \
         process which recorded the redemption is gone"
    );

    // THE FLEET, which on this backend is the ordinary deployment: a second, simultaneous dlopen
    // against the same Valkey. It shares the signing key, so it shares the seal, and every check but
    // this one passes on both.
    let node_b = load_store(&path, &cfg).expect("a second node loads the same plugin");
    assert!(store
        .redeem_ask_state(&nonce_fleet, NOW + 900, NOW + 2)
        .expect("redeem_ask_state"));
    assert!(
        !node_b
            .redeem_ask_state(&nonce_fleet, NOW + 900, NOW + 3)
            .expect("redeem_ask_state"),
        "a second node redeemed an approval the first already spent, which is one operator \
         confirmation executing once per node"
    );
    // THE CONTROL: a ledger that refused everything would satisfy both cases above and would have
    // deleted the feature.
    assert!(
        node_b
            .redeem_ask_state(&nonce_fresh, NOW + 900, NOW + 4)
            .expect("redeem_ask_state"),
        "a freshly minted approval is not the one that was spent; refusing it would make the shared \
         ledger a blanket refusal of every confirmation after the first"
    );
    drop(store);
    drop(node_b);

    // LEG 3 — the same state through the plain `ValkeyStore`, a code path that never touches the
    // cdylib, the C ABI or the loader. A plugin answering the reads above out of its own in-process
    // state passes both boots and fails here.
    assert!(
        Store::list_mcp_demotions(&direct)
            .expect("list_mcp_demotions via the direct connection")
            .iter()
            .any(|r| r.server == srv_demoted && r.reason == "digest-mismatch"),
        "the demotion must be physically present in Valkey, not merely cached in the plugin"
    );
    assert!(
        !Store::redeem_ask_state(&direct, &nonce_restart, NOW + 900, NOW + 5)
            .expect("redeem_ask_state via the direct connection"),
        "the spent-approval entry must be physically present in Valkey: a direct connection that \
         never loaded the plugin has to see the redemption the plugin recorded"
    );

    // Clean up this run's demotion through the contract. The ledger entries are left to their own
    // TTL on purpose — the contract gives them no delete, and that TTL is exactly the bound this
    // backend's ledger is supposed to have.
    Store::clear_mcp_demotion(&direct, &srv_demoted).expect("clean up this run's demotion");
}
