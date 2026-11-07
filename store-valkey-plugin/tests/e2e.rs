// SPDX-License-Identifier: Apache-2.0
//! Dropped/linked primitive persistence and actual binary administration acceptance.
mod support;
use busbar_contract::persistence::PersistenceBackend;
use busbar_contract::{persistence as p, Secret};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use support::*;
const TEST_SIGNING_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
fn plugin_path() -> PathBuf {
    cdylib()
}

#[test]
fn load_and_exercise_valkey_plugin_persists_to_real_valkey_across_reopen() {
    let Some(base) = valkey_url() else { return };
    let url = db_url(&base, 14);
    let _db = database::Database::take(&url);
    block(async {
        let backend = open(true, &url).await;
        bootstrap(&backend).await;
        let info = backend.info();
        let address = p::Address {
            namespace: [9; 16],
            key: b"real-cdylib".to_vec(),
        };
        let candidate = prepared(
            info,
            2,
            vec![],
            vec![p::Mutation::Put {
                address: address.clone(),
                value: Secret::new(vec![0, 255, 7]),
            }],
        );
        assert!(matches!(
            backend.commit(candidate.clone()).await.unwrap(),
            p::Decision::Applied(_)
        ));
        drop(backend);
        let linked = open(false, &url).await;
        assert_eq!(linked.info(), info);
        assert!(
            matches!(linked.read(Arc::new(p::Read{dataset:info.dataset,addresses:vec![address.clone()],time:None})).await.unwrap(),p::ReadResult::Values{values,..} if values==vec![Some(Secret::new(vec![0,255,7]))])
        );
        assert!(matches!(
            linked.commit(candidate).await.unwrap(),
            p::Decision::Applied(_)
        ));
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let physical = format!(
            "busbar:v4:{{{}}}:r:{}:{}",
            hex(&info.dataset.0),
            hex(&address.namespace),
            hex(&address.key)
        );
        let bytes: Vec<u8> = redis::cmd("GET")
            .arg(physical)
            .query(&mut _db.connection().unwrap())
            .unwrap();
        assert_eq!(bytes, vec![1, 0, 255, 7]);
    });
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The busbar checkout the real binaries are built from: `BUSBAR_CHECKOUT` when set (CI checks
/// GetBusbar/busbar out at the `.busbar-ref` rev and points this at it), otherwise a sibling
/// `../busbar` beside this repo. It must be the rev `.busbar-ref` pins — the rev this plugin's
/// contract comes from. A missing checkout is a FAILURE, never a skip: this is the only proof that
/// a real busbar installs and boots on this store.
fn busbar_root() -> PathBuf {
    let root = match std::env::var_os("BUSBAR_CHECKOUT") {
        Some(p) => PathBuf::from(p),
        None => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../busbar"),
    };
    root.canonicalize().unwrap_or_else(|e| {
        panic!(
            "no busbar checkout at {} ({e}): set BUSBAR_CHECKOUT to a checkout of \
             GetBusbar/busbar at the .busbar-ref rev",
            root.display()
        )
    })
}

/// Build (once, cached by cargo) the real `busbar` binary and the real `busbar-plugin-pack` tool
/// from that checkout — never a fixture, never a stub. The pack tool is a feature-gated bin of
/// `busbar-plugin-loader` in busbar 1.6.0. busbar is the `test-harness` build, the one that takes a
/// test's first-party key ([`HARNESS_FIRST_PARTY_KEY_ENV`]); no release build reads it.
fn build_real_binaries() -> (PathBuf, PathBuf) {
    let root = busbar_root();
    let toolchain =
        std::env::var_os("RUSTUP_TOOLCHAIN").unwrap_or_else(|| std::ffi::OsString::from("1.98"));
    let target = match std::env::var_os("CARGO_TARGET_DIR") {
        Some(dir) => root.join(dir),
        None => root.join("target"),
    };
    for args in [
        &[
            "build",
            "--locked",
            "--release",
            "--manifest-path",
            "dist/default/Cargo.toml",
            "--features",
            "test-harness",
            "--bin",
            "busbar",
        ][..],
        &[
            "build",
            "--locked",
            "--release",
            "-p",
            "busbar-plugin-loader",
            "--features",
            "pack",
            "--bin",
            "busbar-plugin-pack",
        ][..],
    ] {
        let status = Command::new("cargo")
            .env("RUSTUP_TOOLCHAIN", &toolchain)
            .args(args)
            .arg("--target-dir")
            .arg(&target)
            .current_dir(&root)
            .status()
            .expect("run cargo build for busbar + busbar-plugin-pack");
        assert!(
            status.success(),
            "building the real busbar + busbar-plugin-pack binaries must succeed ({args:?})"
        );
    }
    (
        target.join("release/busbar"),
        target.join("release/busbar-plugin-pack"),
    )
}

/// A placeholder provider credential: busbar 1.6.0 refuses to boot on an unresolvable provider
/// credential (BUSBAR-9007), and the mock provider is never dialled.
const SECRET_PLACEHOLDER: &str = "0000000000000000000000000000000000000000000000000000000000000001";

/// THE FIRST-PARTY KEY THIS TEST SIGNS THE PLUGIN WITH (its ed25519 secret, 64 hex): the store's
/// `tcp` need sits in the `operator-infrastructure` egress class, which the host grants to a
/// FIRST-PARTY plugin only (`BUSBAR-1.6.0.md` §5), and no test holds the embedded release key's
/// private half. So the pack tool signs with this key (`BUSBAR_SIGN_KEY`), and the child busbar, a
/// `test-harness` build, takes its public half as its first-party key through the harness seam
/// ([`HARNESS_FIRST_PARTY_KEY_ENV`], ARCHITECT ruling busbar #700), as busbar's own end-to-end
/// battery admits a first-party plugin it signed.
const HARNESS_SIGN_KEY: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

/// The variable a `test-harness` busbar reads its first-party key from (busbar's
/// `root::boot::HARNESS_FIRST_PARTY_KEY_ENV`).
const HARNESS_FIRST_PARTY_KEY_ENV: &str = "BUSBAR_TEST_HARNESS_FIRST_PARTY_KEY";

/// The public half of [`HARNESS_SIGN_KEY`], 64 hex: what the child trusts as first-party.
fn harness_public_key() -> String {
    let mut secret = [0_u8; 32];
    for (i, b) in secret.iter_mut().enumerate() {
        *b = u8::from_str_radix(&HARNESS_SIGN_KEY[2 * i..2 * i + 2], 16).expect("hex");
    }
    busbar_plugin_loader::sign::SigningKey::from_bytes(&secret)
        .verifying_key()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
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
    valkey_url_in_db(base, 15)
}

/// `base` pointed at database `db`.
fn valkey_url_in_db(base: &str, db: u32) -> String {
    let (base, query) = base
        .split_once('?')
        .map_or((base, ""), |(base, q)| (base, q));
    let without_path = match base.rfind('/') {
        Some(i) if base[..i].contains("://") => &base[..i],
        _ => base,
    };
    if query.is_empty() {
        format!("{without_path}/{db}")
    } else {
        format!("{without_path}/{db}?{query}")
    }
}

#[test]
fn admin_api_installs_the_valkey_plugin_and_writes_land_in_real_valkey() {
    const INSTALLED_ARCHIVE: &str = "busbar-store-valkey-plugin-0.0.0-e2e.tar.gz";
    let Some(base_url) = valkey_url() else { return };
    let url = admin_test_valkey_url(&base_url);
    let _database = database::Database::take(&url);
    let so_path = plugin_path();

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

    let tarball = work.join("store-valkey.tar.gz");
    let status = Command::new(&pack_bin)
        .args([
            "pack",
            "--lib",
            so_path.to_str().unwrap(),
            "--name",
            "busbar-store-valkey",
            "--alias",
            "valkey",
            "--kind",
            "store",
            "--version",
            env!("CARGO_PKG_VERSION"),
            "--publisher",
            "busbar",
            "--description",
            "e2e admin-api install proof",
            "--license",
            "Apache-2.0",
            "--out",
            tarball.to_str().unwrap(),
        ])
        .env("BUSBAR_SIGN_KEY", HARNESS_SIGN_KEY)
        .status()
        .expect("run busbar-plugin-pack");
    assert!(status.success(), "packing the plugin must succeed");

    let admin_token = format!("e2e-admin-{}-{}", std::process::id(), free_port());
    let port = free_port();

    let admin_port = loop {
        let candidate = free_port();
        if candidate != port {
            break candidate;
        }
    };
    let admin = format!("http://127.0.0.1:{admin_port}/api/v1/admin");

    let providers = work.join("providers.yaml");
    let config = work.join("config.yaml");
    let overlay = work.join("overlay.json");
    std::fs::write(
        &providers,
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n",
    )
    .unwrap();

    let config_text = |bootstrap_pin: Option<&str>, store_url: Option<&str>| {
        let fetch = bootstrap_pin
            .map(|sha256| {
                format!(
                    "  fetch:\n    - url: \"https://plugins.invalid/{INSTALLED_ARCHIVE}\"\n      sha256: \"{sha256}\"\n"
                )
            })
            .unwrap_or_default();
        let store = store_url.map_or_else(
            || "store:\n  module: memory\n".to_string(),
            |url| {
                format!(
                    "store:\n  module: busbar-store-valkey\n  settings:\n    url: {}\n    input_budget: 67108864\n    durability: ephemeral\n",
                    serde_json::to_string(url).expect("the Store URL encodes as a YAML string")
                )
            },
        );
        format!(
            "listen: \"127.0.0.1:{port}\"\n\
             admin_listen: \"127.0.0.1:{admin_port}\"\n\
             identity-providers:\n  admin-tokens:\n    module: admin-tokens\n    token: {{ env: E2E_ADMIN_TOKEN }}\n\
             auth:\n  chain: [keys]\n  signing_key: {{ env: BUSBAR_SIGNING_KEY }}\n  admin_auth: [admin-tokens]\n\
             credentials:\n  at_rest:\n    key: {{ env: BUSBAR_SIGNING_KEY }}\n\
             plugins:\n  enabled: true\n  dir: {}\n{fetch}  trust:\n    allow_unsigned: true\n\
             providers:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\n\
             models:\n  test-model:\n    provider: mock\n\
             {store}",
            plugins_dir.display()
        )
    };
    std::fs::write(&config, config_text(None, None)).unwrap();

    let client = reqwest::blocking::Client::new();

    let spawn = |label: &str| {
        let log = std::fs::File::create(work.join(format!("busbar-{label}.log")))
            .expect("create boot log file");
        let mut cmd = Command::new(&busbar_bin);
        cmd.env("BUSBAR_CONFIG", &config)
            .env("BUSBAR_PROVIDERS", &providers)
            .env("E2E_ADMIN_TOKEN", &admin_token)
            .env("BUSBAR_SIGNING_KEY", TEST_SIGNING_KEY)
            .env("MOCK_KEY", SECRET_PLACEHOLDER)
            .env("BUSBAR_STATE_FILE", "")
            .env("BUSBAR_CONFIG_OVERLAY", &overlay)
            .env(HARNESS_FIRST_PARTY_KEY_ENV, harness_public_key())
            .stdout(Stdio::from(log.try_clone().expect("clone log fd")))
            .stderr(Stdio::from(log));
        cmd.spawn().expect("spawn a real busbar boot")
    };
    let boot_log = |label: &str| {
        std::fs::read_to_string(work.join(format!("busbar-{label}.log"))).unwrap_or_default()
    };

    let mut guard = ChildGuard(spawn("1"));
    assert!(
        poll_admin_up(&admin, &admin_token, &client),
        "busbar (boot #1) must come up with the admin listener responsive; log:\n{}",
        boot_log("1")
    );

    let tarball_bytes = std::fs::read(&tarball).unwrap();
    use base64::Engine as _;
    let tarball_b64 = base64::engine::general_purpose::STANDARD.encode(&tarball_bytes);
    let install_resp = client
        .post(format!("{admin}/plugins"))
        .bearer_auth(&admin_token)
        .json(&serde_json::json!({
            "file": INSTALLED_ARCHIVE,
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
        Some("busbar-store-valkey"),
        "install response must name the installed plugin: {install_body}"
    );

    let installed_bytes = std::fs::read(plugins_dir.join(INSTALLED_ARCHIVE))
        .expect("the successful admin install retained its archive");
    assert_eq!(
        installed_bytes, tarball_bytes,
        "install retains the supplied archive bytes"
    );
    let archive_sha256 = busbar_plugin_loader::sign::sha256_hex(&installed_bytes);
    std::fs::write(&config, config_text(Some(&archive_sha256), None)).unwrap();

    let settings_resp = client
        .put(format!("{admin}/config/settings"))
        .bearer_auth(&admin_token)
        .json(&serde_json::json!({
            "store": { "module": "busbar-store-valkey", "settings": { "url": url,"input_budget":67108864,"durability":"ephemeral" } },
        }))
        .send()
        .expect("PUT /api/v1/admin/config/settings");
    let settings_status = settings_resp.status();
    let settings_body = settings_resp.text().unwrap_or_default();
    assert!(
        settings_status.is_success(),
        "PUT /api/v1/admin/config/settings must succeed: {settings_status}: {settings_body}"
    );

    // Successful settings writes persist through the configured Store; no `persist` flag is needed.
    let settings_body: serde_json::Value =
        serde_json::from_str(&settings_body).expect("the settings response is JSON");
    assert_eq!(settings_body["applied"], true);
    assert_eq!(
        settings_body["settings"]["store"]["module"],
        "busbar-store-valkey"
    );
    assert!(
        settings_body["reload_to_apply"]
            .as_array()
            .expect("restart fields")
            .iter()
            .any(|field| field == "store"),
        "the stored backend change must require restart: {settings_body}"
    );

    std::fs::write(&config, config_text(Some(&archive_sha256), Some(&url))).unwrap();

    let restart = client
        .post(format!("{admin}/restart"))
        .bearer_auth(&admin_token)
        .json(&serde_json::json!({ "confirm": true }))
        .send()
        .expect("POST /api/v1/admin/restart");
    let restart_status = restart.status();
    let restart_body = restart.text().unwrap_or_default();
    assert!(
        restart_status.is_success(),
        "restart must be accepted: {restart_status}: {restart_body}"
    );

    let exit_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match guard.0.try_wait().expect("observe restart exit") {
            Some(status) => {
                assert!(status.success(), "restart must exit successfully: {status}");
                break;
            }
            None => assert!(
                Instant::now() < exit_deadline,
                "the accepted restart must exit boot #1; log:\n{}",
                boot_log("1")
            ),
        }
        std::thread::sleep(Duration::from_millis(50));
    }

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
        list_body.contains("busbar-store-valkey"),
        "the restarted instance must list the installed valkey plugin: {list_body}"
    );

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

    drop(guard2);
    drop(guard);

    let mut raw = redis::Client::open(url.as_str())
        .unwrap()
        .get_connection()
        .unwrap();
    let keys: Vec<Vec<u8>> = redis::cmd("KEYS")
        .arg("busbar:v4:*")
        .query(&mut raw)
        .unwrap();
    assert!(!keys.is_empty(), "real API must publish native target rows");
    let mut key_row = false;
    let mut credential_row = false;
    for key in keys {
        let bytes: Vec<u8> = redis::cmd("GET").arg(key).query(&mut raw).unwrap();
        key_row |= bytes.windows(key_id.len()).any(|v| v == key_id.as_bytes());
        credential_row |= bytes
            .windows(access_key_id.len())
            .any(|v| v == access_key_id.as_bytes());
    }
    assert!(
        key_row,
        "minted key identity must be persisted independently of plugin process"
    );
    assert!(
        credential_row,
        "credential public identity must be persisted independently of plugin process"
    );
    let _ = std::fs::remove_dir_all(&work);
}
