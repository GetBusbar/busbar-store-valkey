// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **Valkey** backend for busbar's durable governance store: the shared, multi-node store
//! over a key-value data model. It serves the store v3 door (`busbar_contract::abi::sdk::store`)
//! over the HOST'S CONNECTOR: it speaks RESP2 itself ([`resp`]) and holds no socket, TLS stack or
//! runtime of its own. `redis://` / `rediss://` URLs (and the `valkey://` spellings) are read as
//! the upstream `redis` driver reads them.
//!
//! ## Keyspace (schema v9, every key under `busbar:`)
//!
//! - **keys**: `key:<id>` (JSON [`VirtualKey`], tombstoned on delete, never removed), `keys` (SET of
//!   ids), `keys:byrev` (ZSET by revision, for `list_keys_since`).
//! - **credentials**: `cred:<key_id>:<kind>:<slot>` (JSON [`CredentialSecret`]; the metadata view is
//!   the decoded row minus `.secret`), `cred:pub:<kind>:<public_id>` (UNIQUE(kind, public_id)),
//!   `cred:id:<cred_id>`, `cred:ids:<key_id>` (SET of `<kind>:<slot>`), `creds:byrev`.
//! - **usage** `usage:<bucket>:<window>` (HASH; reserved units `m:<model>:<unit>`, open units
//!   `u:<hex unit>:<model>`, floored at 0 server-side); **metering** `metering:<bucket>` (SET of row
//!   hashes); **audit** `audit` (ZSET); **denylist** `denylist` / `denylist:<sub>`.
//! - **plane records** ([`plane`]); the v6 typed keyspaces are copied into it on connect ([`legacy`]).
//!
//! ## Atomicity
//!
//! Every multi-key write is ONE `MULTI`/`EXEC` pipeline, or, where it depends on a value read just
//! before (credential slot occupancy, `delete_key`'s credential fan-out), an optimistic
//! `WATCH`/`MULTI`/`EXEC` transaction (`transaction!`) that re-runs on an abort.
//!
//! ## Connections
//!
//! One kept connection, dialled through the host's connector
//! for the store's one `tcp` need, secured for `rediss://` (unverified for `#insecure`), then `AUTH`
//! and `SELECT` as the URL says; `connect_timeout_ms` bounds dial plus handshake. A connection-level
//! failure on a `with_conn!` call reconnects and re-runs that call once; `with_conn_no_retry!` calls
//! (non-idempotent writes) fail instead. `open` only parses; its connect step migrates the schema and
//! checks `noeviction`. Error strings are scrubbed of the URL password. Rows carry no TTL: retention
//! is the engine's.

#![forbid(unsafe_code)]

use busbar_contract::abi::sdk::store::column::{clamp, read_u64};
use busbar_contract::abi::sdk::store::wire::{Pool, Wire};
use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringRow, ModelTokens, RecordStoreError,
    RecordStoreResult, UsageDelta, UsageLedger, VirtualKey, RESERVED_UNITS,
};
use resp::{cmd, pipe, Conn, ErrorKind, Pipeline, RedisError, RedisResult};
use std::sync::Arc;
use std::time::Duration;

/// The RESP2 client over the host's connector (the store has no socket of its own).
#[macro_use]
mod resp;

/// `self.with_conn(|c| EXPR)` over the blocking client, now: `EXPR` on the op's one connection
/// `c`, its failure in the store's words (`valkey command: …`, the URL password scrubbed).
///
/// A CONNECTION-LEVEL failure closes the connection and runs `EXPR` once more on a fresh one (its
/// failure then reads `valkey reconnect after drop: …` / `valkey retry after reconnect: …`); any
/// other failure clears a `WATCH` it left in force before the connection goes back to the next
/// caller.
macro_rules! with_conn {
    ($me:expr, |$c:ident| $e:expr $(,)?) => {
        match $crate::resp::rr(async { $e }).await {
            Ok(v) => Ok(v),
            Err(err) if err.is_connection_error() => match $me.reconnect(&mut *$c).await {
                Err(e2) => Err($me.err(e2, "reconnect after drop")),
                Ok(()) => $crate::resp::rr(async { $e })
                    .await
                    .map_err(|e2| $me.err(e2, "retry after reconnect")),
            },
            Err(err) => {
                if $c.watching() {
                    let _ = $crate::resp::cmd("UNWATCH").exec(&mut *$c).await;
                }
                Err($me.err(err, "command"))
            }
        }
    };
}

/// Like `with_conn`, but `EXPR` once, never replayed (a non-idempotent write whose lost
/// reply may have applied); a connection-level failure leaves the connection unfit, and the next op
/// dials fresh.
macro_rules! with_conn_no_retry {
    ($me:expr, |$c:ident| $e:expr $(,)?) => {
        match $crate::resp::rr(async { $e }).await {
            Ok(v) => Ok(v),
            Err(err) => {
                if !err.is_connection_error() && $c.watching() {
                    let _ = $crate::resp::cmd("UNWATCH").exec(&mut *$c).await;
                }
                Err($me.err(err, "command"))
            }
        }
    };
}

/// Default connect timeout: bounds each new connection's dial and handshake, so a
/// blackholed/firewalled host cannot wedge engine boot indefinitely. The `connect_timeout_ms`
/// setting overrides it.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

// Key-space helpers: one namespace prefix so a Valkey shared with other apps never collides.
const KEY_PREFIX: &str = "busbar:key:";
const KEYS_INDEX: &str = "busbar:keys";
const KEYS_BYREV: &str = "busbar:keys:byrev";
const CRED_IDS_PREFIX: &str = "busbar:cred:ids:";
const CRED_PUB_PREFIX: &str = "busbar:cred:pub:";
const CRED_ID_PREFIX: &str = "busbar:cred:id:";
const CREDS_BYREV: &str = "busbar:creds:byrev";
const AUDIT_ZSET: &str = "busbar:audit";

mod legacy;
mod plane;

const DENYLIST_PREFIX: &str = "busbar:denylist:";
const DENYLIST_INDEX: &str = "busbar:denylist";
/// The store-global revision counter (`INCR`), stamped on key and credential rows.
const REVISION_KEY: &str = "busbar:revision";
/// The schema marker. v6 is the oldest namespace migrated in place (older is REFUSED, never wiped);
/// v7 copied the v6 typed task / event / demotion / spent-approval keys into the plane
/// keyspace ([`legacy`]); v8 never shipped; v9 deleted the keys of the dropped money, journal and
/// session slots ([`ValkeyStore::drop_dead_slot_keys`]). A NEWER marker is refused.
const SCHEMA_KEY: &str = "busbar:schema";
const SCHEMA_VERSION: i64 = 9;
/// The slots whose `busbar:op:*` dedupe hashes survive the v9 upgrade.
const KEPT_OP_SLOTS: [&str; 3] = [
    "add_usage_batch",
    "add_metering_batch",
    "append_plane_record",
];
const FIRST_MIGRATED_SCHEMA: i64 = 6;

/// Whether an op record's body belongs to a kept slot: a digest (32 bytes, or 64 lowercase hex), or
/// the older textual form that starts with the slot's name. Only the dead slots' bodies are neither.
fn kept_op_body(body: &[u8]) -> bool {
    let hex64 = body.len() == 64 && body.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    let name = body.split(|b| *b == b':').next().unwrap_or_default();
    body.len() == 32 || hex64 || KEPT_OP_SLOTS.iter().any(|k| k.as_bytes() == name)
}

fn usage_key(bucket_id: &str, window_start: u64) -> String {
    format!("busbar:usage:{bucket_id}:{window_start}")
}

fn cred_row_key(key_id: &str, kind: &str, slot: u8) -> String {
    format!("busbar:cred:{key_id}:{kind}:{slot}")
}

fn cred_ids_key(key_id: &str) -> String {
    format!("{CRED_IDS_PREFIX}{key_id}")
}

fn cred_pub_key(kind: &str, public_id: &str) -> String {
    format!("{CRED_PUB_PREFIX}{kind}:{public_id}")
}

fn cred_id_key(cred_id: &str) -> String {
    format!("{CRED_ID_PREFIX}{cred_id}")
}

/// `s` with a `\\` before every character of `special` (which holds `\\` itself, so the escape
/// round-trips). Glob metacharacters for a `SCAN MATCH` that must match LITERALLY (else an id could
/// match other ids' keys); `|` for a metering row's joined identity (else two identities collide).
fn escape(s: &str, special: &[char]) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if special.contains(&c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// The glob metacharacters [`escape`] quotes in a `SCAN MATCH` pattern.
const GLOB: &[char] = &['*', '?', '[', ']', '\\'];
/// The characters [`escape`] quotes in a metering row's identity component.
const ROW_SEP: &[char] = &['\\', '|'];

/// Hash field for one (model, unit) counter in a usage window. The four RESERVED units keep the v6
/// spelling `m:<model>:<tier>` (parsed with a RIGHT split on the tier, so a model name containing `:`
/// still round-trips, and a v6 row reads back unchanged). Every OTHER (open) unit is spelled
/// `u:<hex unit>:<model>`: an open unit name is caller-supplied and may itself contain `:`, and hex
/// has none, so the split is unambiguous whatever the model and unit are.
fn usage_field(model: &str, unit: &str) -> String {
    if RESERVED_UNITS.contains(&unit) {
        format!("m:{model}:{unit}")
    } else {
        format!("u:{}:{model}", hex(unit.as_bytes()))
    }
}

/// Parse a usage-window hash field back into `(model, unit)` — the inverse of [`usage_field`].
/// `None` for the two request counters and anything else that is not a unit field.
fn parse_usage_field(field: &str) -> Option<(String, String)> {
    if let Some(rest) = field.strip_prefix("m:") {
        let (model, tier) = rest.rsplit_once(':')?;
        return Some((model.to_string(), tier.to_string()));
    }
    let rest = field.strip_prefix("u:")?;
    let (unit_hex, model) = rest.split_once(':')?;
    let unit = String::from_utf8(unhex(unit_hex)?).ok()?;
    Some((model.to_string(), unit))
}

/// Lower-case hex of `bytes` — the collision-free spelling of a caller-supplied component inside a
/// key or field name (hex contains no separator character).
pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// The inverse of [`hex`]; `None` on anything that is not an even-length lower/upper-case hex string.
fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn metering_set(bucket: u64) -> String {
    format!("busbar:metering:{bucket}")
}

/// The hash key of one metering cell: `(bucket, key_id, model, provider, priced_from_ms)`.
///
/// `priced_from_ms` joins the identity (a rate-card edit SPLITS the day's cell at the edit, and each
/// half prices at the card it was earned under). A cell whose price started at `0` —
/// the opening entry, and every row written before the field existed — keeps the v6 three-component
/// key, so a v6 cell and a v7 write of the same undated cell are one cell. A dated cell appends a
/// fourth `|<ms>` component. Each component is escaped before joining (see
/// [`escape`]), so the join is injective: an escaped component never contains a bare
/// `|`, so a three-component key and a four-component key can never render the same, and two
/// different identities never share a row.
fn metering_row(
    bucket: u64,
    key_id: &str,
    model: &str,
    provider: &str,
    priced_from_ms: u64,
) -> String {
    let base = format!(
        "busbar:metering:{bucket}:{}|{}|{}",
        escape(key_id, ROW_SEP),
        escape(model, ROW_SEP),
        escape(provider, ROW_SEP)
    );
    match priced_from_ms {
        0 => base,
        ms => format!("{base}|{ms}"),
    }
}

/// The metering-cell hash field an open (non-token) ledgered class accumulates under. Everything after
/// the fixed `u:` prefix is the class name, verbatim, so no class name can collide with a fixed field.
const METERING_UNIT_PREFIX: &str = "u:";

/// Extract the PASSWORD from a valkey URL, if any - the secret that must never appear in an error
/// string or a Debug print. Two forms carry one: the userinfo (`redis://user:pass@host/...`,
/// `redis://:pass@host/...`) and the query (`valkey+unix:///path?pass=secret`, or `password=`),
/// which is how a unix-socket URL states it ([`parse_unix`]). The value is returned as written in
/// the URL (percent-escapes intact); [`scrub`] redacts it in both that and its decoded form.
fn url_password(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let (before_query, query) = match rest.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (rest, None),
    };
    // The userinfo lives in the authority only (up to the first `/`), never in the path or query.
    let authority = before_query.split('/').next().unwrap_or("");
    if let Some((userinfo, _)) = authority.rsplit_once('@') {
        if let Some((_, pass)) = userinfo.split_once(':') {
            if !pass.is_empty() {
                return Some(pass.to_string());
            }
        }
    }
    query?
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(k, v)| matches!(*k, "pass" | "password") && !v.is_empty())
        .map(|(_, v)| v.to_string())
}

/// Percent-DECODE a URL component (`%40` -> `@`); a malformed escape is left verbatim.
fn percent_bytes(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// [`percent_bytes`], lossily as text: the scrub redacts both the raw and decoded password.
fn percent_decode(s: &str) -> String {
    String::from_utf8_lossy(&percent_bytes(s)).into_owned()
}

/// Replace every occurrence of `secret` (in BOTH its raw and percent-decoded forms) in `msg` with
/// `<redacted>` - the password-in-error scrub.
fn scrub(msg: String, secret: Option<&str>) -> String {
    let Some(s) = secret.filter(|s| !s.is_empty()) else {
        return msg;
    };
    let mut out = msg;
    if out.contains(s) {
        out = out.replace(s, "<redacted>");
    }
    let decoded = percent_decode(s);
    if decoded != s && !decoded.is_empty() && out.contains(&decoded) {
        out = out.replace(&decoded, "<redacted>");
    }
    // A query value's `+` reads as a space (form encoding: the unix URL's `?pass=`).
    let spaced = percent_decode(&s.replace('+', " "));
    if spaced != decoded && !spaced.is_empty() && out.contains(&spaced) {
        out = out.replace(&spaced, "<redacted>");
    }
    out
}

/// What the store connects to, parsed once from its settings' URL.
#[derive(Clone)]
struct Target {
    /// The connection's target on the host's connector: `host:port`, or `unix:<path>` for a
    /// unix-socket URL.
    addr: String,
    /// The host name (for connection security's name check).
    host: String,
    /// `rediss://` / `valkeys://`: secure the connection before its first byte.
    tls: bool,
    /// `#insecure` on a TLS URL: secure it WITHOUT verifying the server's certificate (the host
    /// honours it for this store's operator-infrastructure need only, and logs a WARN naming the
    /// instance).
    insecure: bool,
    /// `AUTH` (`user`, `password`), when the URL carries a password.
    auth: Option<(Option<String>, String)>,
    /// `SELECT`, when the URL names a database other than 0.
    db: i64,
}

impl std::fmt::Debug for Target {
    /// Every field but the URL password, which prints as `<redacted>`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Target")
            .field("addr", &self.addr)
            .field("host", &self.host)
            .field("tls", &self.tls)
            .field("insecure", &self.insecure)
            .field(
                "auth",
                &self.auth.as_ref().map(|(user, _)| (user, "<redacted>")),
            )
            .field("db", &self.db)
            .finish()
    }
}

/// The upstream driver's refusal of a URL, word for word.
fn url_refused(why: &'static str) -> RedisError {
    RedisError::from((ErrorKind::InvalidClientConfig, why))
}

/// Percent-decode `s` as UTF-8 (the upstream driver's user/password reading).
fn percent_decode_utf8(s: &str) -> Option<String> {
    String::from_utf8(percent_bytes(s)).ok()
}

/// Every query parameter a URL form reads is named in `known`; any other one is REFUSED (the
/// upstream driver ignored it silently, which would leave an operator believing a setting applied).
/// The parameter's name is echoed only when the URL carries no password: a password written
/// unencoded can split at `?` and arrive here as a "name" (one holding the `@` that ended it).
fn check_query(url: &url::Url, known: &[&str], has_secret: bool) -> RedisResult<()> {
    match url.query_pairs().find(|(k, _)| !known.contains(&k.as_ref())) {
        None => Ok(()),
        Some((k, _)) if has_secret || k.contains('@') => Err(url_refused(
            "an unknown URL parameter is not supported (its name is withheld: the URL carries a password)",
        )),
        Some((k, _)) => Err(RedisError::from((
            ErrorKind::InvalidClientConfig,
            "URL parameter is not supported by this store",
            k.into_owned(),
        ))),
    }
}

/// The upstream driver's `protocol=` query check (`2`/`resp2`/`3`/`resp3`). The store speaks
/// RESP2 whatever it says: every reply it reads converts the same either way.
fn check_protocol(url: &url::Url) -> RedisResult<()> {
    match url.query_pairs().find(|(k, _)| k == "protocol") {
        None => Ok(()),
        Some((_, p)) if matches!(p.as_ref(), "2" | "resp2" | "3" | "resp3") => Ok(()),
        Some((_, p)) => Err(RedisError::from((
            ErrorKind::InvalidClientConfig,
            "Invalid protocol version",
            p.into_owned(),
        ))),
    }
}

/// Parse a Valkey URL exactly as the upstream driver reads it (`redis` 1.7.1's
/// `IntoConnectionInfo for &str`): `redis://[user[:password]@]host[:port][/db]`, `rediss://` for TLS
/// (`#insecure` the one fragment it took), the `valkey://` / `valkeys://` spellings, and the
/// unix-socket URLs `unix://`, `redis+unix://`, `valkey+unix://` (`?db=`, `?user=`, `?pass=`).
fn parse_url(input: &str) -> RedisResult<Target> {
    let url = url::Url::parse(input)
        .ok()
        .filter(|u| {
            matches!(
                u.scheme(),
                "redis" | "rediss" | "valkey" | "valkeys" | "redis+unix" | "valkey+unix" | "unix"
            )
        })
        .ok_or_else(|| url_refused("Redis URL did not parse"))?;
    if matches!(url.scheme(), "unix" | "redis+unix" | "valkey+unix") {
        return parse_unix(&url);
    }
    let host = match url.host() {
        Some(url::Host::Domain(d)) => d.to_string(),
        Some(url::Host::Ipv4(v4)) => v4.to_string(),
        Some(url::Host::Ipv6(v6)) => v6.to_string(),
        None => return Err(url_refused("Missing hostname")),
    };
    if host == "0.0.0.0" || host == "::" {
        return Err(url_refused(
            "Cannot connect to a wildcard address (0.0.0.0 or ::)",
        ));
    }
    let port = url.port().unwrap_or(6379);
    let tls = matches!(url.scheme(), "rediss" | "valkeys");
    let insecure = if tls {
        match url.fragment() {
            None => false,
            Some("insecure") => true,
            Some(_) => {
                return Err(url_refused("only #insecure is supported as URL fragment"));
            }
        }
    } else {
        false
    };
    check_protocol(&url)?;
    check_query(&url, &["protocol"], url_password(input).is_some())?;
    let db = match url.path().trim_matches('/') {
        "" => 0,
        path => path
            .parse::<i64>()
            .map_err(|_| url_refused("Invalid database number"))?,
    };
    let user = if url.username().is_empty() {
        None
    } else {
        Some(
            percent_decode_utf8(url.username())
                .ok_or_else(|| url_refused("Username is not valid UTF-8 string"))?,
        )
    };
    let pass = match url.password() {
        Some(pw) => Some(
            percent_decode_utf8(pw)
                .ok_or_else(|| url_refused("Password is not valid UTF-8 string"))?,
        ),
        None => None,
    };
    let addr = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    Ok(Target {
        addr,
        host,
        tls,
        insecure,
        auth: pass.map(|p| (user, p)),
        db,
    })
}

/// A unix-socket URL, as the upstream driver read it: its path, and `db` / `user` / `pass` from
/// the query.
fn parse_unix(url: &url::Url) -> RedisResult<Target> {
    let path = url
        .to_file_path()
        .map_err(|()| url_refused("Missing path"))?;
    let query: std::collections::HashMap<_, _> = url.query_pairs().collect();
    let db = match query.get("db") {
        Some(db) => db
            .parse::<i64>()
            .map_err(|_| url_refused("Invalid database number"))?,
        None => 0,
    };
    check_protocol(url)?;
    check_query(
        url,
        &["db", "user", "pass", "protocol"],
        query.contains_key("pass") || query.contains_key("password"),
    )?;
    let user = query.get("user").map(|u| u.to_string());
    let pass = query.get("pass").map(|p| p.to_string());
    Ok(Target {
        addr: format!("unix:{}", path.display()),
        host: String::new(),
        tls: false,
        insecure: false,
        auth: pass.map(|p| (user, p)),
        db,
    })
}

/// Valkey `RecordStore` backend (durable, shared across a cluster), reached through the HOST'S
/// CONNECTOR: one kept connection (dialled, secured, `AUTH`, `SELECT` once), every op on it in turn;
/// the store holds no socket and no TLS stack of its own.
#[derive(Debug, Clone)]
pub struct ValkeyStore {
    inner: Arc<Inner>,
}

struct Inner {
    target: Target,
    /// The URL password (if any), scrubbed out of every error string this crate emits.
    secret: Option<String>,
    /// `connect_timeout_ms` (default [`DEFAULT_CONNECT_TIMEOUT`]): every dial's bound.
    connect_timeout: Duration,
    /// The kept connection: ONE (there is no pool setting), so the set holds one.
    pool: Arc<Pool>,
}

impl std::fmt::Debug for Inner {
    /// Every field but the URL password (`secret`), which prints as `<redacted>`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            target,
            secret,
            connect_timeout,
            pool,
        } = self;
        f.debug_struct("Inner")
            .field("target", target)
            .field("secret", &secret.as_ref().map(|_| "<redacted>"))
            .field("connect_timeout", connect_timeout)
            .field("pool", pool)
            .finish()
    }
}

/// The store's one outbound need: a `tcp` stream to the server the settings' URL names (the store
/// names the target at each connect), governed as operator infrastructure (private, loopback and
/// plaintext allowed). Its timeout bounds the dial.
pub const NEEDS: &[busbar_contract::abi::host::conn::connector::Need] = {
    use busbar_contract::abi::host::conn::connector::{
        Need, DIRECTION_OUTBOUND, EGRESS_OPERATOR_INFRASTRUCTURE, KEEP_NAMED,
    };
    &[Need {
        direction: DIRECTION_OUTBOUND,
        egress_class: EGRESS_OPERATOR_INFRASTRUCTURE,
        transport: busbar_contract::abi::sdk::door::abi_str("tcp"),
        timeout_ms: DEFAULT_CONNECT_TIMEOUT.as_millis() as u64,
        keep_mode: KEEP_NAMED,
        ..Need::ZERO
    }]
};

/// The need index of [`NEEDS`]' one entry.
const NEED_TCP: u32 = 0;

impl ValkeyStore {
    /// The op's connection over `wire`: the kept one when it is idle (its handshake done), else a
    /// fresh dial, secured for `rediss://`, `AUTH` and `SELECT` as the URL says — the dial AND the
    /// handshake bounded by `connect_timeout_ms` in all. A failure reads `valkey {ctx}: …` (`connect`
    /// at boot, `reconnect` when an op had to dial).
    async fn conn(&self, wire: Wire, ctx: &str) -> RecordStoreResult<Conn> {
        let failed = |e: String| {
            RecordStoreError(scrub(
                format!("valkey {ctx}: {e}"),
                self.inner.secret.as_deref(),
            ))
        };
        let ms = self.inner.connect_timeout.as_millis();
        if ms == 0 {
            // The upstream driver's TCP connect refused a zero timeout, in std's words.
            return Err(failed("cannot set a 0 duration timeout".into()));
        }
        let ms = u32::try_from(ms).unwrap_or(u32::MAX);
        wire.bound(ms);
        let connected = wire
            .connect_timed(NEED_TCP, Some(&self.inner.target.addr), ms)
            .await;
        let mut c = Conn::new(wire);
        let ready = match connected {
            Ok(()) if c.wire().reused() => Ok(()),
            Ok(()) => self.handshake(&mut c).await.map_err(|e| e.to_string()),
            Err(e) => Err(e.to_string()),
        };
        c.wire().unbound();
        ready.map_err(failed)?;
        Ok(c)
    }

    /// A NEW connection's handshake: TLS for `rediss://` (before its first byte; unverified for
    /// `#insecure`), `AUTH`, `SELECT`.
    async fn handshake(&self, c: &mut Conn) -> RedisResult<()> {
        let t = &self.inner.target;
        if t.tls {
            let secured = if t.insecure {
                c.wire().upgrade_secure_unverified(Some(&t.host)).await
            } else {
                c.wire().upgrade_secure(Some(&t.host)).await
            };
            secured.map_err(|e| RedisError::io(&e))?;
        }
        if let Some((user, pass)) = &t.auth {
            let mut auth = cmd("AUTH");
            if let Some(u) = user {
                auth.arg(u);
            }
            auth.arg(pass).exec(c).await?;
        }
        if t.db != 0 {
            cmd("SELECT").arg(t.db).exec(c).await?;
        }
        Ok(())
    }

    /// Reconnect after a dropped connection: close it, dial a fresh one, handshake (the
    /// dial and the handshake bounded by `connect_timeout_ms`, as every new connection is).
    async fn reconnect(&self, c: &mut Conn) -> RedisResult<()> {
        let ms = u32::try_from(self.inner.connect_timeout.as_millis()).unwrap_or(u32::MAX);
        c.wire().bound(ms);
        let r = match c.wire().reconnect().await {
            Ok(()) => {
                c.reset();
                self.handshake(c).await
            }
            Err(e) => Err(RedisError::io(&e)),
        };
        c.wire().unbound();
        r
    }

    /// The store's kept connection set.
    pub(crate) fn pool(&self) -> &Arc<Pool> {
        &self.inner.pool
    }

    /// `open`'s connect step: the first connection, the schema migration and the noeviction check
    /// (its failures are the load's refusal).
    async fn connect_step(&self, wire: Wire) -> RecordStoreResult<()> {
        let mut c = self.conn(wire, "connect").await?;
        self.migrate(&mut c).await?;
        let r = self.assert_noeviction(&mut c).await;
        c.settle();
        r
    }

    /// STARTUP ASSERTION, non-negotiable: `maxmemory-policy` must be `noeviction`. Under any eviction
    /// policy, Valkey can silently evict a denylist entry (un-revoking a compromised key) or a
    /// metering row (destroying billing evidence) under memory pressure, with zero error anywhere in
    /// the request path — the loss is invisible until someone goes looking for data that should be
    /// there. Refuse to start rather than risk it. If `CONFIG GET` itself is disabled by an ACL
    /// (a legitimate hardened deployment), we cannot verify the policy either way — fail loud with a
    /// distinct message rather than silently assuming it's safe.
    async fn assert_noeviction(&self, c: &mut Conn) -> RecordStoreResult<()> {
        let pairs: Vec<(String, String)> = with_conn!(self, |c| {
            cmd("CONFIG")
                .arg("GET")
                .arg("maxmemory-policy")
                .query(c)
                .await
        })?;
        let policy = pairs
            .iter()
            .find(|(k, _)| k == "maxmemory-policy")
            .map(|(_, v)| v.as_str());
        match policy {
            Some("noeviction") => Ok(()),
            Some(other) => Err(RecordStoreError(format!(
                "valkey maxmemory-policy is '{other}', not 'noeviction': an eviction policy \
                 can silently drop a denylist entry (un-revoking a key) or a metering row \
                 (destroying billing evidence) under memory pressure with no error anywhere. \
                 Refusing to start. Run `CONFIG SET maxmemory-policy noeviction` (and persist it in \
                 the server's own config, since CONFIG SET does not survive a restart) before \
                 pointing busbar at this instance."
            ))),
            None => Err(RecordStoreError(
                "valkey CONFIG GET maxmemory-policy returned no value — either this server \
                 restricts CONFIG GET via ACL, or something unexpected happened. Refusing to start: \
                 cannot verify the noeviction invariant governance data durability depends on."
                    .to_string(),
            )),
        }
    }

    /// SCHEMA MIGRATION (currently v9; see `SCHEMA_VERSION`'s own doc for what each version did).
    /// A fresh namespace (no `busbar:*` keys) is simply marked ; one already
    /// at the current version passes through untouched; one NEWER than this build is refused; a v6
    /// namespace is upgraded IN PLACE ([`legacy::migrate_v6_to_v7`]) and a v6, v7 or v8 one then gets
    /// the v9 step ([`ValkeyStore::drop_dead_slot_keys`]), each idempotent, the marker written last
    /// so a crash mid-upgrade re-runs it on the next connect.
    ///
    /// NOTHING IS EVER WIPED. A namespace with `busbar:*` keys whose marker is absent or older than
    /// v6 is REFUSED with an explained error and left byte-for-byte as found: a missing marker is
    /// indistinguishable from a live v6/v7 namespace whose marker was lost (operator `DEL`, partial
    /// restore), and two nodes first-booting on an empty server must not wipe each other. Before
    /// refusing, the marker is re-read once, so a peer that marked the namespace in the meantime is
    /// honoured rather than refused.
    async fn migrate(&self, c: &mut Conn) -> RecordStoreResult<()> {
        let mut marker: Option<i64> =
            with_conn!(self, |c| c.get::<_, Option<i64>>(SCHEMA_KEY).await)?;
        let mut rechecked = false;
        loop {
            let version = marker.unwrap_or(0);
            if version > SCHEMA_VERSION {
                return Err(RecordStoreError(format!(
                    "valkey schema check: schema v{version} is newer than this build \
                     (v{SCHEMA_VERSION}); refusing to open. NOTHING was changed. An older build \
                     on a newer namespace would not know what the newer schema did to the namespace: run a build of v{version} or later."
                )));
            }
            if version == SCHEMA_VERSION {
                return Ok(());
            }
            if version >= FIRST_MIGRATED_SCHEMA {
                if version < 7 {
                    legacy::migrate_v6_to_v7(self, c).await?;
                }
                self.drop_dead_slot_keys(c).await?;
                return with_conn!(self, |c| c
                    .set::<_, _, ()>(SCHEMA_KEY, SCHEMA_VERSION)
                    .await);
            }
            let existing = self.scan(c, "busbar:*").await?;
            let others: Vec<&String> = existing.iter().filter(|k| *k != SCHEMA_KEY).collect();
            if others.is_empty() {
                return with_conn!(self, |c| c
                    .set::<_, _, ()>(SCHEMA_KEY, SCHEMA_VERSION)
                    .await);
            }
            if !rechecked {
                // A peer may have marked the namespace between our read and the SCAN.
                rechecked = true;
                let again: Option<i64> =
                    with_conn!(self, |c| c.get::<_, Option<i64>>(SCHEMA_KEY).await)?;
                if again.is_some_and(|v| v >= FIRST_MIGRATED_SCHEMA) {
                    marker = again;
                    continue;
                }
            }
            let found = match marker {
                None => "the `busbar:schema` marker is missing".to_string(),
                Some(v) => format!("the `busbar:schema` marker is {v}"),
            };
            // Key PREFIXES only (first two `:`-segments + `*`): full names can carry a credential's
            // public id.
            let mut sample: Vec<String> = others
                .iter()
                .map(|k| {
                    let mut seg = k.splitn(3, ':');
                    match (seg.next(), seg.next(), seg.next()) {
                        (Some(a), Some(b), Some(_)) => format!("{a}:{b}:*"),
                        _ => k.to_string(),
                    }
                })
                .collect();
            sample.sort_unstable();
            sample.dedup();
            sample.truncate(3);
            return Err(RecordStoreError(format!(
                "valkey schema check: {found} (a version below {FIRST_MIGRATED_SCHEMA} cannot be \
                 upgraded in place) but the namespace holds {} other `busbar:*` key(s), key prefixes e.g. [{}]. \
                 Refusing to start. NOTHING was changed: no key was deleted and no marker written. \
                 If this is a current namespace whose marker was lost, restore it with \
                 `SET {SCHEMA_KEY} {FIRST_MIGRATED_SCHEMA}` and restart ({FIRST_MIGRATED_SCHEMA} is safe \
                 either way: the v6->v7 copy is append-if-absent and the v9 step deletes keys a v6/v7 namespace already lacks or no longer reads, \
                 so both are safe on a namespace already past them, whereas {SCHEMA_VERSION} on a namespace last run by a v6 build would skip the copy \
                 and strand its task and ask-state data). If it was written by plugin v1.0.0 or an earlier 1.5.0 \
                 development build, it cannot be migrated: back it up if needed, delete the \
                 `busbar:*` keys, and restart to start a fresh namespace.",
                others.len(),
                sample.join(", ")
            )));
        }
    }

    /// THE v9 STEP (`SCHEMA_VERSION`): delete what the deleted slots kept. The key families go
    /// by `SCAN` + `UNLINK` (never `KEYS`, never a blocking `DEL`), once, at the upgrade: the
    /// money keys (`busbar:cap:*`, `busbar:slice:*`, `busbar:open:*`, `busbar:slices`,
    /// `busbar:epoch`), the journal (`busbar:journal:*`, its `streams` set included) and the
    /// sessions (`busbar:session:*`, `busbar:sessions:*`). The `busbar:op:*` dedupe hashes of the
    /// deleted slots go too, told apart by the op's value fields (`b`), which start with the
    /// slot's name; the hashes of the kept slots (`add_usage_batch`, `add_metering_batch`,
    /// `append_plane_record`) are untouched, so a retry across the upgrade still answers its
    /// original. Idempotent (a re-run finds nothing more), so a crash before the marker is
    /// written re-runs it and two nodes upgrading at once land in the same place.
    async fn drop_dead_slot_keys(&self, c: &mut Conn) -> RecordStoreResult<()> {
        for pattern in [
            "busbar:cap:*",
            "busbar:slice:*",
            "busbar:open:*",
            "busbar:slices",
            "busbar:epoch",
            "busbar:journal:*",
            "busbar:session:*",
            "busbar:sessions:*",
        ] {
            let keys = self.scan(c, pattern).await?;
            self.unlink_all(c, &keys).await?;
        }
        let ops = self.scan(c, "busbar:op:*").await?;
        let mut dead = Vec::new();
        for chunk in ops.chunks(500) {
            let bodies: Vec<Option<Vec<u8>>> = with_conn!(self, |c| {
                let mut pipe = pipe();
                for k in chunk {
                    pipe.cmd("HGET").arg(k).arg("b");
                }
                pipe.query(c).await
            })?;
            for (key, body) in chunk.iter().zip(bodies) {
                let Some(body) = body else { continue };
                if !kept_op_body(&body) {
                    dead.push(key.clone());
                }
            }
        }
        self.unlink_all(c, &dead).await
    }

    /// `UNLINK` `keys`, a chunk at a time.
    async fn unlink_all(&self, c: &mut Conn, keys: &[String]) -> RecordStoreResult<()> {
        for chunk in keys.chunks(500) {
            with_conn!(self, |c| cmd("UNLINK").arg(chunk).query::<i64>(c).await)?;
        }
        Ok(())
    }

    /// Every key matching `pattern`.
    async fn scan(&self, c: &mut Conn, pattern: &str) -> RecordStoreResult<Vec<String>> {
        with_conn!(self, |c| c.scan_match(pattern).await)
    }

    fn err(&self, e: RedisError, ctx: &str) -> RecordStoreError {
        RecordStoreError(scrub(
            format!("valkey {ctx}: {e}"),
            self.inner.secret.as_deref(),
        ))
    }

    /// Allocate the next revision — a plain `INCR`. Called once per key/credential mutation, inside
    /// whatever pipe/transaction performs the write, so the stamped value and the write are never
    /// observed apart.
    async fn next_revision(&self, c: &mut Conn) -> RedisResult<u64> {
        let v: i64 = c.incr(REVISION_KEY, 1).await?;
        Ok(v.max(0) as u64)
    }
}

/// `put_credential`'s owner precondition, read inside its WATCHed transaction: the key row named by
/// `key_id` must exist and must not be tombstoned. An unparseable owner row is refused too — a
/// credential cannot be attached to a key whose liveness cannot be established.
async fn owner_is_live(c: &mut Conn, key_row: &str, key_id: &str) -> RedisResult<()> {
    let raw: Option<String> = c.get(key_row).await?;
    let refuse = |why: String| Err(RedisError::refused(why));
    let Some(raw) = raw else {
        return refuse(format!(
            "put_credential: key '{key_id}' does not exist; a credential must hang off a real key"
        ));
    };
    match key_from_json(&raw) {
        Ok(k) if k.deleted_at.is_none() => Ok(()),
        Ok(_) => refuse(format!(
            "put_credential: key '{key_id}' is tombstoned; its credentials were revoked with it \
             and are never reissued"
        )),
        Err(_) => refuse(format!(
            "put_credential: key '{key_id}' does not decode; refusing to attach a credential to it"
        )),
    }
}

/// Whether the key row at `row` is a stored tombstone. A row that does not decode is not one:
/// refusing it would make a corrupt row permanently unwritable.
async fn tombstoned(c: &mut Conn, row: &str) -> RedisResult<bool> {
    let prior: Option<String> = c.get(row).await?;
    Ok(prior
        .as_deref()
        .and_then(|r| key_from_json(r).ok())
        .is_some_and(|k| k.deleted_at.is_some()))
}

/// What a credential slot allows a mint of `secret`, read inside the WATCHed transaction.
enum Slot {
    /// The slot already holds THIS credential, live: a reconnect-and-retry replaying an `EXEC` that
    /// had committed. Nothing to write.
    Replay,
    /// Free; a revoked previous occupant's `(public_id, id)`, whose pointers the write deletes.
    Free(Option<(String, String)>),
}

/// The slot checks of a credential mint (`op` names the refusals): a DIFFERENT live credential in
/// the slot is refused (never silently destroyed mid-overlap), a revoked one is never re-minted
/// under its own id, and `UNIQUE(kind, public_id)` is a real read of the pointer (a `SETNX` queued
/// in an `.ignore()`d pipe would discard the "already claimed" answer).
async fn read_slot(c: &mut Conn, secret: &CredentialSecret, op: &str) -> RedisResult<Slot> {
    let m = &secret.meta;
    let solo = op == "put_credential";
    let existing: Option<String> = c.get(cred_row_key(&m.key_id, &m.kind, m.slot)).await?;
    let mut prior = None;
    if let Some(raw) = &existing {
        let cur: CredentialSecret = serde_json::from_str(raw)
            .map_err(|_| RedisError::from((ErrorKind::Client, "cred decode")))?;
        if cur.meta.revoked_at.is_none() {
            if cur.meta.id == m.id {
                return Ok(Slot::Replay);
            }
            return Err(RedisError::from((
                ErrorKind::Client,
                if solo {
                    "put_credential: slot holds a live credential; revoke it first"
                } else {
                    "put_key_with_credential: slot holds a live credential; revoke it first"
                },
            )));
        }
        if cur.meta.id == m.id {
            return Err(RedisError::refused(format!(
                "{op}: credential {} is revoked; a revoked credential is never re-minted",
                m.id
            )));
        }
        prior = Some((cur.meta.public_id, cur.meta.id));
    }
    let holder: Option<String> = c.get(cred_pub_key(&m.kind, &m.public_id)).await?;
    if holder.is_some_and(|h| h != slot_pointer(m)) {
        return Err(RedisError::from((
            ErrorKind::Client,
            if solo {
                "put_credential: public_id already claimed by a different credential"
            } else {
                "put_key_with_credential: public_id already claimed"
            },
        )));
    }
    Ok(Slot::Free(prior))
}

/// A credential's `<key_id>:<kind>:<slot>` pointer.
fn slot_pointer(m: &CredentialMeta) -> String {
    format!("{}:{}:{}", m.key_id, m.kind, m.slot)
}

/// Queue the writes of a credential row and its pointers on `pipe`, deleting a revoked previous
/// occupant's pointers in the same atomic step (a stale `cred:id:<old>` would let a later revoke of
/// the old id wipe the new occupant).
fn queue_credential(
    pipe: &mut Pipeline,
    secret: &CredentialSecret,
    prior: &Option<(String, String)>,
) -> RedisResult<()> {
    let m = &secret.meta;
    let json =
        cred_to_json(secret).map_err(|_| RedisError::from((ErrorKind::Client, "cred encode")))?;
    let ptr = slot_pointer(m);
    if let Some((old_pub, old_id)) = prior {
        if *old_pub != m.public_id {
            pipe.del(cred_pub_key(&m.kind, old_pub)).ignore();
        }
        if *old_id != m.id {
            pipe.del(cred_id_key(old_id)).ignore();
        }
    }
    pipe.set(cred_pub_key(&m.kind, &m.public_id), &ptr).ignore();
    pipe.set(cred_id_key(&m.id), &ptr).ignore();
    pipe.set(cred_row_key(&m.key_id, &m.kind, m.slot), &json)
        .ignore();
    pipe.sadd(cred_ids_key(&m.key_id), format!("{}:{}", m.kind, m.slot))
        .ignore();
    pipe.zadd(CREDS_BYREV, &ptr, m.revision).ignore();
    Ok(())
}

fn key_from_json(raw: &str) -> RecordStoreResult<VirtualKey> {
    serde_json::from_str(raw).map_err(|e| RecordStoreError(format!("key decode failed: {e}")))
}
fn cred_to_json(cred: &CredentialSecret) -> RecordStoreResult<String> {
    serde_json::to_string(cred)
        .map_err(|e| RecordStoreError(format!("credential encode failed: {e}")))
}
fn cred_from_json(raw: &str) -> RecordStoreResult<CredentialSecret> {
    serde_json::from_str(raw)
        .map_err(|e| RecordStoreError(format!("credential decode failed: {e}")))
}

/// Parse a `"<key_id>:<kind>:<slot>"` pointer value back into its parts. `kind` cannot itself contain
/// `:` (enforced by the fixed kind allowlist upstream), so a right-split on `:` twice is unambiguous
/// even if a future `key_id` contained a colon.
fn parse_slot_pointer(s: &str) -> Option<(String, String, u8)> {
    let (rest, slot) = s.rsplit_once(':')?;
    let (key_id, kind) = rest.rsplit_once(':')?;
    Some((key_id.to_string(), kind.to_string(), slot.parse().ok()?))
}

/// The fields one usage delta adds, as `(hash field, delta)` pairs for `add_usage_batch`: the two
/// request counters always, and every non-zero unit.
fn usage_fields(delta: &UsageDelta) -> Vec<(String, i64)> {
    let mut fields: Vec<(String, i64)> = vec![
        ("requests".to_string(), delta.requests),
        ("billable_requests".to_string(), delta.billable_requests),
    ];
    for m in &delta.models {
        for (unit, d) in &m.usage_units {
            if *d != 0 {
                fields.push((usage_field(&m.model, unit), *d));
            }
        }
    }
    fields
}

/// The base op set's bodies, each over the op's one connection `c` (the store door, `slots`, runs
/// each as one op through the host's connector). The un-deduped writes (`add_usage`,
/// `add_metering`, `append_plane_record`) reach the store as their `op_id` slots.
impl ValkeyStore {
    pub(crate) async fn put_key(&self, c: &mut Conn, key: &VirtualKey) -> RecordStoreResult<()> {
        let row_key = format!("{KEY_PREFIX}{}", key.id);
        with_conn!(self, |c| {
            // A live-shaped write must not clear a tombstone (an id is never reissued), WATCHed so
            // a `delete_key` committing in between aborts and retries this.
            transaction!(c, &[row_key.as_str()], |c, pipe| {
                if key.deleted_at.is_none() && tombstoned(c, &row_key).await? {
                    return Err(RedisError::refused(format!(
                        "put_key: '{}' is tombstoned and its id is never reissued; \
                             refusing to clear the tombstone",
                        key.id
                    )));
                }
                let mut key = key.clone();
                let rev = self.next_revision(c).await?;
                key.revision = rev;
                let json = serde_json::to_string(&key)
                    .map_err(|_e| RedisError::from((ErrorKind::Client, "encode")))?;
                pipe.atomic()
                    .set(&row_key, &json)
                    .ignore()
                    .sadd(KEYS_INDEX, &key.id)
                    .ignore()
                    .zadd(KEYS_BYREV, &key.id, rev)
                    .ignore()
                    .query(c)
                    .await
            })
        })
    }

    pub(crate) async fn get_key(
        &self,
        c: &mut Conn,
        id: &str,
    ) -> RecordStoreResult<Option<VirtualKey>> {
        let raw: Option<String> = with_conn!(self, |c| c.get(format!("{KEY_PREFIX}{id}")).await)?;
        raw.map(|r| key_from_json(&r)).transpose()
    }

    pub(crate) async fn list_keys(&self, c: &mut Conn) -> RecordStoreResult<Vec<VirtualKey>> {
        // UNFILTERED, tombstones included: a hydrator must see a tombstone to evict its credentials.
        let ids: Vec<String> = with_conn!(self, |c| c.smembers(KEYS_INDEX).await)?;
        let mut out = self.get_keys(c, &ids).await?;
        out.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(out)
    }

    pub(crate) async fn list_keys_since(
        &self,
        c: &mut Conn,
        since: u64,
    ) -> RecordStoreResult<Vec<VirtualKey>> {
        let ids: Vec<String> = with_conn!(self, |c| c
            .zrangebyscore(KEYS_BYREV, format!("({since}"), "+inf")
            .await)?;
        self.get_keys(c, &ids).await
    }

    /// The key rows of `ids` (a missing row is skipped, a corrupt one refused).
    async fn get_keys(&self, c: &mut Conn, ids: &[String]) -> RecordStoreResult<Vec<VirtualKey>> {
        let rows: Vec<String> = ids.iter().map(|id| format!("{KEY_PREFIX}{id}")).collect();
        let raws = self.get_all(c, &rows).await?;
        raws.into_iter()
            .flatten()
            .map(|r| key_from_json(&r))
            .collect()
    }

    /// `GET` every one of `keys`, in one pipeline.
    async fn get_all(
        &self,
        c: &mut Conn,
        keys: &[String],
    ) -> RecordStoreResult<Vec<Option<String>>> {
        with_conn!(self, |c| {
            let mut pipe = pipe();
            for k in keys {
                pipe.get(k);
            }
            pipe.query(c).await
        })
    }

    pub(crate) async fn delete_key(&self, c: &mut Conn, id: &str) -> RecordStoreResult<()> {
        let ids_key = cred_ids_key(id);
        let key_row = format!("{KEY_PREFIX}{id}");
        // Usage windows: best-effort cleanup by a SCAN outside the transaction (a window raced in
        // before the EXEC is stale data, not an identity issue).
        let pattern = format!("busbar:usage:{}:*", escape(id, GLOB));
        let usage_keys = self.scan(c, &pattern).await?;
        // WATCH the key row, its credential-id index AND every member's credential row (a slot
        // rewritten in place changes no index). The row set depends on the membership, so a
        // membership change rebuilds the watch set from fresh state (the outer loop).
        with_conn!(self, |c| loop {
            let members: Vec<String> = c.smembers(&ids_key).await?;
            let row_keys: Vec<String> = members
                .iter()
                .filter_map(|m| parse_slot_pointer(&format!("{id}:{m}")))
                .map(|(_, kind, slot)| cred_row_key(id, &kind, slot))
                .collect();
            let mut watch_keys: Vec<&str> = vec![key_row.as_str(), ids_key.as_str()];
            watch_keys.extend(row_keys.iter().map(String::as_str));

            let outcome = transaction!(c, &watch_keys, |c, pipe| {
                let raw: Option<String> = c.get(&key_row).await?;
                let Some(raw) = raw else {
                    // Unknown id: an error, as the SQL backends (a tombstoned one is a no-op).
                    return Err(RedisError::refused(format!(
                        "delete_key: unknown id '{id}'"
                    )));
                };
                let mut key: VirtualKey = serde_json::from_str(&raw)
                    .map_err(|_| RedisError::from((ErrorKind::Client, "key decode")))?;
                if key.deleted_at.is_some() {
                    // Already tombstoned: an idempotent no-op.
                    pipe.atomic();
                    return pipe.query(c).await;
                }
                // `transaction!` re-runs this body with the SAME watch set: a membership change
                // goes back to the outer loop to rebuild it.
                let fresh_members: Vec<String> = c.smembers(&ids_key).await?;
                if fresh_members.len() != members.len()
                    || !fresh_members.iter().all(|m| members.contains(m))
                {
                    return Err(RedisError::retry());
                }
                let rev = self.next_revision(c).await?;
                key.enabled = false;
                key.deleted_at = Some(crate::now());
                key.revision = rev;
                let key_json = serde_json::to_string(&key)
                    .map_err(|_| RedisError::from((ErrorKind::Client, "key encode")))?;

                pipe.atomic();
                pipe.set(&key_row, &key_json).ignore();
                pipe.zadd(KEYS_BYREV, id, rev).ignore();
                for uk in &usage_keys {
                    pipe.del(uk).ignore();
                }
                // Destroy every credential row and its pointers (a consumer evicts off the key's
                // own tombstone delta).
                for member in &members {
                    let Some((_, kind, slot)) = parse_slot_pointer(&format!("{id}:{member}"))
                    else {
                        continue;
                    };
                    let row_key = cred_row_key(id, &kind, slot);
                    // A row that does not decode aborts the cascade: skipping it would leave its
                    // pointers dangling behind a reported success.
                    if let Some(raw) = c.get::<_, Option<String>>(&row_key).await? {
                        let cred: CredentialSecret = serde_json::from_str(&raw).map_err(|_| {
                            RedisError::from((
                                ErrorKind::Client,
                                "delete_key: corrupt credential row",
                            ))
                        })?;
                        pipe.del(cred_pub_key(&kind, &cred.meta.public_id)).ignore();
                        pipe.del(cred_id_key(&cred.meta.id)).ignore();
                    }
                    pipe.del(&row_key).ignore();
                }
                pipe.del(&ids_key).ignore();
                pipe.query(c).await
            });

            match outcome {
                Err(e) if e.is_retry() => continue,
                other => break other,
            }
        })
    }

    pub(crate) async fn get_usage(
        &self,
        c: &mut Conn,
        bucket_id: &str,
        window_start: u64,
    ) -> RecordStoreResult<UsageLedger> {
        let k = usage_key(bucket_id, window_start);
        let fields: Vec<(String, i64)> = with_conn!(self, |c| c.hgetall(&k).await)?;
        let mut ledger = UsageLedger::default();
        for (name, v) in fields {
            if name == "requests" {
                ledger.requests = read_u64(v);
                continue;
            }
            if name == "billable_requests" {
                ledger.billable_requests = read_u64(v);
                continue;
            }
            let Some((model, unit)) = parse_usage_field(&name) else {
                continue;
            };
            let entry = match ledger.models.iter_mut().find(|m| m.model == model) {
                Some(m) => m,
                None => {
                    ledger.models.push(ModelTokens {
                        model,
                        ..Default::default()
                    });
                    ledger.models.last_mut().expect("just pushed")
                }
            };
            // A zero counter is not carried: the map is sparse (`ModelTokens::is_zero` reads an
            // absent key and a zero one the same), and a v6 row wrote all four tiers, zeros included.
            let n = read_u64(v);
            if n != 0 {
                entry.usage_units.insert(unit, n);
            }
        }
        ledger.models.sort_by(|a, b| a.model.cmp(&b.model));
        Ok(ledger)
    }

    pub(crate) async fn put_usage(
        &self,
        c: &mut Conn,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> RecordStoreResult<()> {
        let k = usage_key(bucket_id, window_start);
        with_conn!(self, |c| {
            let mut pipe = pipe();
            pipe.atomic();
            pipe.del(&k).ignore();
            pipe.hset(&k, "requests", clamp(ledger.requests)).ignore();
            pipe.hset(&k, "billable_requests", clamp(ledger.billable_requests))
                .ignore();
            for m in &ledger.models {
                for (unit, n) in &m.usage_units {
                    pipe.hset(&k, usage_field(&m.model, unit), clamp(*n))
                        .ignore();
                }
            }
            pipe.query(c).await
        })
    }

    pub(crate) async fn list_metering(
        &self,
        c: &mut Conn,
        bucket: u64,
    ) -> RecordStoreResult<Vec<MeteringRow>> {
        let set = metering_set(bucket);
        let row_keys: Vec<String> = with_conn!(self, |c| c.smembers(&set).await)?;
        if row_keys.is_empty() {
            return Ok(Vec::new());
        }
        let all_fields: Vec<Vec<(String, String)>> = with_conn!(self, |c| {
            let mut pipe = pipe();
            for row_key in &row_keys {
                pipe.hgetall(row_key);
            }
            pipe.query(c).await
        })?;
        let mut out = Vec::with_capacity(row_keys.len());
        for fields in all_fields {
            if fields.is_empty() {
                continue;
            }
            let mut m = MeteringRow {
                key_id: String::new(),
                model: String::new(),
                provider: String::new(),
                tokens_input: 0,
                tokens_output: 0,
                tokens_cache_read: 0,
                tokens_cache_write: 0,
                requests: 0,
                billable_requests: 0,
                key_group_at_use: String::new(),
                pricing_version: String::new(),
                priced_from_ms: 0,
                usage_units: Default::default(),
            };
            for (name, val) in fields {
                // Every other decode path in this file (key_from_json, cred_from_json, audit
                // records) propagates a RecordStoreError on a corrupt value rather than silently
                // substituting a default -- a malformed numeric field here must not silently
                // read back as 0 and under-report billing/usage data.
                let num = |field: &str, val: &str| {
                    val.parse::<i64>().map_err(|e| {
                        RecordStoreError(format!("list_metering: bad {field} value {val:?}: {e}"))
                    })
                };
                if let Some(class) = name.strip_prefix(METERING_UNIT_PREFIX) {
                    let n = read_u64(num(&name, &val)?);
                    if n != 0 {
                        m.usage_units.insert(class.to_string(), n);
                    }
                    continue;
                }
                match name.as_str() {
                    "key_id" => m.key_id = val.clone(),
                    "model" => m.model = val.clone(),
                    "provider" => m.provider = val.clone(),
                    "tokens_input" => m.tokens_input = read_u64(num("tokens_input", &val)?),
                    "tokens_output" => m.tokens_output = read_u64(num("tokens_output", &val)?),
                    "tokens_cache_read" => {
                        m.tokens_cache_read = read_u64(num("tokens_cache_read", &val)?)
                    }
                    "tokens_cache_write" => {
                        m.tokens_cache_write = read_u64(num("tokens_cache_write", &val)?)
                    }
                    "requests" => m.requests = read_u64(num("requests", &val)?),
                    "billable_requests" => {
                        m.billable_requests = read_u64(num("billable_requests", &val)?)
                    }
                    "priced_from_ms" => {
                        m.priced_from_ms = val.parse::<u64>().map_err(|e| {
                            RecordStoreError(format!(
                                "list_metering: bad priced_from_ms value {val:?}: {e}"
                            ))
                        })?
                    }
                    "key_group_at_use" => m.key_group_at_use = val.clone(),
                    "pricing_version" => m.pricing_version = val.clone(),
                    _ => {}
                }
            }
            out.push(m);
        }
        Ok(out)
    }

    pub(crate) async fn put_credential(
        &self,
        c: &mut Conn,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        let m = &secret.meta;
        let row_key = cred_row_key(&m.key_id, &m.kind, m.slot);
        let pub_key = cred_pub_key(&m.kind, &m.public_id);
        let key_row = format!("{KEY_PREFIX}{}", m.key_id);
        with_conn!(self, |c| {
            // WATCHed: the owning key's row (a `delete_key` in between must abort this, never slip
            // under it), the slot's row and the public id pointer.
            let watched = [row_key.as_str(), pub_key.as_str(), key_row.as_str()];
            transaction!(c, &watched, |c, pipe| {
                owner_is_live(c, &key_row, &m.key_id).await?;
                let prior = match read_slot(c, secret, "put_credential").await? {
                    Slot::Replay => return pipe.atomic().query(c).await,
                    Slot::Free(prior) => prior,
                };
                let mut secret = secret.clone();
                secret.meta.revision = self.next_revision(c).await?;
                queue_credential(pipe.atomic(), &secret, &prior)?;
                pipe.query(c).await
            })
        })
    }

    pub(crate) async fn put_key_with_credential(
        &self,
        c: &mut Conn,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        if secret.meta.key_id != key.id {
            return Err(RecordStoreError(format!(
                "put_key_with_credential: the credential names key '{}', not the key '{}' being \
                 minted with it",
                secret.meta.key_id, key.id
            )));
        }
        // The atomic mint: `put_key`'s tombstone check and `put_credential`'s slot checks, WATCHing
        // the key row, the slot's row and the public id pointer.
        let m = &secret.meta;
        let key_row = format!("{KEY_PREFIX}{}", key.id);
        let row_key = cred_row_key(&m.key_id, &m.kind, m.slot);
        let pub_key = cred_pub_key(&m.kind, &m.public_id);
        with_conn!(self, |c| {
            transaction!(
                c,
                &[key_row.as_str(), row_key.as_str(), pub_key.as_str()],
                |c, pipe| {
                    if key.deleted_at.is_none() && tombstoned(c, &key_row).await? {
                        return Err(RedisError::refused(format!(
                            "put_key_with_credential: '{}' is tombstoned and its id is \
                                 never reissued",
                            key.id
                        )));
                    }
                    let prior = match read_slot(c, secret, "put_key_with_credential").await? {
                        Slot::Replay => return pipe.atomic().query(c).await,
                        Slot::Free(prior) => prior,
                    };
                    let (mut key, mut secret) = (key.clone(), secret.clone());
                    key.revision = self.next_revision(c).await?;
                    secret.meta.revision = self.next_revision(c).await?;
                    let key_json = serde_json::to_string(&key)
                        .map_err(|_| RedisError::from((ErrorKind::Client, "key encode")))?;
                    pipe.atomic();
                    pipe.set(&key_row, &key_json).ignore();
                    pipe.sadd(KEYS_INDEX, &key.id).ignore();
                    pipe.zadd(KEYS_BYREV, &key.id, key.revision).ignore();
                    queue_credential(pipe, &secret, &prior)?;
                    pipe.query(c).await
                },
            )
        })
    }

    pub(crate) async fn list_credentials(
        &self,
        c: &mut Conn,
        key_id: &str,
    ) -> RecordStoreResult<Vec<CredentialMeta>> {
        let members: Vec<String> = with_conn!(self, |c| c.smembers(cred_ids_key(key_id)).await)?;
        let row_keys: Vec<String> = members
            .iter()
            .filter_map(|m| {
                let (kind, slot) = m.split_once(':')?;
                Some(cred_row_key(key_id, kind, slot.parse().ok()?))
            })
            .collect();
        // The metadata view is the decoded row minus its secret: there is one decode path.
        let raws = self.get_all(c, &row_keys).await?;
        raws.into_iter()
            .flatten()
            .map(|r| cred_from_json(&r).map(|c| c.meta))
            .collect()
    }

    pub(crate) async fn revoke_credential(
        &self,
        c: &mut Conn,
        id: &str,
        reason: &str,
    ) -> RecordStoreResult<()> {
        let id_key = cred_id_key(id);
        with_conn!(self, |c| {
            transaction!(c, &[id_key.as_str()], |c, pipe| {
                let ptr: Option<String> = c.get(&id_key).await?;
                let Some(ptr) = ptr else {
                    // Unknown id: an ERROR (only an already-revoked id is an idempotent no-op).
                    return Err(RedisError::refused(format!(
                        "revoke_credential: unknown id '{id}'"
                    )));
                };
                // A pointer that does not parse is corruption: never report a revocation that
                // did not happen.
                let Some((key_id, kind, slot)) = parse_slot_pointer(&ptr) else {
                    return Err(RedisError::from((
                        ErrorKind::Client,
                        "corrupt credential pointer",
                        format!("busbar:cred:id:{id} does not parse as <key_id>:<kind>:<slot>"),
                    )));
                };
                let row_key = cred_row_key(&key_id, &kind, slot);
                let raw: Option<String> = c.get(&row_key).await?;
                let Some(raw) = raw else {
                    pipe.atomic();
                    return pipe.query(c).await;
                };
                let mut cred: CredentialSecret = serde_json::from_str(&raw)
                    .map_err(|_| RedisError::from((ErrorKind::Client, "cred decode")))?;
                if cred.meta.revoked_at.is_some() {
                    // Already revoked: idempotent no-op.
                    pipe.atomic();
                    return pipe.query(c).await;
                }
                let rev = self.next_revision(c).await?;
                cred.meta.revoked_at = Some(crate::now());
                cred.meta.revoke_reason = Some(reason.to_string());
                cred.meta.revision = rev;
                // Destroy the secret material on revoke — defense in depth: a revoked credential's
                // plaintext has no further legitimate reader, so there is no reason to retain it.
                cred.secret = String::new();
                let json = cred_to_json(&cred)
                    .map_err(|_| RedisError::from((ErrorKind::Client, "cred encode")))?;
                pipe.atomic();
                pipe.set(&row_key, &json).ignore();
                pipe.zadd(CREDS_BYREV, format!("{key_id}:{kind}:{slot}"), rev)
                    .ignore();
                pipe.query(c).await
            })
        })
    }

    pub(crate) async fn list_credentials_since(
        &self,
        c: &mut Conn,
        since: u64,
    ) -> RecordStoreResult<Vec<CredentialSecret>> {
        let members: Vec<String> = with_conn!(self, |c| c
            .zrangebyscore(CREDS_BYREV, format!("({since}"), "+inf")
            .await)?;
        let row_keys: Vec<String> = members
            .iter()
            .filter_map(|m| {
                let (key_id, kind, slot) = parse_slot_pointer(m)?;
                Some(cred_row_key(&key_id, &kind, slot))
            })
            .collect();
        let raws = self.get_all(c, &row_keys).await?;
        // A row that does not decode is SKIPPED (and logged; the row key carries no secret): this
        // global hydration delta must not fail whole on one corrupt row, and omitting a credential
        // denies access, never grants it. (`delete_key` fails loud instead: it writes.)
        let mut out = Vec::with_capacity(raws.len());
        for (i, raw) in raws.into_iter().enumerate() {
            let Some(raw) = raw else { continue };
            match cred_from_json(&raw) {
                Ok(cred) => out.push(cred),
                Err(e) => {
                    tracing::warn!(
                        "busbar-store-valkey: skipping undecodable credential row {} in the \
                         hydration delta ({e}); that credential cannot authenticate until the row \
                         is repaired, and the rest of the delta is unaffected",
                        row_keys.get(i).map(String::as_str).unwrap_or("<unknown>")
                    );
                }
            }
        }
        Ok(out)
    }

    pub(crate) async fn list_audit(&self, c: &mut Conn) -> RecordStoreResult<Vec<AuditRecord>> {
        self.audit_from(c, 0).await
    }

    /// The audit chain from rank `start` (negative counts from the end) to its end.
    async fn audit_from(&self, c: &mut Conn, start: isize) -> RecordStoreResult<Vec<AuditRecord>> {
        let members: Vec<String> = with_conn!(self, |c| c.zrange(AUDIT_ZSET, start, -1).await)?;
        members
            .iter()
            .map(|m| {
                serde_json::from_str(m)
                    .map_err(|e| RecordStoreError(format!("audit decode failed: {e}")))
            })
            .collect()
    }

    pub(crate) async fn list_audit_tail(
        &self,
        c: &mut Conn,
        limit: u64,
    ) -> RecordStoreResult<Vec<AuditRecord>> {
        if limit == 0 {
            // The contract's empty tail; `ZRANGE 0 -1` would be the WHOLE chain.
            return Ok(Vec::new());
        }
        self.audit_from(c, isize::try_from(limit).map(|n| -n).unwrap_or(isize::MIN))
            .await
    }

    pub(crate) async fn add_denylist(
        &self,
        c: &mut Conn,
        sub: &str,
        reason: &str,
    ) -> RecordStoreResult<()> {
        with_conn!(self, |c| {
            pipe()
                .atomic()
                .set(format!("{DENYLIST_PREFIX}{sub}"), reason)
                .ignore()
                .sadd(DENYLIST_INDEX, sub)
                .ignore()
                .query(c)
                .await
        })
    }

    pub(crate) async fn list_denylist(&self, c: &mut Conn) -> RecordStoreResult<Vec<String>> {
        with_conn!(self, |c| c.smembers(DENYLIST_INDEX).await)
    }
}

/// Current unix time in seconds. A thin wrapper so tests can be deterministic about "now" only via
/// real elapsed time (no injected clock in this crate — governance timestamps are advisory metadata
/// here, never used for admission math inside the store itself).
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// The store's door lives HERE, in the logic crate (`slots`: `store_door!` over this store's
// `StoreSlots`): a busbar build that links this crate registers `door` as its compiled-in row
// (`LinkedRow::of(door)`), and the sibling `busbar-store-valkey-plugin` cdylib exports the same
// `door` as the image's one symbol (`export_door!`). One source, both doors.

/// The store's package name: the name its Statement states and its signed tarball carries.
pub const NAME: &str = "busbar-store-valkey";

impl ValkeyStore {
    /// Construct a Valkey-protocol store from the settings JSON the host hands `validate` and
    /// `open`:
    ///
    /// ```json
    /// { "url": "redis://:password@host:6379/0", "connect_timeout_ms": 10000 }
    /// ```
    ///
    /// It PARSES and connects to nothing: the first connection is `open`'s connect step
    /// ([`StoreSlots::connect`](busbar_contract::abi::sdk::store::StoreSlots::connect)), through the
    /// host's connector. `connect_timeout_ms` is optional (default [`DEFAULT_CONNECT_TIMEOUT`]).
    ///
    /// # Errors
    /// A text naming why the settings do not open a store.
    pub fn from_settings(settings: &[u8]) -> Result<Self, String> {
        let v: serde_json::Value = if settings.iter().all(u8::is_ascii_whitespace) {
            serde_json::Value::Object(Default::default())
        } else {
            serde_json::from_slice(settings)
                .map_err(|e| format!("invalid valkey plugin config: {e}"))?
        };
        const BAD: &str = "invalid valkey plugin config";
        // A top-level key this plugin does not read is a typo or a setting for another backend; it
        // must not be swallowed into quietly opening with the defaults.
        if let Some(unknown) = v.as_object().and_then(|o| {
            o.keys()
                .find(|k| !matches!(k.as_str(), "url" | "connect_timeout_ms"))
        }) {
            return Err(format!(
                "{BAD}: unknown setting `{unknown}` (accepted: url, connect_timeout_ms)"
            ));
        }
        let url = match v.get("url") {
            None => {
                return Err(
                    "valkey plugin config requires a \"url\" (a redis:// connection string)"
                        .to_string(),
                )
            }
            Some(serde_json::Value::String(s)) if !s.trim().is_empty() => s.as_str(),
            Some(_) => return Err(format!("{BAD}: `url` must be a non-empty string")),
        };
        let timeout = match v.get("connect_timeout_ms") {
            None => DEFAULT_CONNECT_TIMEOUT,
            Some(x) => match x.as_u64().filter(|ms| *ms > 0) {
                Some(ms) => Duration::from_millis(ms),
                None => {
                    return Err(format!(
                        "{BAD}: `connect_timeout_ms` must be a positive integer (milliseconds), \
                         got {x}"
                    ))
                }
            },
        };
        // A URL that does not parse is a settings refusal: nothing was connected.
        let secret = url_password(url);
        let target =
            parse_url(url).map_err(|e| scrub(format!("{BAD}: url: {e}"), secret.as_deref()))?;
        Ok(Self {
            inner: Arc::new(Inner {
                target,
                secret,
                connect_timeout: timeout,
                // ONE connection (there is no pool setting).
                pool: Pool::new(1),
            }),
        })
    }
}

mod slots;

/// The store door (store v3, `busbar_contract::abi::store`): every slot of the store v3 table over
/// [`ValkeyStore`], through the contract's store SDK.
pub use slots::door;

#[cfg(test)]
mod tests;
