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
//! - **records** `records:<hex schema>:k` / `:v` (the door's ordered key-value records), **op
//!   records** `op:<hex op_id>` (HASH, the dedupe state of the `op_id` writes), `revision` (the
//!   store-wide counter) and `schema` (the version marker).
//!
//! ## Atomicity
//!
//! Multi-key writes use one server-side script or one `MULTI`/`EXEC` pipeline. Writes that depend
//! on a value read just before (credential slot occupancy, `delete_key`'s credential fan-out) use
//! an optimistic `WATCH`/`MULTI`/`EXEC` transaction (`transaction!`) that re-runs on an abort.
//!
//! ## Connections
//!
//! Up to [`KEPT_CONNECTIONS`] kept connections, one per op in flight, dialled through the host's
//! connector for the store's one `tcp` need, secured for `rediss://` (unverified for `#insecure`), then `AUTH`
//! and `SELECT` as the URL says; `connect_timeout_ms` bounds dial plus handshake. A connection-level
//! failure on a `with_conn!` call reconnects and re-runs that call once; `with_conn_no_retry!` calls
//! (non-idempotent writes) fail instead. `open` only parses; its connect step migrates the schema and
//! checks `noeviction`. Error strings are scrubbed of the URL password. Op records
//! (`OP_ID_RETENTION_SECS`) and redeemed-token entries carry TTLs; no other row does: retention is
//! the engine's.

#![forbid(unsafe_code)]

use busbar_contract::abi::sdk::cred::{settings_lent, Cred, ValkeyUrl};
use busbar_contract::abi::sdk::store::column::read_u64;
use busbar_contract::abi::sdk::store::wire::{Pool, Wire};
use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringRow, ModelTokens, RecordStoreError,
    RecordStoreResult, SecretForm, UsageDelta, UsageLedger, VirtualKey, RESERVED_UNITS,
};
use resp::{cmd, pipe, Conn, ErrorKind, Pipeline, RedisError, RedisResult, Script};
use zeroize::{Zeroize, Zeroizing};

use std::sync::Arc;
use std::time::Duration;

/// The RESP2 client over the host's connector (the store has no socket of its own).
#[macro_use]
mod resp;

/// `with_conn!(self, |c| EXPR)`: `EXPR` on the op's one connection `c`, its failure in the store's
/// words (`valkey command: …`, the URL password scrubbed).
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
                Err(e2) => Err($crate::RecordStoreError(format!(
                    "{}; {}",
                    $me.err(err, "command"),
                    $me.err(e2, "reconnect after drop")
                ))),
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
/// The store-global revision counter, read and rewritten (`next_revision`) inside the `WATCH`ed
/// transaction that stamps key and credential rows with it.
const REVISION_KEY: &str = "busbar:revision";
/// The schema marker. v6 is the oldest namespace migrated in place; older stores are refused.
const SCHEMA_KEY: &str = "busbar:schema";
/// v7 upgrades the released v6 schema: copy typed plane rows, remove retired slots,
/// scrub revoked credentials, preserve metering attribution and repair token expiries.
/// v8 converts quantity aggregates to micro-units, atomically with its schema marker.
/// v9 admits the full nonnegative i128 mantissa range; v8 micro-units are never scaled again.
const SCHEMA_VERSION: i64 = 9;
/// The slots whose `busbar:op:*` dedupe hashes survive the v6 -> v7 upgrade.
const KEPT_OP_SLOTS: [&str; 3] = [
    "add_usage_batch",
    "add_metering_batch",
    "append_plane_record",
];
const FIRST_MIGRATED_SCHEMA: i64 = 6;

/// The most connections the store keeps (one op, one connection; `WATCH`/`MULTI` are per op).
const KEPT_CONNECTIONS: usize = 8;

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

fn expired_usage_key(key: &str, before: u64) -> bool {
    let Some((_, stamp)) = key
        .strip_prefix("busbar:usage:")
        .and_then(|rest| rest.rsplit_once(':'))
    else {
        return false;
    };
    let Ok(window) = stamp.parse::<u64>() else {
        return false;
    };
    window != 0 && window < before && stamp == window.to_string()
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
/// round-trips): `|` for a metering row's joined identity (else two identities collide).
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

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Lower-case hex of `bytes` — the collision-free spelling of a caller-supplied component inside a
/// key or field name (hex contains no separator character).
pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(HEX_DIGITS[usize::from(b >> 4)]));
        out.push(char::from(HEX_DIGITS[usize::from(b & 15)]));
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
        .map(|i| {
            let pair = s.get(i..i + 2)?;
            // `from_str_radix` alone would accept a sign (`+a`).
            if !pair.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            u8::from_str_radix(pair, 16).ok()
        })
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

/// Percent-decode public URL components (the upstream driver's username reading).
fn percent_decode_utf8(s: &str) -> Option<String> {
    let mut out = Vec::with_capacity(s.len());
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let mut rest = bytes.clone();
            if let (Some(h), Some(l)) = (rest.next(), rest.next()) {
                if let (Some(h), Some(l)) = ((h as char).to_digit(16), (l as char).to_digit(16)) {
                    out.push((h * 16 + l) as u8);
                    bytes = rest;
                    continue;
                }
            }
        }
        out.push(b);
    }
    String::from_utf8(out).ok()
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
    auth: Option<(Option<String>, Cred)>,
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

/// Every query parameter a URL form reads is named in `known`; any other one is REFUSED (the
/// upstream driver ignored it silently, which would leave an operator believing a setting applied).
/// The parameter's name is echoed only when the URL carries no password: a password written
/// unencoded can split at `?` and arrive here as a "name" (one holding the `@` that ended it).
fn check_query(url: &url::Url, known: &[&str], has_secret: bool) -> RedisResult<()> {
    match url
        .query_pairs()
        .find(|(k, _)| !known.contains(&k.as_ref()))
    {
        None => Ok(()),
        Some((k, _)) if has_secret || k.contains('@') || query_has_at(url) => Err(url_refused(
            "an unknown URL parameter is not supported (its name is withheld: the URL carries a password)",
        )),
        Some((k, _)) => Err(RedisError::from((
            ErrorKind::InvalidClientConfig,
            "URL parameter is not supported by this store",
            k.into_owned(),
        ))),
    }
}

/// The raw query holds an `@`: the sign that a password written unencoded split the userinfo at
/// `?`, so every name and value in the query may be password text.
fn query_has_at(url: &url::Url) -> bool {
    url.query().is_some_and(|q| q.contains('@'))
}

/// The upstream driver's `protocol=` query check (`2`/`resp2`/`3`/`resp3`). The store speaks
/// RESP2 whatever it says: every reply it reads converts the same either way.
fn check_protocol(url: &url::Url) -> RedisResult<()> {
    match url.query_pairs().filter(|(k, _)| k == "protocol").last() {
        None => Ok(()),
        Some((_, p)) if matches!(p.as_ref(), "2" | "resp2" | "3" | "resp3") => Ok(()),
        Some((_, _)) if query_has_at(url) => Err(url_refused(
            "Invalid protocol version (its value is withheld: the URL may carry a password)",
        )),
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
fn parse_target(input: &ValkeyUrl) -> RedisResult<Target> {
    if let Some(why) = input
        .parsing_error()
        .filter(|why| *why != "Password is not valid UTF-8 string")
    {
        return Err(url_refused(why));
    }
    let url = url::Url::parse(input.public())
        .ok()
        .filter(|u| {
            matches!(
                u.scheme(),
                "redis" | "rediss" | "valkey" | "valkeys" | "redis+unix" | "valkey+unix" | "unix"
            )
        })
        .ok_or_else(|| url_refused("Redis URL did not parse"))?;
    if matches!(url.scheme(), "unix" | "redis+unix" | "valkey+unix") {
        return parse_unix(&url, input);
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
    check_query(
        &url,
        &["protocol"],
        input.password().is_some()
            || url
                .query_pairs()
                .any(|(key, _)| matches!(key.as_ref(), "pass" | "password")),
    )?;
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
    if let Some(why) = input.parsing_error() {
        return Err(url_refused(why));
    }
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
        auth: input.password().cloned().map(|p| (user, p)),
        db,
    })
}

/// A unix-socket URL, as the upstream driver read it: its path, and `db` / `user` / `pass` from
/// the query.
fn parse_unix(url: &url::Url, input: &ValkeyUrl) -> RedisResult<Target> {
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
    Ok(Target {
        addr: format!("unix:{}", path.display()),
        host: String::new(),
        tls: false,
        insecure: false,
        auth: input.password().cloned().map(|p| (user, p)),
        db,
    })
}

/// Valkey `RecordStore` backend (durable, shared across a cluster), reached through the HOST'S
/// CONNECTOR: up to eight kept connections (each dialled, secured, `AUTH`, `SELECT` once),
/// one per op in flight;
/// the store holds no socket and no TLS stack of its own.
#[derive(Debug, Clone)]
pub struct ValkeyStore {
    inner: Arc<Inner>,
}

struct Inner {
    target: Target,
    /// Public URL metadata and SDK-held redaction material; no plaintext password is retained.
    url: ValkeyUrl,
    /// `connect_timeout_ms` (default [`DEFAULT_CONNECT_TIMEOUT`]): every dial's bound.
    connect_timeout: Duration,
    /// The kept connections: [`KEPT_CONNECTIONS`], one per op in flight.
    pool: Arc<Pool>,
}

impl std::fmt::Debug for Inner {
    /// The URL credential prints only its redaction marker.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            target,
            url,
            connect_timeout,
            pool,
        } = self;
        f.debug_struct("Inner")
            .field("target", target)
            .field("secret", &url.password().map(|_| "<redacted>"))
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
    /// handshake bounded by `connect_timeout_ms` in all. A failure reads `valkey {ctx}: …` (`ctx`
    /// `reconnect` when an op had to dial) or, at boot (`None`), the driver's words alone: the
    /// door's connect step adds its one prefix.
    async fn conn(&self, wire: Wire, ctx: Option<&str>) -> RecordStoreResult<Conn> {
        let failed = |e: String| {
            let text = match ctx {
                Some(ctx) => format!("valkey {ctx}: {e}"),
                None => e,
            };
            RecordStoreError(self.inner.url.redact_echo(&text))
        };
        let ms = self.inner.connect_timeout.as_millis();
        if ms == 0 {
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
        if ready.is_err() {
            c.wire().discard();
        }
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
            c.authenticate(pass, user.as_deref()).await?;
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
        if r.is_err() {
            c.wire().discard();
        }
        r
    }

    /// The store's kept connection set.
    pub(crate) fn pool(&self) -> &Arc<Pool> {
        &self.inner.pool
    }

    /// `open`'s connect step: the first connection, the noeviction check and the schema migration
    /// (its failures are the load's refusal).
    async fn connect_step(&self, wire: Wire) -> RecordStoreResult<()> {
        let mut c = self.conn(wire, None).await?;
        // The policy is judged FIRST: a start refused for it must not have rewritten and re-marked
        // the namespace on a server that can evict what the upgrade just wrote.
        let r = match self.assert_noeviction(&mut c).await {
            Ok(()) => self.migrate(&mut c).await,
            Err(e) => Err(e),
        };
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
                "maxmemory-policy is '{other}', not 'noeviction': an eviction policy \
                 can silently drop a denylist entry (un-revoking a key) or a metering row \
                 (destroying billing evidence) under memory pressure with no error anywhere. \
                 Refusing to start. Run `CONFIG SET maxmemory-policy noeviction` (and persist it in \
                 the server's own config, since CONFIG SET does not survive a restart) before \
                 pointing busbar at this instance."
            ))),
            None => Err(RecordStoreError(
                "CONFIG GET maxmemory-policy returned no value — either this server \
                 restricts CONFIG GET via ACL, or something unexpected happened. Refusing to start: \
                 cannot verify the noeviction invariant governance data durability depends on."
                    .to_string(),
            )),
        }
    }

    /// SCHEMA MIGRATION (see `SCHEMA_VERSION` for what each version did).
    /// A fresh namespace (no `busbar:*` keys) is simply marked; one already
    /// at the current version passes through untouched; one NEWER than this build is refused; a v6
    /// namespace is upgraded IN PLACE ([`legacy::migrate_v6_to_v7`]) and then gets
    /// the retired-slot cleanup step ([`ValkeyStore::drop_dead_slot_keys`]); v7 scrubs revoked credentials.
    /// Each step is idempotent, the marker written last
    /// so a crash mid-upgrade re-runs it on the next connect.
    ///
    /// NOTHING IS EVER WIPED. A namespace with `busbar:*` keys whose marker is absent or older than
    /// v6 is REFUSED with an explained error and left byte-for-byte as found: a missing marker is
    /// indistinguishable from a live v6/v7 namespace whose marker was lost (operator `DEL`, partial
    /// restore), and two nodes first-booting on an empty server must not wipe each other. Before
    /// refusing, the marker is re-read once, so a peer that marked the namespace in the meantime is
    /// honoured rather than refused.
    async fn migrate(&self, c: &mut Conn) -> RecordStoreResult<()> {
        let mut marker = self.read_schema(c).await?;
        let mut rechecked = false;
        loop {
            let version = marker.unwrap_or(0);
            if version > SCHEMA_VERSION {
                return Err(RecordStoreError(format!(
                    "schema v{version} is newer than this build \
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
                    self.drop_dead_slot_keys(c).await?;
                    self.scrub_revoked_credentials(c).await?;
                    self.migrate_metering_attribution(c).await?;
                    self.repair_token_expiries(c).await?;
                }
                match self.migrate_exact_counts(c, marker).await? {
                    None => return Ok(()),
                    // A peer marked it meanwhile: judge the new marker, never overwrite it.
                    Some(now) => {
                        marker = Some(now);
                        continue;
                    }
                }
            }
            let others: Vec<String> =
                with_conn!(self, |c| c.scan_some("busbar:*", SCHEMA_KEY, 3).await)?;
            if others.is_empty() {
                match self.mark_schema(c, marker).await? {
                    None => return Ok(()),
                    Some(now) => {
                        marker = Some(now);
                        continue;
                    }
                }
            }
            if !rechecked {
                rechecked = true;
                let again = self.read_schema(c).await?;
                if again.is_some_and(|v| v >= FIRST_MIGRATED_SCHEMA) {
                    marker = again;
                    continue;
                }
            }
            let found = match marker {
                None => "the `busbar:schema` marker is missing".to_string(),
                Some(v) => format!("the `busbar:schema` marker is {v}"),
            };

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
                "{found} (a version below {FIRST_MIGRATED_SCHEMA} cannot be \
                 upgraded in place) but the namespace holds other `busbar:*` keys (e.g. {}); \
                 refusing to start. NOTHING was changed: no key was deleted and no marker written. \
                 If a namespace's marker was lost, restore only the original version verified \
                 from a backup or deployment record. Never guess a legacy version: v8 converted \
                 quantities to micro-units, and a guessed older marker would multiply them again. If it was written by plugin v1.0.0 or an earlier 1.5.0 \
                 development build, it cannot be migrated: back it up if needed, delete the \
                 `busbar:*` keys, and restart to start a fresh namespace.",
                sample.join(", ")
            )));
        }
    }

    async fn read_schema(&self, c: &mut Conn) -> RecordStoreResult<Option<i64>> {
        let raw: Option<String> = with_conn!(self, |c| c.get(SCHEMA_KEY).await)?;
        raw.map(|value| {
            value.parse().map_err(|_| {
                RecordStoreError(
                    "the `busbar:schema` marker is not a number; NOTHING was changed".into(),
                )
            })
        })
        .transpose()
    }

    /// One atomic script preflights every quantity, converts exact decimal strings and
    /// advances the schema together. Reopening an already migrated namespace changes nothing.
    async fn migrate_exact_counts(
        &self,
        c: &mut Conn,
        read: Option<i64>,
    ) -> RecordStoreResult<Option<i64>> {
        let expected = read.map(|v| v.to_string()).unwrap_or_default();
        let now: Option<String> = with_conn!(self, |c| MIGRATE_EXACT_COUNTS
            .key(SCHEMA_KEY)
            .arg(&expected)
            .arg(SCHEMA_VERSION)
            .invoke(c)
            .await)?;
        let now = now
            .map(|value| {
                value
                    .parse()
                    .map_err(|_| RecordStoreError("invalid exact count schema marker".into()))
            })
            .transpose()?;
        if now.is_some() && now == read {
            return Err(RecordStoreError(
                "exact count migration made no schema progress; refusing to repeat it".into(),
            ));
        }
        Ok(now)
    }

    /// Write the current schema marker if it still is `read` (what this run saw); `None` when
    /// written, else the marker a peer put there meanwhile (left untouched).
    async fn mark_schema(&self, c: &mut Conn, read: Option<i64>) -> RecordStoreResult<Option<i64>> {
        let expected = read.map(|v| v.to_string()).unwrap_or_default();
        let now: Option<String> = with_conn!(self, |c| SET_SCHEMA_MARKER
            .key(SCHEMA_KEY)
            .arg(&expected)
            .arg(SCHEMA_VERSION)
            .invoke(c)
            .await)?;
        let now = now
            .map(|v| {
                v.parse().map_err(|_| {
                    RecordStoreError(format!("the `{SCHEMA_KEY}` marker is not a number: {v}"))
                })
            })
            .transpose()?;
        if now.is_some() && now == read {
            // The swap refused the very marker it was told to expect: judging it again would
            // re-run every upgrade step forever.
            return Err(RecordStoreError(format!(
                "the `{SCHEMA_KEY}` marker could not be rewritten: it still reads {} after an upgrade; refusing to start (re-running the upgrade would not change it). NOTHING further was changed.",
                read.map(|v| v.to_string()).unwrap_or_default()
            )));
        }
        Ok(now)
    }

    /// RETIRED-SLOT CLEANUP: delete what the deleted slots kept. The key families go
    /// by `SCAN` + `UNLINK` (never `KEYS`, never a blocking `DEL`), once, at the upgrade: the
    /// money keys (`busbar:cap:*`, `busbar:slice:*`, `busbar:open:*`, `busbar:slices`,
    /// `busbar:epoch`), the journal (`busbar:journal:*`, its `streams` set included) and the
    /// sessions (`busbar:session:*`, `busbar:sessions:*`). The `busbar:op:*` dedupe hashes of the
    /// deleted slots go too, told apart by the op's body (`b`): a kept slot's body is a 32-byte
    /// digest (or 64 lowercase hex), or the older text that starts with the slot's name; only the
    /// dead slots' bodies are neither. The hashes of the kept slots (`add_usage_batch`,
    /// `add_metering_batch`, `append_plane_record`) are untouched, so a retry across the upgrade still answers its
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

    /// REVOKED-CREDENTIAL SCRUB: scrub the secret out of every revoked credential row. Walks the
    /// revision index (`CREDS_BYREV`) and, for each revoked row that still carries secret bytes,
    /// clears the secret, sets its form to `None` and stamps a fresh revision, so the delta feed
    /// carries the change. Idempotent (a scrubbed row is skipped, a missing row is skipped), one
    /// `WATCH`ed transaction per row, so a crash before the marker is written re-runs it and two
    /// nodes upgrading at once land in the same place. Runs on every upgrade (version below
    /// `SCHEMA_VERSION`), after copying legacy rows and removing retired slots.
    async fn scrub_revoked_credentials(&self, c: &mut Conn) -> RecordStoreResult<()> {
        let members: Vec<String> = with_conn!(self, |c| c.zrange(CREDS_BYREV, 0, -1).await)?;
        for ptr in members {
            let (key_id, kind, slot) = parse_slot_pointer(&ptr).ok_or_else(|| {
                RecordStoreError(format!(
                    "credential upgrade: malformed revision-index pointer `{ptr}` in {CREDS_BYREV}"
                ))
            })?;
            let row_key = cred_row_key(&key_id, &kind, slot);
            let watched = [row_key.as_str(), REVISION_KEY];
            with_conn!(self, |c| transaction!(c, &watched, |c, pipe| {
                let raw: Option<String> = c.get(&row_key).await?;
                let Some(raw) = raw else {
                    return Ok(Some(()));
                };
                let raw = Zeroizing::new(raw);
                let mut cred = OwnedCredential(serde_json::from_str(&raw).map_err(|_| {
                    RedisError::refused(format!(
                        "credential upgrade: malformed credential at `{row_key}` (pointer `{ptr}`)"
                    ))
                })?);
                if slot_pointer(&cred.meta) != ptr {
                    return Err(RedisError::refused(format!(
                        "credential upgrade: mismatched slot at `{row_key}` (pointer `{ptr}`)"
                    )));
                }
                if cred.meta.revoked_at.is_none()
                    || (cred.secret.is_empty() && cred.meta.secret_form == SecretForm::None)
                {
                    return Ok(Some(()));
                }
                cred.secret.zeroize();
                cred.meta.secret_form = SecretForm::None;
                cred.meta.revision = self.next_revision(c, pipe, 1).await?;
                let json = cred_to_json(&cred)
                    .map_err(|_| RedisError::refused("credential upgrade: encode failed"))?;
                pipe.set(&row_key, json.as_str()).ignore();
                pipe.zadd(CREDS_BYREV, &ptr, cred.meta.revision).ignore();
                pipe.query(c).await
            }))?;
        }
        Ok(())
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

    /// `e` as the store's error: a refusal as written, anything else a backend failure under
    /// `valkey {ctx}: `.
    fn err(&self, e: RedisError, ctx: &str) -> RecordStoreError {
        let text = if e.is_refusal() {
            e.to_string()
        } else {
            format!("valkey {ctx}: {e}")
        };
        RecordStoreError(self.inner.url.redact_echo(&text))
    }

    /// Reserve `n` consecutive revisions and return the first. Called inside a `transaction!` that
    /// WATCHes [`REVISION_KEY`]: the counter is read here and written back by the same `EXEC` as
    /// the stamped rows, so a writer overtaken since the read aborts and restamps. Stamps then
    /// become visible in revision order, which the hydration watermarks rely on.
    async fn next_revision(&self, c: &mut Conn, pipe: &mut Pipeline, n: u64) -> RedisResult<u64> {
        let cur: Option<i64> = c.get(REVISION_KEY).await?;
        let cur = u64::try_from(cur.unwrap_or(0)).map_err(|_| {
            RedisError::refused(
                "next_revision: busbar:revision is negative; refusing to reuse revisions",
            )
        })?;
        let last = cur
            .checked_add(n)
            .filter(|last| *last <= i64::MAX as u64)
            .filter(|_| n != 0)
            .ok_or_else(|| {
                RedisError::refused(
                    "next_revision: busbar:revision has no room for the reservation",
                )
            })?;
        let first = cur + 1;
        pipe.set(REVISION_KEY, last).ignore();
        Ok(first)
    }
}

/// A revoked credential has no remaining secret reader; new writes obey the same invariant as
/// revocation and the v7 repair, without ever persisting supplied secret material.
fn validate_revoked_credential(op: &str, secret: &CredentialSecret) -> RecordStoreResult<()> {
    if secret.meta.revoked_at.is_some()
        && (!secret.secret.is_empty() || secret.meta.secret_form != SecretForm::None)
    {
        return Err(RecordStoreError(format!(
            "{op}: a revoked credential must have no secret and secret_form None"
        )));
    }
    Ok(())
}

/// `put_credential`'s owner precondition, read inside its WATCHed transaction: the key row named by
/// `key_id` must exist and must not be tombstoned. An unparseable owner row is refused too — a
/// credential cannot be attached to a key whose liveness cannot be established.
async fn owner_is_live(c: &mut Conn, key_row: &str, key_id: &str, op: &str) -> RedisResult<()> {
    let raw: Option<String> = c.get(key_row).await?;
    let refuse = |why: String| Err(RedisError::refused(why));
    let Some(raw) = raw else {
        return refuse(format!(
            "{op}: key '{key_id}' does not exist; a credential must hang off a real key"
        ));
    };
    match key_from_json(&raw) {
        Ok(k) if k.deleted_at.is_none() => Ok(()),
        Ok(_) => refuse(format!(
            "{op}: key '{key_id}' is tombstoned; its credentials were revoked with it \
             and are never reissued"
        )),
        Err(_) => refuse(format!(
            "{op}: key '{key_id}' does not decode; refusing to attach a credential to it"
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

/// The credential mints' names, in the refusals that name the calling method.
const OP_PUT_CREDENTIAL: &str = "put_credential";
const OP_PUT_KEY_WITH_CREDENTIAL: &str = "put_key_with_credential";

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
/// under its own id, a credential id lives in one slot, and `UNIQUE(kind, public_id)` is a real
/// read of the pointer (a `SETNX` queued in an `.ignore()`d pipe would discard the "already
/// claimed" answer).
async fn read_slot(c: &mut Conn, secret: &CredentialSecret, op: &str) -> RedisResult<Slot> {
    let m = &secret.meta;
    let row_key = cred_row_key(&m.key_id, &m.kind, m.slot);
    let existing: Option<String> = c.get(&row_key).await?;
    let existing = existing.map(Zeroizing::new);
    let mut prior = None;
    if let Some(raw) = &existing {
        let cur = OwnedCredential(serde_json::from_str(raw).map_err(|_| {
            RedisError::from((ErrorKind::Client, "credential row does not decode", row_key))
        })?);
        if cur.meta.revoked_at.is_none() {
            if cur.meta.id == m.id {
                let mut same = cur;
                same.meta.revision = m.revision;
                if same.0 != *secret {
                    return Err(RedisError::refused(format!(
                        "{op}: credential '{}' already exists with different content",
                        m.id
                    )));
                }
                return Ok(Slot::Replay);
            }
            return Err(RedisError::refused(format!(
                "{op}: slot {} for key '{}' kind '{}' holds a live credential; revoke it first",
                m.slot, m.key_id, m.kind
            )));
        }
        if cur.meta.id == m.id {
            return Err(RedisError::refused(format!(
                "{op}: credential '{}' is revoked; a revoked credential is never re-minted",
                m.id
            )));
        }
        prior = Some((cur.meta.public_id.clone(), cur.meta.id.clone()));
    }
    let ptr = slot_pointer(m);
    let id_holder: Option<String> = c.get(cred_id_key(&m.id)).await?;
    if id_holder.is_some_and(|h| h != ptr) {
        return Err(RedisError::refused(format!(
            "{op}: credential '{}' already exists in another slot",
            m.id
        )));
    }
    let holder: Option<String> = c.get(cred_pub_key(&m.kind, &m.public_id)).await?;
    if holder.is_some_and(|h| h != ptr) {
        return Err(RedisError::refused(format!(
            "{op}: public_id '{}' is already in use for kind '{}'",
            m.public_id, m.kind
        )));
    }
    Ok(Slot::Free(prior))
}

/// A credential's `<key_id>:<kind>:<slot>` pointer.
fn slot_pointer(m: &CredentialMeta) -> String {
    pointer(&m.key_id, &m.kind, m.slot)
}

/// The pointer of the slot `(key_id, kind, slot)`.
fn pointer(key_id: &str, kind: &str, slot: u8) -> String {
    format!("{key_id}:{kind}:{slot}")
}

/// A key's credential-index member for a slot: `<kind>:<slot>`.
fn member(kind: &str, slot: u8) -> String {
    format!("{kind}:{slot}")
}

/// The refusal for a credential-index member that is not `<kind>:<slot>`.
fn corrupt_index_member() -> RedisError {
    RedisError::from((
        ErrorKind::Client,
        "delete_key: corrupt credential-index member",
    ))
}

/// The inverse of [`member`].
fn parse_member(m: &str) -> Option<(&str, u8)> {
    let (kind, slot) = m.split_once(':')?;
    Some((kind, slot.parse().ok()?))
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
    let json = Zeroizing::new(
        cred_to_json(secret).map_err(|_| RedisError::from((ErrorKind::Client, "cred encode")))?,
    );
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
    pipe.set(cred_row_key(&m.key_id, &m.kind, m.slot), json.as_str())
        .ignore();
    pipe.sadd(cred_ids_key(&m.key_id), member(&m.kind, m.slot))
        .ignore();
    pipe.zadd(CREDS_BYREV, &ptr, m.revision).ignore();
    Ok(())
}

/// A decode failure in words that name where, never the stored value (serde's type errors echo it).
fn decode_text(e: &serde_json::Error) -> String {
    if e.is_data() {
        format!(
            "a value does not fit its type at line {} column {}",
            e.line(),
            e.column()
        )
    } else {
        e.to_string()
    }
}

fn key_from_json(raw: &str) -> RecordStoreResult<VirtualKey> {
    serde_json::from_str(raw)
        .map_err(|e| RecordStoreError(format!("key decode failed: {}", decode_text(&e))))
}
fn cred_to_json(cred: &CredentialSecret) -> RecordStoreResult<String> {
    serde_json::to_string(cred)
        .map_err(|e| RecordStoreError(format!("credential encode failed: {e}")))
}
/// The credential row stored at `row`, decoded for `op`; a failure names the row, never its value.
fn cred_from_json(op: &str, row: &str, raw: &str) -> RecordStoreResult<CredentialSecret> {
    serde_json::from_str(raw).map_err(|e| {
        RecordStoreError(format!(
            "{op}: credential row '{row}' does not decode: {}",
            decode_text(&e)
        ))
    })
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
fn usage_fields(delta: &UsageDelta) -> Vec<(String, i128)> {
    let mut fields: Vec<(String, i128)> = vec![
        ("requests".to_string(), i128::from(delta.requests)),
        (
            "billable_requests".to_string(),
            i128::from(delta.billable_requests),
        ),
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

/// The rows of a metering bucket: `KEYS[1]` = the bucket's row set; each row's `HGETALL`, in one
/// atomic step.
static LIST_METERING: std::sync::LazyLock<Script> = std::sync::LazyLock::new(|| {
    Script::new(
        r"
        local out = {}
        for _, row in ipairs(redis.call('SMEMBERS', KEYS[1])) do
            out[#out + 1] = redis.call('HGETALL', row)
        end
        return out",
    )
});

/// Decode exact unsigned ledger counters while retaining the legacy negative-as-zero read rule.
fn ledger_count(value: &str) -> RecordStoreResult<u64> {
    value
        .parse::<u64>()
        .or_else(|_| value.parse::<i64>().map(read_u64))
        .map_err(|_| RecordStoreError("invalid ledger counter".into()))
}

/// Quantity mantissas are exact signed-i128 values with a nonnegative persisted-total invariant.
/// Request counters retain their separate unsigned reader and are never scaled.
fn quantity_count(value: &str) -> RecordStoreResult<i128> {
    value
        .parse::<i128>()
        .ok()
        .filter(|count| *count >= 0)
        .ok_or_else(|| RecordStoreError("invalid nonnegative quantity mantissa".into()))
}

/// The ordinary reader and correction predicate use the same canonical raw ledger.
fn usage_from_fields(fields: Vec<(String, String)>) -> RecordStoreResult<UsageLedger> {
    let mut ledger = UsageLedger::default();
    let mut positions = std::collections::HashMap::new();
    for (name, v) in fields {
        if name == "requests" {
            ledger.requests = ledger_count(&v)?;
            continue;
        }
        if name == "billable_requests" {
            ledger.billable_requests = ledger_count(&v)?;
            continue;
        }
        let Some((model, unit)) = parse_usage_field(&name) else {
            return Err(RecordStoreError(format!(
                "unreadable usage field {name}; refusing to report a partial ledger"
            )));
        };
        let count = quantity_count(&v)?;
        let index = *positions.entry(model.clone()).or_insert_with(|| {
            let index = ledger.models.len();
            ledger.models.push(ModelTokens {
                scale: 6,
                model,
                ..Default::default()
            });
            index
        });
        let entry = &mut ledger.models[index];

        if count != 0 {
            entry.usage_units.insert(unit, count);
        }
    }
    ledger.models.sort_by(|a, b| a.model.cmp(&b.model));
    Ok(ledger)
}

/// Decode all C4 counts and historical pricing fields without signed narrowing.
fn metering_from_fields(fields: Vec<(String, String)>) -> RecordStoreResult<MeteringRow> {
    let mut m = MeteringRow {
        scale: 6,
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
        if let Some(class) = name.strip_prefix(METERING_UNIT_PREFIX) {
            let n = quantity_count(&val)?;
            if n != 0 {
                m.usage_units.insert(class.to_string(), n);
            }
            continue;
        }
        match name.as_str() {
            "key_id" => m.key_id = val,
            "model" => m.model = val,
            "provider" => m.provider = val,
            "tokens_input" => m.tokens_input = quantity_count(&val)?,
            "tokens_output" => m.tokens_output = quantity_count(&val)?,
            "tokens_cache_read" => m.tokens_cache_read = quantity_count(&val)?,
            "tokens_cache_write" => m.tokens_cache_write = quantity_count(&val)?,
            "requests" => m.requests = ledger_count(&val)?,
            "billable_requests" => m.billable_requests = ledger_count(&val)?,
            "priced_from_ms" => {
                m.priced_from_ms = val.parse::<u64>().map_err(|e| {
                    RecordStoreError(format!("list_metering: bad priced_from_ms value: {e}"))
                })?
            }
            "key_group_at_use" => m.key_group_at_use = val,
            "pricing_version" => m.pricing_version = val,
            _ => {}
        }
    }
    Ok(m)
}

/// Mark the schema: `KEYS[1]` = the marker, `ARGV[1]` = the version this run read (empty for none),
/// `ARGV[2]` = the version to write. Written only if the marker still is what this run read; else
/// nothing is written and the marker now there is returned, so a newer build's mark is never
/// overwritten.
static SET_SCHEMA_MARKER: std::sync::LazyLock<Script> = std::sync::LazyLock::new(|| {
    Script::new(
        r"
        local cur = redis.call('GET', KEYS[1])
        -- Compared by value too: a restored marker may be spelled `06` or `+6`, which the
        -- caller read as 6 and expects to match.
        local n = cur and tonumber(cur)
        if (not cur and ARGV[1] == '') or cur == ARGV[1]
            or (n and n == tonumber(ARGV[1])) then
            redis.call('SET', KEYS[1], ARGV[2])
            return false
        end
        return cur or 'missing'",
    )
});

/// The base op set's bodies, each over the op's one connection `c` (the store door, `slots`, runs
/// each as one op through the host's connector). The `op_id` writes (`add_usage_batch`,
/// `add_metering_batch`, `append_plane_record`) are the door's own slots, deduped durably.
impl ValkeyStore {
    pub(crate) async fn put_key(&self, c: &mut Conn, key: &VirtualKey) -> RecordStoreResult<()> {
        let row_key = format!("{KEY_PREFIX}{}", key.id);
        with_conn!(self, |c| {
            // A live-shaped write must not clear a tombstone (an id is never reissued), WATCHed so
            // a `delete_key` committing in between aborts and retries this.
            transaction!(c, &[row_key.as_str(), REVISION_KEY], |c, pipe| {
                if key.deleted_at.is_none() && tombstoned(c, &row_key).await? {
                    return Err(RedisError::refused(format!(
                        "put_key: '{}' is tombstoned and its id is never reissued; \
                             refusing to clear the tombstone",
                        key.id
                    )));
                }
                let mut key = key.clone();
                pipe.atomic();
                let rev = self.next_revision(c, pipe, 1).await?;
                key.revision = rev;
                let json = serde_json::to_string(&key)
                    .map_err(|_e| RedisError::from((ErrorKind::Client, "encode")))?;
                pipe.set(&row_key, &json)
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
        self.delta_rows(c, KEYS_BYREV, since, |id| Some(format!("{KEY_PREFIX}{id}")))
            .await?
            .into_iter()
            .filter_map(|(_, raw, unstamped)| {
                key_from_json(&raw)
                    .map(|row| (unstamped || row.revision > since).then_some(row))
                    .transpose()
            })
            .collect()
    }

    /// Read index membership and values from one stable revision snapshot. A writer between
    /// enumeration and GET must abort the read, otherwise a newer row can advance the caller's
    /// cursor beyond an intervening row the index snapshot did not include.
    async fn delta_rows(
        &self,
        c: &mut Conn,
        zset: &str,
        since: u64,
        key_of: fn(&str) -> Option<String>,
    ) -> RecordStoreResult<Vec<(String, String, bool)>> {
        with_conn!(self, |c| {
            transaction!(c, &[zset, REVISION_KEY], |c, reads| {
                let (unstamped, stamped): (Vec<String>, Vec<String>) = pipe()
                    .cmd("ZRANGEBYSCORE")
                    .arg(zset)
                    .arg(0)
                    .arg(0)
                    .cmd("ZRANGEBYSCORE")
                    .arg(zset)
                    // Scores are doubles: distinct revisions above 2^53 may share a score.
                    // Include that score, then compare decoded u64 revisions at the caller.
                    // Zero-score legacy rows are read separately and always returned.
                    .arg(since.max(1))
                    .arg("+inf")
                    .query(c)
                    .await?;
                let keys: Vec<_> = unstamped
                    .iter()
                    .map(|m| (m, true))
                    .chain(stamped.iter().map(|m| (m, false)))
                    .map(|(m, legacy)| {
                        key_of(m).map(|key| (key, legacy)).ok_or_else(|| {
                            RedisError::refused("delta_rows: revision index member does not parse")
                        })
                    })
                    .collect::<RedisResult<Vec<_>>>()?;
                // An EXEC here would clear WATCH before the values are read. Keep the index
                // queries ordinary and validate them with the final read-only EXEC, even empty.
                reads.get(REVISION_KEY).ignore();
                for (key, _) in &keys {
                    reads.get(key);
                }
                let raw: Option<Vec<Option<String>>> = reads.query(c).await?;
                Ok(raw.map(|values| {
                    keys.into_iter()
                        .zip(values)
                        .filter_map(|((key, legacy), raw)| Some((key, raw?, legacy)))
                        .collect()
                }))
            })
        })
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

        with_conn!(self, |c| loop {
            let members: Vec<String> = c.smembers(&ids_key).await?;
            // An index member that does not parse names a slot we cannot find: refuse, rather than
            // delete the index and strand that slot's row and pointers behind a success.
            let row_keys: Vec<String> = members
                .iter()
                .map(|m| {
                    parse_member(m)
                        .map(|(kind, slot)| cred_row_key(id, kind, slot))
                        .ok_or_else(corrupt_index_member)
                })
                .collect::<Result<_, _>>()?;
            let mut watch_keys: Vec<&str> = vec![key_row.as_str(), ids_key.as_str(), REVISION_KEY];
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
                    // Already tombstoned: an idempotent no-op, no EXEC (it would contend on the
                    // watched revision for nothing).
                    return Ok(Some(()));
                }
                // `transaction!` re-runs this body with the SAME watch set: a membership change
                // goes back to the outer loop to rebuild it.
                let fresh_members: Vec<String> = c.smembers(&ids_key).await?;
                if fresh_members.len() != members.len()
                    || !fresh_members.iter().all(|m| members.contains(m))
                {
                    return Err(RedisError::retry());
                }
                pipe.atomic();
                let rev = self.next_revision(c, pipe, 1).await?;
                key.enabled = false;
                key.deleted_at = Some(crate::now());
                key.revision = rev;
                let key_json = serde_json::to_string(&key)
                    .map_err(|_| RedisError::from((ErrorKind::Client, "key encode")))?;

                pipe.set(&key_row, &key_json).ignore();
                pipe.zadd(KEYS_BYREV, id, rev).ignore();
                // Destroy every credential row and its pointers (a consumer evicts off the key's
                // own tombstone delta).
                for m in &members {
                    let (kind, slot) = parse_member(m).ok_or_else(corrupt_index_member)?;
                    let row_key = cred_row_key(id, kind, slot);
                    // A row that does not decode aborts the cascade: skipping it would leave its
                    // pointers dangling behind a reported success.
                    if let Some(raw) = c.get::<_, Option<String>>(&row_key).await? {
                        let raw = Zeroizing::new(raw);
                        let cred = OwnedCredential(serde_json::from_str(&raw).map_err(|_| {
                            RedisError::from((
                                ErrorKind::Client,
                                "delete_key: corrupt credential row",
                            ))
                        })?);
                        pipe.del(cred_pub_key(kind, &cred.meta.public_id)).ignore();
                        pipe.del(cred_id_key(&cred.meta.id)).ignore();
                    }
                    pipe.del(&row_key).ignore();
                    pipe.cmd("ZREM")
                        .arg(CREDS_BYREV)
                        .arg(pointer(id, kind, slot))
                        .ignore();
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
        let fields: Vec<(String, String)> = with_conn!(self, |c| c.hgetall(&k).await)?;
        usage_from_fields(fields).map_err(|e| RecordStoreError(format!("usage row {k}: {e}")))
    }

    pub(crate) async fn purge_usage_before(
        &self,
        c: &mut Conn,
        before: u64,
    ) -> RecordStoreResult<u64> {
        if before == 0 {
            return Ok(0);
        }
        let mut cursor = String::from("0");
        let mut removed = 0_u64;
        loop {
            let (next, keys) = with_conn!(self, |c| c.scan_page(&cursor, "busbar:usage:*").await)?;
            let expired: Vec<String> = keys
                .into_iter()
                .filter(|key| expired_usage_key(key, before))
                .collect();
            if !expired.is_empty() {
                let deleted: u64 =
                    with_conn_no_retry!(self, |c| cmd("DEL").arg(&expired).query(c).await)?;
                removed = removed.checked_add(deleted).ok_or_else(|| {
                    RecordStoreError("usage cleanup removed-window count overflow".into())
                })?;
            }
            if next == "0" {
                return Ok(removed);
            }
            cursor = next;
        }
    }

    pub(crate) async fn put_usage(
        &self,
        c: &mut Conn,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> RecordStoreResult<()> {
        let mut ledger = ledger.clone();
        ledger
            .normalize_scale6()
            .map_err(|e| RecordStoreError(e.to_string()))?;
        let ledger = &ledger;

        if busbar_contract::abi::sdk::store::correction::reserved_bucket(bucket_id) {
            return Err(RecordStoreError(
                "reserved adjustment rows require atomic usage correction".into(),
            ));
        }
        let k = usage_key(bucket_id, window_start);
        with_conn!(self, |c| {
            let mut pipe = pipe();
            pipe.atomic();
            pipe.del(&k).ignore();
            pipe.hset(&k, "requests", ledger.requests).ignore();
            pipe.hset(&k, "billable_requests", ledger.billable_requests)
                .ignore();
            for m in &ledger.models {
                for (unit, n) in &m.usage_units {
                    pipe.hset(&k, usage_field(&m.model, unit), *n).ignore();
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

        let all_fields: Vec<Vec<(String, String)>> =
            with_conn!(self, |c| LIST_METERING.key(&set).invoke(c).await)?;
        all_fields
            .into_iter()
            .filter(|fields| !fields.is_empty())
            .map(metering_from_fields)
            .collect()
    }

    pub(crate) async fn put_credential(
        &self,
        c: &mut Conn,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        validate_revoked_credential(OP_PUT_CREDENTIAL, secret)?;
        let m = &secret.meta;
        let row_key = cred_row_key(&m.key_id, &m.kind, m.slot);
        let pub_key = cred_pub_key(&m.kind, &m.public_id);
        let key_row = format!("{KEY_PREFIX}{}", m.key_id);
        let id_key = cred_id_key(&m.id);
        with_conn!(self, |c| {
            // WATCHed: the owning key's row (a `delete_key` in between must abort this, never slip
            // under it), the slot's row, the public id and credential id pointers.
            let watched = [
                row_key.as_str(),
                pub_key.as_str(),
                id_key.as_str(),
                key_row.as_str(),
                REVISION_KEY,
            ];
            transaction!(c, &watched, |c, pipe| {
                owner_is_live(c, &key_row, &m.key_id, OP_PUT_CREDENTIAL).await?;
                let prior = match read_slot(c, secret, OP_PUT_CREDENTIAL).await? {
                    Slot::Replay => return Ok(Some(())),
                    Slot::Free(prior) => prior,
                };
                let mut secret = OwnedCredential(secret.clone());
                pipe.atomic();
                secret.meta.revision = self.next_revision(c, pipe, 1).await?;
                queue_credential(pipe, &secret, &prior)?;
                pipe.query(c).await
            })
        })
    }

    pub(crate) async fn rewrap_credential(
        &self,
        c: &mut Conn,
        expected: &CredentialSecret,
        replacement: &str,
    ) -> RecordStoreResult<bool> {
        if expected.meta.revoked_at.is_some()
            || expected.meta.secret_form != SecretForm::Recoverable
            || expected.secret == replacement
        {
            return Ok(false);
        }
        let meta = &expected.meta;
        let row_key = cred_row_key(&meta.key_id, &meta.kind, meta.slot);
        let owner_key = format!("{KEY_PREFIX}{}", meta.key_id);
        let id_key = cred_id_key(&meta.id);
        let pub_key = cred_pub_key(&meta.kind, &meta.public_id);
        let pointer = slot_pointer(meta);

        with_conn_no_retry!(self, |c| {
            let watched = [
                row_key.as_str(),
                owner_key.as_str(),
                id_key.as_str(),
                pub_key.as_str(),
                REVISION_KEY,
                CREDS_BYREV,
            ];
            transaction!(c, &watched, |c, pipe| {
                let owner: Option<String> = c.get(&owner_key).await?;
                let Some(owner) = owner.map(zeroize::Zeroizing::new) else {
                    return Ok(Some(false));
                };
                let owner = key_from_json(&owner).map_err(|_| {
                    RedisError::from((ErrorKind::Client, "credential owner decode"))
                })?;
                if owner.id != meta.key_id || owner.deleted_at.is_some() {
                    return Ok(Some(false));
                }
                let id_pointer: Option<String> = c.get(&id_key).await?;
                let pub_pointer: Option<String> = c.get(&pub_key).await?;
                if id_pointer.as_deref() != Some(pointer.as_str())
                    || pub_pointer.as_deref() != Some(pointer.as_str())
                {
                    return Ok(Some(false));
                }
                let raw: Option<String> = c.get(&row_key).await?;
                let Some(raw) = raw.map(zeroize::Zeroizing::new) else {
                    return Ok(Some(false));
                };
                let mut current: CredentialSecret = serde_json::from_str(&raw).map_err(|_| {
                    RedisError::from((ErrorKind::Client, "credential rewrap decode"))
                })?;
                let matches = &current == expected;
                zeroize::Zeroize::zeroize(&mut current.secret);
                if !matches {
                    return Ok(Some(false));
                }
                // EXEC does not roll back a runtime WRONGTYPE. Check and WATCH the only
                // non-SET target before queuing any write.
                let index_type: String = cmd("TYPE").arg(CREDS_BYREV).query(c).await?;
                if index_type != "none" && index_type != "zset" {
                    return Err(RedisError::from((
                        ErrorKind::Client,
                        "credential revision index has the wrong type",
                    )));
                }
                current.meta.revision = self.next_revision(c, pipe, 1).await?;
                current.secret = replacement.to_owned();
                let encoded = cred_to_json(&current);
                zeroize::Zeroize::zeroize(&mut current.secret);
                let encoded = zeroize::Zeroizing::new(encoded.map_err(|_| {
                    RedisError::from((ErrorKind::Client, "credential rewrap encode"))
                })?);
                pipe.set(&row_key, encoded.as_str()).ignore();
                pipe.zadd(CREDS_BYREV, &pointer, current.meta.revision)
                    .ignore();
                pipe.query::<Option<()>>(c)
                    .await
                    .map(|answer| answer.map(|()| true))
            })
        })
    }

    pub(crate) async fn put_key_with_credential(
        &self,
        c: &mut Conn,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> RecordStoreResult<()> {
        validate_revoked_credential(OP_PUT_KEY_WITH_CREDENTIAL, secret)?;
        if key.deleted_at.is_some() {
            return Err(RecordStoreError(format!(
                "{OP_PUT_KEY_WITH_CREDENTIAL}: key '{}' is tombstoned; a credential is never \
                 minted onto it",
                key.id
            )));
        }
        if secret.meta.key_id != key.id {
            return Err(RecordStoreError(format!(
                "{OP_PUT_KEY_WITH_CREDENTIAL}: the credential names key '{}', not the key '{}' \
                 being minted with it",
                secret.meta.key_id, key.id
            )));
        }

        let m = &secret.meta;
        let key_row = format!("{KEY_PREFIX}{}", key.id);
        let row_key = cred_row_key(&m.key_id, &m.kind, m.slot);
        let pub_key = cred_pub_key(&m.kind, &m.public_id);
        let id_key = cred_id_key(&m.id);
        with_conn!(self, |c| {
            transaction!(
                c,
                &[
                    key_row.as_str(),
                    row_key.as_str(),
                    pub_key.as_str(),
                    id_key.as_str(),
                    REVISION_KEY
                ],
                |c, pipe| {
                    if tombstoned(c, &key_row).await? {
                        return Err(RedisError::refused(format!(
                            "{OP_PUT_KEY_WITH_CREDENTIAL}: '{}' is tombstoned and its id is \
                             never reissued",
                            key.id
                        )));
                    }
                    let prior = match read_slot(c, secret, OP_PUT_KEY_WITH_CREDENTIAL).await? {
                        Slot::Replay => {
                            let raw: Option<String> = c.get(&key_row).await?;
                            let same = raw
                                .as_deref()
                                .map(key_from_json)
                                .transpose()
                                .map_err(|e| RedisError::refused(e.0))?
                                .is_some_and(|mut stored| {
                                    stored.revision = key.revision;
                                    stored == *key
                                });
                            if !same {
                                return Err(RedisError::refused(format!(
                                    "{OP_PUT_KEY_WITH_CREDENTIAL}: credential '{}' already exists with a different owning key",
                                    m.id
                                )));
                            }
                            return Ok(Some(()));
                        }
                        Slot::Free(prior) => prior,
                    };
                    let (mut key, mut secret) = (key.clone(), OwnedCredential(secret.clone()));
                    pipe.atomic();
                    key.revision = self.next_revision(c, pipe, 2).await?;
                    secret.meta.revision = key.revision + 1;
                    let key_json = serde_json::to_string(&key)
                        .map_err(|_| RedisError::from((ErrorKind::Client, "key encode")))?;
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
            .map(|m| {
                let (kind, slot) = parse_member(m).ok_or_else(|| {
                    RecordStoreError("list_credentials: corrupt credential index member".into())
                })?;
                Ok(cred_row_key(key_id, kind, slot))
            })
            .collect::<RecordStoreResult<_>>()?;

        let raws = self.get_all(c, &row_keys).await?;
        let mut metas = row_keys
            .iter()
            .zip(raws)
            .filter_map(|(row, raw)| Some((row, raw?)))
            .map(|(row, raw)| cred_from_json("list_credentials", row, &raw).map(|c| c.meta.clone()))
            .collect::<RecordStoreResult<Vec<_>>>()?;
        metas.sort_by(|a, b| a.kind.cmp(&b.kind).then(a.slot.cmp(&b.slot)));
        Ok(metas)
    }

    pub(crate) async fn revoke_credential(
        &self,
        c: &mut Conn,
        id: &str,
        reason: &str,
    ) -> RecordStoreResult<()> {
        let id_key = cred_id_key(id);
        with_conn!(self, |c| loop {
            // The row to rewrite is named by the pointer, so the pointer is read first, then BOTH
            // are WATCHed (a pointer that moves in between reruns this from the top).
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
            let watched = [id_key.as_str(), row_key.as_str(), REVISION_KEY];
            let outcome = transaction!(c, &watched, |c, pipe| {
                let now_ptr: Option<String> = c.get(&id_key).await?;
                if now_ptr.as_deref() != Some(ptr.as_str()) {
                    return Err(RedisError::retry());
                }
                let raw: Option<String> = c.get(&row_key).await?;
                let Some(raw) = raw else {
                    return Err(RedisError::refused(format!(
                        "revoke_credential: busbar:cred:id:{id} -> {ptr} names no credential row '{row_key}' (dangling pointer); nothing was revoked"
                    )));
                };
                let raw = Zeroizing::new(raw);
                let mut cred = OwnedCredential(
                    cred_from_json("revoke_credential", &row_key, &raw)
                        .map_err(|e| RedisError::refused(e.0))?,
                );
                if cred.meta.id != id || slot_pointer(&cred.meta) != ptr {
                    return Err(RedisError::refused(format!(
                        "revoke_credential: stale pointer busbar:cred:id:{id} -> {ptr} holds credential '{}' at row '{row_key}'; nothing was revoked",
                        cred.meta.id
                    )));
                }
                if cred.meta.revoked_at.is_some() {
                    // Already revoked: idempotent no-op.
                    return Ok(Some(()));
                }
                pipe.atomic();
                let rev = self.next_revision(c, pipe, 1).await?;
                cred.meta.revoked_at = Some(crate::now());
                cred.meta.revoke_reason = Some(reason.to_string());
                cred.meta.revision = rev;
                // Destroy the secret material on revoke — defense in depth: a revoked credential's
                // plaintext has no further legitimate reader, so there is no reason to retain it.
                cred.secret.zeroize();
                cred.meta.secret_form = SecretForm::None;
                let json = cred_to_json(&cred)
                    .map_err(|_| RedisError::from((ErrorKind::Client, "cred encode")))?;
                pipe.set(&row_key, json.as_str()).ignore();
                pipe.zadd(CREDS_BYREV, pointer(&key_id, &kind, slot), rev)
                    .ignore();
                pipe.query(c).await
            });
            match outcome {
                Err(e) if e.is_retry() => continue,
                other => break other,
            }
        })
    }

    pub(crate) async fn list_credentials_since(
        &self,
        c: &mut Conn,
        since: u64,
    ) -> RecordStoreResult<Vec<CredentialSecret>> {
        self.delta_rows(c, CREDS_BYREV, since, |member| {
            let (key_id, kind, slot) = parse_slot_pointer(member)?;
            Some(cred_row_key(&key_id, &kind, slot))
        })
        .await?
        .into_iter()
        .filter_map(|(key, raw, unstamped)| {
            cred_from_json("list_credentials_since", &key, &raw)
                .map(|row| (unstamped || row.meta.revision > since).then_some(row))
                .transpose()
        })
        .collect()
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
                serde_json::from_str(m).map_err(|e| {
                    RecordStoreError(format!("audit decode failed: {}", decode_text(&e)))
                })
            })
            .collect()
    }

    pub(crate) async fn list_audit_tail(
        &self,
        c: &mut Conn,
        limit: u64,
    ) -> RecordStoreResult<Vec<AuditRecord>> {
        if limit == 0 {
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
                .cmd("SET")
                .arg(format!("{DENYLIST_PREFIX}{sub}"))
                .arg(reason)
                .arg("NX")
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

/// Current unix time in seconds, stamped on tombstones and revocations (advisory metadata; the store
/// has no injected clock and does no admission math with it).
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

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
        Self::from_settings_lent(settings, &[])
    }

    fn from_settings_lent(settings: &[u8], secrets: &[&[u8]]) -> Result<Self, String> {
        const BAD: &str = "invalid valkey plugin config";

        struct Settings {
            url: Option<ValkeyUrl>,
            connect_timeout_ms: Option<serde_json::Value>,
        }
        impl<'de> serde::Deserialize<'de> for Settings {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                struct SettingsVisitor;
                impl<'de> serde::de::Visitor<'de> for SettingsVisitor {
                    type Value = Settings;
                    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        f.write_str("a JSON object")
                    }
                    fn visit_map<M: serde::de::MapAccess<'de>>(
                        self,
                        mut map: M,
                    ) -> Result<Settings, M::Error> {
                        let mut out = Settings {
                            url: None,
                            connect_timeout_ms: None,
                        };
                        let mut unknown = None;
                        let mut url_error = None;
                        while let Some(key) = map.next_key::<String>()? {
                            match key.as_str() {
                                "url" => match map.next_value() {
                                    Ok(url) => out.url = url,
                                    Err(error) => url_error = Some(error),
                                },
                                "connect_timeout_ms" => {
                                    out.connect_timeout_ms = map.next_value()?
                                }
                                _ => {
                                    map.next_value::<serde::de::IgnoredAny>()?;
                                    unknown.get_or_insert(key);
                                }
                            }
                        }

                        if let Some(key) = unknown {
                            return Err(serde::de::Error::unknown_field(
                                &key,
                                &["url", "connect_timeout_ms"],
                            ));
                        }
                        if let Some(error) = url_error {
                            return Err(error);
                        }
                        Ok(out)
                    }
                }
                d.deserialize_map(SettingsVisitor)
            }
        }
        let settings = if settings.iter().all(u8::is_ascii_whitespace) {
            b"{}"
        } else {
            settings
        };
        let parsed: Settings = settings_lent(settings, secrets).map_err(|e| {
            let text = e.to_string();
            let shape = if text.contains("integer") || text.contains("floating point") {
                "a number"
            } else if text.contains("boolean") {
                "a boolean"
            } else if text.contains("sequence") {
                "an array"
            } else if text.contains("map") {
                "an object"
            } else if text.contains("string") {
                "a string"
            } else {
                "null"
            };
            if let Some(rest) = text.strip_prefix("settings: unknown field `") {
                let key = rest.split('`').next().unwrap_or("");
                format!("{BAD}: unknown setting `{key}` (accepted: url, connect_timeout_ms)")
            } else if e.path() == "url" && text.contains("invalid type") {
                format!("{BAD}: `url` must be a non-empty string, got {shape}")
            } else if e.path().is_empty() && text.contains("invalid type") {
                format!("{BAD}: expected a JSON object, got {shape}")
            } else {
                format!("{BAD}: {e}")
            }
        })?;
        let url = parsed
            .url
            .ok_or_else(|| format!("{BAD}: `url` is required (a redis:// connection string)"))?;
        if url.public().trim().is_empty() && url.parsing_error().is_none() {
            return Err(format!("{BAD}: `url` must be a non-empty string"));
        }
        let timeout = match parsed.connect_timeout_ms {
            None | Some(serde_json::Value::Null) => DEFAULT_CONNECT_TIMEOUT,
            Some(x) => match x.as_u64().filter(|ms| *ms > 0) {
                Some(ms) => Duration::from_millis(ms),
                None => {
                    // A number is not secret: echo it, so `0` or `2.5` does not read as a type error.
                    let got = match x {
                        serde_json::Value::Number(n) => n.to_string(),
                        other => json_type(&other).to_string(),
                    };
                    return Err(format!(
                        "{BAD}: `connect_timeout_ms` must be a positive integer (milliseconds), \
                         got {got}"
                    ));
                }
            },
        };
        let target =
            parse_target(&url).map_err(|e| url.redact_echo(&format!("{BAD}: url: {e}")))?;
        Ok(Self {
            inner: Arc::new(Inner {
                target,
                url,
                connect_timeout: timeout,
                pool: Pool::new(KEPT_CONNECTIONS),
            }),
        })
    }
}

/// A JSON value's type, as a settings refusal names it (never the value).
fn json_type(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}

mod slots;

/// The store door (store v3, `busbar_contract::abi::store`): every slot of the store v3 table over
/// [`ValkeyStore`], through the contract's store SDK.
pub use slots::door;

/// Unlike the legacy three/four-component row key, this always has six escaped components.
fn attributed_metering_row(
    bucket: u64,
    key_id: &str,
    model: &str,
    provider: &str,
    priced_from_ms: u64,
    group: &str,
    version: &str,
) -> String {
    format!(
        "busbar:metering:{bucket}:{}|{}|{}|{priced_from_ms}|{}|{}",
        escape(key_id, ROW_SEP),
        escape(model, ROW_SEP),
        escape(provider, ROW_SEP),
        escape(group, ROW_SEP),
        escape(version, ROW_SEP)
    )
}

/// Rename whole hashes without decoding or rewriting their counters or unknown fields.
/// Every fallible shape/identity check precedes the first mutation: Lua errors do not roll back.
static MIGRATE_METERING_ATTRIBUTION: std::sync::LazyLock<Script> = std::sync::LazyLock::new(|| {
    Script::new(
        r#"
        if redis.call('TYPE', KEYS[1]).ok ~= 'set' then return 'metering index is not a set' end
        local ty = redis.call('TYPE', KEYS[2]).ok
        if ty == 'none' then
            if redis.call('SISMEMBER', KEYS[1], KEYS[2]) == 0 then return '' end
            return 'metering index has a missing row'
        end
        if ty ~= 'hash' then return 'metering row is not a hash' end
        local fields = {'key_id', 'model', 'provider', 'priced_from_ms', 'key_group_at_use', 'pricing_version'}
        for i, f in ipairs(fields) do
            local found = redis.call('HGET', KEYS[2], f)
            if not found then found = (i == 4 and '0' or '') end
            if found ~= ARGV[i] then return 'metering identity changed during migration' end
        end
        if KEYS[2] == KEYS[3] then return '' end
        if redis.call('EXISTS', KEYS[3]) ~= 0 then return 'metering attribution destination already exists' end
        redis.call('RENAME', KEYS[2], KEYS[3])
        redis.call('SREM', KEYS[1], KEYS[2])
        redis.call('SADD', KEYS[1], KEYS[3])
        return ''
    "#,
    )
});

impl ValkeyStore {
    async fn migrate_metering_attribution(&self, c: &mut Conn) -> RecordStoreResult<()> {
        for set in self.scan(c, "busbar:metering:*").await? {
            let Some(suffix) = set.strip_prefix("busbar:metering:") else {
                continue;
            };

            if suffix.contains(':') {
                continue;
            }
            let bucket = suffix
                .parse::<u64>()
                .map_err(|_| RecordStoreError(format!("invalid metering bucket index {set:?}")))?;
            if set != metering_set(bucket) {
                return Err(RecordStoreError(format!(
                    "noncanonical metering bucket index {set:?}"
                )));
            }
            let rows: Vec<String> = with_conn!(self, |c| c.smembers(&set).await)?;
            for row in rows {
                let fields: Vec<Option<String>> = with_conn!(self, |c| cmd("HMGET")
                    .arg(&row)
                    .arg("key_id")
                    .arg("model")
                    .arg("provider")
                    .arg("priced_from_ms")
                    .arg("key_group_at_use")
                    .arg("pricing_version")
                    .query(c)
                    .await)?;
                if fields.len() != 6 {
                    return Err(RecordStoreError(
                        "invalid metering identity response".into(),
                    ));
                }

                if fields.iter().all(Option::is_none) {
                    let present: u64 = with_conn!(self, |c| cmd("SISMEMBER")
                        .arg(&set)
                        .arg(&row)
                        .query(c)
                        .await)?;
                    if present == 0 {
                        continue;
                    }
                    return Err(RecordStoreError(
                        "metering index has a missing or empty row".into(),
                    ));
                }
                let get = |index: usize| fields[index].as_deref().unwrap_or("");
                let price = fields[3].as_deref().unwrap_or("0");
                let priced_from = price.parse::<u64>().map_err(|_| {
                    RecordStoreError(format!("invalid metering price instant at {row:?}"))
                })?;
                let target = attributed_metering_row(
                    bucket,
                    get(0),
                    get(1),
                    get(2),
                    priced_from,
                    get(4),
                    get(5),
                );
                if row != target && row != metering_row(bucket, get(0), get(1), get(2), priced_from)
                {
                    return Err(RecordStoreError(format!(
                        "metering row {row:?} disagrees with attribution"
                    )));
                }
                let why: String = with_conn!(self, |c| MIGRATE_METERING_ATTRIBUTION
                    .key(&set)
                    .key(&row)
                    .key(&target)
                    .arg(get(0))
                    .arg(get(1))
                    .arg(get(2))
                    .arg(price)
                    .arg(get(4))
                    .arg(get(5))
                    .invoke(c)
                    .await)?;
                if !why.is_empty() {
                    return Err(RecordStoreError(why));
                }
            }
        }
        Ok(())
    }

    async fn repair_token_expiries(&self, c: &mut Conn) -> RecordStoreResult<()> {
        for key in self.scan(c, plane::TOKEN_PATTERN).await? {
            with_conn!(self, |c| plane::REPAIR_TOKEN_EXPIRY
                .key(&key)
                .invoke::<i64>(c)
                .await)?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

/// An internal credential copy whose secret is wiped on every exit, including refusals.
struct OwnedCredential(CredentialSecret);
impl std::ops::Deref for OwnedCredential {
    type Target = CredentialSecret;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for OwnedCredential {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for OwnedCredential {
    fn drop(&mut self) {
        self.0.secret.zeroize();
    }
}

/// Captured operation inputs retain wiping ownership while an async operation is pending.
trait SecureOwned {
    type Owned;
    fn secure_owned(&self) -> Self::Owned;
}
impl SecureOwned for CredentialSecret {
    type Owned = OwnedCredential;
    fn secure_owned(&self) -> Self::Owned {
        OwnedCredential(self.clone())
    }
}
impl SecureOwned for str {
    type Owned = Zeroizing<String>;
    fn secure_owned(&self) -> Self::Owned {
        Zeroizing::new(self.to_owned())
    }
}

/// No Lua numeric conversion touches a quantity: appending six zeroes is exact even beyond
/// IEEE-754's integer range. Every read/type/range check precedes the first write.
static MIGRATE_EXACT_COUNTS: std::sync::LazyLock<Script> = std::sync::LazyLock::new(|| {
    Script::new(
        r#"
        local marker = redis.call('GET', KEYS[1]) or ''
        -- Rust already parsed a supported small schema version. Match its value too, so a
        -- verified restored marker spelled '06' or '+6' does not prevent atomic migration.
        if marker ~= ARGV[1] and tonumber(marker) ~= tonumber(ARGV[1]) then return marker end
        local changes = {}
        local seen = {}
        local whole_units = tonumber(ARGV[1]) < 8
        local quantity_max = '170141183460469231731687303715884105727'
        for _, pattern in ipairs({'busbar:usage:*', 'busbar:metering:*'}) do
            local cursor = '0'
            repeat
                local page = redis.call('SCAN', cursor, 'MATCH', pattern, 'COUNT', 1000)
                cursor = page[1]
                for _, key in ipairs(page[2]) do
                    if not seen[key] then
                        seen[key] = true
                        local kind = redis.call('TYPE', key).ok
                        local usage = string.sub(key, 1, 13) == 'busbar:usage:'
                        if kind ~= 'hash' and kind ~= 'none' and not (not usage and kind == 'set') then
                            return redis.error_reply('exact count migration: invalid quantity key type; nothing converted')
                        end
                        if kind == 'hash' then
                            local fields = redis.call('HGETALL', key)
                            for i = 1, #fields, 2 do
                                local field, value = fields[i], fields[i + 1]
                                local quantity = usage and field ~= 'requests' and field ~= 'billable_requests'
                                if not usage then
                                    quantity = field == 'tokens_input' or field == 'tokens_output'
                                        or field == 'tokens_cache_read' or field == 'tokens_cache_write'
                                        or string.sub(field, 1, 2) == 'u:'
                                end
                                if quantity then
                                    if not string.match(value, '^%d+$') then
                                        return redis.error_reply('exact count migration: invalid quantity; nothing converted')
                                    end
                                    value = string.gsub(value, '^0+', '')
                                    if value == '' then value = '0' end
                                    local scaled = whole_units and value ~= '0' and value .. '000000' or value
                                    if #scaled > #quantity_max or (#scaled == #quantity_max and scaled > quantity_max) then
                                        return redis.error_reply('exact count migration: quantity outside i128 scale-6 range; nothing converted')
                                    end
                                    changes[#changes + 1] = {key, field, scaled}
                                end
                            end
                        end
                    end
                end
            until cursor == '0'
        end
        for _, change in ipairs(changes) do
            redis.call('HSET', change[1], change[2], change[3])
        end
        redis.call('SET', KEYS[1], ARGV[2])
        return false
    "#,
    )
});
