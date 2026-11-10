// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Primitive Valkey persistence over the host connector. Native pre-open lifecycle
//! captures and fences historical data before core selects the serving dataset.

#![forbid(unsafe_code)]

use busbar_contract::abi::sdk::cred::{settings_lent, Cred};
use busbar_contract::abi::sdk::store::wire::{Pool, Wire};
use credentials::ValkeyUrl;
use resp::{cmd, Conn, ErrorKind, RedisError, RedisResult};
use std::sync::Arc;
use std::time::Duration;

mod credentials;
mod historical;
mod resp;
mod v4;
pub use v4::{door, MACRO_DOOR};

/// A redacted connector failure.
#[derive(Debug)]
pub(crate) struct TransportError(pub String);
impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for TransportError {}
/// Connector operation result.
pub(crate) type TransportResult<T> = Result<T, TransportError>;

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const KEPT_CONNECTIONS: usize = 8;

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

/// Valkey connector transport, reached through the HOST'S
/// CONNECTOR: up to eight kept connections (each dialled, secured, `AUTH`, `SELECT` once),
/// one per op in flight;
/// the store holds no socket and no TLS stack of its own.
#[derive(Debug, Clone)]
pub(crate) struct ValkeyStore {
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
pub(crate) const NEEDS: &[busbar_contract::abi::host::conn::connector::Need] = {
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
    async fn conn(&self, wire: Wire, ctx: Option<&str>) -> TransportResult<Conn> {
        let failed = |e: String| {
            let text = match ctx {
                Some(ctx) => format!("valkey {ctx}: {e}"),
                None => e,
            };
            TransportError(self.inner.url.redact_echo(&text))
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

    pub(crate) fn pool(&self) -> &Arc<Pool> {
        &self.inner.pool
    }

    async fn assert_noeviction(&self, c: &mut Conn) -> TransportResult<()> {
        let pairs: Vec<(String, String)> = cmd("CONFIG")
            .arg("GET")
            .arg("maxmemory-policy")
            .query(c)
            .await
            .map_err(|e| self.err(e, "inspect eviction policy"))?;
        let policy = pairs
            .iter()
            .find(|(k, _)| k == "maxmemory-policy")
            .map(|(_, v)| v.as_str());
        match policy {
            Some("noeviction") => Ok(()),
            Some(other) => Err(TransportError(format!(
                "maxmemory-policy is '{other}', not 'noeviction': an eviction policy \
                 can silently drop a denylist entry (un-revoking a key) or a metering row \
                 (destroying billing evidence) under memory pressure with no error anywhere. \
                 Refusing to start. Run `CONFIG SET maxmemory-policy noeviction` (and persist it in \
                 the server's own config, since CONFIG SET does not survive a restart) before \
                 pointing busbar at this instance."
            ))),
            None => Err(TransportError(
                "CONFIG GET maxmemory-policy returned no value — either this server \
                 restricts CONFIG GET via ACL, or something unexpected happened. Refusing to start: \
                 cannot verify the noeviction invariant governance data durability depends on."
                    .to_string(),
            )),
        }
    }

    fn err(&self, e: RedisError, ctx: &str) -> TransportError {
        let text = if e.is_refusal() {
            e.to_string()
        } else {
            format!("valkey {ctx}: {e}")
        };
        TransportError(self.inner.url.redact_echo(&text))
    }
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
    /// through the
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

#[cfg(test)]
mod tests;

mod source_interpretation;
