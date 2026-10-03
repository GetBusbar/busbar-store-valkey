// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A RESP2 CLIENT OVER THE HOST'S CONNECTOR: the subset of the Valkey protocol this store speaks,
//! sans-IO. Every byte goes out and comes back through the op's one connection (the store SDK's
//! [`Wire`]); this module only encodes commands, parses replies and converts them to Rust values.
//! No socket, no TLS stack and no runtime of its own: the host's connector owns all three.
//!
//! The surface mirrors what the store used of the upstream driver (`cmd`, `pipe`, `Script`, the
//! typed `get`/`hgetall`/... helpers and the optimistic [`transaction!`]), as `async` calls, so the
//! store's bodies read as they did over the blocking client.

use std::fmt;
use std::future::Future;

use busbar_contract::abi::sdk::conn::ConnFailure;
use busbar_contract::abi::sdk::store::wire::Wire;

// ── errors ───────────────────────────────────────────────────────────────────────────────────

/// What kind of failure a [`RedisError`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// A refusal or failure the store itself raised.
    Client,
    /// A reply that does not convert to the type asked for.
    TypeError,
    /// A reply that does not parse as RESP.
    Parse,
    /// A connection string that does not parse.
    InvalidClientConfig,
}

#[derive(Debug, Clone)]
enum Repr {
    General(ErrorKind, &'static str, Option<String>),
    Server(String),
    Io(String),
}

/// A command's failure. Its text is the upstream driver's shape (`desc - Kind: detail`), so the
/// store's error strings read as they did.
#[derive(Debug, Clone)]
pub struct RedisError {
    repr: Repr,
}

impl RedisError {
    /// A connector failure.
    #[must_use]
    pub fn io(e: &ConnFailure) -> Self {
        Self {
            repr: Repr::Io(e.to_string()),
        }
    }

    fn server(text: String) -> Self {
        Self {
            repr: Repr::Server(text),
        }
    }

    fn type_error(what: String) -> Self {
        Self::from((
            ErrorKind::TypeError,
            "Response was of incompatible type",
            what,
        ))
    }
}

impl From<(ErrorKind, &'static str)> for RedisError {
    fn from((kind, desc): (ErrorKind, &'static str)) -> Self {
        Self {
            repr: Repr::General(kind, desc, None),
        }
    }
}

impl From<(ErrorKind, &'static str, String)> for RedisError {
    fn from((kind, desc, detail): (ErrorKind, &'static str, String)) -> Self {
        Self {
            repr: Repr::General(kind, desc, Some(detail)),
        }
    }
}

impl fmt::Display for RedisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.repr {
            Repr::General(kind, desc, detail) => {
                write!(f, "{desc} - {kind:?}")?;
                match detail {
                    Some(d) => write!(f, ": {d}"),
                    None => Ok(()),
                }
            }
            Repr::Server(t) | Repr::Io(t) => f.write_str(t),
        }
    }
}

impl std::error::Error for RedisError {}

/// A command's result.
pub type RedisResult<T> = Result<T, RedisError>;

// ── values ───────────────────────────────────────────────────────────────────────────────────

/// One RESP2 reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// The null bulk string or array.
    Nil,
    /// An integer.
    Int(i64),
    /// A bulk string.
    Data(Vec<u8>),
    /// A simple string (`+OK`).
    Status(String),
    /// An array.
    Array(Vec<Value>),
    /// An error reply.
    Error(String),
}

/// Parse one reply from the front of `buf`: the reply and how many bytes it took, or `None` when
/// `buf` does not hold a whole reply yet.
///
/// # Errors
/// Bytes that are not RESP2.
pub fn parse(buf: &[u8]) -> RedisResult<Option<(Value, usize)>> {
    fn line(buf: &[u8], from: usize) -> Option<(&[u8], usize)> {
        let rest = buf.get(from..)?;
        let at = rest.windows(2).position(|w| w == b"\r\n")?;
        Some((&rest[..at], from + at + 2))
    }
    fn bad(what: &str) -> RedisError {
        RedisError::from((ErrorKind::Parse, "invalid RESP reply", what.to_string()))
    }
    fn int(t: &[u8]) -> RedisResult<i64> {
        std::str::from_utf8(t)
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| bad("a length or integer is not a number"))
    }
    fn one(buf: &[u8], at: usize) -> RedisResult<Option<(Value, usize)>> {
        let Some(&tag) = buf.get(at) else {
            return Ok(None);
        };
        let Some((text, next)) = line(buf, at + 1) else {
            return Ok(None);
        };
        match tag {
            b'+' => Ok(Some((
                Value::Status(String::from_utf8_lossy(text).into_owned()),
                next,
            ))),
            b'-' => Ok(Some((
                Value::Error(String::from_utf8_lossy(text).into_owned()),
                next,
            ))),
            b':' => Ok(Some((Value::Int(int(text)?), next))),
            b'$' => {
                let n = int(text)?;
                if n < 0 {
                    return Ok(Some((Value::Nil, next)));
                }
                let n = usize::try_from(n).map_err(|_| bad("a bulk length overflows"))?;
                let end = next + n;
                if buf.len() < end + 2 {
                    return Ok(None);
                }
                if &buf[end..end + 2] != b"\r\n" {
                    return Err(bad("a bulk string is not terminated"));
                }
                Ok(Some((Value::Data(buf[next..end].to_vec()), end + 2)))
            }
            b'*' => {
                let n = int(text)?;
                if n < 0 {
                    return Ok(Some((Value::Nil, next)));
                }
                let mut items = Vec::with_capacity(usize::try_from(n).unwrap_or(0).min(4096));
                let mut at = next;
                for _ in 0..n {
                    match one(buf, at)? {
                        Some((v, after)) => {
                            items.push(v);
                            at = after;
                        }
                        None => return Ok(None),
                    }
                }
                Ok(Some((Value::Array(items), at)))
            }
            _ => Err(bad("an unknown reply type")),
        }
    }
    one(buf, 0)
}

/// Encode one command (an array of bulk strings) onto `out`.
pub fn encode(args: &[Vec<u8>], out: &mut Vec<u8>) {
    out.extend_from_slice(format!("*{}\r\n", args.len()).as_bytes());
    for a in args {
        out.extend_from_slice(format!("${}\r\n", a.len()).as_bytes());
        out.extend_from_slice(a);
        out.extend_from_slice(b"\r\n");
    }
}

// ── arguments ────────────────────────────────────────────────────────────────────────────────

/// What a command argument writes: one or more bulk strings.
pub trait ToArgs {
    /// Append this argument's bulk strings.
    fn write_args(&self, out: &mut Vec<Vec<u8>>);
}

impl<T: ToArgs + ?Sized> ToArgs for &T {
    fn write_args(&self, out: &mut Vec<Vec<u8>>) {
        (**self).write_args(out);
    }
}

impl ToArgs for str {
    fn write_args(&self, out: &mut Vec<Vec<u8>>) {
        out.push(self.as_bytes().to_vec());
    }
}

impl ToArgs for String {
    fn write_args(&self, out: &mut Vec<Vec<u8>>) {
        out.push(self.as_bytes().to_vec());
    }
}

impl ToArgs for [u8] {
    fn write_args(&self, out: &mut Vec<Vec<u8>>) {
        out.push(self.to_vec());
    }
}

impl ToArgs for Vec<u8> {
    fn write_args(&self, out: &mut Vec<Vec<u8>>) {
        out.push(self.clone());
    }
}

macro_rules! numeric_args {
    ($($t:ty),*) => {$(
        impl ToArgs for $t {
            fn write_args(&self, out: &mut Vec<Vec<u8>>) {
                out.push(self.to_string().into_bytes());
            }
        }
    )*};
}
numeric_args!(i64, u64, i32, u32, usize, isize);

impl<T: ToArgs> ToArgs for [T] {
    fn write_args(&self, out: &mut Vec<Vec<u8>>) {
        for t in self {
            t.write_args(out);
        }
    }
}

impl<T: ToArgs> ToArgs for Vec<T> {
    fn write_args(&self, out: &mut Vec<Vec<u8>>) {
        self.as_slice().write_args(out);
    }
}

impl<T: ToArgs, const N: usize> ToArgs for [T; N] {
    fn write_args(&self, out: &mut Vec<Vec<u8>>) {
        self.as_slice().write_args(out);
    }
}

impl<A: ToArgs, B: ToArgs> ToArgs for (A, B) {
    fn write_args(&self, out: &mut Vec<Vec<u8>>) {
        self.0.write_args(out);
        self.1.write_args(out);
    }
}

fn args_of<T: ToArgs>(t: T) -> Vec<Vec<u8>> {
    let mut v = Vec::new();
    t.write_args(&mut v);
    v
}

// ── conversions ──────────────────────────────────────────────────────────────────────────────

/// A Rust value a reply converts to (the upstream driver's conversions, as the store used them).
pub trait FromValue: Sized {
    /// Convert one reply.
    ///
    /// # Errors
    /// A reply of another shape.
    fn from_value(v: Value) -> RedisResult<Self>;

    /// Convert an array's items (a tuple type takes them pairwise from a flat array).
    ///
    /// # Errors
    /// An item of another shape.
    fn from_values(items: Vec<Value>) -> RedisResult<Vec<Self>> {
        items.into_iter().map(Self::from_value).collect()
    }

    /// A bulk string as a `Vec<Self>`: `u8` takes it whole (a `Vec<u8>` is bytes); every other
    /// type hands it back.
    ///
    /// # Errors
    /// The bytes back, for the caller to convert as one item.
    fn from_bytes(bytes: Vec<u8>) -> Result<Vec<Self>, Vec<u8>> {
        Err(bytes)
    }
}

impl FromValue for Value {
    fn from_value(v: Value) -> RedisResult<Self> {
        Ok(v)
    }
}

impl FromValue for () {
    fn from_value(_: Value) -> RedisResult<Self> {
        Ok(())
    }
}

impl FromValue for String {
    fn from_value(v: Value) -> RedisResult<Self> {
        match v {
            Value::Data(b) => String::from_utf8(b)
                .map_err(|_| RedisError::type_error("a bulk string is not UTF-8".into())),
            Value::Status(s) => Ok(s),
            Value::Int(i) => Ok(i.to_string()),
            other => Err(RedisError::type_error(format!("(response was {other:?})"))),
        }
    }
}

macro_rules! numeric_from {
    ($($t:ty),*) => {$(
        impl FromValue for $t {
            fn from_value(v: Value) -> RedisResult<Self> {
                let parsed = match &v {
                    Value::Int(i) => <$t>::try_from(*i).ok(),
                    Value::Data(b) => std::str::from_utf8(b).ok().and_then(|s| s.parse().ok()),
                    Value::Status(s) => s.parse().ok(),
                    _ => None,
                };
                parsed.ok_or_else(|| RedisError::type_error(format!("(response was {v:?})")))
            }
        }
    )*};
}
numeric_from!(i64, u64, i32, u32, usize, isize);

impl FromValue for u8 {
    fn from_value(v: Value) -> RedisResult<Self> {
        match &v {
            Value::Int(i) => u8::try_from(*i).ok(),
            _ => None,
        }
        .ok_or_else(|| RedisError::type_error(format!("(response was {v:?})")))
    }

    fn from_bytes(bytes: Vec<u8>) -> Result<Vec<Self>, Vec<u8>> {
        Ok(bytes)
    }
}

impl FromValue for bool {
    fn from_value(v: Value) -> RedisResult<Self> {
        match &v {
            Value::Nil => Ok(false),
            Value::Int(i) => Ok(*i != 0),
            Value::Status(s) if s == "OK" => Ok(true),
            Value::Data(b) if b == b"1" => Ok(true),
            Value::Data(b) if b == b"0" => Ok(false),
            _ => Err(RedisError::type_error(format!("(response was {v:?})"))),
        }
    }
}

impl<T: FromValue> FromValue for Option<T> {
    fn from_value(v: Value) -> RedisResult<Self> {
        match v {
            Value::Nil => Ok(None),
            v => T::from_value(v).map(Some),
        }
    }
}

impl<T: FromValue> FromValue for Vec<T> {
    fn from_value(v: Value) -> RedisResult<Self> {
        match v {
            Value::Nil => Ok(Vec::new()),
            Value::Array(items) => T::from_values(items),
            Value::Data(b) => match T::from_bytes(b) {
                Ok(v) => Ok(v),
                Err(b) => Ok(vec![T::from_value(Value::Data(b))?]),
            },
            other => Ok(vec![T::from_value(other)?]),
        }
    }
}

fn is_array(v: &Value) -> bool {
    matches!(v, Value::Array(_))
}

impl<A: FromValue, B: FromValue> FromValue for (A, B) {
    fn from_value(v: Value) -> RedisResult<Self> {
        match v {
            Value::Array(items) if items.len() == 2 => {
                let mut it = items.into_iter();
                let (a, b) = (it.next(), it.next());
                Ok((
                    A::from_value(a.unwrap_or(Value::Nil))?,
                    B::from_value(b.unwrap_or(Value::Nil))?,
                ))
            }
            other => Err(RedisError::type_error(format!("a pair from {other:?}"))),
        }
    }

    fn from_values(items: Vec<Value>) -> RedisResult<Vec<Self>> {
        if items.iter().all(is_array) {
            return items.into_iter().map(Self::from_value).collect();
        }
        if !items.len().is_multiple_of(2) {
            return Err(RedisError::type_error(
                "pairs from an odd-length array".into(),
            ));
        }
        let mut out = Vec::with_capacity(items.len() / 2);
        let mut it = items.into_iter();
        while let (Some(a), Some(b)) = (it.next(), it.next()) {
            out.push((A::from_value(a)?, B::from_value(b)?));
        }
        Ok(out)
    }
}

impl<A: FromValue, B: FromValue, C: FromValue> FromValue for (A, B, C) {
    fn from_value(v: Value) -> RedisResult<Self> {
        match v {
            Value::Array(items) if items.len() == 3 => {
                let mut it = items.into_iter();
                Ok((
                    A::from_value(it.next().unwrap_or(Value::Nil))?,
                    B::from_value(it.next().unwrap_or(Value::Nil))?,
                    C::from_value(it.next().unwrap_or(Value::Nil))?,
                ))
            }
            other => Err(RedisError::type_error(format!("a triple from {other:?}"))),
        }
    }
}

// ── the connection ───────────────────────────────────────────────────────────────────────────

/// ONE OP'S CONNECTION to the server, over its [`Wire`].
#[derive(Debug)]
pub struct Conn {
    wire: Wire,
    /// A `WATCH` is in force (no `EXEC` or `UNWATCH` has cleared it since).
    watching: bool,
}

impl Conn {
    /// A connection over `wire` (connected, and secured where it must be).
    #[must_use]
    pub fn new(wire: Wire) -> Self {
        Self {
            wire,
            watching: false,
        }
    }

    async fn send(&mut self, cmds: &[Vec<Vec<u8>>]) -> RedisResult<()> {
        let mut out = Vec::new();
        for c in cmds {
            encode(c, &mut out);
        }
        self.wire
            .write_all(&out)
            .await
            .map_err(|e| RedisError::io(&e))
    }

    async fn read(&mut self) -> RedisResult<Value> {
        loop {
            let got = self.wire.input(|i| -> RedisResult<Option<Value>> {
                Ok(parse(i)?.map(|(v, n)| {
                    i.drain(..n);
                    v
                }))
            })?;
            if let Some(v) = got {
                return Ok(v);
            }
            let n = self.wire.fill().await.map_err(|e| RedisError::io(&e))?;
            if n == 0 {
                return Err(RedisError {
                    repr: Repr::Io("the server closed the connection".into()),
                });
            }
        }
    }

    /// Send `cmds` in one write and read one raw reply for each (error replies included).
    async fn round_trip(&mut self, cmds: &[Vec<Vec<u8>>]) -> RedisResult<Vec<Value>> {
        self.send(cmds).await?;
        let mut out = Vec::with_capacity(cmds.len());
        for _ in cmds {
            out.push(self.read().await?);
        }
        Ok(out)
    }

    /// One command's reply; an error reply is `Err`.
    async fn request(&mut self, args: Vec<Vec<u8>>) -> RedisResult<Value> {
        let name = args.first().map(|a| a.to_ascii_uppercase());
        let v = self
            .round_trip(std::slice::from_ref(&args))
            .await?
            .pop()
            .unwrap_or(Value::Nil);
        match name.as_deref() {
            Some(b"WATCH") => self.watching = true,
            Some(b"UNWATCH" | b"EXEC" | b"DISCARD") => self.watching = false,
            _ => {}
        }
        match v {
            Value::Error(e) => Err(RedisError::server(e)),
            v => Ok(v),
        }
    }

    /// Whether a `WATCH` is still in force.
    #[must_use]
    pub fn watching(&self) -> bool {
        self.watching
    }

    /// `GET`.
    pub async fn get<K: ToArgs, RV: FromValue>(&mut self, key: K) -> RedisResult<RV> {
        cmd("GET").arg(key).query(self).await
    }

    /// `SET`.
    pub async fn set<K: ToArgs, V: ToArgs, RV: FromValue>(
        &mut self,
        key: K,
        value: V,
    ) -> RedisResult<RV> {
        cmd("SET").arg(key).arg(value).query(self).await
    }

    /// `DEL` (one key or several).
    pub async fn del<K: ToArgs, RV: FromValue>(&mut self, key: K) -> RedisResult<RV> {
        cmd("DEL").arg(key).query(self).await
    }

    /// `SMEMBERS`.
    pub async fn smembers<K: ToArgs, RV: FromValue>(&mut self, key: K) -> RedisResult<RV> {
        cmd("SMEMBERS").arg(key).query(self).await
    }

    /// `HGET`.
    pub async fn hget<K: ToArgs, F: ToArgs, RV: FromValue>(
        &mut self,
        key: K,
        field: F,
    ) -> RedisResult<RV> {
        cmd("HGET").arg(key).arg(field).query(self).await
    }

    /// `HGETALL`.
    pub async fn hgetall<K: ToArgs, RV: FromValue>(&mut self, key: K) -> RedisResult<RV> {
        cmd("HGETALL").arg(key).query(self).await
    }

    /// `ZRANGEBYSCORE key min max`.
    pub async fn zrangebyscore<K: ToArgs, M: ToArgs, MM: ToArgs, RV: FromValue>(
        &mut self,
        key: K,
        min: M,
        max: MM,
    ) -> RedisResult<RV> {
        cmd("ZRANGEBYSCORE")
            .arg(key)
            .arg(min)
            .arg(max)
            .query(self)
            .await
    }

    /// `ZRANGE key start stop`.
    pub async fn zrange<K: ToArgs, RV: FromValue>(
        &mut self,
        key: K,
        start: isize,
        stop: isize,
    ) -> RedisResult<RV> {
        cmd("ZRANGE")
            .arg(key)
            .arg(start)
            .arg(stop)
            .query(self)
            .await
    }

    /// `INCRBY`.
    pub async fn incr<K: ToArgs, V: ToArgs, RV: FromValue>(
        &mut self,
        key: K,
        delta: V,
    ) -> RedisResult<RV> {
        cmd("INCRBY").arg(key).arg(delta).query(self).await
    }

    /// `LLEN`.
    pub async fn llen<K: ToArgs, RV: FromValue>(&mut self, key: K) -> RedisResult<RV> {
        cmd("LLEN").arg(key).query(self).await
    }

    /// Every key matching `pattern` (`SCAN ... MATCH`, followed to the end), as the upstream
    /// driver's iterator of results.
    pub async fn scan_match<P: ToArgs, RV: FromValue>(
        &mut self,
        pattern: P,
    ) -> RedisResult<std::vec::IntoIter<RedisResult<RV>>> {
        let pattern = args_of(pattern);
        let mut cursor = String::from("0");
        let mut out = Vec::new();
        loop {
            let (next, keys): (String, Vec<Value>) = cmd("SCAN")
                .arg(&cursor)
                .arg("MATCH")
                .arg(&pattern)
                .query(self)
                .await?;
            out.extend(keys.into_iter().map(RV::from_value));
            if next == "0" {
                break;
            }
            cursor = next;
        }
        Ok(out.into_iter())
    }
}

// ── commands ─────────────────────────────────────────────────────────────────────────────────

/// One command.
#[derive(Debug, Clone, Default)]
pub struct Cmd {
    args: Vec<Vec<u8>>,
}

/// The command `name`.
#[must_use]
pub fn cmd(name: &str) -> Cmd {
    Cmd {
        args: vec![name.as_bytes().to_vec()],
    }
}

impl Cmd {
    /// Append an argument.
    pub fn arg<T: ToArgs>(&mut self, a: T) -> &mut Self {
        a.write_args(&mut self.args);
        self
    }

    /// Run it and convert its reply.
    ///
    /// # Errors
    /// The connection failed, the server answered an error, or the reply does not convert.
    pub async fn query<T: FromValue>(&self, c: &mut Conn) -> RedisResult<T> {
        T::from_value(c.request(self.args.clone()).await?)
    }

    /// Run it for its effect.
    ///
    /// # Errors
    /// As [`Cmd::query`].
    pub async fn exec(&self, c: &mut Conn) -> RedisResult<()> {
        c.request(self.args.clone()).await.map(drop)
    }
}

// ── pipelines ────────────────────────────────────────────────────────────────────────────────

/// Several commands in one write; atomic ([`Pipeline::atomic`]) as `MULTI`/`EXEC`.
#[derive(Debug, Clone, Default)]
pub struct Pipeline {
    cmds: Vec<(Vec<Vec<u8>>, bool)>,
    atomic: bool,
}

/// A new pipeline.
#[must_use]
pub fn pipe() -> Pipeline {
    Pipeline::default()
}

macro_rules! pipe_cmd {
    ($(#[$m:meta])* $name:ident($($a:ident: $t:ident),*) => $word:literal) => {
        $(#[$m])*
        pub fn $name<$($t: ToArgs),*>(&mut self, $($a: $t),*) -> &mut Self {
            self.cmd($word);
            $(self.arg($a);)*
            self
        }
    };
}

impl Pipeline {
    /// A new pipeline.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Run the commands as one transaction (`MULTI`/`EXEC`).
    pub fn atomic(&mut self) -> &mut Self {
        self.atomic = true;
        self
    }

    /// Start the command `name`.
    pub fn cmd(&mut self, name: &str) -> &mut Self {
        self.cmds.push((vec![name.as_bytes().to_vec()], false));
        self
    }

    /// Append an argument to the last command.
    pub fn arg<T: ToArgs>(&mut self, a: T) -> &mut Self {
        if let Some((args, _)) = self.cmds.last_mut() {
            a.write_args(args);
        }
        self
    }

    /// Leave the last command's reply out of the result.
    pub fn ignore(&mut self) -> &mut Self {
        if let Some((_, ignored)) = self.cmds.last_mut() {
            *ignored = true;
        }
        self
    }

    pipe_cmd!(
        /// `GET`.
        get(k: K) => "GET");
    pipe_cmd!(
        /// `SET`.
        set(k: K, v: V) => "SET");
    pipe_cmd!(
        /// `DEL`.
        del(k: K) => "DEL");
    pipe_cmd!(
        /// `SADD`.
        sadd(k: K, m: M) => "SADD");
    pipe_cmd!(
        /// `SREM`.
        srem(k: K, m: M) => "SREM");
    pipe_cmd!(
        /// `HSET key field value`.
        hset(k: K, f: F, v: V) => "HSET");
    /// `HSET key field value ...` (every pair).
    pub fn hset_multiple<K: ToArgs, F: ToArgs, V: ToArgs>(
        &mut self,
        k: K,
        items: &[(F, V)],
    ) -> &mut Self {
        self.cmd("HSET").arg(k).arg(items)
    }
    pipe_cmd!(
        /// `HGETALL`.
        hgetall(k: K) => "HGETALL");
    pipe_cmd!(
        /// `RPUSH key value ...`.
        rpush(k: K, v: V) => "RPUSH");
    pipe_cmd!(
        /// `LLEN`.
        llen(k: K) => "LLEN");
    pipe_cmd!(
        /// `EXPIRE key seconds`.
        expire(k: K, s: S) => "EXPIRE");
    pipe_cmd!(
        /// `TTL`.
        ttl(k: K) => "TTL");

    /// `ZADD key score member`.
    pub fn zadd<K: ToArgs, M: ToArgs, S: ToArgs>(&mut self, k: K, m: M, s: S) -> &mut Self {
        self.cmd("ZADD").arg(k).arg(s).arg(m)
    }

    /// Run the pipeline and convert the replies of the commands not ignored (as one array). An
    /// atomic pipeline whose `EXEC` a watched key aborted answers `Nil` (so `Option<_>` is
    /// `None`); an error reply anywhere is `Err`.
    ///
    /// # Errors
    /// The connection failed, a command answered an error, or the replies do not convert.
    pub async fn query<T: FromValue>(&self, c: &mut Conn) -> RedisResult<T> {
        if self.cmds.is_empty() {
            return T::from_value(Value::Array(Vec::new()));
        }
        let mut wire: Vec<Vec<Vec<u8>>> = Vec::with_capacity(self.cmds.len() + 2);
        if self.atomic {
            wire.push(vec![b"MULTI".to_vec()]);
        }
        wire.extend(self.cmds.iter().map(|(a, _)| a.clone()));
        if self.atomic {
            wire.push(vec![b"EXEC".to_vec()]);
        }
        let mut replies = c.round_trip(&wire).await?;
        let replies = if self.atomic {
            c.watching = false;
            let exec = replies.pop().unwrap_or(Value::Nil);
            // A command the server refused to queue: `EXEC` answers EXECABORT; name the first.
            if let Some(Value::Error(e)) = replies.iter().find(|r| matches!(r, Value::Error(_))) {
                return Err(RedisError::server(e.clone()));
            }
            match exec {
                Value::Nil => return T::from_value(Value::Nil),
                Value::Error(e) => return Err(RedisError::server(e)),
                Value::Array(items) => items,
                other => vec![other],
            }
        } else {
            replies
        };
        let mut kept = Vec::with_capacity(replies.len());
        for ((_, ignored), r) in self.cmds.iter().zip(replies) {
            if let Value::Error(e) = r {
                return Err(RedisError::server(e));
            }
            if !ignored {
                kept.push(r);
            }
        }
        T::from_value(Value::Array(kept))
    }
}

// ── scripts ──────────────────────────────────────────────────────────────────────────────────

/// A Lua script, run as `EVAL` (its source travels with each call: no script cache to miss).
#[derive(Debug, Clone)]
pub struct Script {
    src: String,
}

impl Script {
    /// The script `src`.
    #[must_use]
    pub fn new(src: &str) -> Self {
        Self {
            src: src.to_string(),
        }
    }

    /// An invocation with its first key.
    pub fn key<T: ToArgs>(&self, k: T) -> ScriptInvocation<'_> {
        let mut inv = ScriptInvocation {
            script: self,
            keys: Vec::new(),
            args: Vec::new(),
        };
        inv.key(k);
        inv
    }
}

/// One call of a [`Script`]: its keys and arguments.
#[derive(Debug, Clone)]
pub struct ScriptInvocation<'s> {
    script: &'s Script,
    keys: Vec<Vec<u8>>,
    args: Vec<Vec<u8>>,
}

impl ScriptInvocation<'_> {
    /// Add a key.
    pub fn key<T: ToArgs>(&mut self, k: T) -> &mut Self {
        k.write_args(&mut self.keys);
        self
    }

    /// Add an argument.
    pub fn arg<T: ToArgs>(&mut self, a: T) -> &mut Self {
        a.write_args(&mut self.args);
        self
    }

    /// Run it and convert its reply.
    ///
    /// # Errors
    /// As [`Cmd::query`].
    pub async fn invoke<T: FromValue>(&self, c: &mut Conn) -> RedisResult<T> {
        cmd("EVAL")
            .arg(&self.script.src)
            .arg(self.keys.len())
            .arg(&self.keys)
            .arg(&self.args)
            .query(c)
            .await
    }
}

// ── transactions ─────────────────────────────────────────────────────────────────────────────

/// Pin an async block's output to a command result (so `?` inside it knows its error type).
pub fn rr<T, F: Future<Output = RedisResult<T>>>(f: F) -> F {
    f
}

/// THE OPTIMISTIC TRANSACTION, as the upstream driver's `transaction`: `WATCH` the keys, run the
/// body (it reads, and queues its writes on the atomic pipeline it is handed, then answers that
/// pipeline's `query`: `None` when a watched key changed and `EXEC` aborted), and run it all again
/// on an abort. Evaluates to the body's `Some` value, or its error (a `WATCH` left in force by a
/// failed body is cleared).
macro_rules! transaction {
    ($c:ident, $keys:expr, |$c2:ident, $pipe:ident| $body:expr $(,)?) => {
        $crate::resp::rr(async {
            let __keys = $keys;
            loop {
                $crate::resp::cmd("WATCH")
                    .arg(__keys)
                    .exec(&mut *$c)
                    .await?;
                let mut __pipe = $crate::resp::Pipeline::new();
                __pipe.atomic();
                let __ran: $crate::resp::RedisResult<Option<_>> = $crate::resp::rr(async {
                    let $pipe = &mut __pipe;
                    let $c2 = &mut *$c;
                    $body
                })
                .await;
                match __ran {
                    Ok(Some(v)) => {
                        if $c.watching() {
                            $crate::resp::cmd("UNWATCH").exec(&mut *$c).await?;
                        }
                        break Ok(v);
                    }
                    Ok(None) => continue,
                    Err(e) => {
                        if $c.watching() {
                            let _ = $crate::resp::cmd("UNWATCH").exec(&mut *$c).await;
                        }
                        break Err(e);
                    }
                }
            }
        })
        .await
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_reply_type_and_waits_for_a_whole_one() {
        let all = b"*6\r\n+OK\r\n-ERR no\r\n:-7\r\n$3\r\nabc\r\n$-1\r\n*-1\r\n";
        let (v, n) = parse(all).unwrap().unwrap();
        assert_eq!(n, all.len());
        assert_eq!(
            v,
            Value::Array(vec![
                Value::Status("OK".into()),
                Value::Error("ERR no".into()),
                Value::Int(-7),
                Value::Data(b"abc".to_vec()),
                Value::Nil,
                Value::Nil,
            ])
        );
        for cut in 0..all.len() {
            assert_eq!(parse(&all[..cut]).unwrap(), None, "cut at {cut}");
        }
        assert!(parse(b"?x\r\n").is_err());
        let (v, n) = parse(b"$0\r\n\r\n:1\r\n").unwrap().unwrap();
        assert_eq!((v, n), (Value::Data(Vec::new()), 6));
    }

    #[test]
    fn encodes_a_command_as_bulk_strings() {
        let mut out = Vec::new();
        encode(&args_of(("SET", ["k", "v"])), &mut out);
        assert_eq!(out, b"*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n");
    }

    #[test]
    fn converts_as_the_store_reads() {
        let flat = Value::Array(vec![
            Value::Data(b"a".to_vec()),
            Value::Data(b"1".to_vec()),
            Value::Data(b"b".to_vec()),
            Value::Data(b"-2".to_vec()),
        ]);
        let pairs: Vec<(String, i64)> = FromValue::from_value(flat).unwrap();
        assert_eq!(pairs, vec![("a".into(), 1), ("b".into(), -2)]);
        let bytes: Option<Vec<u8>> = FromValue::from_value(Value::Data(b"xy".to_vec())).unwrap();
        assert_eq!(bytes, Some(b"xy".to_vec()));
        let none: Option<String> = FromValue::from_value(Value::Nil).unwrap();
        assert_eq!(none, None);
        let nested: Vec<(Option<String>, Option<String>)> =
            FromValue::from_value(Value::Array(vec![Value::Array(vec![
                Value::Data(b"n".to_vec()),
                Value::Nil,
            ])]))
            .unwrap();
        assert_eq!(nested, vec![(Some("n".into()), None)]);
        let ids: Vec<u64> =
            FromValue::from_value(Value::Array(vec![Value::Data(b"7".to_vec())])).unwrap();
        assert_eq!(ids, vec![7]);
        assert!(String::from_value(Value::Nil).is_err());
    }

    #[test]
    fn errors_read_as_the_upstream_driver_wrote_them() {
        let e = RedisError::from((ErrorKind::Client, "put_key refused", "why".to_string()));
        assert_eq!(e.to_string(), "put_key refused - Client: why");
        let e = RedisError::from((ErrorKind::Client, "delete_key: unknown id"));
        assert_eq!(e.to_string(), "delete_key: unknown id - Client");
    }
}
