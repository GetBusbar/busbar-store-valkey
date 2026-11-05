// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A RESP2 client over the host's connector: the subset of the Valkey protocol this store speaks,
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
use busbar_contract::abi::sdk::cred::Cred;
use busbar_contract::abi::sdk::store::wire::Wire;

/// What kind of failure a [`RedisError`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// A client-side failure the store itself raised; verbatim refusals use `RedisError::refused`.
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
    /// The store's own refusal, its text verbatim (no `- Kind` suffix).
    Refused(String),
    /// A transaction body's request to rebuild its watch set and run again.
    Retry,
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

    /// A CONNECTION-LEVEL failure (the connector's: dropped, refused, timed out; or the server
    /// closing), worth one reconnect-and-retry (the upstream driver's `is_io_error` /
    /// `is_connection_dropped` / `is_connection_refusal` / `is_timeout`).
    #[must_use]
    pub fn is_connection_error(&self) -> bool {
        matches!(self.repr, Repr::Io(_))
    }

    /// The store's own refusal of an op (an unknown id, a tombstoned id): `text` reads verbatim,
    /// with no ` - Client` suffix, in the siblings' `<op>: <reason>` shape.
    #[must_use]
    pub fn refused(text: impl Into<String>) -> Self {
        Self {
            repr: Repr::Refused(text.into()),
        }
    }

    /// Whether this is a store refusal ([`RedisError::refused`]), which reaches the caller as
    /// written.
    #[must_use]
    pub fn is_refusal(&self) -> bool {
        matches!(self.repr, Repr::Refused(_))
    }

    /// A body's own signal that the state it watched changed shape: the caller reruns it.
    #[must_use]
    pub fn retry() -> Self {
        Self { repr: Repr::Retry }
    }

    /// Whether this is [`RedisError::retry`].
    #[must_use]
    pub fn is_retry(&self) -> bool {
        matches!(self.repr, Repr::Retry)
    }

    /// The server refused a multi-key operation across cluster slots.
    pub fn is_crossslot(&self) -> bool {
        matches!(&self.repr, Repr::Server(t) if t.split_whitespace().next() == Some("CROSSSLOT"))
    }

    /// The server's script cache does not hold the script an `EVALSHA` named.
    fn is_noscript(&self) -> bool {
        matches!(&self.repr, Repr::Server(t) if t.starts_with("NOSCRIPT"))
    }

    fn server(text: String) -> Self {
        Self {
            repr: Repr::Server(
                text.chars()
                    .flat_map(|c| {
                        if c.is_control() {
                            c.escape_default().collect::<Vec<_>>()
                        } else {
                            vec![c]
                        }
                    })
                    .collect(),
            ),
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
            Repr::Server(t) | Repr::Io(t) | Repr::Refused(t) => f.write_str(t),
            Repr::Retry => f.write_str("transaction retry requested"),
        }
    }
}

impl std::error::Error for RedisError {}

/// A command's result.
pub type RedisResult<T> = Result<T, RedisError>;

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

/// The deepest array nesting a reply may have; deeper is refused rather than recursed into.
const MAX_REPLY_DEPTH: usize = 32;
/// Maximum complete reply, including framing, accepted from a semi-trusted endpoint.
pub(crate) const MAX_REPLY_BYTES: usize = 512 * 1024 * 1024;
/// Status/error/integer/length lines are never bulk payloads.
const MAX_REPLY_LINE: usize = 64 * 1024;
/// Bound array object overhead as well as encoded bytes.
pub(crate) const MAX_REPLY_ELEMENTS: u64 = 1_000_000;

// Elements the measuring walk looked at, to prove a reply that arrives in many fills is measured
// in time linear in its size.

impl Value {
    /// The reply's kind, for error text: never its content.
    pub(crate) fn shape(&self) -> &'static str {
        match self {
            Value::Nil => "nil",
            Value::Int(_) => "integer",
            Value::Data(_) => "bulk string",
            Value::Status(_) => "status",
            Value::Array(_) => "array",
            Value::Error(_) => "error",
        }
    }
}

/// A CRLF-terminated line at `from`: its text and the offset after the terminator.
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

/// A bulk or array length: `None` for the null (`-1`, RESP2's only one), an error for any other
/// negative.
fn length(t: &[u8]) -> RedisResult<Option<i64>> {
    match int(t)? {
        -1 => Ok(None),
        n if n < 0 => Err(bad("a negative length other than -1")),
        n => Ok(Some(n)),
    }
}

/// Where a measuring walk of one reply has got to, so a reply that arrives over many fills is
/// measured once, each element looked at once, not again from byte 0 at every fill. Valid only
/// while the buffer it measures only grows; start afresh ([`Frame::default`]) after a reply is
/// drained.
#[derive(Debug, Default)]
struct Frame {
    /// Offset of the next element to measure.
    at: usize,
    /// Elements still to come in each array being walked, outermost first.
    open: Vec<u64>,
    /// Whether the root counter has been initialized.
    started: bool,
    /// Already searched prefix of an incomplete header.
    searched: usize,
    /// Total array entries declared in this frame.
    elements: u64,
}

impl Frame {
    /// Measure on from where the last call stopped: the length of the whole reply at the front of
    /// `buf`, or `None` while `buf` does not hold it yet. Allocates and copies nothing.
    ///
    /// # Errors
    /// Bytes that are not RESP2, an array nested deeper than 32, or a length that overflows.
    fn measure(&mut self, buf: &[u8]) -> RedisResult<Option<usize>> {
        if !self.started {
            self.started = true;
            self.open.push(1);
        }
        while let Some(&left) = self.open.last() {
            if left == 0 {
                self.open.pop();
                continue;
            }
            let Some(&tag) = buf.get(self.at) else {
                return Ok(None);
            };
            if self.at >= MAX_REPLY_BYTES {
                return Err(bad("reply exceeds the byte limit"));
            }
            let from = self.at + 1;
            let search = self.searched.max(from);
            let Some((_, next)) = line(buf, search) else {
                if buf.len().saturating_sub(from) > MAX_REPLY_LINE {
                    return Err(bad("reply line exceeds the limit"));
                }
                self.searched = buf.len().saturating_sub(1).max(from);
                return Ok(None);
            };
            if next - from > MAX_REPLY_LINE || next > MAX_REPLY_BYTES {
                return Err(bad("reply line exceeds the limit"));
            }
            let text = &buf[from..next - 2];
            self.searched = 0;
            let after = match tag {
                b'+' | b'-' => next,
                b':' => {
                    int(text)?;
                    next
                }
                b'$' => match length(text)? {
                    None => next,
                    Some(n) => {
                        let n = usize::try_from(n).map_err(|_| bad("a bulk length overflows"))?;
                        let after = next
                            .checked_add(n)
                            .and_then(|end| end.checked_add(2))
                            .ok_or_else(|| bad("a bulk length overflows"))?;
                        if after > MAX_REPLY_BYTES {
                            return Err(bad("reply exceeds the byte limit"));
                        }
                        if buf.len() < after {
                            return Ok(None);
                        }
                        if &buf[after - 2..after] != b"\r\n" {
                            return Err(bad("a bulk string is not terminated"));
                        }
                        after
                    }
                },
                b'*' => {
                    let n = length(text)?;
                    // The root is not an array: the depth is the arrays open above this one.
                    if self.open.len() > MAX_REPLY_DEPTH {
                        return Err(bad("arrays are nested too deeply"));
                    }
                    if let Some(n) = n.filter(|&n| n > 0) {
                        self.elements = self.elements.saturating_add(n.unsigned_abs());
                        if self.elements > MAX_REPLY_ELEMENTS {
                            return Err(bad("reply exceeds the array element limit"));
                        }
                        // This array is one of its parent's elements: counted before its items.
                        if let Some(top) = self.open.last_mut() {
                            *top -= 1;
                        }
                        self.open.push(n.unsigned_abs());
                        self.at = next;
                        continue;
                    }
                    next
                }
                _ => return Err(bad("an unknown reply type")),
            };
            if let Some(top) = self.open.last_mut() {
                *top -= 1;
            }
            self.at = after;
        }
        Ok(Some(self.at))
    }
}

/// Parse a reply, resuming `frame`'s measuring walk of `buf`.
fn parse_from(frame: &mut Frame, buf: &[u8]) -> RedisResult<Option<(Value, usize)>> {
    match frame.measure(buf)? {
        None => Ok(None),
        Some(_) => walk(buf, 0, 0),
    }
}

/// One whole reply at `at` (already measured complete), built.
fn walk(buf: &[u8], at: usize, depth: usize) -> RedisResult<Option<(Value, usize)>> {
    let Some(&tag) = buf.get(at) else {
        return Ok(None);
    };
    let Some((text, next)) = line(buf, at + 1) else {
        return Ok(None);
    };
    let text_of = |text: &[u8]| String::from_utf8_lossy(text).into_owned();
    match tag {
        b'+' => Ok(Some((Value::Status(text_of(text)), next))),
        b'-' => Ok(Some((Value::Error(text_of(text)), next))),
        b':' => Ok(Some((Value::Int(int(text)?), next))),
        b'$' => {
            let Some(n) = length(text)? else {
                return Ok(Some((Value::Nil, next)));
            };
            let n = usize::try_from(n).map_err(|_| bad("a bulk length overflows"))?;
            let end = next
                .checked_add(n)
                .ok_or_else(|| bad("a bulk length overflows"))?;
            let after = end
                .checked_add(2)
                .ok_or_else(|| bad("a bulk length overflows"))?;
            if buf.len() < after {
                return Ok(None);
            }
            if &buf[end..after] != b"\r\n" {
                return Err(bad("a bulk string is not terminated"));
            }
            Ok(Some((Value::Data(buf[next..end].to_vec()), after)))
        }
        b'*' => {
            let Some(n) = length(text)? else {
                return Ok(Some((Value::Nil, next)));
            };
            if depth >= MAX_REPLY_DEPTH {
                return Err(bad("arrays are nested too deeply"));
            }
            let mut items = Vec::with_capacity(usize::try_from(n).unwrap_or(0).min(4096));
            let mut at = next;
            for _ in 0..n {
                match walk(buf, at, depth + 1)? {
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

/// Encode one command (an array of bulk strings) onto `out`.
pub fn encode(args: &[Vec<u8>], out: &mut Vec<u8>) {
    out.extend_from_slice(format!("*{}\r\n", args.len()).as_bytes());
    for a in args {
        out.extend_from_slice(format!("${}\r\n", a.len()).as_bytes());
        out.extend_from_slice(a);
        out.extend_from_slice(b"\r\n");
    }
}

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
numeric_args!(i128, i64, u64, i32, u32, usize, isize);

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

impl FromValue for () {
    fn from_value(_: Value) -> RedisResult<Self> {
        Ok(())
    }
}

impl FromValue for Value {
    fn from_value(v: Value) -> RedisResult<Self> {
        Ok(v)
    }
}

impl FromValue for String {
    fn from_value(v: Value) -> RedisResult<Self> {
        match v {
            Value::Data(b) => String::from_utf8(b)
                .map_err(|_| RedisError::type_error("a bulk string is not UTF-8".into())),
            Value::Status(s) => Ok(s),
            Value::Int(i) => Ok(i.to_string()),
            other => Err(RedisError::type_error(format!(
                "expected a string, got {}",
                other.shape()
            ))),
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
                parsed.ok_or_else(|| {
                    RedisError::type_error(format!(
                        "expected an integer representable as {}, got {}",
                        stringify!($t), v.shape()
                    ))
                })
            }
        }
    )*};
}
numeric_from!(i64, u64, u32);

impl FromValue for u8 {
    fn from_value(v: Value) -> RedisResult<Self> {
        match &v {
            Value::Int(i) => u8::try_from(*i).ok(),
            _ => None,
        }
        .ok_or_else(|| {
            RedisError::type_error(format!("expected a byte, got a non-byte {}", v.shape()))
        })
    }

    fn from_bytes(bytes: Vec<u8>) -> Result<Vec<Self>, Vec<u8>> {
        Ok(bytes)
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
            other => Err(RedisError::type_error(format!(
                "expected a pair, got {}",
                other.shape()
            ))),
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

/// ONE OP'S CONNECTION to the server, over its [`Wire`].
#[derive(Debug)]
pub struct Conn {
    wire: Wire,
    /// A `WATCH` is in force (no `EXEC` or `UNWATCH` has cleared it since).
    watching: bool,
    /// The measuring walk of the reply being read, resumed at each fill.
    frame: Frame,
    scan_pages: usize,
}

impl Conn {
    /// A connection over `wire` (connected, and secured where it must be).
    #[must_use]
    pub fn new(wire: Wire) -> Self {
        Self {
            wire,
            watching: false,
            frame: Frame::default(),
            scan_pages: 0,
        }
    }

    async fn send<C: AsRef<[Vec<u8>]>>(&mut self, cmds: &[C]) -> RedisResult<()> {
        let mut out = zeroize::Zeroizing::new(Vec::new());
        for c in cmds {
            encode(c.as_ref(), &mut out);
        }
        self.wire.write_all(&out).await.map_err(|e| {
            self.wire.discard();
            RedisError::io(&e)
        })
    }

    /// Authenticate with one SDK-owned complete RESP command. Neither the credential nor its
    /// packet enters the public command encoder; the wire retains the seal across partial writes
    /// and Pending, and discards an interrupted exchange before it can be reused.
    pub async fn authenticate(&mut self, password: &Cred, user: Option<&str>) -> RedisResult<()> {
        self.wire
            .write_sealed(password.resp_auth(user))
            .await
            .map_err(|e| RedisError::io(&e))?;
        match self.read().await? {
            Value::Error(e) => Err(RedisError::server(e)),
            _ => Ok(()),
        }
    }

    async fn read(&mut self) -> RedisResult<Value> {
        self.frame = Frame::default();
        loop {
            let frame = &mut self.frame;
            let got = self.wire.input(|i| -> RedisResult<Option<Value>> {
                Ok(parse_from(frame, i)?.map(|(v, n)| {
                    i.drain(..n);
                    v
                }))
            });
            let got = match got {
                Ok(got) => got,
                Err(e) => {
                    self.wire.discard();
                    return Err(e);
                }
            };
            if let Some(v) = got {
                return Ok(v);
            }
            let n = self.wire.fill().await.map_err(|e| {
                self.wire.discard();
                RedisError::io(&e)
            })?;
            if n == 0 {
                self.wire.discard();
                return Err(RedisError {
                    repr: Repr::Io("the server closed the connection".into()),
                });
            }
        }
    }

    /// Send `cmds` in one write and read one raw reply for each (error replies included).
    async fn round_trip<C: AsRef<[Vec<u8>]>>(&mut self, cmds: &[C]) -> RedisResult<Vec<Value>> {
        self.send(cmds).await?;
        let mut out = Vec::with_capacity(cmds.len());
        for _ in cmds {
            out.push(self.read().await?);
        }
        Ok(out)
    }

    /// One command's reply; an error reply is `Err`.
    async fn request(&mut self, args: &[Vec<u8>]) -> RedisResult<Value> {
        let name = args.first().map(Vec::as_slice);
        let v = self
            .round_trip(std::slice::from_ref(&args))
            .await?
            .pop()
            .unwrap_or(Value::Nil);
        if let Some(name) = name {
            if name.eq_ignore_ascii_case(b"WATCH") {
                self.watching = true;
            } else if [b"UNWATCH".as_slice(), b"EXEC", b"DISCARD"]
                .iter()
                .any(|verb| name.eq_ignore_ascii_case(verb))
            {
                self.watching = false;
            }
        }
        match v {
            Value::Error(e) => Err(RedisError::server(e)),
            v => Ok(v),
        }
    }

    /// The connection's wire.
    #[must_use]
    pub fn wire(&self) -> &Wire {
        &self.wire
    }

    /// The connection was replaced by a fresh one: no `WATCH` is in force on it.
    pub fn reset(&mut self) {
        self.watching = false;
    }

    /// The op is done with the connection: one that still has a `WATCH` in force (a body that left
    /// it in doubt) is not kept for the next op.
    pub fn settle(&self) {
        if self.watching {
            self.wire.discard();
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

    /// Up to `max` keys matching `pattern` other than `skip`, stopping the `SCAN` as soon as
    /// that many are found.
    pub async fn scan_some(
        &mut self,
        pattern: &str,
        skip: &str,
        max: usize,
    ) -> RedisResult<Vec<String>> {
        let mut cursor = String::from("0");
        let mut out = Vec::new();
        loop {
            let (next, keys) = self.scan_page(&cursor, pattern).await?;
            out.extend(keys.into_iter().filter(|k| k != skip));
            if out.len() >= max || next == "0" {
                out.truncate(max);
                return Ok(out);
            }
            cursor = next;
        }
    }

    /// One `SCAN` page, including an empty page whose returned cursor may still be nonzero.
    pub async fn scan_page(
        &mut self,
        cursor: &str,
        pattern: &str,
    ) -> RedisResult<(String, Vec<String>)> {
        self.scan_pages += 1;
        if self.scan_pages > MAX_SCAN_PAGES {
            return Err(RedisError::refused(
                "SCAN exceeded the per-operation page limit",
            ));
        }
        cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(pattern)
            .arg("COUNT")
            .arg(SCAN_COUNT)
            .query(self)
            .await
    }

    /// Every key matching `pattern` (`SCAN ... MATCH`, followed to the end).
    pub async fn scan_match(&mut self, pattern: &str) -> RedisResult<Vec<String>> {
        let mut cursor = String::from("0");
        let mut out = Vec::new();
        let mut bytes = 0usize;
        loop {
            let (next, keys) = self.scan_page(&cursor, pattern).await?;
            bytes = keys
                .iter()
                .fold(bytes, |n, key| n.saturating_add(key.len()));
            if bytes > MAX_REPLY_BYTES {
                return Err(RedisError::refused(
                    "SCAN exceeded the collected-byte limit",
                ));
            }
            if out.len().saturating_add(keys.len()) > MAX_REPLY_ELEMENTS as usize {
                return Err(RedisError::refused("SCAN exceeded the collected-key limit"));
            }
            out.extend(keys);
            if next == "0" {
                return Ok(out);
            }
            cursor = next;
        }
    }
}

/// Keys a `SCAN` step is asked for.
const SCAN_COUNT: usize = 1000;
pub(crate) const MAX_SCAN_PAGES: usize = 1_000_000;

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
        T::from_value(c.request(&self.args).await?)
    }

    /// Run it for its effect.
    ///
    /// # Errors
    /// As [`Cmd::query`].
    pub async fn exec(&self, c: &mut Conn) -> RedisResult<()> {
        c.request(&self.args).await.map(drop)
    }
}

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
        /// `HSET key field value`.
        hset(k: K, f: F, v: V) => "HSET");

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
        let multi = [b"MULTI".to_vec()];
        let exec = [b"EXEC".to_vec()];
        let mut wire: Vec<&[Vec<u8>]> = Vec::with_capacity(self.cmds.len() + 2);
        if self.atomic {
            wire.push(&multi);
        }
        wire.extend(self.cmds.iter().map(|(a, _)| a.as_slice()));
        if self.atomic {
            wire.push(&exec);
        }
        let mut replies = c.round_trip(&wire).await?;
        let replies = if self.atomic {
            c.watching = false;
            let exec = replies.pop().unwrap_or(Value::Nil);

            if let Some(Value::Error(e)) = replies.iter().find(|r| matches!(r, Value::Error(_))) {
                return Err(RedisError::server(e.clone()));
            }
            match exec {
                Value::Nil => return T::from_value(Value::Nil),
                Value::Error(e) => return Err(RedisError::server(e)),
                Value::Array(items) if items.len() == self.cmds.len() => items,
                _ => {
                    c.wire.discard();
                    return Err(RedisError::from((
                        ErrorKind::Parse,
                        "EXEC reply does not match the queued command count",
                    )));
                }
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

/// A Lua script, run as `EVALSHA` (its digest from one `SCRIPT LOAD`), and as `EVAL` when the
/// server's script cache misses it (`NOSCRIPT`).
#[derive(Debug, Clone)]
pub struct Script {
    src: String,
    sha: std::sync::OnceLock<String>,
}

impl Script {
    /// The script `src`.
    #[must_use]
    pub fn new(src: &str) -> Self {
        Self {
            src: src.to_string(),
            sha: std::sync::OnceLock::new(),
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

    /// Run it and convert its reply. A `NOSCRIPT` miss never ran it, so `EVAL` runs it once.
    ///
    /// # Errors
    /// As [`Cmd::query`].
    pub async fn invoke<T: FromValue>(&self, c: &mut Conn) -> RedisResult<T> {
        let sha = match self.script.sha.get() {
            Some(sha) => sha,
            None => {
                let sha: String = cmd("SCRIPT")
                    .arg("LOAD")
                    .arg(&self.script.src)
                    .query(c)
                    .await?;
                self.script.sha.get_or_init(|| sha)
            }
        };
        match self.call("EVALSHA", sha).query(c).await {
            Err(e) if e.is_noscript() => self.call("EVAL", &self.script.src).query(c).await,
            ran => ran,
        }
    }

    fn call(&self, how: &str, script: &str) -> Cmd {
        let mut c = cmd(how);
        c.arg(script)
            .arg(self.keys.len())
            .arg(&self.keys)
            .arg(&self.args);
        c
    }
}

/// Pin an async block's output to a command result (so `?` inside it knows its error type).
pub fn rr<T, F: Future<Output = RedisResult<T>>>(f: F) -> F {
    f
}

/// The most attempts a `transaction!` makes, including the first, before it gives up.
pub const MAX_TRANSACTION_ATTEMPTS: usize = 64;

impl RedisError {
    /// A `transaction!` that gave up after `aborts` aborted attempts.
    #[must_use]
    pub fn transaction_exhausted(aborts: usize) -> Self {
        Self::from((
            ErrorKind::Client,
            "transaction aborted by concurrent writers; giving up",
            format!("aborted {aborts} times"),
        ))
    }
}

/// The optimistic transaction, as the upstream driver's `transaction`: `WATCH` the keys, run the
/// body (it reads, and queues its writes on the atomic pipeline it is handed, then answers that
/// pipeline's `query`: `None` when a watched key changed and `EXEC` aborted), and run it all again
/// on an abort, for at most [`MAX_TRANSACTION_ATTEMPTS`] attempts in total. Evaluates to the
/// body's `Some` value, or its error (a `WATCH` left in force by a failed body is cleared).
macro_rules! transaction {
    ($c:ident, $keys:expr, |$c2:ident, $pipe:ident| $body:expr $(,)?) => {
        $crate::resp::rr(async {
            let __keys = $keys;
            let mut __aborts = 0usize;
            loop {
                $crate::resp::cmd("WATCH")
                    .arg(__keys)
                    .exec(&mut *$c)
                    .await?;
                let mut __pipe = $crate::resp::pipe();
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
                    Ok(None) => {
                        __aborts += 1;
                        if __aborts >= $crate::resp::MAX_TRANSACTION_ATTEMPTS {
                            if $c.watching() {
                                let _ = $crate::resp::cmd("UNWATCH").exec(&mut *$c).await;
                            }
                            break Err($crate::resp::RedisError::transaction_exhausted(__aborts));
                        }
                        continue;
                    }
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
#[path = "tests/resp_tests.rs"]
pub(crate) mod tests;

impl Drop for Cmd {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.args);
    }
}
impl Drop for Pipeline {
    fn drop(&mut self) {
        for (args, _) in &mut self.cmds {
            zeroize::Zeroize::zeroize(args);
        }
    }
}
impl Drop for ScriptInvocation<'_> {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.keys);
        zeroize::Zeroize::zeroize(&mut self.args);
    }
}
