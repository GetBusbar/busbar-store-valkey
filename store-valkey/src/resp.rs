// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A RESP2 client over the host's connector: the subset of the Valkey protocol this store speaks,
//! sans-IO. Every byte goes out and comes back through the op's one connection (the store SDK's
//! [`Wire`]); this module only encodes commands, parses replies and converts them to Rust values.
//! No socket, no TLS stack and no runtime of its own: the host's connector owns all three.
//!
//! Commands use the host-owned connection; atomic persistence is published by the v4 script.

use std::fmt;

use busbar_contract::abi::sdk::conn::ConnFailure;
use busbar_contract::abi::sdk::cred::Cred;
use busbar_contract::abi::sdk::store::wire::Wire;

/// Frame AUTH without reading any captured credential bytes.
fn auth_message(password: &Cred, user: Option<&str>) -> busbar_contract::abi::sdk::cred::Seal {
    use busbar_contract::abi::sdk::chip::{CredentialPart as Part, SealedValue};
    let mut prefix =
        format!("*{}\r\n$4\r\nAUTH\r\n", if user.is_some() { 3 } else { 2 }).into_bytes();
    if let Some(user) = user {
        prefix.extend_from_slice(format!("${}\r\n", user.len()).as_bytes());
        prefix.extend_from_slice(user.as_bytes());
        prefix.extend_from_slice(b"\r\n");
    }
    prefix.extend_from_slice(format!("${}\r\n", password.len()).as_bytes());
    SealedValue::compose(&[
        Part::Public(&prefix),
        Part::Credential(password),
        Part::Public(b"\r\n"),
    ])
    .field()
}

/// What kind of failure a [`RedisError`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
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

    /// Whether this is a permanent capability denial: the server definitively said it cannot
    /// or will not execute this command. Transient server errors (`LOADING`, `BUSY`, `OOM`,
    /// `MASTERDOWN`, `READONLY`, `NOAUTH`) are **not** capability denials.
    #[must_use]
    pub fn is_capability_denial(&self) -> bool {
        let text = match &self.repr {
            Repr::Server(t) => t.as_str(),
            _ => return false,
        };
        text.starts_with("NOPERM")
            || text.starts_with("ERR unknown command")
            || text.starts_with("ERR unknown subcommand")
            || text.starts_with("ERR wrong number of arguments")
    }

    /// Whether this is a type conversion error (the server replied successfully but the value
    /// could not be converted to the requested Rust type).
    #[must_use]
    pub fn is_type_error(&self) -> bool {
        matches!(self.repr, Repr::General(ErrorKind::TypeError, ..))
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
    /// v4 uses the explicit instance allocation budget instead of the legacy byte ceiling.
    max_bytes: Option<usize>,
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
            if self.at >= self.max_bytes.unwrap_or(MAX_REPLY_BYTES) {
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
            if next - from > MAX_REPLY_LINE || next > self.max_bytes.unwrap_or(MAX_REPLY_BYTES) {
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
                        if after > self.max_bytes.unwrap_or(MAX_REPLY_BYTES) {
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

// Parsed payloads also need wiping if a later sibling is malformed.
struct ParsedItems(Vec<Value>);
impl Drop for ParsedItems {
    fn drop(&mut self) {
        fn wipe(value: &mut Value) {
            use zeroize::Zeroize;
            match value {
                Value::Data(bytes) => bytes.zeroize(),
                Value::Status(text) | Value::Error(text) => text.zeroize(),
                Value::Array(items) => items.iter_mut().for_each(wipe),
                _ => {}
            }
        }
        self.0.iter_mut().for_each(wipe);
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
            let mut items = ParsedItems(Vec::with_capacity(
                usize::try_from(n).unwrap_or(0).min(4096),
            ));
            let mut at = next;
            for _ in 0..n {
                match walk(buf, at, depth + 1)? {
                    Some((v, after)) => {
                        items.0.push(v);
                        at = after;
                    }
                    None => return Ok(None),
                }
            }
            Ok(Some((Value::Array(std::mem::take(&mut items.0)), at)))
        }
        _ => Err(bad("an unknown reply type")),
    }
}

/// The exact encoded size of one RESP2 command, for pre-allocation.
fn encode_len(args: &[Vec<u8>]) -> usize {
    fn decimal_len(mut n: usize) -> usize {
        if n == 0 {
            return 1;
        }
        let mut len = 0;
        while n > 0 {
            n /= 10;
            len += 1;
        }
        len
    }
    // *N\r\n
    let mut total = 1 + decimal_len(args.len()) + 2;
    for a in args {
        // $L\r\n{data}\r\n
        total += 1 + decimal_len(a.len()) + 2 + a.len() + 2;
    }
    total
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
    reply_budget: Option<usize>,
}

impl Conn {
    /// A connection over `wire` (connected, and secured where it must be).
    #[must_use]
    pub fn new(wire: Wire) -> Self {
        Self {
            wire,
            watching: false,
            frame: Frame::default(),
            reply_budget: None,
        }
    }

    async fn send<C: AsRef<[Vec<u8>]>>(&mut self, cmds: &[C]) -> RedisResult<()> {
        let mut out = zeroize::Zeroizing::new(Vec::new());
        let needed: usize = cmds.iter().map(|c| encode_len(c.as_ref())).sum();
        out.reserve(needed);
        for c in cmds {
            encode(c.as_ref(), &mut out);
        }
        self.wire.write_all(&out).await.map_err(|e| {
            self.wire.discard();
            RedisError::io(&e)
        })
    }

    /// Authenticate with one owner-framed RESP command in SDK sealed custody. Neither the credential nor its
    /// packet enters the public command encoder; the wire retains the seal across partial writes
    /// and Pending, and discards an interrupted exchange before it can be reused.
    pub async fn authenticate(&mut self, password: &Cred, user: Option<&str>) -> RedisResult<()> {
        self.wire
            .write_sealed(auth_message(password, user))
            .await
            .map_err(|e| RedisError::io(&e))?;
        match self.read().await? {
            Value::Error(e) => Err(RedisError::server(e)),
            _ => Ok(()),
        }
    }

    /// v4 resource admission follows its explicit instance budget. Legacy callers
    /// keep their existing parser limits. v4 packs rows into a bulk frame, so the
    /// legacy array-element cap never limits record/range cardinality.
    pub(crate) fn reply_budget(&mut self, budget: usize) {
        self.reply_budget = Some(budget);
    }

    async fn read(&mut self) -> RedisResult<Value> {
        self.frame = Frame {
            max_bytes: self.reply_budget,
            ..Frame::default()
        };
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

    /// Length-prefixed native replication RDB transfer. Valkey does not append
    /// RESP's bulk CRLF to this payload. EOF-marker mode is never negotiated.
    pub(crate) async fn native_rdb_length(&mut self) -> RedisResult<u64> {
        loop {
            let length = self.wire.input(|input| -> RedisResult<Option<u64>> {
                // Replication sends bare newlines while the fork is pending.
                while matches!(input.first(), Some(b'\r' | b'\n')) {
                    input.drain(..1);
                }
                let Some(end) = input.windows(2).position(|v| v == b"\r\n") else {
                    if input.len() > 64 {
                        return Err(RedisError::refused("invalid native RDB length"));
                    }
                    return Ok(None);
                };
                if end > 64 || input.first() != Some(&b'$') {
                    return Err(RedisError::refused("invalid native RDB length"));
                }
                let raw = &input[1..end];
                if raw.is_empty() || !raw.iter().all(u8::is_ascii_digit) {
                    return Err(RedisError::refused("unsupported native RDB framing"));
                }
                let length = std::str::from_utf8(raw)
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
                    .filter(|v| *v > 0)
                    .ok_or_else(|| RedisError::refused("invalid native RDB length"))?;
                input.drain(..end + 2);
                Ok(Some(length))
            })?;
            if let Some(length) = length {
                return Ok(length);
            }
            if self.wire.fill().await.map_err(|e| RedisError::io(&e))? == 0 {
                self.wire.discard();
                return Err(RedisError::refused("truncated native RDB header"));
            }
        }
    }

    /// Consume at most one admitted payload chunk without materializing the RDB.
    pub(crate) async fn native_rdb_chunk(
        &mut self,
        count: usize,
    ) -> RedisResult<zeroize::Zeroizing<Vec<u8>>> {
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(count)
            .map_err(|_| RedisError::refused("native RDB chunk allocation"))?;
        while bytes.len() < count {
            self.wire.input(|input| {
                let take = (count - bytes.len()).min(input.len());
                bytes.extend_from_slice(&input[..take]);
                input.drain(..take);
            });
            if bytes.len() == count {
                break;
            }
            if self.wire.fill().await.map_err(|e| RedisError::io(&e))? == 0 {
                self.wire.discard();
                return Err(RedisError::refused("truncated native RDB payload"));
            }
        }
        Ok(bytes)
    }

    /// One command's reply; an error reply is `Err`.
    async fn round_trip<C: AsRef<[Vec<u8>]>>(&mut self, cmds: &[C]) -> RedisResult<Vec<Value>> {
        self.send(cmds).await?;
        let mut out = Vec::with_capacity(cmds.len());
        for _ in cmds {
            out.push(self.read().await?);
        }
        Ok(out)
    }

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

    /// The op is done with the connection: one that still has a `WATCH` in force (a body that left
    /// it in doubt) is not kept for the next op.
    pub fn settle(&self) {
        if self.watching {
            self.wire.discard();
        }
    }
}

/// One command.
#[derive(Clone, Default)]
pub struct Cmd {
    args: Vec<Vec<u8>>,
}

impl fmt::Debug for Cmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Cmd([REDACTED])")
    }
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

#[cfg(test)]
#[path = "tests/resp_tests.rs"]
pub(crate) mod tests;

impl Drop for Cmd {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.args);
    }
}
#[cfg(test)]
mod v4_budget_tests {
    use super::*;

    #[test]
    fn instance_reply_budget_preserves_legacy_default_and_has_no_lower_bulk_ceiling() {
        let header = format!("${}\r\n", MAX_REPLY_BYTES + 1);
        assert!(Frame::default().measure(header.as_bytes()).is_err());
        let mut frame = Frame {
            max_bytes: Some(MAX_REPLY_BYTES + 1024),
            ..Frame::default()
        };
        assert_eq!(frame.measure(header.as_bytes()).unwrap(), None);
        let mut frame = Frame {
            max_bytes: Some(16),
            ..Frame::default()
        };
        assert!(frame.measure(b"$32\r\n").is_err());
    }
}
