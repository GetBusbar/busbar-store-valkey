// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native migration snapshot codec and protected RESP bytes.

pub(crate) mod snapshot;

use crate::resp::{FromValue, RedisError, RedisResult, Value};
use zeroize::{Zeroize, Zeroizing};

/// Protected binary storage; Debug never reveals keys, fields or values.
pub struct Bytes(Zeroizing<Vec<u8>>);
impl Bytes {
    pub(crate) fn into_guarded(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
    /// Borrow only while the wiping owner is alive.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
impl std::fmt::Debug for Bytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HistoricalBytes([REDACTED])")
    }
}
// A malformed native reply must not leave the unconverted tail unwiped.
pub(crate) struct Raw(pub(crate) Value);
impl Drop for Raw {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}
fn wipe(value: &mut Value) {
    match value {
        Value::Data(bytes) => bytes.zeroize(),
        Value::Status(text) | Value::Error(text) => text.zeroize(),
        Value::Array(items) => {
            for value in items.iter_mut() {
                wipe(value);
            }
        }
        _ => {}
    }
}
fn take_bytes(value: &mut Value) -> RedisResult<Bytes> {
    match value {
        Value::Data(bytes) => Ok(Bytes(Zeroizing::new(std::mem::take(bytes)))),
        Value::Status(text) => Ok(Bytes(Zeroizing::new(std::mem::take(text).into_bytes()))),
        _ => Err(RedisError::refused("invalid historical binary cell")),
    }
}
impl FromValue for Bytes {
    fn from_value(value: Value) -> RedisResult<Self> {
        take_bytes(&mut Raw(value).0)
    }
}
