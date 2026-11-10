// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Valkey's native URL capture and transport requirement, evaluated before public URL parsing.

use busbar_contract::abi::sdk::cred::{redact_encoded_echoes, Cred};
use zeroize::Zeroizing;
mod capture;

type Bytes = Zeroizing<Vec<u8>>;
enum PasswordAt {
    Userinfo,
    Query,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CredUrl {
    public: String,
    password: Option<Cred>,
    echoes: Vec<Cred>,
    parsing_error: Option<&'static str>,
}

impl CredUrl {
    pub(crate) fn parse_valkey(text: &str) -> Result<Self, &'static str> {
        Ok(capture::valkey(text))
    }
    pub(crate) fn public(&self) -> &str {
        &self.public
    }
    pub(crate) fn password(&self) -> Option<&Cred> {
        self.password.as_ref()
    }
    pub(crate) fn parsing_error(&self) -> Option<&'static str> {
        self.parsing_error
    }
    pub(crate) fn redact_echo(&self, text: &str) -> String {
        let credentials: Vec<_> = self.password.iter().chain(self.echoes.iter()).collect();
        redact_encoded_echoes(text, &credentials)
    }
}

fn captured(public: String, found: Option<(Bytes, PasswordAt)>, echoes: Vec<Cred>) -> CredUrl {
    let secure = public.split_once(':').is_some_and(|(scheme, _)| {
        scheme.eq_ignore_ascii_case("rediss") || scheme.eq_ignore_ascii_case("valkeys")
    });
    CredUrl {
        public,
        password: found.map(|(bytes, _)| Cred::captured(bytes).require_secure_if(secure)),
        echoes,
        parsing_error: None,
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ValkeyUrl(pub(crate) CredUrl);
impl core::ops::Deref for ValkeyUrl {
    type Target = CredUrl;
    fn deref(&self) -> &CredUrl {
        &self.0
    }
}

impl<'de> serde::Deserialize<'de> for ValkeyUrl {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Capture;
        impl serde::de::Visitor<'_> for Capture {
            type Value = ValkeyUrl;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a string")
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<ValkeyUrl, E> {
                CredUrl::parse_valkey(value)
                    .map(ValkeyUrl)
                    .map_err(|_| E::custom("invalid credential URL"))
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<ValkeyUrl, E> {
                self.visit_str(&Zeroizing::new(value))
            }
        }
        deserializer.deserialize_string(Capture)
    }
}

#[cfg(test)]
mod capture_tests;
