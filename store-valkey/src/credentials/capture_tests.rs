// SPDX-License-Identifier: Apache-2.0
// Native capture assertions transferred from the SDK. Secret bytes are observed only by test-seal.
use super::*;
use busbar_contract::abi::sdk::cred::{settings, settings_lent};
use busbar_contract::abi::sdk::test_support::chip::observe_credential;
fn password(url: &CredUrl) -> Option<Vec<u8>> {
    url.password().map(|value| {
        let mut out = Vec::new();
        observe_credential(value, |bytes| out.extend_from_slice(bytes));
        out
    })
}
#[test]
fn valkey_capture_separates_tcp_and_unix_rules() {
    let p = CredUrl::parse_valkey(" \nReDiSs://u:a%2fb@host/2?protocol=resp2\t ").unwrap();
    assert_eq!(password(&p).as_deref(), Some(&b"a/b"[..]));
    assert!(p.password().unwrap().secure_required());
    assert_eq!(p.redact_echo("a/b a%2Fb A/b"), "<redacted> <redacted> A/b");
    let p =
        CredUrl::parse_valkey("unix:/run/v.sock?db=2&%70ass=first&pass=s%3Dc+ret&password=ignored")
            .unwrap();
    assert_eq!(password(&p).as_deref(), Some(&b"s=c ret"[..]));
    assert_eq!(p.public(), "unix:/run/v.sock?db=2&%70ass=&pass=&password=");
    assert_eq!(
        p.redact_echo("first ignored s%3dc+ret s=c+ret s=c ret"),
        "<redacted> <redacted> <redacted> <redacted> <redacted>"
    );
    let p = CredUrl::parse_valkey("unix:///run/v.sock?pass=%FF").unwrap();
    assert_eq!(password(&p).as_deref(), Some("\u{fffd}".as_bytes()));
    assert_eq!(p.redact_echo("%ff \u{fffd}"), "<redacted> <redacted>");
    let p = CredUrl::parse_valkey("redis://u:p@h?pass=ignored&password=also").unwrap();
    assert_eq!(password(&p).as_deref(), Some(&b"p"[..]));
    assert!(p.public().contains("?pass=&password="));
    let p = CredUrl::parse_valkey("unix://u:ignored@localhost/run/v.sock").unwrap();
    assert!(p.password().is_none());
    assert!(!p.public().contains("ignored"));
}

#[test]
fn valkey_empty_and_invalid_password_metadata_survives_typed_settings() {
    for text in ["redis://:@h", "redis://u:@h", "redis://h"] {
        assert!(CredUrl::parse_valkey(text).unwrap().password().is_none());
    }
    assert!(CredUrl::parse_valkey("unix:/run/v.sock?pass=")
        .unwrap()
        .password()
        .is_some());
    let p: ValkeyUrl = settings_lent(br#"{"$secret":0}"#, &[b"redis://u:%ff@h"]).unwrap();
    assert_eq!(
        p.parsing_error(),
        Some("Password is not valid UTF-8 string")
    );
    assert_eq!(p.public(), "redis://u@h");
    let p: ValkeyUrl = settings(br#""unsupported://u:private@h""#).unwrap();
    assert_eq!(p.parsing_error(), Some("Redis URL did not parse"));
    assert!(!p.public().contains("private"));
}

#[test]
fn raw_delimiters_do_not_turn_a_path_or_query_into_native_userinfo() {
    for text in [
        "redis://u:secret?tail@db/0",
        "redis://u:secret/tail@db/0",
        "redis://u:secret#tail@db/0",
    ] {
        let p = CredUrl::parse_valkey(text).unwrap();
        assert_eq!(p.parsing_error(), Some("Redis URL did not parse"));
        assert!(!p.public().contains("secret"));
        assert!(!p.public().contains("tail"));
        assert!(p.password().is_none());
    }
    let p = CredUrl::parse_valkey("redis://u:12?abc@127.0.0.1/0").unwrap();
    assert!(p.password().is_none());
    assert!(p.parsing_error().is_none());
    assert_eq!(p.public(), "redis://u:12?redacted@");
    assert_eq!(p.redact_echo("12?abc"), "<redacted>");
    let p = CredUrl::parse_valkey("valkeys://u:p@host").unwrap();
    assert!(p.password().unwrap().secure_required());
}
