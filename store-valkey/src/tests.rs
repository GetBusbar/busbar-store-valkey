// SPDX-License-Identifier: Apache-2.0
use super::*;
#[path = "../../test-support/valkey_io.rs"]
pub(crate) mod valkey_io;
fn parse_url(input: &str) -> resp::RedisResult<Target> {
    let url = crate::credentials::ValkeyUrl(
        crate::credentials::CredUrl::parse_valkey(input).map_err(url_refused)?,
    );
    parse_target(&url)
}
fn captured_url(input: &str) -> ValkeyUrl {
    ValkeyUrl(crate::credentials::CredUrl::parse_valkey(input).unwrap())
}
fn assert_auth(target: &Target, user: Option<&str>, password: &str) {
    let (got_user, got_password) = target.auth.as_ref().expect("AUTH configured");
    assert_eq!(got_user.as_deref(), user);
    let expected: Cred =
        busbar_contract::abi::sdk::cred::settings(&serde_json::to_vec(password).unwrap()).unwrap();
    assert!(got_password == &expected, "sealed password differs");
}
/// A clearly synthetic password generated at test time, so no credential-shaped literal sits in
/// source: `test-only-<tag>-<random hex>`.
fn test_secret(tag: &str) -> String {
    use std::hash::BuildHasher;
    let hex = std::collections::hash_map::RandomState::new().hash_one(tag);
    format!("test-only-{tag}-{hex:016x}")
}

/// An unencoded password starting with `?` moves the userinfo `@` into the query: the refusal must
/// not echo the query's first key (a password fragment) or a `protocol=` value.
#[test]
fn a_password_split_at_question_mark_is_not_echoed_in_the_refusal() {
    let part = test_secret("part");
    for url in [
        format!("redis://default:?{part}=x@valkey.internal:6379"),
        format!("redis://default:?protocol={part}@valkey.internal:6379"),
    ] {
        let err = parse_url(&url).expect_err("refused").to_string();
        assert!(!err.contains(&part), "{url}: secret echoed: {err}");
    }
}
/// The password-scrub never lets the URL secret out in an error string, and the URL password
/// extractor handles every URL shape.
#[test]
fn password_capture_and_redaction_preserve_raw_and_decoded_forms() {
    let s = test_secret("scrub");
    for (url, decoded, raw) in [
        (format!("redis://:{s}@host:6379/0"), s.clone(), s.clone()),
        (
            format!("rediss://user:{s}%40ss@host:6380"),
            format!("{s}@ss"),
            format!("{s}%40ss"),
        ),
    ] {
        let (decoded, raw) = (decoded.as_str(), raw.as_str());
        let captured = captured_url(&url);
        assert!(captured.password().is_some());
        for leak in [
            format!("connection refused for {url}"),
            format!("AUTH {decoded} refused"),
        ] {
            let scrubbed = captured.redact_echo(&leak);
            assert!(
                !scrubbed.contains(raw) && !scrubbed.contains(decoded),
                "{scrubbed}"
            );
            assert!(scrubbed.contains("<redacted>"));
        }
    }
    for url in ["redis://host:6379", "redis://user@host:6379", "not a url"] {
        assert!(captured_url(url).password().is_none());
    }
    assert_eq!(captured_url("redis://h").redact_echo("plain"), "plain");
    assert_eq!(percent_decode_utf8("p%40ss").as_deref(), Some("p@ss"));
    assert_eq!(percent_decode_utf8("bad%zz").as_deref(), Some("bad%zz"));
}

#[test]
fn tls_url_scheme_is_accepted() {
    let t = parse_url("rediss://:pw@localhost:6380/0").expect("a rediss URL parses");
    assert!(t.tls);
    assert_eq!(t.addr, "localhost:6380");
    assert_auth(&t, None, "pw");
}

/// The `valkeys://` spelling reads as `rediss://`: TLS, and `#insecure` its one fragment.
#[test]
fn valkeys_scheme_selects_tls_and_takes_insecure() {
    let t = parse_url("valkeys://host").expect("a valkeys URL parses");
    assert!(t.tls && !t.insecure, "valkeys:// is TLS, verified");
    assert_eq!(t.addr, "host:6379");
    let t = parse_url("valkeys://host#insecure").expect("valkeys + #insecure parses");
    assert!(
        t.tls && t.insecure,
        "valkeys://…#insecure is TLS, unverified"
    );
    assert!(!parse_url("valkey://host").unwrap().tls);
}

/// The URL reads as the upstream driver read it: user, percent-decoded password, port, database,
/// IPv6 literals, and its refusals in its words.
#[test]
fn urls_parse_as_the_upstream_driver_read_them() {
    let t = parse_url("redis://alice:p%40ss@db.internal:7000/3").unwrap();
    assert_eq!(
        (t.addr.as_str(), t.host.as_str(), t.tls, t.db),
        ("db.internal:7000", "db.internal", false, 3)
    );
    assert_auth(&t, Some("alice"), "p@ss");
    let t = parse_url("valkey://[::1]/").unwrap();
    assert_eq!(
        (t.addr.as_str(), t.host.as_str(), t.db),
        ("[::1]:6379", "::1", 0)
    );
    assert!(parse_url("redis://h").unwrap().auth.is_none());
    assert_eq!(
        parse_url("not-a-valkey-url").unwrap_err().to_string(),
        "Redis URL did not parse - InvalidClientConfig"
    );
    assert_eq!(
        parse_url("redis://h/x").unwrap_err().to_string(),
        "Invalid database number - InvalidClientConfig"
    );
    assert!(parse_url("http://h").is_err());
    assert_eq!(
        parse_url("redis://0.0.0.0:6379").unwrap_err().to_string(),
        "Cannot connect to a wildcard address (0.0.0.0 or ::) - InvalidClientConfig"
    );
    assert_eq!(
        parse_url("redis://h/?protocol=9").unwrap_err().to_string(),
        "Invalid protocol version - InvalidClientConfig: 9"
    );
    assert!(parse_url("redis://h/?protocol=resp3").is_ok());

    let t = parse_url("rediss://h:6380/#insecure").unwrap();
    assert!(t.tls && t.insecure);
    assert!(!parse_url("rediss://h:6380/").unwrap().insecure);
    assert_eq!(
        parse_url("rediss://h/#other").unwrap_err().to_string(),
        "only #insecure is supported as URL fragment - InvalidClientConfig"
    );
}

/// The unix-socket URLs 1.5.5's driver read (VALKEY-UNIX): the path is the connector's
/// `unix:<path>` target, the database, user and password come from the query.
#[test]
fn unix_socket_urls_parse_as_the_upstream_driver_read_them() {
    for url in [
        "redis+unix:///run/valkey.sock",
        "unix:///run/valkey.sock",
        "valkey+unix:///run/valkey.sock",
        "unix:/run/valkey.sock",
    ] {
        let t = parse_url(url).unwrap_or_else(|e| panic!("{url}: {e}"));
        assert_eq!(
            (t.addr.as_str(), t.tls, t.db),
            ("unix:/run/valkey.sock", false, 0)
        );
        assert!(t.auth.is_none());
    }
    let t = parse_url("redis+unix:///run/v.sock?db=2&user=%25al&pass=%26%3F+x").unwrap();
    assert_eq!(t.db, 2);
    assert_auth(&t, Some("%al"), "&? x");
    assert_eq!(
        parse_url("unix:///run/v.sock?db=x")
            .unwrap_err()
            .to_string(),
        "Invalid database number - InvalidClientConfig"
    );
}
#[test]
fn debug_output_redacts_the_url_password() {
    let password = test_secret("debug");
    let url = format!("redis://user:{password}@host:6379/0");
    let store =
        crate::ValkeyStore::from_settings(format!(r#"{{"url":"{url}"}}"#).as_bytes()).unwrap();
    let t = parse_url(&url).unwrap();
    for out in [format!("{store:?}"), format!("{t:?}")] {
        assert!(!out.contains(&password), "password leaked: {out}");
        assert!(out.contains("<redacted>"), "no redaction marker: {out}");
    }
}

fn settings_err(json: &str) -> String {
    crate::ValkeyStore::from_settings(json.as_bytes())
        .expect_err(&format!("{json} must be refused"))
}

#[test]
fn settings_refuse_an_unknown_top_level_key() {
    let e = settings_err(r#"{"url":"redis://127.0.0.1:6379/0","urll":"x"}"#);
    assert_eq!(
        e,
        "invalid valkey plugin config: unknown setting `urll` (accepted: url, connect_timeout_ms)"
    );
}

#[test]
fn settings_refuse_a_connect_timeout_that_is_not_a_positive_integer() {
    for (bad, got) in [
        ("\"5000\"", "a string"),
        ("1.5", "1.5"),
        ("-3", "-3"),
        ("0", "0"),
        ("true", "a boolean"),
        ("[]", "an array"),
        ("{}", "an object"),
    ] {
        let e = settings_err(&format!(
            r#"{{"url":"redis://127.0.0.1:6379/0","connect_timeout_ms":{bad}}}"#
        ));
        assert_eq!(
            e,
            format!(
                "invalid valkey plugin config: `connect_timeout_ms` must be a positive integer \
                 (milliseconds), got {got}"
            ),
            "{bad}"
        );
    }
    crate::ValkeyStore::from_settings(
        br#"{"url":"redis://127.0.0.1:6379/0","connect_timeout_ms":250}"#,
    )
    .expect("a positive integer is accepted");
}

/// A `null` optional setting means the setting is absent.
#[test]
fn a_null_optional_setting_means_absent() {
    crate::ValkeyStore::from_settings(
        br#"{"url":"redis://127.0.0.1:6379/0","connect_timeout_ms":null}"#,
    )
    .expect("a null connect_timeout_ms is the default");
}

#[test]
fn settings_refuse_a_url_that_is_not_a_non_empty_string() {
    for (bad, want) in [
        ("5", "`url` must be a non-empty string, got a number"),
        ("\"\"", "`url` must be a non-empty string"),
        ("[]", "`url` must be a non-empty string, got an array"),
    ] {
        let e = settings_err(&format!(r#"{{"url":{bad}}}"#));
        assert_eq!(e, format!("invalid valkey plugin config: {want}"), "{bad}");
    }
}

/// A missing (or null) `url` and a settings document that is no object are refused in the one
/// grammar: `invalid valkey plugin config: ...`, naming the JSON type, never the value.
#[test]
fn every_settings_refusal_starts_with_the_one_prefix() {
    for json in ["{}", r#"{"url":null}"#] {
        assert_eq!(
            settings_err(json),
            "invalid valkey plugin config: `url` is required (a redis:// connection string)"
        );
    }
    for (json, got) in [
        ("[]", "an array"),
        ("\"redis://h\"", "a string"),
        ("5", "a number"),
        ("true", "a boolean"),
        ("null", "null"),
    ] {
        assert_eq!(
            settings_err(json),
            format!("invalid valkey plugin config: expected a JSON object, got {got}"),
            "{json}"
        );
    }
    assert!(settings_err("{not json").starts_with("invalid valkey plugin config: "));
}

#[test]
fn a_url_parse_refusal_is_not_worded_as_a_failed_connect() {
    let e = settings_err(r#"{"url":"http://127.0.0.1:6379/0"}"#);
    assert!(e.starts_with("invalid valkey plugin config: url: "), "{e}");
    assert!(
        !e.contains("failed to connect"),
        "nothing was connected: {e}"
    );
}

#[test]
fn the_unix_socket_query_password_never_reaches_an_error_or_a_debug() {
    let s = test_secret("unix");
    let encoded = format!("{s}%40w0rd");
    let decoded = format!("{s}@w0rd");
    for (url, secret) in [
        (format!("valkey+unix:///run/v.sock?pass={s}"), s.as_str()),
        (
            format!("valkey+unix:///run/v.sock?db=1&password={s}"),
            s.as_str(),
        ),
        (
            format!("unix:///run/v.sock?user=al&pass={encoded}"),
            encoded.as_str(),
        ),
    ] {
        let captured = captured_url(&url);
        let leaked = captured.redact_echo(&format!("could not reach {url}"));
        assert!(
            !leaked.contains(secret) && !leaked.contains(&decoded),
            "{url}: {leaked}"
        );

        let shown = match parse_url(&url) {
            Ok(t) => format!("{t:?}"),
            Err(e) => e.to_string(),
        };
        assert!(
            !shown.contains(secret) && !shown.contains(&decoded),
            "{shown}"
        );
    }

    let e = crate::ValkeyStore::from_settings(
        format!(r#"{{"url":"valkey+unix:///run/v.sock?pass={s}&db=notanumber"}}"#).as_bytes(),
    )
    .expect_err("a bad db is refused");
    assert!(!e.contains(&s), "{e}");
}
#[test]
fn an_unknown_url_parameter_is_refused_not_ignored() {
    for url in [
        "redis://127.0.0.1:6379/0?timeout=5",
        "valkey+unix:///run/v.sock?db=1&password=x",
        "redis://u:12?abc@127.0.0.1:6379/0",
    ] {
        assert!(parse_url(url).is_err(), "{url} must be refused");
    }
    let e = parse_url("redis://127.0.0.1:6379/0?timeout=5")
        .unwrap_err()
        .to_string();
    assert!(e.contains("timeout") && e.contains("not supported"), "{e}");
    let e = parse_url("redis://u:12?abc@127.0.0.1:6379/0")
        .unwrap_err()
        .to_string();
    assert!(!e.contains("abc"), "the password tail leaked: {e}");
    for ok in [
        "redis://127.0.0.1:6379/0?protocol=resp2",
        "valkey+unix:///run/v.sock?db=1&user=al&pass=x",
    ] {
        parse_url(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
    }
}

#[path = "tests/recorded_connector.rs"]
mod recorded_connector;
#[path = "tests/transport.rs"]
mod transport;
