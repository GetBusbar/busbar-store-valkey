// SPDX-License-Identifier: Apache-2.0
use super::*;
fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn decode_form(s: &str) -> Bytes {
    let spaced = Zeroizing::new(s.replace('+', " "));
    decode(&spaced)
}

fn decode(s: &str) -> Bytes {
    let b = s.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(b.len()));
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fn remember(echoes: &mut Vec<Cred>, raw: &str, decoded: &Bytes) {
    echoes.push(Cred::captured(Zeroizing::new(raw.as_bytes().to_vec())));
    echoes.push(Cred::captured(decoded.clone()));
}
fn normalized(text: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(text.len()));
    for c in text.trim_matches(|c: char| c <= '\u{20}').chars() {
        if !matches!(c, '\t' | '\n' | '\r') {
            out.push(c);
        }
    }
    out
}

fn lossy(bytes: &[u8]) -> Bytes {
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len().saturating_mul(3)));
    let mut rest = bytes;
    while !rest.is_empty() {
        match core::str::from_utf8(rest) {
            Ok(_) => {
                out.extend_from_slice(rest);
                break;
            }
            Err(e) => {
                out.extend_from_slice(&rest[..e.valid_up_to()]);
                out.extend_from_slice("\u{fffd}".as_bytes());
                rest = &rest
                    [e.valid_up_to() + e.error_len().unwrap_or(rest.len() - e.valid_up_to())..];
            }
        }
    }
    out
}

pub(super) fn valkey(text: &str) -> CredUrl {
    let text = normalized(text);
    let mut echoes = Vec::new();
    let mut found = None;
    let mut error = None;
    let Some(colon) = text.find(':') else {
        let mut out = captured(String::new(), None, echoes);

        out.parsing_error = if text.is_empty() {
            None
        } else {
            Some("Redis URL did not parse")
        };
        return out;
    };
    let scheme = &text[..colon];
    let unix = ["unix", "redis+unix", "valkey+unix"]
        .iter()
        .any(|s| scheme.eq_ignore_ascii_case(s));
    let supported = unix
        || ["redis", "rediss", "valkey", "valkeys"]
            .iter()
            .any(|s| scheme.eq_ignore_ascii_case(s));
    if !supported {
        error = Some("Redis URL did not parse");
    }
    let rest = &text[colon + 1..];
    if !supported || (!rest.starts_with("//") && (!unix || !rest.starts_with('/'))) {
        let mut out = captured(format!("{scheme}:"), None, echoes);
        out.parsing_error = error;
        return out;
    }
    let mut ambiguous = false;
    let mut public = String::with_capacity(text.len());
    public.push_str(scheme);
    public.push(':');
    let after = if let Some(authority_rest) = rest.strip_prefix("//") {
        public.push_str("//");
        let end = authority_rest
            .find(['/', '?', '#'])
            .unwrap_or(authority_rest.len());
        let authority = &authority_rest[..end];
        if !authority.contains('@') && !authority.starts_with('[') {
            if let Some((_, port)) = authority.rsplit_once(':') {
                if let Some(at) = authority_rest[end..].rfind('@') {
                    ambiguous = true;
                    let start = authority.find(':').expect("authority colon") + 1;
                    let raw = &authority_rest[start..end + at];
                    let b = decode(raw);
                    remember(&mut echoes, raw, &b);
                    if !port.is_empty() && port.parse::<u16>().is_err() {
                        let mut out = captured(String::new(), None, echoes);
                        out.parsing_error = Some("Redis URL did not parse");
                        return out;
                    }
                }
            }
        }
        if let Some((userinfo, host)) = authority.rsplit_once('@') {
            if let Some((user, pass)) = userinfo.split_once(':') {
                let b = decode(pass);
                remember(&mut echoes, pass, &b);
                echoes.push(Cred::captured(lossy(&b)));
                echoes.push(Cred::captured(lossy(&decode_form(pass))));
                if !unix && !pass.is_empty() {
                    if core::str::from_utf8(&b).is_err() {
                        error = Some("Password is not valid UTF-8 string");
                    }
                    found = Some((b, PasswordAt::Userinfo));
                }
                public.push_str(user);
            } else {
                public.push_str(userinfo);
            }
            public.push('@');
            public.push_str(host);
        } else {
            public.push_str(authority);
        }
        &authority_rest[end..]
    } else {
        rest
    };
    let (before_fragment, fragment) = after
        .split_once('#')
        .map_or((after, None), |(a, f)| (a, Some(f)));
    let (path, query) = before_fragment
        .split_once('?')
        .map_or((before_fragment, None), |(a, q)| (a, Some(q)));
    if ambiguous {
        for (i, segment) in path.split('/').enumerate() {
            if i != 0 {
                public.push('/');
            }
            public.push_str(if segment.contains('@') {
                "redacted@"
            } else {
                segment
            });
        }
    } else {
        public.push_str(path);
    }
    if let Some(query) = query {
        public.push('?');
        for (i, pair) in query.split('&').enumerate() {
            if i != 0 {
                public.push('&');
            }
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let key_decoded = decode_form(key);
            if matches!(&key_decoded[..], b"pass" | b"password") {
                let b = decode_form(value);
                remember(&mut echoes, value, &b);

                let value = lossy(&b);
                echoes.push(Cred::captured(decode(
                    pair.split_once('=').map_or("", |(_, v)| v),
                )));
                if unix && &key_decoded[..] == b"pass" {
                    found = Some((value, PasswordAt::Query));
                } else {
                    echoes.push(Cred::captured(value));
                }
                public.push_str(key);
                public.push('=');
            } else if ambiguous {
                let known = if unix {
                    &["db", "user", "protocol"][..]
                } else {
                    &["protocol"][..]
                };
                let key_text = core::str::from_utf8(&key_decoded).unwrap_or("");
                if known.contains(&key_text) {
                    public.push_str(key);
                    if pair.contains('=') {
                        public.push('=');
                        public.push_str(if value.contains('@') {
                            "<redacted>"
                        } else {
                            value
                        });
                    }
                } else {
                    public.push_str("redacted@");
                }
            } else {
                public.push_str(pair);
            }
        }
    }
    if let Some(f) = fragment {
        public.push('#');
        public.push_str(if ambiguous && f.contains('@') {
            "redacted@"
        } else {
            f
        });
    }
    let mut out = captured(public, found, echoes);
    out.parsing_error = error;
    if scheme.eq_ignore_ascii_case("valkeys") {
        out.password = out.password.map(Cred::require_secure);
    }
    out
}
