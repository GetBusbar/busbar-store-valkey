// SPDX-License-Identifier: Apache-2.0
/// Parse one reply from the front of `buf`: the reply and how many bytes it took, or `None` when
/// `buf` does not hold a whole reply yet. A first pass only checks that the reply is complete (it
/// allocates and copies nothing), so a reply that arrives in many fills is built once, when whole.
///
/// # Errors
/// Bytes that are not RESP2, nesting beyond [`MAX_REPLY_DEPTH`], or a length that overflows.
pub fn parse(buf: &[u8]) -> RedisResult<Option<(Value, usize)>> {
    parse_from(&mut Frame::default(), buf)
}

use super::*;

fn args_of<T: ToArgs>(t: T) -> Vec<Vec<u8>> {
    let mut v = Vec::new();
    t.write_args(&mut v);
    v
}

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
fn a_malformed_or_partial_bulk_is_refused_or_waited_for() {
    assert!(parse(b"$3\r\nabcX\r\n").is_err());

    let (v, n) = parse(b"$4\r\na\r\nb\r\n").unwrap().unwrap();
    assert_eq!((v, n), (Value::Data(b"a\r\nb".to_vec()), 10));

    assert!(parse(b"$x\r\n").is_err());

    assert_eq!(parse(b"$5\r\nab").unwrap(), None);
    assert_eq!(parse(b"$3\r\nabc").unwrap(), None);
    assert_eq!(parse(b"$3\r\nabc\r").unwrap(), None);
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
    let nested: Vec<(Option<String>, Option<String>)> = FromValue::from_value(Value::Array(vec![
        Value::Array(vec![Value::Data(b"n".to_vec()), Value::Nil]),
    ]))
    .unwrap();
    assert_eq!(nested, vec![(Some("n".into()), None)]);
    let ids: Vec<u64> =
        FromValue::from_value(Value::Array(vec![Value::Data(b"7".to_vec())])).unwrap();
    assert_eq!(ids, vec![7]);
    assert!(String::from_value(Value::Nil).is_err());
}

#[test]
fn conversions_refuse_what_does_not_fit() {
    assert!(u64::from_value(Value::Int(-1)).is_err());
    assert!(u32::from_value(Value::Int(i64::from(u32::MAX) + 1)).is_err());
    assert_eq!(u64::from_value(Value::Int(5)).unwrap(), 5);
    let odd = Value::Array(vec![
        Value::Data(b"a".to_vec()),
        Value::Data(b"1".to_vec()),
        Value::Data(b"b".to_vec()),
    ]);
    assert!(<Vec<(String, String)>>::from_value(odd).is_err());
}

#[test]
fn errors_read_as_the_upstream_driver_wrote_them() {
    let e = RedisError::from((ErrorKind::TypeError, "command refused", "why".to_string()));
    assert_eq!(e.to_string(), "command refused - TypeError: why");
    let e = RedisError::refused("historical source refused");
    assert_eq!(e.to_string(), "historical source refused");
}

#[test]
fn nested_arrays_past_the_depth_cap_are_refused_not_recursed_into() {
    let deep = "*1\r\n".repeat(100_000);
    assert!(parse(deep.as_bytes()).is_err());
    let ok = format!("{}:1\r\n", "*1\r\n".repeat(30));
    assert!(parse(ok.as_bytes()).unwrap().is_some());
}

#[test]
fn a_huge_declared_length_waits_and_never_overflows() {
    assert!(parse(format!("${}\r\n", i64::MAX).as_bytes()).is_err());
    assert!(parse(format!("${}\r\n", u64::MAX).as_bytes()).is_err());
    assert!(parse(b"*9223372036854775807\r\n:1\r\n").is_err());
}

#[test]
fn a_reply_delivered_in_many_fills_is_materialised_once() {
    let mut reply = b"*40\r\n".to_vec();
    for _ in 0..40 {
        reply.extend_from_slice(b"$1000\r\n");
        reply.extend_from_slice(&[b'x'; 1000]);
        reply.extend_from_slice(b"\r\n");
    }
    let mut got = None;
    for end in (100..=reply.len() + 99).step_by(100) {
        got = parse(&reply[..end.min(reply.len())]).unwrap();
        if got.is_some() {
            break;
        }
    }
    assert_eq!(got.expect("whole").1, reply.len());
}

#[test]
fn a_large_array_arriving_in_many_fills_is_measured_in_linear_time() {
    let n = 100_000;
    let mut reply = format!("*{n}\r\n").into_bytes();
    for _ in 0..n {
        reply.extend_from_slice(b":1\r\n");
    }
    let mut have = 0;
    let mut done = None;
    let mut frame = Frame::default();
    while done.is_none() {
        have = (have + 16 * 1024).min(reply.len());
        done = parse_from(&mut frame, &reply[..have]).unwrap();
    }
    assert_eq!(done.expect("whole").1, reply.len());
}

#[test]
fn a_negative_length_other_than_minus_one_is_a_parse_error() {
    assert!(parse(b"$-5\r\n").is_err());
    assert!(parse(b"*-7\r\n").is_err());
    assert!(parse(b"*1\r\n$-5\r\n").is_err());
    assert_eq!(parse(b"$-1\r\n").unwrap(), Some((Value::Nil, 5)));
    assert_eq!(parse(b"*-1\r\n").unwrap(), Some((Value::Nil, 5)));
}

#[test]
fn a_resumed_walk_agrees_with_a_whole_one_at_every_split() {
    let reply = b"*3\r\n*2\r\n$3\r\nabc\r\n:7\r\n*0\r\n*2\r\n+OK\r\n$-1\r\n";
    let whole = parse(reply).unwrap();
    assert!(whole.is_some());
    for cut in 0..reply.len() {
        let mut frame = Frame::default();
        assert_eq!(parse_from(&mut frame, &reply[..cut]).unwrap(), None);
        assert_eq!(parse_from(&mut frame, reply).unwrap(), whole);
        // The measuring walk itself: a cut reply is unfinished, and the resumed walk ends
        // exactly at the reply's last byte (parse_from re-walks from byte 0, so it cannot
        // show a resume that finishes early or late).
        let mut measuring = Frame::default();
        assert_eq!(measuring.measure(&reply[..cut]).unwrap(), None, "cut {cut}");
        assert_eq!(
            measuring.measure(reply).unwrap(),
            Some(reply.len()),
            "cut {cut}"
        );
    }
}

#[test]
fn hostile_reply_sizes_and_lines_are_refused_before_payload_allocation() {
    assert!(parse(format!("${MAX_REPLY_BYTES}\r\n").as_bytes()).is_err());
    assert!(parse(format!("*{}\r\n", MAX_REPLY_ELEMENTS + 1).as_bytes()).is_err());
    let mut line = vec![b'+'; MAX_REPLY_LINE + 2];
    assert!(parse(&line).is_err());
    line.extend_from_slice(b"\r\n");
    assert!(parse(&line).is_err());
}

#[test]
fn incomplete_header_search_resumes_at_the_previous_boundary() {
    let mut frame = Frame::default();
    let mut input = b"+".to_vec();
    for _ in 0..1000 {
        input.extend_from_slice(b"ordinary status ");
        assert_eq!(frame.measure(&input).unwrap(), None);
        assert_eq!(frame.searched, input.len() - 1);
    }
    input.extend_from_slice(b"\r\n");
    assert_eq!(frame.measure(&input).unwrap(), Some(input.len()));
}

#[test]
fn server_error_controls_are_escaped_and_numeric_range_is_named() {
    let error = RedisError::server("ERR\n\x1b[2J\x07".into()).to_string();
    assert!(!error.chars().any(char::is_control));
    assert!(error.contains("\\n"));
    assert!(u32::from_value(Value::Int(-1))
        .unwrap_err()
        .to_string()
        .contains("u32"));
}

#[test]
fn i128_quantity_arguments_are_exact_decimal_bulk_strings() {
    for count in [i128::MIN, i128::MAX, i128::from(u64::MAX) + 1] {
        assert_eq!(args_of(count), vec![count.to_string().into_bytes()]);
        let mut wire = Vec::new();
        encode(&args_of(count), &mut wire);
        let expected = format!("*1\r\n${}\r\n{count}\r\n", count.to_string().len());
        assert_eq!(wire, expected.as_bytes());
    }
}

#[test]
fn resp_auth_is_one_whole_command() {
    use busbar_contract::abi::sdk::cred::SealedWrite;
    use busbar_contract::abi::sdk::test_support::chip::{cred, drive_sealed};
    use std::task::Poll;
    let c = cred("pw");
    assert!(auth_message(&cred("pw").require_secure(), None).secure_required());
    let wire = |user| {
        let mut out = Vec::new();
        let mut writer = SealedWrite::message(auth_message(&c, user));
        assert!(matches!(
            drive_sealed::<()>(&mut writer, |bytes| {
                out.extend_from_slice(bytes);
                Poll::Ready(Ok(bytes.len()))
            }),
            Poll::Ready(Ok(()))
        ));
        out
    };
    assert_eq!(wire(None), b"*2\r\n$4\r\nAUTH\r\n$2\r\npw\r\n");
    assert_eq!(
        wire(Some("u")),
        b"*3\r\n$4\r\nAUTH\r\n$1\r\nu\r\n$2\r\npw\r\n"
    );
}
