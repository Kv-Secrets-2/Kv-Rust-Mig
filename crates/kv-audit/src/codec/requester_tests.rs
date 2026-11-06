use super::*;
use serde_json::json;
use std::process::Command;
use std::time::Duration;

fn fields(actor: Value, reason: Value) -> Value {
    Value::Object(requester_fields(Some(&actor), Some(&reason)))
}

fn python(script: &str, input: &Value) -> Option<Value> {
    let python = kv_test_support::python_reference()?;
    let mut command = Command::new(python);
    command.args(["-I", "-c", script]);
    let result = test_harness::output(
        command,
        &serde_json::to_vec(input).unwrap(),
        Duration::from_secs(20),
    )
    .expect("bounded Python requester reference");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    Some(serde_json::from_slice(&result.stdout).expect("Python reference JSON"))
}

#[test]
fn labels_distinguish_absent_blank_and_zero_limit() {
    assert_eq!(crate::label_text(None, 80), None);
    for value in [Value::Null, json!(false), json!(42), json!([]), json!({})] {
        assert_eq!(crate::label_text(Some(&value), 80), None);
    }
    let whitespace: String = (0..=0x3000)
        .filter_map(char::from_u32)
        .filter(|character| python_whitespace(*character))
        .collect();
    assert_eq!(crate::label_text(Some(&json!(whitespace)), 80), None);
    assert_eq!(
        crate::label_text(Some(&json!(" nonblank ")), 0),
        Some(String::new())
    );
    assert_eq!(
        crate::label_text(Some(&json!("\u{001c}é🙂 A._-:/@+\u{001f}")), 80),
        Some("___A._-:/@+".to_owned())
    );
    assert_eq!(
        crate::label_text(Some(&json!("é🙂x")), 2),
        Some("__".to_owned())
    );
    let shown = crate::label_text(Some(&json!("a\nname=spoof")), 80).unwrap();
    assert_eq!(crate::label_text(Some(&json!(shown)), 80), Some(shown));
}

#[test]
fn requester_fields_have_fixed_order_and_explicit_null_reason() {
    let result = crate::requester_fields(None, None);
    assert_eq!(
        result.keys().map(String::as_str).collect::<Vec<_>>(),
        ["agent", "agent_reason"]
    );
    assert_eq!(
        Value::Object(result),
        json!({"agent":"unknown", "agent_reason":null})
    );
    for actor in [
        Value::Null,
        json!(42),
        json!([]),
        json!("reported"),
        json!({}),
    ] {
        assert_eq!(
            fields(actor, json!(false)),
            json!({"agent":"unknown", "agent_reason":null})
        );
    }
    assert_eq!(
        fields(
            json!({"session_id":"session-1", "source":"mcp", "client_version":"1.0", "client_name":"my client", "ignored":"other"}),
            json!("  inspect issue 42  "),
        ),
        json!({"agent":"client=my_client version=1.0 source=mcp session=session-1", "agent_reason":"inspect issue 42"}),
    );
}

#[test]
fn requester_identity_checks_raw_and_late_fields_before_truncation() {
    let actor = json!({
        "client_name":"ordinary".repeat(12),
        "client_version":"version".repeat(12),
        "source":"sk-0123456789abcdef",
    });
    assert_eq!(fields(actor.clone(), Value::Null)["agent"], AGENT_WITHHELD);
    let mut ordinary = actor;
    ordinary["source"] = json!("mcp");
    assert_eq!(
        fields(ordinary, Value::Null)["agent"]
            .as_str()
            .unwrap()
            .len(),
        MAX_AGENT_LEN
    );
    assert_eq!(
        fields(
            json!({"client_name":format!("{} sk-0123456789abcdef", "ordinary ".repeat(12))}),
            Value::Null
        )["agent"],
        AGENT_WITHHELD,
    );
    let mcp = "mcp_0123456789abcdef01234567";
    assert_eq!(
        fields(json!({"session_id":mcp}), Value::Null)["agent"],
        format!("session={mcp}")
    );
    assert_eq!(
        fields(
            json!({"client_name":"ordinary words With a build 123456"}),
            Value::Null
        )["agent"],
        "client=ordinary_words_With_a_build_123456",
    );
}

#[test]
fn reasons_use_broader_shape_rules_without_secret_comparisons() {
    let build = "github-actions-runner-2.321.0";
    let result = fields(json!({"client_name":build}), json!(build));
    assert_eq!(result["agent"], format!("client={build}"));
    assert_eq!(result["agent_reason"], REASON_WITHHELD);
    // The identity rule withholds pure long hex; the reason rule needs a digit
    // and a letter unless a known prefix or PEM header matches.
    let hex = "a".repeat(32);
    let result = fields(json!({"client_name":hex}), json!(hex));
    assert_eq!(result["agent"], AGENT_WITHHELD);
    assert_eq!(result["agent_reason"], hex);
    assert_eq!(
        fields(Value::Null, json!("my password is hunter2-short"))["agent_reason"],
        "my password is hunter2-short",
    );
    for reason in [
        format!("{} sk-0123456789abcdef", "ordinary reason ".repeat(20)),
        r#"{"token":"abcdefghijklmno1234567890"}"#.to_owned(),
        "-----BEGIN PRIVATE KEY-----".to_owned(),
    ] {
        assert_eq!(
            fields(Value::Null, json!(reason))["agent_reason"],
            REASON_WITHHELD
        );
    }
}

#[test]
fn reasons_escape_hidden_categories_but_keep_visible_unicode_and_spaces() {
    let raw = "\u{001c}é🙂\t\n\u{0085}\u{2028}\u{2029}\u{00a0}\u{2000}\u{200b}\u{e000}\u{0378}\u{e0001}\\u000a x\u{001f}";
    let expected = "é🙂\\u0009\\u000a\\u0085\\u2028\\u2029\u{00a0}\u{2000}\\u200b\\ue000\\u0378\\U000e0001\\u000a x";
    let shown = fields(Value::Null, json!(raw))["agent_reason"].clone();
    assert_eq!(shown, expected);
    assert_eq!(fields(Value::Null, shown.clone())["agent_reason"], shown);
}

#[test]
fn reason_truncation_counts_characters_and_preserves_whole_escape_pieces() {
    for (character, before) in [('\0', 194), ('\u{f0000}', 190)] {
        let raw = format!("{}{character}", "x".repeat(before));
        let exact = fields(Value::Null, json!(raw))["agent_reason"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(exact.chars().count(), 200);
        let truncated = fields(Value::Null, json!(format!("{raw}y")))["agent_reason"].clone();
        assert_eq!(truncated, format!("{}…", "x".repeat(before)));
        assert_eq!(
            fields(Value::Null, truncated.clone())["agent_reason"],
            truncated
        );
    }
    let visible = "🙂".repeat(200);
    assert_eq!(fields(Value::Null, json!(visible))["agent_reason"], visible);
    assert_eq!(
        fields(Value::Null, json!("🙂".repeat(201)))["agent_reason"],
        format!("{}…", "🙂".repeat(199))
    );
}

#[test]
fn requester_and_label_fields_match_python_reference() {
    let mut texts = vec![
        "".to_owned(),
        " \t\n".to_owned(),
        "\u{001c}separators\u{001f}".to_owned(),
        "é🙂✓ spaces\u{00a0}\u{2000}stay".to_owned(),
        "controls\t\n\u{0085}\u{2028}\u{2029}then".to_owned(),
        "hidden\u{200b}\u{e000}\u{0378}\u{f0000}\u{e0001}end".to_owned(),
        "existing \\u000a remains".to_owned(),
        "github-actions-runner-2.321.0".to_owned(),
        "ordinary words With a build 123456".to_owned(),
        "my password is hunter2-short".to_owned(),
        "-----BEGIN PRIVATE KEY-----".to_owned(),
        "mcp_0123456789abcdef01234567".to_owned(),
        "mcp_0123456789ABCDEF01234567".to_owned(),
        "sK-0123456789abcdef".to_owned(),
        "sİ-0123456789abcdef".to_owned(),
        r#"{"token":"abcdefghijklmno1234567890"}"#.to_owned(),
        "https://example.com?token=AbCdEf0123456789AbCdEf0123456789".to_owned(),
        format!("{} sk-0123456789abcdef", "ordinary ".repeat(40)),
    ];
    for length in [
        15, 16, 23, 24, 31, 32, 79, 80, 81, 159, 160, 161, 199, 200, 201,
    ] {
        texts.extend([
            "a".repeat(length),
            "1".repeat(length),
            "🙂".repeat(length),
            format!("{}1", "a".repeat(length - 1)),
            format!("A{}1", "b".repeat(length - 2)),
            format!("{}\0", "x".repeat(length)),
        ]);
    }
    for prefix in KEY_PREFIXES {
        for length in [15, 16] {
            texts.push(format!("{prefix}{}", "x".repeat(length - prefix.len())));
        }
    }
    for character in (0..=0x3000)
        .filter_map(char::from_u32)
        .filter(|ch| python_whitespace(*ch))
    {
        texts.push(format!("{character}left{character}right{character}"));
    }
    let mut label_cases = Vec::new();
    let mut requester_cases = vec![json!({})];
    for value in [Value::Null, json!(false), json!(12), json!([]), json!({})]
        .into_iter()
        .chain(texts.iter().map(|text| json!(text)))
    {
        for max_len in [0, 1, 2, 6, 80] {
            label_cases.push(json!({"value":value, "max_len":max_len}));
        }
        requester_cases.push(json!({"actor":value, "reason":value}));
        for key in ["client_name", "client_version", "source", "session_id"] {
            requester_cases.push(json!({"actor":{key:value}, "reason":value}));
        }
    }
    requester_cases.extend([
        json!({"actor":{"session_id":"session-1", "source":"mcp", "client_version":"1.0", "client_name":"my client"}, "reason":"inspect issue 42"}),
        json!({"actor":{"client_name":"x".repeat(80), "client_version":"y".repeat(80), "session_id":"sk-0123456789abcdef"}, "reason":null}),
        json!({"actor":{"client_name":false, "source":null, "client_version":[], "session_id":{}}, "reason":""}),
    ]);
    let input = json!({"labels":label_cases, "requesters":requester_cases});
    let Some(expected) = python(
        "import json,sys; from kv.audit import label_text,requester_fields; x=json.load(sys.stdin); print(json.dumps({'labels':[label_text(c.get('value'),c['max_len']) for c in x['labels']], 'requesters':[requester_fields(c.get('actor'),c.get('reason')) for c in x['requesters']]},ensure_ascii=False))",
        &input,
    ) else {
        return;
    };
    let labels: Vec<_> = label_cases
        .iter()
        .map(|case| {
            json!(crate::label_text(
                case.get("value"),
                case["max_len"].as_u64().unwrap() as usize
            ))
        })
        .collect();
    let requesters: Vec<_> = requester_cases
        .iter()
        .map(|case| {
            Value::Object(crate::requester_fields(
                case.get("actor"),
                case.get("reason"),
            ))
        })
        .collect();
    assert_eq!(json!({"labels":labels,"requesters":requesters}), expected);
}

#[test]
fn canonical_requester_hidden_category_inventory() {
    let Some(expected) = python(
        r#"
import json,sys,unicodedata
ranges=[]; start=None
for n in range(0x110000):
    cat=unicodedata.category(chr(n))
    hidden=not 0xd800 <= n <= 0xdfff and (cat.startswith('C') or cat in ('Zl','Zp'))
    if hidden:
        if start is None: start=n
        end=n
    elif start is not None:
        ranges.append([start,end]); start=None
if start is not None: ranges.append([start,end])
print(json.dumps({'unicode':unicodedata.unidata_version,'ranges':ranges}))
"#,
        &Value::Null,
    ) else {
        return;
    };
    let mut actual = Vec::new();
    let mut start = None;
    let mut end = 0;
    for code in 0..=0x10ffff {
        if char::from_u32(code).is_some_and(reason_hidden) {
            start.get_or_insert(code);
            end = code;
        } else if let Some(start) = start.take() {
            actual.push([start, end]);
        }
    }
    if let Some(start) = start {
        actual.push([start, end]);
    }
    if expected["unicode"] == "13.0.0" {
        assert_eq!(json!(actual), expected["ranges"]);
    } else {
        eprintln!(
            "requester reason categories are canonical Unicode 13.0.0; newer Unicode inventories are not claimed equal"
        );
    }
    // Semantic Python lanes check stable characters, including every Zs group
    // and controls which must not be exempted merely because they are whitespace.
    for character in [
        ' ',
        'é',
        '🙂',
        '\0',
        '\t',
        '\n',
        '\u{0085}',
        '\u{00a0}',
        '\u{1680}',
        '\u{2000}',
        '\u{200a}',
        '\u{202f}',
        '\u{205f}',
        '\u{3000}',
        '\u{2028}',
        '\u{2029}',
        '\u{200b}',
        '\u{e000}',
        '\u{0378}',
        '\u{f0000}',
        '\u{e0001}',
    ] {
        let code = u64::from(u32::from(character));
        let reference =
            expected["ranges"].as_array().unwrap().iter().any(|range| {
                range[0].as_u64().unwrap() <= code && code <= range[1].as_u64().unwrap()
            });
        assert_eq!(reason_hidden(character), reference, "{character:?}");
    }
}
