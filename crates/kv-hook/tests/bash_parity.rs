//! Differential test: the Rust lexer and protected-command recognition against
//! Python 0.4.0's `kv.hook` over the Bash corpus (every RR3 Bash command plus
//! hand-written cases).

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use kv_hook::shell::{Cmd, Extras};
use serde_json::{Value, json};

fn lex_dump(text: &str) -> Value {
    let chars = kv_hook::shell::chars(text);
    let (commands, extras, rest): (Vec<Cmd>, Extras, usize) = kv_hook::shell::lex_partial(&chars);
    json!({
        "commands": commands.iter().map(|c| json!({
            "words": c.words,
            "spans": c.spans.iter().map(|(s, e)| json!([s, e])).collect::<Vec<_>>(),
            "quoted": c.quoted,
            "subst": c.subst,
            "pipeline": c.pipeline,
            "pos": c.pos,
            "heredocs": c.heredocs.iter().map(|h| json!([h.text, h.quoted, h.start, h.end])).collect::<Vec<_>>(),
            "herestrings": c.herestrings.iter().map(|h| json!([h.text, h.quoted, h.start, h.end])).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "subs": extras.subs.iter().map(|(b, s, e)| json!([b, s, e])).collect::<Vec<_>>(),
        "comments": extras.comments.iter().map(|(s, e)| json!([s, e])).collect::<Vec<_>>(),
        "redirects": extras.redirects.iter().map(|(s, e)| json!([s, e])).collect::<Vec<_>>(),
        "rest": rest,
    })
}

fn rust_record(text: &str) -> Value {
    json!({
        "reveal": kv_hook::kvcmd::kv_reveal_pattern(text),
        "legacy": kv_hook::kvcmd::legacy_kv_token_scan(text),
        "scan": kv_hook::kvcmd::scan_text(text, 0),
        "has_kv_word": kv_hook::kvcmd::has_kv_word(text),
        "definitions": kv_hook::kvcmd::definitions(text).into_iter().collect::<Vec<_>>(),
        "key_access": kv_hook::kvcmd::has_key_access_code(text),
        "config_mutation": kv_hook::kvcmd::has_kv_config_mutation_code(text),
        "all_paths": kv_hook::fileaccess::extract_all_paths(text),
        "read_targets": kv_hook::fileaccess::extract_read_targets(text),
        "stdin_targets": kv_hook::fileaccess::extract_stdin_redirection_targets(text),
        "variable_path_read": kv_hook::fileaccess::has_variable_path_read(text),
        "glob_to_secrets": kv_hook::fileaccess::has_glob_path_to_secrets(text),
        "git_metadata": kv_hook::fileaccess::is_git_metadata_command(text),
        "git_stripped": kv_hook::fileaccess::strip_git_free_text_values(text),
        "subcommands": kv_hook::fileaccess::extract_shell_subcommands(text),
        "path_candidates": kv_hook::fileaccess::bash_path_candidates(text),
        "lex": lex_dump(text),
    })
}

#[test]
fn bash_text_analysis_matches_python() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let corpus = std::fs::read_to_string(root.join("tests/fixtures/bash_corpus.jsonl")).unwrap();
    let commands: Vec<String> = corpus
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<Value>(line).unwrap()["command"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    let mut child = Command::new(&python)
        .arg("-I")
        .arg(root.join("tests/py/hook_probe.py"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("start Python probe");
    {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(corpus.as_bytes()).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "Python probe failed");
    let python_records: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(python_records.len(), commands.len());
    let mut mismatches = Vec::new();
    for (command, expected) in commands.iter().zip(&python_records) {
        let actual = rust_record(command);
        if &actual != expected {
            mismatches.push(format!(
                "command {:?}\n  python: {}\n  rust:   {}",
                command,
                serde_json::to_string(expected).unwrap(),
                serde_json::to_string(&actual).unwrap()
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} Bash corpus cases differ from Python:\n{}",
        mismatches.len(),
        commands.len(),
        mismatches.join("\n")
    );
}
