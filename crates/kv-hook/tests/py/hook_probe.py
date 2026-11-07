"""Dump kv.hook's Bash-text analysis for each JSON line on stdin (parity oracle).

Each input line is {"command": TEXT}; each output line is the JSON record the
Rust parity test compares against: the lexer's reading of the text and the
protected pattern _is_kv_reveal_command finds.
"""
import json
import sys

from kv import hook


def lex_dump(text):
    commands, extras, rest = hook._lex_partial(text)
    return {
        "commands": [
            {
                "words": c["words"],
                "spans": [list(s) for s in c["spans"]],
                "quoted": c["quoted"],
                "subst": c["subst"],
                "pipeline": c["pipeline"],
                "pos": c["pos"],
                "heredocs": [list(h) for h in c["heredocs"]],
                "herestrings": [list(h) for h in c["herestrings"]],
            }
            for c in commands
        ],
        "subs": [list(s) for s in extras["subs"]],
        "comments": [list(s) for s in extras["comments"]],
        "redirects": [list(s) for s in extras["redirects"]],
        "rest": rest,
    }


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        text = json.loads(line)["command"]
        blocked, pattern = hook._is_kv_reveal_command(text)
        legacy_blocked, legacy_pattern = hook._legacy_kv_token_scan(text)
        record = {
            "reveal": pattern if blocked else None,
            "legacy": legacy_pattern if legacy_blocked else None,
            "scan": hook._scan_text(text),
            "has_kv_word": hook._has_kv_word(text),
            "definitions": sorted(hook._definitions(text)),
            "key_access": hook._has_key_access_code(text),
            "config_mutation": hook._has_kv_config_mutation_code(text),
            "lex": lex_dump(text),
        }
        sys.stdout.write(json.dumps(record, ensure_ascii=True) + "\n")


if __name__ == "__main__":
    main()
