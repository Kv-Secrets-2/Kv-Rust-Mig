"""Report Python 0.4.0's run-environment rules for JSONL cases on stdin.

Each line: {"secrets": {name: value}, "base": {name: value}, "names": [...]}.
Each answer: {"reserved": [bool...], "sensitive": [bool...], "env": {...} | null,
              "error": str | null, "warning": str | null, "pairs_error": str | null,
              "args": [...]}.
"""
import json
import sys

from kv import sandbox


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        case = json.loads(line)
        secrets, base, names = case["secrets"], case["base"], case["names"]
        record = {
            "reserved": [sandbox._reserved_run_env_name(n) for n in names],
            "sensitive": [sandbox._looks_sensitive_env_name(n) for n in names],
            "env": None,
            "error": None,
            "warning": sandbox.run_env_save_warning(names),
            "pairs_error": None,
            "args": sandbox.expected_run_env_args(secrets),
        }
        try:
            record["env"] = sandbox.build_run_env(secrets, base)
        except sandbox.ReservedRunEnvNameError as exc:
            record["error"] = str(exc)
        try:
            sandbox._check_run_env_pairs(secrets)
        except sandbox.RunEnvInjectionError as exc:
            record["pairs_error"] = str(exc)
        sys.stdout.write(json.dumps(record, ensure_ascii=True) + "\n")


if __name__ == "__main__":
    main()
