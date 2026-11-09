"""Report Python 0.4.0's redaction for JSONL cases on stdin.

Each line: {"secrets": {name: value}, "text": str}.
Each answer: {"needles": [...], "redacted": str, "variants": [[variant, name], ...]}
where variants uses build_secret_variants' default limits, in dict order.
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
        secrets = case["secrets"]
        record = {
            "needles": sandbox.redaction_needles(secrets),
            "redacted": sandbox.redact(case["text"], secrets),
            "variants": [[v, n] for v, n in sandbox.build_secret_variants(secrets).items()],
        }
        sys.stdout.write(json.dumps(record, ensure_ascii=True) + "\n")


if __name__ == "__main__":
    main()
