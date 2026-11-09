"""Report Python 0.4.0's leak scanners for one JSON case on stdin.

Input: {"secrets": {...}, "before_time": float, "scan_dirs": [...], "exclude_dirs": [...],
        "snapshot_dirs": [...], "specific": [...], "cwd": str, "temp_dirs": [...], "key_hex": str}
Output: {"snapshot": {path: [size, mtime_ns, ctime_ns]}, "changed": [...], "new": [...],
         "leaked": [[path, name]...] sorted, "specific": [[path, name]...],
         "report": [warning, records]}
"""
import json
import secrets as _secrets
import sys

from kv import sandbox


def main():
    case = json.loads(sys.stdin.read())
    key = bytes.fromhex(case["key_hex"])
    _secrets.token_bytes = lambda n=16: key
    snapshot = sandbox.snapshot_files(case["snapshot_dirs"])
    changed = sandbox.collect_changed_files({k: (v[0], v[1], v[2] - 1) for k, v in snapshot.items()},
                                            case["snapshot_dirs"])
    new = sandbox.collect_new_files(case["before_time"], case["scan_dirs"])
    leaked = sandbox.scan_leaked_files(case["secrets"], case["before_time"],
                                       case["scan_dirs"], case["exclude_dirs"])
    specific = sandbox.scan_specific_files(case["specific"], case["secrets"])
    warning, records = sandbox.leak_report(sorted(leaked), cwd=case["cwd"], temp_dirs=case["temp_dirs"])
    sys.stdout.write(json.dumps({
        "snapshot": {k: list(v) for k, v in sorted(snapshot.items())},
        "changed": sorted(changed),
        "new": sorted(new),
        "leaked": sorted(leaked),
        "specific": specific,
        "report": [warning, records],
    }, ensure_ascii=True))


if __name__ == "__main__":
    main()
