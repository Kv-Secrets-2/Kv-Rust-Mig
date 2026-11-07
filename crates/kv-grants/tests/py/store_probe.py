"""Drive Python 0.4.0's grant/token stores for one JSON case set on stdin.

Input: {"reads": [{"kind": "grants"|"tokens", "root": dir}...],
        "writes": [{"kind": ..., "root": dir, "records": [...]}...]}
Output: {"reads": [{"ok": records} | {"error": type, "message": str}...],
         "writes": [{"ok": true} | {"error": type, "message": str}...]}
"""
import json
import sys

from kv import capabilities, grants

MODULES = {"grants": (grants, "grants"), "tokens": (capabilities, "tokens")}


def attempt(fn):
    try:
        return {"ok": fn()}
    except (OSError, ValueError) as error:
        return {"error": type(error).__name__, "message": str(error)}


def main():
    case = json.loads(sys.stdin.read())
    reads = []
    for item in case["reads"]:
        module, field = MODULES[item["kind"]]
        reads.append(attempt(lambda: module._read_store(item["root"])[field]))
    writes = []
    for item in case["writes"]:
        module, field = MODULES[item["kind"]]
        writes.append(attempt(lambda: module._write_store(
            item["root"], {"version": 1, field: item["records"]}) or True))
    json.dump({"reads": reads, "writes": writes}, sys.stdout)


if __name__ == "__main__":
    main()
