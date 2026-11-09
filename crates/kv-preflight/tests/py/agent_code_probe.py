"""Live installed-reference agent-code scanner probe."""
import dataclasses
import json
import os
import sys

from kv.agent_code_scan import scan_agent_code
from kv import structure

case = json.load(sys.stdin)
os.chdir(case["cwd"])
assert not list(structure._watchers)
results = []
for path in case["paths"]:
    try:
        results.append({"findings": [dataclasses.asdict(f) for f in scan_agent_code(path)]})
    except Exception as exc:
        results.append({"error": {"type": type(exc).__name__, "message": str(exc)}})
json.dump(results, sys.stdout, ensure_ascii=True)
