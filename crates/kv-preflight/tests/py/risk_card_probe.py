"""Live run-risk cards; return the same Python-generated identity to Rust."""
import ast
import json
import sys

from kv.risk_card import build_run_risk_card
from kv.sandbox import build_run_identity
from kv.vault_origin import record_created

data = json.load(sys.stdin)
try:
    ast.parse("x\0")
except (ValueError, SyntaxError) as exc:
    nul_error = type(exc).__name__
for project in data["projects"]:
    record_created(project)
results = []
for case in data["cases"]:
    identity = build_run_identity(case["argv"], cwd=case["cwd"], env_names=[],
                                  secret_scope="capability", run_id="run_shared")
    card = build_run_risk_card(case["argv"], cwd=case["cwd"], run_identity=identity,
                              **case["options"])
    results.append({"identity": identity, "card": card, "nul_error": nul_error})
json.dump(results, sys.stdout)
