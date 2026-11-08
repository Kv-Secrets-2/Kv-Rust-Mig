"""Installed Python reference preflight; only the generated run ID is masked."""
import json
import sys

from kv.preflight import PROVIDERS, manifest_json, preflight_command
from kv.vault_origin import record_created

case = json.load(sys.stdin)
for root in case["projects"]:
    record_created(root)
results = []
for item in case["cases"]:
    try:
        manifest = preflight_command(item["argv"], cwd=item["cwd"])
        manifest.identity["run_id"] = "run_MASKED"
        results.append({"json": manifest_json(manifest)})
    except Exception as exc:
        results.append({"error": {"type": type(exc).__name__, "message": str(exc)}})
json.dump({"results": results, "providers": PROVIDERS, "version": list(sys.version_info[:2])}, sys.stdout)
