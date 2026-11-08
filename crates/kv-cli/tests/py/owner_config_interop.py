"""Copy one disposable vault and inspect its loaded HTTP policy without calling APIs."""
import json
from pathlib import Path
import shutil
import sys

from kv.broker_policy import load_http_policy_snapshot, describe_http_policy_snapshot

root = Path(sys.argv[1])
action = sys.argv[2]
if action == "snapshot":
    shutil.copytree(root / ".secrets", root.parent / "seed")
    result = None
elif action == "restore":
    for child in (root / ".secrets").iterdir():
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()
    shutil.copytree(root.parent / "seed", root / ".secrets", dirs_exist_ok=True)
    result = None
elif action == "policy":
    snapshot = load_http_policy_snapshot(root)
    result = {"configured": snapshot.configured, "providers": snapshot.providers,
              "description": describe_http_policy_snapshot(snapshot)}
else:
    raise ValueError("unknown probe action")
print(json.dumps(result))
