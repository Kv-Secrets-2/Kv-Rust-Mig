"""Seed disposable policy queues through the Python store."""
from pathlib import Path
import json
import sys
from kv.config import load_config, save_config
from kv.policy_requests import create_policy_request, policy_request_store_path

root = Path(sys.argv[1])
action = sys.argv[2]
if action in ("seed", "single"):
    Path(policy_request_store_path(root)).unlink(missing_ok=True)
    ids = ["last"] if action == "single" else ["allow", "block", "deny", "broad", "cancel", "expired", "protected", "keep"]
    for name in ids:
        create_policy_request(root, argv=["python3", name + ".py", "two words"],
            cwd=str(root), pattern="python3" if name == "broad" else "python3 " + name + ".py",
            actor={"source":"mcp", "client_name":"agent\\name", "session_id":"test"},
            reason="review me\ncarefully", command_reason="not in project allowlist",
            now=1000 if name == "expired" else 4102440000, request_id="pol_" + name)
elif action == "unallow":
    config = load_config(root)
    config["security"]["allowed_commands"] = []
    save_config(root, config)
elif action in ("bad-argv", "bad-cwd"):
    path=Path(policy_request_store_path(root))
    doc=json.loads(path.read_text())
    doc["requests"][0][action[4:]]=42
    from kv.policy_requests import _write_store
    _write_store(root,doc)
elif action in ("outside-cwd", "different-cwd"):
    cwd=root.parent
    if action == "different-cwd":
        cwd=cwd/"other"
        (cwd/".secrets").mkdir(parents=True,exist_ok=True,mode=0o700)
    path=Path(policy_request_store_path(root))
    doc=json.loads(path.read_text())
    doc["requests"][0]["cwd"]=str(cwd)
    from kv.policy_requests import _write_store
    _write_store(root,doc)
elif action == "no-key":
    (root / ".secrets/key").unlink()
elif action == "audit":
    records = [json.loads(line) for line in (Path.home() / ".kv/audit.jsonl").read_text().splitlines()]
    record = next(r for r in reversed(records) if r.get("event") in ("policy_request_allowed", "policy_request_blocked"))
    print(json.dumps({k:record.get(k) for k in ("event","request_id","pattern","agent","agent_reason","attribution")},sort_keys=True))
else:
    raise ValueError(action)
