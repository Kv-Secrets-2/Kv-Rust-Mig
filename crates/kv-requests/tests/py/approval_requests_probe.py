"""Live request-store oracle; dependency hooks are deterministic in both languages."""
import json
import os
import sys

from kv import approvals, approval_artifacts, approval_wire, config, grants, store


def secrets_dir(root):
    return os.path.join(root, ".secrets")


# Isolate permission repair/provenance from the store under test.
for module in (approvals, approval_artifacts, config, store):
    module.secrets_dir = secrets_dir


def build_card(argv, **kwargs):
    return {"argv": argv, **kwargs}


def service_calls(names, max_calls, calls_per_service):
    if calls_per_service == {"bad": 0}:
        raise ValueError("stub service budget refused")
    return (max_calls or len(names), calls_per_service or {n: 1 for n in names})


approvals.build_run_risk_card = build_card
approvals.normalize_risk_card = lambda card: card
grants.normalize_service_calls = service_calls


def run(root, op):
    name = op["op"]
    if name == "create":
        options = dict(op["options"])
        identity = options.pop("run_identity")
        reuse = options.pop("reuse", True)
        return approvals.create_approval_request(
            root, identity, reuse_filter=None if reuse else lambda _: False, **options
        )
    if name == "list":
        return approvals.list_approval_requests(root, include_all=op.get("all", False),
                                               include_missed=op.get("missed", False), now=op["now"])
    if name == "get":
        return approvals.get_approval_request(root, op["id"], now=op["now"])
    if name == "deny":
        return approvals.deny_approval_request(root, op["id"], reason=op.get("reason"), now=op["now"])
    if name == "approve":
        return approvals.mark_approval_request_approved(root, op["id"], grant_id=op["grant_id"],
                                                       reason=op.get("reason"), now=op["now"])
    if name == "mark":
        with store.storage_lock(root):
            return approvals.mark_request_in_held_lock(root, op["id"], op["status"],
                                                       fields=op.get("fields", {}),
                                                       from_status=op.get("from_status", "pending"), now=op["now"])
    if name == "unheld":
        return approvals.mark_request_in_held_lock(root, "id", "denied", fields={})
    if name == "normalize":
        return [approvals._normalize_actor(op.get("actor")), approvals._normalize_reason(op.get("reason"))]
    if name == "digest":
        return [approval_wire.request_content_digest(r) for r in approvals._read_store(root)["requests"]]
    if name == "prune":
        return approvals.prune_approval_requests(root, missed=op.get("missed", False), now=op["now"])
    if name == "verify":
        return [approval_artifacts.verify_approval_request_integrity(root, r)
                for r in approvals._read_store(root)["requests"]]
    if name == "status":
        return [[approvals._request_status(r, op["now"]), approvals.is_missed_request(r, op["now"])]
                for r in op["records"]]
    if name == "raw":
        path = approvals.approval_store_path(root)
        if os.path.lexists(path):
            if os.path.isdir(path) and not os.path.islink(path):
                os.chmod(path, 0o700)
                os.rmdir(path)
            else:
                os.unlink(path)
        kind = op.get("kind", "json")
        if kind == "absent":
            return None
        if kind == "link":
            os.symlink("absent-target", path)
            return None
        if kind == "directory":
            os.mkdir(path, 0o600)
            return None
        with open(path, "wb") as f:
            if kind == "oversized":
                f.truncate(64 * 1024 * 1024 + 1)
            elif kind == "text":
                f.write(op["text"].encode())
            else:
                f.write((json.dumps(op["doc"], indent=2, sort_keys=True) + "\n").encode())
        os.chmod(path, op.get("mode", 0o600))
        return None
    raise ValueError("unknown probe operation")


root = sys.argv[1]
operation = json.load(sys.stdin)
try:
    result = {"ok": run(root, operation)}
except Exception as exc:
    result = {"error": str(exc).replace(root, "<root>")}
json.dump(result, sys.stdout, sort_keys=True)
