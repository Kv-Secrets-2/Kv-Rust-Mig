"""Policy-store oracle, including the real config writer and snapshot guard."""
import json
import os
import sys

from kv import policy_requests as policy, config, store


def secrets_dir(root):
    return os.path.join(root, ".secrets")


for module in (policy, config, store):
    module.secrets_dir = secrets_dir


def run(root, op):
    name = op["op"]
    now = op.get("now")
    if name == "create":
        return policy.create_policy_request(root, **op["options"])
    if name == "pattern":
        return policy.policy_pattern_for_argv(op["argv"])
    if name == "fingerprint":
        return policy.request_fingerprint(op["request"])
    if name == "list":
        return policy.list_policy_requests(root, include_all=op.get("all", False), now=now)
    if name == "get":
        return policy.get_policy_request(root, op["id"], now=now)
    if name == "mark_allowed":
        return policy.mark_policy_request_allowed(root, op["id"], reason=op.get("reason"), now=now)
    if name == "block":
        return policy.block_policy_request(root, op["id"], reason=op.get("reason"), now=now)
    if name == "mark":
        with store.storage_lock(root):
            return policy._mark_request_held(root, op["id"], op["status"], now=now, fields=op.get("fields", {}))
    if name == "prune":
        return policy.prune_policy_requests(root, now=now)
    if name == "allow":
        target = os.path.join(root, op.get("target", "."))
        snapshot = config.load_config(target)
        if op.get("stale"):
            with open(os.path.join(target, ".secrets/config.json"), "ab") as f:
                f.write(b" ")
        request = policy.get_policy_request(root, op["id"], now=now)
        fingerprint = op.get("expected", policy.request_fingerprint(request) if request else "")
        if op.get("fail_writer"):
            def fail_writer(*_):
                raise ValueError("pattern writer refused")
            config.add_allowed_command = fail_writer
        return policy.allow_policy_request(root, op["id"], target, snapshot=snapshot,
                                           expected_fingerprint=fingerprint, reason=op.get("reason"), now=now)
    if name == "raw":
        path = policy.policy_request_store_path(root)
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
