"""Reference operations on disposable owner-policy test vaults only."""
import json
from pathlib import Path
import shutil
import sys

from kv.config import get_approval_mode, load_config, save_config, set_approval_mode

root = Path(sys.argv[1])
action = sys.argv[2]
if action == "record-created":
    from kv.vault_origin import record_created
    record_created(root)
elif action == "snapshot":
    shutil.copytree(root / ".secrets", root.parent / "seed")
elif action == "restore":
    for child in (root / ".secrets").iterdir():
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()
    shutil.copytree(root.parent / "seed", root / ".secrets", dirs_exist_ok=True)
elif action == "totp":
    config = load_config(root)
    config.setdefault("security", {})["totp"] = {"enabled": True}
    save_config(root, config)
elif action == "get":
    try:
        print(get_approval_mode(root))
    except (AttributeError, TypeError) as exc:
        print("error: " + str(exc))
elif action == "set":
    try:
        print(json.dumps(set_approval_mode(root, sys.argv[3])))
    except ValueError as exc:
        print(str(exc))
elif action == "lock":
    from kv.authorization import authorization_lock
    with authorization_lock(root):
        print("locked", flush=True)
        sys.stdin.readline()
elif action == "try-lock":
    import fcntl
    with open(root / ".secrets" / "storage.lock", "r+b") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            print("available")
        except BlockingIOError:
            print("blocked")
else:
    raise ValueError("unknown test operation")
