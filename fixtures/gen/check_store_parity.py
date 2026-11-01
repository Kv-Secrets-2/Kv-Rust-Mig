#!/usr/bin/env python3
"""Drive the Python drawer backend for the Rust cross-language parity test."""

import json
import sys
from pathlib import Path

from kv.store import DrawerUpgradeBackend
from kv import vault_origin


def live_values(backend, envs):
    return {env: dict(backend.list_secrets(env)) for env in envs}

def set_history_keep(project_root, keep):
    config_path = project_root / ".secrets" / "config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config.setdefault("history", {})["keep"] = keep
    config_path.write_text(
        json.dumps(config, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def main():
    python_root = Path(sys.argv[1])
    rust_root = Path(sys.argv[2])
    master_key = bytes.fromhex(sys.argv[3])
    operations = json.loads(Path(sys.argv[4]).read_text(encoding="utf-8"))
    envs = ("dev", "prod")
    vault_origin.require_local = lambda _root: None
    python_backend = DrawerUpgradeBackend(python_root, lambda: master_key)
    rust_backend = DrawerUpgradeBackend(rust_root, lambda: master_key)

    for operation in operations:
        env = operation["env"]
        set_history_keep(python_root, operation["keep"])
        if operation["op"] == "set":
            python_backend.set_secret(env, operation["key"], operation["value"])
        elif operation["op"] == "remove":
            python_backend.remove_secret(env, operation["key"])
        elif operation["op"] == "save_env":
            python_backend.save_env(env, {"secrets": operation["secrets"]})
        else:
            raise ValueError("unknown parity operation")

    python_values = live_values(python_backend, envs)
    rust_values = live_values(rust_backend, envs)
    if python_values != rust_values:
        raise AssertionError("Python could not cross-read the Rust drawer values")
    print(
        "PASS python parity operations={} cross-read_envs={} "
        "history.keep updated before each mutation".format(len(operations), len(envs))
    )


if __name__ == "__main__":
    main()
