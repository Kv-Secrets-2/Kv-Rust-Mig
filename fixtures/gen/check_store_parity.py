#!/usr/bin/env python3
"""Drive the Python drawer backend for the Rust cross-language parity test."""

import hashlib
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

def normalized_versions(versions):
    return [
        {
            **version,
            "updated": "TIME" if version.get("updated") is not None else None,
            **(
                {"removed": "TIME" if version.get("removed") is not None else None}
                if version.get("state") == "removed"
                else {}
            ),
        }
        for version in versions
    ]


def main():
    python_root = Path(sys.argv[1])
    rust_root = Path(sys.argv[2])
    master_key = bytes.fromhex(sys.argv[3])
    operations = json.loads(Path(sys.argv[4]).read_text(encoding="utf-8"))
    envs = ("dev", "prod")
    vault_origin.require_local = lambda _root: None
    python_backend = DrawerUpgradeBackend(python_root, lambda: master_key)
    rust_backend = DrawerUpgradeBackend(rust_root, lambda: master_key)

    results = []
    for operation in operations:
        env = operation.get("env")
        op = operation["op"]
        if op == "set":
            set_history_keep(python_root, operation["keep"])
            python_backend.set_secret(env, operation["key"], operation["value"])
            result = python_backend.list_versions(env, operation["key"])[0]["version"]
        elif op == "remove":
            set_history_keep(python_root, operation["keep"])
            result = python_backend.remove_secret(env, operation["key"])
        elif op == "save_env":
            set_history_keep(python_root, operation["keep"])
            python_backend.save_env(env, {"secrets": operation["secrets"]})
            result = None
        elif op == "list_versions":
            result = normalized_versions(python_backend.list_versions(env, operation["key"]))
        elif op == "get_version":
            value = python_backend.get_version(env, operation["key"], operation["version"])
            result = hashlib.sha256(value.encode("utf-8")).hexdigest()
        elif op == "restore_version":
            set_history_keep(python_root, operation["keep"])
            result = python_backend.restore_version(
                env, operation["key"], operation["version"]
            )
        elif op == "undo_remove":
            result = python_backend.undo_remove(env, operation["key"])
        elif op == "prune_envs":
            with python_backend._storage_lock():
                result = sum(
                    python_backend._prune_env_locked(name, operation["keep"])
                    for name in operation["envs"]
                )
            set_history_keep(python_root, operation["keep"])
        elif op == "forget_history":
            result = python_backend.forget_history(env, operation["key"])
        elif op == "forget_env_history":
            result = python_backend.forget_env_history(env)
        elif op == "forget_envs_history":
            with python_backend._storage_lock():
                result = sum(
                    python_backend._forget_locked(name)
                    for name in operation["envs"]
                )
        elif op == "replace_and_forget":
            result = python_backend.replace_and_forget(
                env, operation["key"], operation["value"]
            )
        else:
            raise ValueError(f"unknown parity operation {op}")
        results.append(result)

    python_values = live_values(python_backend, envs)
    rust_values = live_values(rust_backend, envs)
    if python_values != rust_values:
        raise AssertionError("Python could not cross-read the Rust drawer values")
    history_mode = any(operation["op"] == "list_versions" for operation in operations)
    cross_read_restored = (
        rust_backend.get_secret("dev", "history") == "v1" if history_mode else None
    )
    if history_mode and not cross_read_restored:
        raise AssertionError("Python could not read the Rust-restored value")
    label = "PASS python history parity" if history_mode else "PASS python parity"
    print("{} operations={} cross-read_envs={}".format(label, len(operations), len(envs)))
    print(json.dumps({
        "returns": results,
        "python_written_versions": (
            normalized_versions(python_backend.list_versions("dev", "python_history"))
            if history_mode
            else None
        ),
        "cross_read_restored": cross_read_restored,
    }, ensure_ascii=False, separators=(",", ":")))


if __name__ == "__main__":
    main()
