#!/usr/bin/env python3
"""Drive the Python drawer backend for the Rust cross-language parity test."""

import hashlib
import json
import sys
from copy import deepcopy
from pathlib import Path

from kv import backup
from kv import approval_refs
from kv import config as kv_config
from kv.store import CopyChangedError, DrawerUpgradeBackend
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

def normalized_inventory(backend, env):
    index = deepcopy(backend._load_index(env))
    references = {}
    for name, entry in index["secrets"].items():
        record_id = entry.get("current_record_id")
        generation = entry.get("generation")
        if record_id and isinstance(generation, int):
            references[record_id] = (name, generation)
            entry["current_record_id"] = f"record:{name}:{generation}"
        entry["record_hash"] = "HASH"
        for field in ("created", "updated", "deleted"):
            if field in entry:
                entry[field] = "TIME"
        for reference in entry.get("history") or []:
            record_id = reference.get("record_id")
            generation = reference.get("generation")
            if record_id and isinstance(generation, int):
                references[record_id] = (name, generation)
                reference["record_id"] = f"record:{name}:{generation}"
            if "record_hash" in reference:
                reference["record_hash"] = "HASH"
            if "updated" in reference:
                reference["updated"] = "TIME"
    if "updated" in index.get("_meta", {}):
        index["_meta"]["updated"] = "TIME"
    generations = []
    for path in Path(backend._records_dir(env)).glob("*.kvs"):
        record_id = path.name[:-4]
        generations.append(references[record_id])
    return {
        "index": index,
        "record_count": len(generations),
        "record_generations": sorted(generations),
    }

def prepare_restore(backend, keep):
    set_history_keep(backend.root, keep)
    with backend._storage_lock():
        for env in ("dev", "prod", "staging"):
            backend._clear_env_tree(env)

def stage2c_parity(python_root, rust_root, master_key, spec):
    passphrase = spec["passphrase"]
    keep = spec["history_keep"]
    python_backend = DrawerUpgradeBackend(python_root, lambda: master_key)
    rust_backend = DrawerUpgradeBackend(rust_root, lambda: master_key)
    python_copy_backend = DrawerUpgradeBackend(
        Path(spec["python_copy_root"]), lambda: master_key
    )
    rust_copy_backend = DrawerUpgradeBackend(
        Path(spec["rust_copy_root"]), lambda: master_key
    )

    with python_backend._storage_lock():
        python_backend._copy_env_tree("dev", "staging")
    with python_copy_backend._storage_lock():
        python_copy_backend._copy_env_tree("dev", "staging")
    if dict(python_backend.list_secrets("dev")) != dict(
        rust_copy_backend.list_secrets("staging")
    ):
        raise AssertionError("Python could not read the Rust-copied environment tree")
    if normalized_inventory(python_copy_backend, "staging") != normalized_inventory(
        rust_copy_backend, "staging"
    ):
        raise AssertionError("Python and Rust environment-tree copies differ")

    set_history_keep(python_root, keep)
    create_result = python_backend.copy_env_checked(
        "dev", "staging", keep_existing=True
    )
    python_backend.set_secret("staging", "API_KEY", "destination value")
    keep_result = python_backend.copy_env_checked(
        "dev", "staging", keep_existing=True
    )
    try:
        python_backend.copy_env_checked(
            "dev",
            "staging",
            expect_replaced=[],
            expect_keep=keep,
        )
    except CopyChangedError:
        mismatch = "CopyChanged"
    else:
        raise AssertionError("Python checked copy did not reject stale replacements")
    try:
        python_backend.copy_env_checked(
            "dev",
            "staging",
            expect_replaced=["API_KEY"],
            expect_keep=0,
        )
    except CopyChangedError as exc:
        keep_mismatch = str(exc)
    else:
        raise AssertionError("Python checked copy did not reject a changed history setting")
    replace_result = python_backend.copy_env_checked(
        "dev",
        "staging",
        expect_replaced=["API_KEY"],
        expect_keep=keep,
    )
    python_backend.set_secret("staging", "REMOVED", "removed value")
    python_backend.remove_secret("staging", "REMOVED")
    if dict(python_backend.list_secrets("staging")) != dict(
        rust_backend.list_secrets("staging")
    ):
        raise AssertionError("checked copy results differ between Python and Rust")
    if normalized_inventory(python_backend, "staging") != normalized_inventory(
        rust_backend, "staging"
    ):
        raise AssertionError("checked copy indexes differ between Python and Rust")

    python_state = python_backend.backup_state()
    python_backup_data = backup._payload(
        python_root,
        python_state["environments"],
        python_state["default_env"],
        python_state["history_keep"],
    )
    python_plaintext = json.dumps(
        python_backup_data, ensure_ascii=False, sort_keys=True
    ).encode("utf-8")
    python_backup_path = Path(spec["python_backup_path"])
    python_backup_path.write_bytes(
        backup.seal(python_plaintext, passphrase, setting=(14, 8, 1))
    )
    python_backup_data = backup.open_backup(python_backup_path, passphrase)

    rust_backup_data = backup.open_backup(
        Path(spec["rust_backup_path"]), passphrase
    )
    python_restore_backend = DrawerUpgradeBackend(
        Path(spec["python_restore_root"]), lambda: master_key
    )
    python_rust_restore_backend = DrawerUpgradeBackend(
        Path(spec["python_rust_restore_root"]), lambda: master_key
    )
    prepare_restore(python_restore_backend, keep)
    prepare_restore(python_rust_restore_backend, keep)
    python_restore_count = python_restore_backend.restore_snapshot(
        python_backup_data["environments"]
    )
    python_rust_restore_count = python_rust_restore_backend.restore_snapshot(
        rust_backup_data["environments"]
    )

    print("PASS Stage 2c Python parity")
    print(json.dumps({
        "create_copy": create_result,
        "keep_copy": keep_result,
        "replace_copy": replace_result,
        "replace_mismatch": mismatch,
        "keep_setting_mismatch": keep_mismatch,
        "checked_copy": normalized_inventory(python_backend, "staging"),
        "python_restore_count": python_restore_count,
        "python_rust_restore_count": python_rust_restore_count,
        "python_tree": normalized_inventory(python_copy_backend, "staging"),
        "rust_tree": normalized_inventory(rust_copy_backend, "staging"),
        "python_restore": {
            env: normalized_inventory(python_restore_backend, env)
            for env in ("dev", "prod", "staging")
        },
        "python_rust_restore": {
            env: normalized_inventory(python_rust_restore_backend, env)
            for env in ("dev", "prod", "staging")
        },
    }, ensure_ascii=False, separators=(",", ":")))


def config_ignore_parity(root, cases):
    for case in cases:
        secrets = root / case["name"] / ".secrets"
        secrets.mkdir(parents=True, exist_ok=True)
        path = secrets / ".gitignore"
        path.write_bytes(case["existing"].encode("utf-8"))
        kv_config.update_vault_ignores(
            secrets,
            case["rules"],
            writer_tail=case["writer_tail"],
            header=case["header"],
        )
    print("PASS config ignore parity")


def config_writer_parity(root, value):
    secrets = root / ".secrets"
    secrets.mkdir(parents=True, exist_ok=True)
    (secrets / "config.json").write_text(
        json.dumps(value, indent=2) + "\n", encoding="utf-8"
    )
    print("PASS config writer parity")

def approval_refs_parity(root, env):
    # The store-level parity check excludes config.secrets_dir's separate repair sweep.
    repair = kv_config._repair_private_vault_permissions
    kv_config._repair_private_vault_permissions = lambda _sdir: None
    try:
        result = approval_refs.approvals_naming_env(root, env)
    finally:
        kv_config._repair_private_vault_permissions = repair
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))

def py_str_parity(values):
    print(json.dumps([str(value) for value in values], ensure_ascii=False))


def stage3a_lifecycle(root, master_key, operations):
    backend = DrawerUpgradeBackend(root, lambda: master_key)
    results = []
    for operation in operations:
        kind = operation["op"]
        if kind == "add":
            result = kv_config.add_environment(root, operation["name"])
        elif kind == "default":
            kv_config.set_default_env(root, operation["name"])
            result = None
        elif kind == "rename":
            backend.rename_env(operation["old"], operation["new"])
            result = None
        elif kind == "delete":
            entry = backend.delete_env(operation["name"])
            result = {
                "name": entry["name"],
                "deleted_at": "TIME",
                "purge_after": "TIME",
            }
        elif kind == "restore":
            backend.restore_env(operation["name"])
            result = None
        elif kind == "purge":
            result = backend.purge_env(operation["name"])
        else:
            raise ValueError(f"unknown Stage 3a operation {kind}")
        results.append(result)
    print(json.dumps({
        "returns": results,
        "environments": kv_config.list_environments(root),
        "default_env": kv_config.get_default_env(root),
    }, ensure_ascii=False, separators=(",", ":")))

def normalized_config(config):
    value = dict(config)
    if value.get("created") is not None:
        value["created"] = "TIME"
    for entry in value.get("deleted_environments", []):
        for field in ("deleted_at", "purge_after"):
            if field in entry:
                entry[field] = "TIME"
    return value

def stage3a_step(root, master_key, operation):
    backend = DrawerUpgradeBackend(root, lambda: master_key, require_active=True)
    kind = operation["op"]
    try:
        if kind == "history_keep":
            result = backend.set_history_keep(operation["keep"])
        elif kind == "add":
            result = kv_config.add_environment(root, operation["name"])
        elif kind == "deleted_keep_days":
            kv_config.set_deleted_env_keep_days(root, operation["days"])
            result = kv_config.get_deleted_env_keep_days(root)
        elif kind == "default":
            kv_config.set_default_env(root, operation["name"])
            result = None
        elif kind == "rename":
            backend.rename_env(operation["old"], operation["new"])
            result = None
        elif kind == "delete":
            entry = backend.delete_env(operation["name"])
            result = {
                "name": entry["name"],
                "deleted_at": "TIME",
                "purge_after": "TIME",
            }
        elif kind == "restore":
            backend.restore_env(operation["name"])
            result = None
        elif kind == "purge":
            result = backend.purge_env(operation["name"])
        elif kind == "set":
            backend.set_secret(
                operation["env"], operation["key"], operation["value"]
            )
            result = backend.list_versions(
                operation["env"], operation["key"]
            )[0]["version"]
        elif kind == "remove":
            result = backend.remove_secret(operation["env"], operation["key"])
        elif kind == "copy":
            result = backend.copy_env_checked(
                operation["source"],
                operation["destination"],
                keep_existing=operation.get("keep_existing", False),
            )
        elif kind == "queue_wipe":
            kv_config.queue_env_wipes(root, operation["names"])
            result = None
        elif kind == "list_get":
            env, key = operation["env"], operation["key"]
            result = {
                "value": backend.get_secret(env, key),
                "versions": backend.list_versions(env, key),
            }
        else:
            raise ValueError(f"unknown Stage 3a step {kind}")
        result = {"result": result}
    except Exception as exc:
        result = {"error": str(exc)}

    config = kv_config.load_config(root)
    names = list(config.get("environments", []))
    names.extend(
        entry["name"] for entry in kv_config._deleted_entries(config)
    )
    names.extend(kv_config._pending_wipes(config))
    inventories = {}
    for env in dict.fromkeys(names):
        if Path(backend._index_path(env)).exists():
            inventories[env] = normalized_inventory(backend, env)
    normalized = normalized_config(config)
    print(json.dumps({
        **result,
        "config": normalized,
        "config_bytes": json.dumps(
            normalized, ensure_ascii=True, indent=2
        ) + "\n",
        "indexes": inventories,
    }, ensure_ascii=False, separators=(",", ":")))

def stage3a_backup(root, master_key, operation):
    kind = operation["op"]
    passphrase = operation["passphrase"]
    report_master = master_key
    if kind == "make":
        backend = DrawerUpgradeBackend(root, lambda: master_key, require_active=True)
        seal = backup.seal
        backup.seal = lambda plaintext, phrase, setting=None: seal(
            plaintext, phrase, setting=(14, 8, 1)
        )
        try:
            summary = backup.make_backup(
                root, backend, passphrase, operation["path"]
            )
        finally:
            backup.seal = seal
        result = {"summary": summary}
        report_root = root
    elif kind == "restore":
        data = backup.open_backup(operation["path"], passphrase)
        vault_origin.record_created = lambda _root: None
        restored_root, store = backup.restore_backup(
            data, passphrase, operation["target"]
        )
        vault_origin.require_local = lambda _root: None
        restored_backend = DrawerUpgradeBackend(
            restored_root, lambda: store._load_master_key(), require_active=True
        )
        result = {"values": {}, "versions": {}}
        for env in kv_config.list_environments(restored_root):
            values = dict(store.list_secrets(env))
            result["values"][env] = values
            result["versions"][env] = {}
            index = restored_backend._load_index(env)
            for key, entry in index["secrets"].items():
                if not entry.get("current_record_id"):
                    continue
                result["versions"][env][key] = [
                    {
                        "version": item["version"],
                        "value": store.get_version(env, key, item["version"]),
                    }
                    for item in store.list_versions(env, key)
                ]
        report_root = restored_root
        report_master = store._load_master_key()
    else:
        raise ValueError(f"unknown Stage 3a backup step {kind}")

    backend = DrawerUpgradeBackend(
        report_root, lambda: report_master, require_active=True
    )
    config = kv_config.load_config(report_root)
    indexes = {}
    names = list(config.get("environments", []))
    names.extend(entry["name"] for entry in kv_config._deleted_entries(config))
    for env in dict.fromkeys(names):
        if Path(backend._index_path(env)).exists():
            indexes[env] = normalized_inventory(backend, env)
    normalized = normalized_config(config)
    print(json.dumps({
        **result,
        "config": normalized,
        "config_bytes": json.dumps(
            normalized, ensure_ascii=True, indent=2
        ) + "\n",
        "indexes": indexes,
    }, ensure_ascii=False, separators=(",", ":")))


def main():
    python_root = Path(sys.argv[1])
    rust_root = Path(sys.argv[2])
    master_key = bytes.fromhex(sys.argv[3])
    operations = json.loads(Path(sys.argv[4]).read_text(encoding="utf-8"))
    envs = ("dev", "prod")
    vault_origin.require_local = lambda _root: None
    if isinstance(operations, dict) and "config_ignores" in operations:
        config_ignore_parity(python_root, operations["config_ignores"])
        return
    if isinstance(operations, dict) and "config_writer" in operations:
        config_writer_parity(python_root, operations["config_writer"])
        return
    if isinstance(operations, dict) and "approval_refs" in operations:
        approval_refs_parity(python_root, operations["approval_refs"]["env"])
        return
    if isinstance(operations, dict) and "py_str" in operations:
        py_str_parity(operations["py_str"])
        return
    if isinstance(operations, dict) and "stage3a_lifecycle" in operations:
        stage3a_lifecycle(python_root, master_key, operations["stage3a_lifecycle"])
        return
    if isinstance(operations, dict) and "stage3a_step" in operations:
        stage3a_step(python_root, master_key, operations["stage3a_step"])
        return
    if isinstance(operations, dict) and "stage3a_backup" in operations:
        stage3a_backup(python_root, master_key, operations["stage3a_backup"])
        return
    if isinstance(operations, dict) and operations.get("stage2c"):
        stage2c_parity(python_root, rust_root, master_key, operations)
        return
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
