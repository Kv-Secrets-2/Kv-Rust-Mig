#!/usr/bin/env python3
"""Re-open and verify the positive and negative Python 0.4.0 fixtures."""

import base64
import json
import os
from pathlib import Path

import kv
from cryptography.exceptions import InvalidTag
from kv import crypto
from kv.store import SecretStore


REFERENCE_REPO = Path(
    os.environ.get("KV_REFERENCE_REPO", "/home/ubuntu/repos/kv-secrets")
).resolve()
REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = REPO_ROOT / "fixtures" / "v0.4.0"
VAULT_ROOT = Path("/var/tmp/kv-fixture-vaults/basic")


def outcome(call):
    try:
        call()
    except InvalidTag:
        return "invalid_tag"
    except ValueError as exc:
        return f"value_error:{exc}"
    return "ok"


def key_outcome(blob, passphrase):
    try:
        crypto.parse_key_header(blob)
        crypto.unwrap_identity_key(blob, passphrase)
    except InvalidTag:
        return "invalid_tag"
    except ValueError as exc:
        return f"value_error:{exc}"
    return "ok"


def check_import():
    package_path = Path(kv.__file__).resolve()
    assert not package_path.is_relative_to(REFERENCE_REPO), package_path
    assert kv.__version__ == "0.4.0", kv.__version__
    print(f"kv.__file__={package_path}")


def check_labeled_keys():
    data = json.loads((FIXTURES / "labeled_keys.json").read_text(encoding="utf-8"))
    count = 0
    for master in data["vectors"]:
        master_key = bytes.fromhex(master["master_key_hex"])
        for vector in master["vectors"]:
            parts = []
            for part in vector["parts"]:
                parts.append(
                    part["value"] if part["type"] == "str"
                    else bytes.fromhex(part["hex"])
                )
            actual = crypto.derive_labeled_key(
                master_key, vector["label"], *parts
            ).hex()
            assert actual == vector["derived_key_hex"], vector
            count += 1
    return count


def check_aead():
    data = json.loads((FIXTURES / "aead.json").read_text(encoding="utf-8"))
    for vector in data["vectors"]:
        actual = crypto.decrypt(
            bytes.fromhex(vector["key_hex"]),
            bytes.fromhex(vector["blob_hex"]),
            vector["aad"],
        )
        assert actual.hex() == vector["plaintext_hex"], vector["name"]
    for vector in data["tampered"]:
        assert vector["python_outcome"] == "InvalidTag"
        try:
            crypto.decrypt(
                bytes.fromhex(data["vectors"][0]["key_hex"]),
                bytes.fromhex(vector["tampered_blob_hex"]),
                "tamper-aad",
            )
        except InvalidTag:
            continue
        raise AssertionError(f"tampered AEAD {vector['field']} unexpectedly decrypted")
    return len(data["vectors"]), len(data["tampered"])


def check_keys():
    data = json.loads((FIXTURES / "keys.json").read_text(encoding="utf-8"))
    for vector in data["positive"]:
        blob = (FIXTURES / "keys" / vector["file_name"]).read_bytes()
        unwrapped = crypto.unwrap_identity_key(blob, vector["passphrase"])
        assert unwrapped.location.hex() == vector["location_hex"], vector["name"]
        assert list(unwrapped.setting) == vector["setting"], vector["name"]
        assert unwrapped.master_key.hex() == vector["expected"]["master_key_hex"]
        assert bytes(unwrapped.owner_seed).hex() == vector["expected"]["owner_seed_hex"]
        assert (
            unwrapped.local_approval_id.hex()
            == vector["expected"]["local_approval_id_hex"]
        )
        unwrapped.discard_seed()
    for vector in data["negative"]:
        blob = (FIXTURES / "keys" / vector["file_name"]).read_bytes()
        actual = key_outcome(blob, data["positive"][0]["passphrase"])
        assert actual == vector["python_outcome"], (vector["name"], actual)
    return len(data["positive"]), len(data["negative"])


def check_totp():
    data = json.loads((FIXTURES / "totp.json").read_text(encoding="utf-8"))
    for vector in data["codes"]:
        assert crypto.totp_code(vector["secret"], vector["time"]) == vector["code"]
    for vector in data["uris"]:
        assert crypto.totp_uri(
            vector["secret"], account=vector["account"], issuer=vector["issuer"]
        ) == vector["uri"]
    for vector in data["encrypted_v3"]:
        assert crypto.decrypt_totp_secret(
            vector["blob_base64"], vector["passphrase"]
        ) == vector["secret"]
    for vector in data["negative"]:
        actual = outcome(
            lambda vector=vector: crypto.decrypt_totp_secret(
                vector["blob_base64"], vector["passphrase"]
            )
        )
        assert actual == vector["python_outcome"], (vector["name"], actual)
    return (
        len(data["codes"]),
        len(data["uris"]),
        len(data["encrypted_v3"]),
        len(data["negative"]),
    )


def check_recovery():
    data = json.loads((FIXTURES / "recovery.json").read_text(encoding="utf-8"))
    for vector in data["wrapped_keys"]:
        parsed = crypto.parse_recovery_key(vector["token"])
        assert parsed.hex() == vector["parsed_recovery_key_hex"]
        assert crypto.unwrap_master_key_with_recovery(
            vector["wrapped_base64"], vector["token"]
        ).hex() == vector["master_key_hex"]
    for vector in data["malformed_tokens"]:
        actual = outcome(lambda vector=vector: crypto.parse_recovery_key(vector["token"]))
        assert actual == vector["python_outcome"], (vector["name"], actual)
    return len(data["wrapped_keys"]), len(data["malformed_tokens"])


def check_backup_and_sharing():
    data = json.loads((FIXTURES / "backup_codes.json").read_text(encoding="utf-8"))
    for vector in data["codes"]:
        assert crypto.normalize_backup_code(vector["code"]) == vector["normalized"]
        assert crypto.hash_backup_code(vector["code"]) == vector["sha256_hex"]
    for vector in data["passphrase_strength"]:
        assert crypto.check_passphrase_strength(vector["passphrase"]) == (
            vector["ok"], vector["reason"]
        )
    for vector in data["key_export_import"]:
        assert crypto.export_key(bytes.fromhex(vector["master_key_hex"])) == vector["token"]
        assert crypto.import_key(vector["token"]).hex() == vector["imported_key_hex"]
    for vector in data["malformed_key_tokens"]:
        actual = outcome(lambda vector=vector: crypto.import_key(vector["token"]))
        assert actual == vector["python_outcome"], (vector["name"], actual)
    return (
        len(data["codes"]),
        len(data["passphrase_strength"]),
        len(data["key_export_import"]),
        len(data["malformed_key_tokens"]),
    )


def check_vault():
    data = json.loads(
        (FIXTURES / "vaults" / "basic.expected.json").read_text(encoding="utf-8")
    )
    copied = FIXTURES / "vaults" / "basic" / ".secrets"
    original = VAULT_ROOT / ".secrets"
    assert os.path.realpath(VAULT_ROOT) == data["realpath"]
    assert crypto.canonical_location(VAULT_ROOT).hex() == data["location_hex"]

    copied_paths = {
        path.relative_to(copied).as_posix()
        for path in copied.rglob("*")
        if path.is_file()
    }
    for relative in copied_paths:
        source = original / relative
        target = copied / relative
        assert source.read_bytes() == target.read_bytes(), relative
        assert source.stat().st_mode & 0o777 == target.stat().st_mode & 0o777, relative

    store = SecretStore(os.fspath(VAULT_ROOT), passphrase=data["passphrase"])
    actual = {
        env_name: dict(store.list_secrets(env_name))
        for env_name in ("dev", "prod")
    }
    assert actual == data["live_secrets"], actual
    backend = store._active_backend()
    env_ids = {
        env_name: backend._env_id(env_name)
        for env_name in ("dev", "prod")
    }
    assert env_ids == data["env_id"]
    for env_name, env_id in env_ids.items():
        assert (
            VAULT_ROOT / ".secrets" / "drawers" / "envs" / env_id
        ).is_dir(), env_name
    index = backend._load_index("dev")
    assert index["secrets"][data["removed_name"]]["state"] != "live"
    assert (
        index["secrets"]["API_KEY"]["generation"] == data["api_key_generation"]
    )
    return actual, env_ids, len(copied_paths)


def main():
    check_import()
    print(f"PASS labeled_keys={check_labeled_keys()}")
    aead_positive, aead_tampered = check_aead()
    print(f"PASS aead_positive={aead_positive} aead_tampered={aead_tampered}")
    key_positive, key_negative = check_keys()
    print(f"PASS keys_positive={key_positive} keys_negative={key_negative}")
    codes, uris, encrypted, negative = check_totp()
    print(
        f"PASS totp_codes={codes} uris={uris} encrypted_v3={encrypted} "
        f"negative={negative}"
    )
    wrapped, malformed = check_recovery()
    print(f"PASS recovery_wrapped={wrapped} malformed={malformed}")
    codes, strength, exports, malformed = check_backup_and_sharing()
    print(
        f"PASS backup_codes={codes} passphrase_checks={strength} "
        f"key_roundtrips={exports} malformed_imports={malformed}"
    )
    secrets, env_ids, copied_files = check_vault()
    print(f"PASS vault_secrets={json.dumps(secrets, ensure_ascii=False, sort_keys=True)}")
    print(f"PASS vault_env_ids={json.dumps(env_ids, sort_keys=True)}")
    print(f"PASS copied_vault_files={copied_files} (source-path authentication retained)")
    print("ALL PYTHON REFERENCE FIXTURE CHECKS PASSED")


if __name__ == "__main__":
    main()
