#!/usr/bin/env python3
"""Generate golden vectors using the installed kv-secrets 0.4.0 package."""

import base64
import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import cryptography
from cryptography.exceptions import InvalidTag

import kv
from kv import config, crypto
from kv.store import SecretStore


REFERENCE_COMMIT = "9a497d91a0f6e95b0949deaf8f5c431f9a4333c0"
REFERENCE_REPO = Path(
    os.environ.get("KV_REFERENCE_REPO", "/home/ubuntu/repos/kv-secrets")
).resolve()
REPO_ROOT = Path(__file__).resolve().parents[2]
OUTPUT = REPO_ROOT / "fixtures" / "v0.4.0"
VAULT_ROOT = Path("/var/tmp/kv-fixture-vaults/basic")
VAULT_COPY = OUTPUT / "vaults" / "basic"
VAULT_EXCLUSIONS = {
    ".secrets/vault-marker": (
        "Machine-local provenance marker bound to the source directory object; "
        "it is not vault-format data."
    ),
    ".secrets/storage.lock": (
        "Machine-local synchronization lock; it carries no vault-format data."
    ),
    ".secrets/config.lock": (
        "Machine-local configuration writer lock; it carries no vault-format data."
    ),
}
SETTINGS = (14, 8, 1)


def ensure_installed_reference():
    actual_commit = subprocess.check_output(
        ["git", "-C", str(REFERENCE_REPO), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    if actual_commit != REFERENCE_COMMIT:
        raise RuntimeError(
            f"reference checkout is {actual_commit}, expected {REFERENCE_COMMIT}"
        )
    package_path = Path(kv.__file__).resolve()
    if package_path.is_relative_to(REFERENCE_REPO):
        raise RuntimeError(f"kv imported from source checkout: {package_path}")
    if kv.__version__ != "0.4.0":
        raise RuntimeError(f"expected kv 0.4.0, got {kv.__version__}")
    if Path.cwd().resolve().is_relative_to(REFERENCE_REPO):
        raise RuntimeError("run this generator from a neutral working directory")
    print(f"kv.__file__={package_path}")


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o644)


def write_bytes(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)


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


def labeled_keys():
    masters = [
        ("ascending", bytes(range(32))),
        ("all-ff", b"\xff" * 32),
        ("fixed-pattern", bytes.fromhex("0123456789abcdef" * 4)),
    ]
    inputs = [
        ("kv-drawer:index", [("str", "dev")]),
        ("kv-drawer:record", [
            ("str", "dev"),
            ("str", "r_" + "ab" * 32),
        ]),
        ("kv-drawer:env-id", []),
        ("kv-drawer:index", [("str", "prod-ü")]),
        ("x", [("str", "")]),
        ("x", [("bytes", bytes.fromhex("00ff"))]),
    ]
    result = []
    for master_name, master_key in masters:
        vectors = []
        for label, parts in inputs:
            passed_parts = [
                value if kind == "str" else value
                for kind, value in parts
            ]
            encoded_parts = [
                {"type": kind, "value": value}
                if kind == "str"
                else {"type": kind, "hex": value.hex()}
                for kind, value in parts
            ]
            vectors.append({
                "label": label,
                "parts": encoded_parts,
                "derived_key_hex": crypto.derive_labeled_key(
                    master_key, label, *passed_parts
                ).hex(),
            })
        result.append({
            "master_key_name": master_name,
            "master_key_hex": master_key.hex(),
            "vectors": vectors,
        })
    write_json(OUTPUT / "labeled_keys.json", {"vectors": result})


def aead_vectors():
    key = bytes.fromhex("00112233445566778899aabbccddeeff"
                        "ffeeddccbbaa99887766554433221100")
    cases = [
        ("empty", b"", "dev"),
        ("ascii", b"hello from kv", "dev"),
        ("unicode", "värde ✓ — 東京".encode("utf-8"), "dev"),
        ("four-kib", bytes(range(256)) * 16, "dev"),
        ("unicode-aad", "fixture plaintext".encode("utf-8"), "pröd-ü"),
    ]
    vectors = []
    for name, plaintext, aad in cases:
        blob = crypto.encrypt(key, plaintext, aad)
        vectors.append({
            "name": name,
            "key_hex": key.hex(),
            "aad": aad,
            "plaintext_hex": plaintext.hex(),
            "blob_hex": blob.hex(),
        })

    tamper_base = crypto.encrypt(key, b"tamper me", "tamper-aad")
    tampered = []
    for name, offset in (
        ("nonce", 0),
        ("ciphertext", 12),
        ("tag", len(tamper_base) - 1),
    ):
        altered = bytearray(tamper_base)
        altered[offset] ^= 1
        try:
            crypto.decrypt(key, bytes(altered), "tamper-aad")
        except InvalidTag:
            python_outcome = "InvalidTag"
        else:
            raise AssertionError(f"tampered {name} unexpectedly decrypted")
        tampered.append({
            "field": name,
            "original_blob_hex": tamper_base.hex(),
            "tampered_blob_hex": bytes(altered).hex(),
            "python_outcome": python_outcome,
        })
    write_json(OUTPUT / "aead.json", {
        "vectors": vectors,
        "tampered": tampered,
    })


def key_files():
    master_key = bytes(range(0x80, 0xA0))
    owner_seed = bytes(range(0x20, 0x40))
    local_approval_id = bytes(range(0x40, 0x50))
    standard_location = b"/home/u/proj"
    passphrases = [
        "correct horse battery staple",
        "pässwörd-ユニコード",
        "x",
    ]
    cases = []

    def add_case(name, passphrase, location, setting):
        blob = crypto.wrap_key_v4(
            master_key,
            owner_seed,
            local_approval_id,
            passphrase,
            location,
            setting=setting,
        )
        file_name = f"{name}.kvw"
        write_bytes(OUTPUT / "keys" / file_name, blob)
        unwrapped = crypto.unwrap_identity_key(blob, passphrase)
        cases.append({
            "name": name,
            "file_name": file_name,
            "passphrase": passphrase,
            "location_hex": location.hex(),
            "setting": list(setting),
            "expected": {
                "master_key_hex": unwrapped.master_key.hex(),
                "owner_seed_hex": bytes(unwrapped.owner_seed).hex(),
                "local_approval_id_hex": unwrapped.local_approval_id.hex(),
            },
        })
        unwrapped.discard_seed()
        return blob

    baseline = None
    for index, passphrase in enumerate(passphrases, 1):
        blob = add_case(
            f"v4-setting14-passphrase-{index}",
            passphrase,
            standard_location,
            SETTINGS,
        )
        if index == 1:
            baseline = blob
    add_case("v4-setting17", passphrases[0], standard_location, (17, 8, 1))
    add_case(
        "v4-location-4096",
        passphrases[0],
        b"/" + b"x" * 4095,
        SETTINGS,
    )
    add_case(
        "v4-location-non-utf8",
        passphrases[0],
        b"/var/tmp/\xff\xfe",
        SETTINGS,
    )

    header = crypto.parse_key_header(baseline)
    setting_offset = 6 + len(header.location)
    changed_setting = bytearray(baseline)
    changed_setting[setting_offset:setting_offset + 3] = bytes((15, 8, 1))
    bad_setting_cases = [
        ("setting-13-8-1", (13, 8, 1), "header_error"),
        ("setting-18-8-1", (18, 8, 1), "header_error"),
        ("setting-14-9-1", (14, 9, 1), "header_error"),
        ("setting-14-8-2", (14, 8, 2), "header_error"),
    ]

    mutations = []

    def add_negative(name, blob, passphrase, rust_expected):
        path = OUTPUT / "keys" / "negative" / f"{name}.kvw"
        write_bytes(path, blob)
        mutations.append({
            "name": name,
            "file_name": f"negative/{name}.kvw",
            "python_outcome": key_outcome(blob, passphrase),
            "rust_expected": rust_expected,
        })

    for name, offset in (
        ("location-byte-flipped", 6),
        ("salt-byte-flipped", header.tail),
        ("nonce-byte-flipped", header.tail + 16),
        ("ciphertext-byte-flipped", header.tail + 28),
        ("tag-byte-flipped", len(baseline) - 1),
    ):
        altered = bytearray(baseline)
        altered[offset] ^= 1
        add_negative(name, bytes(altered), passphrases[0], "auth_error")
    add_negative(
        "setting-15-8-1",
        bytes(changed_setting),
        passphrases[0],
        "auth_error",
    )
    for name, setting, rust_expected in bad_setting_cases:
        altered = bytearray(baseline)
        altered[setting_offset:setting_offset + 3] = bytes(setting)
        add_negative(name, bytes(altered), passphrases[0], rust_expected)
    add_negative("truncated-by-one", baseline[:-1], passphrases[0], "header_error")
    add_negative("extended-by-one", baseline + b"\x00", passphrases[0], "header_error")
    zero_location = bytearray(baseline)
    zero_location[4:6] = b"\x00\x00"
    add_negative(
        "location-length-zero", bytes(zero_location), passphrases[0], "header_error"
    )
    long_location = bytearray(baseline)
    long_location[4:6] = (4097).to_bytes(2, "big")
    add_negative(
        "location-length-4097", bytes(long_location), passphrases[0], "header_error"
    )
    add_negative(
        "magic-kvw-05",
        b"KVW\x05" + baseline[4:],
        passphrases[0],
        "unsupported_version",
    )

    legacy_v3 = crypto.wrap_key_v3(
        master_key,
        owner_seed,
        local_approval_id,
        passphrases[0],
        standard_location,
    )
    write_bytes(OUTPUT / "keys" / "legacy-v3.kvw", legacy_v3)
    mutations.append({
        "name": "real-v3-file",
        "file_name": "legacy-v3.kvw",
        "python_outcome": key_outcome(legacy_v3, passphrases[0]),
        "rust_expected": "unsupported_version",
    })
    legacy_v2 = crypto.wrap_master_key(master_key, passphrases[0])
    write_bytes(OUTPUT / "keys" / "legacy-v2.kvw", legacy_v2)
    mutations.append({
        "name": "real-v2-file",
        "file_name": "legacy-v2.kvw",
        "python_outcome": key_outcome(legacy_v2, passphrases[0]),
        "rust_expected": "unsupported_version",
    })

    write_json(OUTPUT / "keys.json", {
        "positive": cases,
        "negative": mutations,
    })


def totp_vectors():
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    times = [0, 59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000]
    generated_secret = crypto.generate_totp_secret()
    code_vectors = [
        {"secret": secret, "time": timestamp, "code": crypto.totp_code(secret, timestamp)}
        for timestamp in times
    ]
    code_vectors.append({
        "secret": generated_secret,
        "time": 1234567890,
        "code": crypto.totp_code(generated_secret, 1234567890),
    })

    uri_vectors = []
    for name, account, issuer in (
        ("defaults", None, None),
        ("spaces-and-at", "a b@c.d", "My Org"),
        ("unicode", "ü", "kv"),
    ):
        if account is None:
            uri = crypto.totp_uri(secret)
            account, issuer = "kv-secrets", "kv"
        else:
            uri = crypto.totp_uri(secret, account=account, issuer=issuer)
        uri_vectors.append({
            "name": name,
            "secret": secret,
            "account": account,
            "issuer": issuer,
            "uri": uri,
        })

    encrypted = []
    totp_passphrases = [
        "fixture-totp-16",
        "fixture-totp-32",
        "fixture-totp-128",
    ]
    secrets = [
        "JBSWY3DPEHPK3PXP",
        "JBSWY3DPEHPK3PXP" * 2,
        "JBSWY3DPEHPK3PXP" * 8,
    ]
    for length, totp_secret, passphrase in zip((16, 32, 128), secrets, totp_passphrases):
        blob_b64 = crypto.encrypt_totp_secret(
            totp_secret, passphrase, setting=SETTINGS
        )
        encrypted.append({
            "secret": totp_secret,
            "secret_length": length,
            "passphrase": passphrase,
            "setting": list(SETTINGS),
            "blob_base64": blob_b64,
            "blob_hex": base64.urlsafe_b64decode(blob_b64).hex(),
        })

    negative = []
    v2_secret = "JBSWY3DPEHPK3PXP"
    v2_blob = crypto.legacy_encrypt_totp_secret_v2(v2_secret, "fixture-totp-v2")
    negative.append({
        "name": "real-v2-blob",
        "secret": v2_secret,
        "passphrase": "fixture-totp-v2",
        "blob_base64": v2_blob,
        "python_outcome": outcome(
            lambda: crypto.decrypt_totp_secret(v2_blob, "fixture-totp-v2")
        ),
    })
    valid_v3 = encrypted[1]
    raw_v3 = base64.urlsafe_b64decode(valid_v3["blob_base64"])
    truncated_b64 = base64.urlsafe_b64encode(raw_v3[:-1]).decode("ascii")
    negative.append({
        "name": "v3-truncated-by-one",
        "passphrase": valid_v3["passphrase"],
        "blob_base64": truncated_b64,
        "python_outcome": outcome(
            lambda: crypto.decrypt_totp_secret(truncated_b64, valid_v3["passphrase"])
        ),
    })
    altered_v3 = bytearray(raw_v3)
    altered_v3[-1] ^= 1
    altered_b64 = base64.urlsafe_b64encode(altered_v3).decode("ascii")
    negative.append({
        "name": "v3-tag-byte-flipped",
        "passphrase": valid_v3["passphrase"],
        "blob_base64": altered_b64,
        "python_outcome": outcome(
            lambda: crypto.decrypt_totp_secret(altered_b64, valid_v3["passphrase"])
        ),
    })
    write_json(OUTPUT / "totp.json", {
        "codes": code_vectors,
        "uris": uri_vectors,
        "encrypted_v3": encrypted,
        "negative": negative,
    })


def recovery_vectors():
    pairs = []
    for key_name, master_key in (
        ("ascending", bytes(range(32))),
        ("all-ff", b"\xff" * 32),
    ):
        token = crypto.generate_recovery_key()
        wrapped = crypto.wrap_master_key_with_recovery(master_key, token)
        parsed = crypto.parse_recovery_key(token)
        unwrapped = crypto.unwrap_master_key_with_recovery(wrapped, token)
        if unwrapped != master_key:
            raise AssertionError("recovery wrap did not round-trip")
        pairs.append({
            "master_key_name": key_name,
            "master_key_hex": master_key.hex(),
            "token": token,
            "parsed_recovery_key_hex": parsed.hex(),
            "wrapped_base64": wrapped,
        })

    token = pairs[0]["token"]
    suffix = token[len(crypto.RECOVERY_KEY_PREFIX):]
    malformed = [
        ("wrong-prefix", "notkvrecovery_" + suffix),
        ("wrong-length", crypto.RECOVERY_KEY_PREFIX + "ABCD"),
        ("bad-characters", crypto.RECOVERY_KEY_PREFIX + "!!!!"),
    ]
    outcomes = []
    for name, value in malformed:
        outcomes.append({
            "name": name,
            "token": value,
            "python_outcome": outcome(lambda value=value: crypto.parse_recovery_key(value)),
        })
    write_json(OUTPUT / "recovery.json", {
        "wrapped_keys": pairs,
        "malformed_tokens": outcomes,
    })


def backup_and_key_sharing_vectors():
    fixed_codes = [
        "ABCDE-FGHIJ",
        "abcde-fghij",
        " ABCDE FGHIJ ",
        "ABCDEFGHIJ",
    ]
    generated_codes = crypto.generate_backup_codes(3)
    code_results = []
    for kind, codes in (("fixed", fixed_codes), ("generated", generated_codes)):
        for index, value in enumerate(codes, 1):
            code_results.append({
                "source": kind,
                "index": index,
                "code": value,
                "normalized": crypto.normalize_backup_code(value),
                "sha256_hex": crypto.hash_backup_code(value),
            })

    passphrases = [
        "password",
        " password ",
        "short",
        "1234567890123",
        "1234567890123456",
        "aaaaaaaaaaaa",
        "correct horse battery staple",
        "pässphrase-✓-2026",
        "Tr0ub4dor&3-long",
        "hello world",
        "letmein1",
        "这是一个足够长的口令",
    ]
    strength = []
    for value in passphrases:
        ok, reason = crypto.check_passphrase_strength(value)
        strength.append({"passphrase": value, "ok": ok, "reason": reason})

    fixed_keys = [
        ("ascending", bytes(range(32))),
        ("all-ff", b"\xff" * 32),
    ]
    roundtrips = []
    for name, master_key in fixed_keys:
        token = crypto.export_key(master_key)
        roundtrips.append({
            "name": name,
            "master_key_hex": master_key.hex(),
            "token": token,
            "imported_key_hex": crypto.import_key(token).hex(),
        })
    malformed_tokens = [
        ("wrong-prefix", "not-a-kvkey"),
        ("wrong-length", "kvkey_AA"),
        ("bad-character", "kvkey_" + "!" * 43),
    ]
    imports = []
    for name, token in malformed_tokens:
        imports.append({
            "name": name,
            "token": token,
            "python_outcome": outcome(lambda token=token: crypto.import_key(token)),
        })
    write_json(OUTPUT / "backup_codes.json", {
        "codes": code_results,
        "passphrase_strength": strength,
        "key_export_import": roundtrips,
        "malformed_key_tokens": imports,
    })


def create_vault():
    if VAULT_ROOT.is_symlink():
        raise RuntimeError(f"refusing to replace symlink vault root {VAULT_ROOT}")
    if VAULT_ROOT.exists():
        shutil.rmtree(VAULT_ROOT)
    VAULT_ROOT.parent.mkdir(parents=True, exist_ok=True)

    crypto.KDF_TARGET = SETTINGS
    config.init_project(VAULT_ROOT, passphrase="fixture-pass-1")
    location = os.path.realpath(VAULT_ROOT)
    store = SecretStore(location, passphrase="fixture-pass-1")
    store.set_secret("dev", "API_KEY", "sk-test-123")
    store.set_secret("dev", "API_KEY", "sk-test-456")
    store.set_secret("dev", "UNICODE", "värde ✓")
    store.set_secret("dev", "MULTILINE", "a\nb")
    store.set_secret("dev", "GONE", "remove me")
    if not store.remove_secret("dev", "GONE"):
        raise AssertionError("GONE was not removed")
    config.add_environment(location, "prod")
    store.set_secret("prod", "DB_URL", "postgres://u:p@h/db")

    backend = store._active_backend()
    env_ids = {
        env_name: backend._env_id(env_name)
        for env_name in ("dev", "prod")
    }
    live_secrets = {
        env_name: dict(store.list_secrets(env_name))
        for env_name in ("dev", "prod")
    }
    expected_live_secrets = {
        "dev": {
            "API_KEY": "sk-test-456",
            "MULTILINE": "a\nb",
            "UNICODE": "värde ✓",
        },
        "prod": {
            "DB_URL": "postgres://u:p@h/db",
        },
    }
    if live_secrets != expected_live_secrets:
        raise AssertionError(f"unexpected live secrets: {live_secrets!r}")
    for env_name, env_id in env_ids.items():
        if not (VAULT_ROOT / ".secrets" / "drawers" / "envs" / env_id).is_dir():
            raise AssertionError(f"computed env id does not match directory for {env_name}")
    dev_index = backend._load_index("dev")
    if dev_index["secrets"]["API_KEY"]["generation"] != 2:
        raise AssertionError("API_KEY was not written as generation 2")

    expected = {
        "passphrase": "fixture-pass-1",
        "realpath": location,
        "location_hex": crypto.canonical_location(location).hex(),
        "live_secrets": live_secrets,
        "removed_name": "GONE",
        "api_key_generation": 2,
        "env_id": env_ids,
    }
    write_json(OUTPUT / "vaults" / "basic.expected.json", expected)

    if VAULT_COPY.exists():
        shutil.rmtree(VAULT_COPY)
    VAULT_COPY.parent.mkdir(parents=True, exist_ok=True)
    exclusions_seen = set()
    for relative, _reason in VAULT_EXCLUSIONS.items():
        if (VAULT_ROOT / relative).exists():
            exclusions_seen.add(relative)
    if exclusions_seen != set(VAULT_EXCLUSIONS):
        raise AssertionError(
            f"expected vault exclusions {sorted(VAULT_EXCLUSIONS)}, "
            f"found {sorted(exclusions_seen)}"
        )
    shutil.copytree(
        VAULT_ROOT / ".secrets",
        VAULT_COPY / ".secrets",
        copy_function=shutil.copy2,
        ignore=shutil.ignore_patterns(
            "vault-marker", "storage.lock", "config.lock"
        ),
    )
    return expected, exclusions_seen


def build_manifest(exclusions_seen):
    files = {}
    for path in sorted(OUTPUT.rglob("*")):
        if not path.is_file() or path.name == "manifest.json":
            continue
        relative = path.relative_to(OUTPUT).as_posix()
        content = path.read_bytes()
        files[relative] = {
            "sha256": hashlib.sha256(content).hexdigest(),
            "size_bytes": len(content),
            "mode": f"0o{stat.S_IMODE(path.stat().st_mode):04o}",
        }
    excluded = [
        {"path": path, "reason": VAULT_EXCLUSIONS[path]}
        for path in sorted(exclusions_seen)
    ]
    write_json(OUTPUT / "manifest.json", {
        "reference": {
            "commit": REFERENCE_COMMIT,
            "package": "kv-secrets",
            "package_version": kv.__version__,
            "python_version": platform.python_version(),
            "cryptography_version": cryptography.__version__,
        },
        "files": files,
        "excluded_vault_paths": excluded,
        "manifest_note": (
            "Hashes cover every generated file except manifest.json itself, "
            "which cannot contain its own SHA-256 without a self-reference."
        ),
    })


def main():
    ensure_installed_reference()
    if OUTPUT.exists():
        shutil.rmtree(OUTPUT)
    OUTPUT.mkdir(parents=True)
    labeled_keys()
    aead_vectors()
    key_files()
    totp_vectors()
    recovery_vectors()
    backup_and_key_sharing_vectors()
    _expected, exclusions_seen = create_vault()
    build_manifest(exclusions_seen)
    print(f"generated={OUTPUT}")
    print(f"fixture_files={sum(1 for p in OUTPUT.rglob('*') if p.is_file())}")
    print(f"vault_exclusions={','.join(sorted(exclusions_seen))}")


if __name__ == "__main__":
    main()
