#!/usr/bin/env python3
"""Verify kv-crypto output blobs with the installed Python kv reference."""

import base64
import json
import sys
from pathlib import Path

import kv
from kv import crypto


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: check_rust_outputs.py <rust-output-directory>")
    output = Path(sys.argv[1])
    vectors = json.loads((output / "vectors.json").read_text(encoding="utf-8"))

    key_case = vectors["key"]
    identity = crypto.unwrap_identity_key(
        (output / key_case["file"]).read_bytes(),
        key_case["passphrase"],
    )
    assert identity.location == bytes.fromhex(key_case["location_hex"])
    assert identity.master_key.hex() == key_case["master_key_hex"]
    assert bytes(identity.owner_seed).hex() == key_case["owner_seed_hex"]
    assert identity.local_approval_id.hex() == key_case["local_approval_id_hex"]

    aead_case = vectors["aead"]
    plaintext = crypto.decrypt(
        bytes.fromhex(aead_case["key_hex"]),
        (output / aead_case["file"]).read_bytes(),
        aead_case["aad"],
    )
    assert plaintext.hex() == aead_case["plaintext_hex"]

    totp_case = vectors["totp"]
    totp_blob = (output / totp_case["file"]).read_bytes()
    encrypted_b64 = base64.urlsafe_b64encode(totp_blob).decode("ascii")
    secret = crypto.decrypt_totp_secret(
        encrypted_b64,
        totp_case["passphrase"],
    )
    assert secret == totp_case["secret"]
    assert tuple(totp_blob[4:7]) == tuple(totp_case["setting"])

    print(f"kv.__file__={kv.__file__}")
    print("PASS keyfile=v4 identity fields and location")
    print("PASS aead=nonce+ciphertext+tag with authenticated aad")
    print("PASS totp=v3 encrypted secret and scrypt setting")
    print("ALL RUST OUTPUTS VERIFIED BY PYTHON REFERENCE")


if __name__ == "__main__":
    main()
