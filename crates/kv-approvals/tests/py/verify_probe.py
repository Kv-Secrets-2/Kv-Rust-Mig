"""Report Python 0.4.0's approval_verify core results for one JSON case set on stdin.

Input: {"ctx": {"protected": bool, "owner_public_key": hex, "local_approval_id": hex,
                "location": hex, "owner_key_id": str, "session_nonce": hex},
        "signed": [grant...], "wallets": [scope...], "entry_counts": [{"per_entry", "record"}...],
        "mismatch": [{"payload", "run": {"env_name", "secret_names", "capability_names"},
                      "snapshot"}...], "split_keys": [any...]}
Output: {"signed": [{"payload", "digest", "verified"|"error"}|null...], "wallets": [...],
         "entry_counts": [bool...], "mismatch": [str|null...], "split_keys": [[p, r]|null...]}
"""
import dataclasses
import json
import sys
from types import SimpleNamespace

from kv import approval_verify as av


def attempt(fn, *args):
    try:
        return {"ok": fn(*args)}
    except av.AdmissionRefused as error:
        return {"error": str(error), "code": error.code}


def main():
    case = json.loads(sys.stdin.read())
    c = case["ctx"]
    ctx = SimpleNamespace(
        protected=c["protected"],
        owner_public_key=bytes.fromhex(c["owner_public_key"]),
        local_approval_id=bytes.fromhex(c["local_approval_id"]),
        location=bytes.fromhex(c["location"]),
        owner_key_id=c["owner_key_id"],
        session_nonce=bytes.fromhex(c["session_nonce"]),
    )
    signed = []
    for grant in case["signed"]:
        payload = av.signed_payload(ctx, grant)
        if payload is None:
            signed.append(None)
            continue
        digest = av.payload_digest(payload)
        result = attempt(av._from_payload, payload, digest)
        if "ok" in result:
            result["ok"] = dataclasses.asdict(result["ok"])
        signed.append({"payload": payload, "digest": digest, **result})
    wallets = []
    for scope in case["wallets"]:
        result = attempt(av.post_wallet_binding, scope)
        if "ok" in result and result["ok"] is not None:
            result["ok"] = [list(entry) for entry in result["ok"]]
        wallets.append(result)
    out = {
        "signed": signed,
        "wallets": wallets,
        "entry_counts": [av._valid_entry_counts(item["per_entry"], item["record"])
                         for item in case["entry_counts"]],
        "mismatch": [av.run_mismatch(item["payload"],
                                     av.RunFacts(item["run"]["env_name"],
                                                 tuple(item["run"]["secret_names"]),
                                                 tuple(item["run"]["capability_names"])),
                                     item["snapshot"])
                     for item in case["mismatch"]],
        "split_keys": [av.split_wallet_entry_key(key) for key in case["split_keys"]],
    }
    json.dump(out, sys.stdout)


if __name__ == "__main__":
    main()
