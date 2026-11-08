"""Sign a run grant for whichever daemon serves this vault, the way kv grant approve does
(kv/owner_approval.py SigningContext.sign_grant), without the request-record steps: open
the owner channel, take the session nonce and owner key id it proves, and attach the
owner approval over a grant kv.grants creates. stdin: one JSON case; stdout: the grant id."""
import hashlib
import json
import os
import sys

from kv import approval_channel, approval_wire as wire, grants
from kv.approval_artifacts import OwnerGrantVerifier, session_verifier
from kv.crypto import derive_labeled_key
from kv.agent import agent_request
from kv.approval_signing import attach_owner_approval
from kv.owner_approval import prompt_unwrapped
from kv.sandbox import build_run_identity


def main():
    case = json.loads(sys.stdin.read())
    root = case["root"]
    unwrapped = prompt_unwrapped(root, lambda: case["passphrase"])
    try:
        secret_names = case.get("secret_names") or []
        capability_names = case.get("capability_names") or []
        channel = approval_channel.open_channel(
            unwrapped, providers=bool(capability_names),
            send=lambda cmd, **fields: agent_request(cmd, project_root=root, **fields))
        if not channel.protected:
            raise SystemExit("the daemon says this session is unprotected")
        # kv grant approve signs the daemon's own provider definitions for each api: capability
        # (owner_approval.SigningContext.provider_definitions), so the pass's calls verify.
        snapshot = {name: definition for name, definition in channel.providers}
        provider_digests = {}
        for capability in capability_names:
            name = capability[len("api:"):]
            if name not in snapshot:
                raise SystemExit(f"the daemon's snapshot has no definition for provider {name}")
            provider_digests[name] = wire.provider_digest(json.loads(snapshot[name]))
        identity = build_run_identity(
            case["argv"], cwd=case["cwd"], env_names=secret_names, secrets_injected=True,
            secret_scope="selected" if secret_names else "capability")
        request_id = "req_" + os.urandom(12).hex()

        def sign(grant):
            return attach_owner_approval(
                grant, unwrapped.owner_seed, request_id=request_id,
                request_digest=hashlib.sha256(request_id.encode()).hexdigest(),
                request_expires_at_epoch=grant["expires_at_epoch"],
                local_approval_id=unwrapped.local_approval_id, location=unwrapped.location,
                owner_key_id=channel.owner_key_id, environment=case["env"],
                network=bool(case.get("network", False)), network_reason="parity test",
                max_runs=case.get("max_runs"), calls_per_run=case.get("max_calls"),
                provider_digests=provider_digests, session_nonce=channel.session_nonce)

        # The grant writer kv grant approve uses: its state seal is keyed from the master key
        # (owner_approval.SigningContext.grant_writer), so the daemon's verifier accepts it.
        writer = OwnerGrantVerifier(
            (root,), derive_labeled_key(unwrapped.master_key, "kv-approval:grant-state"))
        with session_verifier(writer):
            grant = grants.create_run_grant(
                root, identity, secret_names=secret_names or None,
                capability_names=capability_names or None, actor=case.get("actor"),
                owner_sign=sign, **({"usage_mode": "reusable", "max_runs": case["max_runs"]}
                                    if case.get("max_runs") else {}))
        print(json.dumps({"grant_id": grant["grant_id"],
                          "command_fingerprint": identity["command_fingerprint"]}))
    finally:
        unwrapped.discard_seed()


if __name__ == "__main__":
    main()
