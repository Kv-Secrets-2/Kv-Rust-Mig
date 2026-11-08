"""Python 0.4.0 side of the grants/capability-token comparison.

Mode "scenario": make a protected vault under `base`, run the shared scenario
with the given `now` and side tag, print the session facts (test-vault secrets)
and the results. Mode "cross": reopen that vault as the same session and check
the grants and tokens the Rust side wrote.
"""
import hashlib
import json
import os
import sys

from unittest.mock import patch

from kv import approval_wire as wire
from kv import capabilities, config, config_authority, grants
from kv.approval_artifacts import (
    session_verifier,
    verify_grant_state_integrity,
    verify_token_integrity,
)
from kv.approval_signing import attach_owner_approval
from kv.approval_verify import RunFacts
from kv.owner_approval import prompt_unwrapped
from kv.store import SecretStore
from kv.trust import TrustContext

PASS = "correct-horse-battery-staple"


def approve_config(root):
    """The owner ceremony with a fake terminal (tests/vault_factory.approve_config)."""
    class Terminal:
        def write(self, value):
            return len(value)

        def readline(self):
            return "yes\n"
    with patch.object(config_authority, "owner_terminal") as tty, \
            patch.object(config_authority, "read_passphrase", return_value=PASS):
        tty.return_value.__enter__.return_value = Terminal()
        config_authority.approve_config(str(root))


def protected_store(path):
    """A passphrase vault with its service's trust context, as `kv unlock` builds it
    (the reference's tests/nopass_owner helper)."""
    root = config.init_project(str(path), passphrase=PASS)
    approve_config(root)
    store = SecretStore(root, passphrase=PASS)
    store.trust = TrustContext.at_unlock(root, PASS, store.master_key)
    store.pin()
    assert store.trust.protected
    return store


def owner_seed(store):
    unwrapped = prompt_unwrapped(store.root, lambda: PASS)
    try:
        return bytes(unwrapped.owner_seed)
    finally:
        unwrapped.discard_seed()

STRIP = {"grant_id", "token", "token_id", "token_hash", "admission_id", "grant_artifact_id",
         "owner_approval", "state_integrity", "token_integrity", "_verified",
         "command_fingerprint", "script_sha256", "script_ref_hash"}  # the side tag differs


def h(text):
    return hashlib.sha256(text.encode()).hexdigest()


def hx(value):
    if isinstance(value, str):
        value = os.fsencode(value)
    return bytes(value).hex()


def public(value):
    if isinstance(value, dict):
        return {k: public(v) for k, v in value.items() if k not in STRIP}
    if isinstance(value, (list, tuple)):
        return [public(v) for v in value]
    return value


def attempt(fn, *args, **kwargs):
    try:
        return {"ok": public(fn(*args, **kwargs))}
    except grants.GrantSpentError as error:
        return {"spent": {"message": str(error), "spent": error.spent,
                          "error_type": error.error_type}}
    except Exception as error:  # noqa: BLE001 - the kind and words are the comparison
        return {"error": type(error).__name__, "message": str(error)}


def identity(side, tag="cmd1"):
    return {"command_fingerprint": h(f"{side}:{tag}"), "run_id": "run-1",
            "script_kind": "python", "script_sha256": h(f"{side}:script"),
            "script_ref_hash": h(f"{side}:ref")}


ACTOR = {"source": "mcp", "client_name": "claude", "client_version": "1.0",
         "session_id": "s1", "user_id": "u1"}


def signer(trust, seed, side, providers):
    digests = {name: wire.provider_digest(d) for name, d in providers.items()}
    counter = [0]

    def sign(grant):
        counter[0] += 1
        request_id = f"approval_{side}_{counter[0]}"
        return attach_owner_approval(
            grant, seed, request_id=request_id, request_digest=h(request_id),
            request_expires_at_epoch=grant["expires_at_epoch"],
            local_approval_id=trust.local_approval_id, location=trust.location,
            owner_key_id=trust.owner_key_id, environment="dev", network=False,
            network_reason="test", max_runs=grant.get("max_runs"),
            calls_per_run=grant.get("max_calls"), provider_digests=digests,
            session_nonce=trust.session_nonce)
    return sign


def creation_cases(cwd):
    wallet = [{"provider": "openai", "rule_id": "r1", "rule_digest": "a" * 64, "calls": 2},
              {"provider": "openai", "rule_id": "r0", "rule_digest": "b" * 64, "calls": 1}]
    return [
        ("secret_once", dict(secret_names=["OPENAI_API_KEY"], reason="r1", ttl_seconds=300)),
        ("two_services", dict(capability_names=["api:openai", "api:github"],
                              calls_per_service={"api:openai": 2, "api:github": None},
                              max_calls=2, usage_mode="reusable", max_runs=3,
                              when_spent="pause", owner_wait_seconds=60, ttl_seconds=600)),
        ("wallet", dict(capability_names=["api:openai"], post_wallet=wallet, max_calls=3,
                        ttl_seconds=300)),
        ("single_card", dict(capability_names=["api:openai"], max_calls=5, ttl_seconds=300,
                             risk_card={"version": 1, "generator": "kv_risk_card_v1",
                                        "facts": {"argv": ["python3", "app.py"], "cwd": cwd}})),
        ("empty_scope", dict(reason="x")),
        ("bad_mode", dict(secret_names=["A"], usage_mode="weird")),
        ("runs_on_once", dict(secret_names=["A"], max_runs=2)),
        ("zero_ttl", dict(secret_names=["A"], ttl_seconds=0)),
        ("ends_past", dict(secret_names=["A"], ends_at_epoch=5)),
        ("counts_no_cap", dict(secret_names=["A"], calls_per_service={"api:x": 1})),
        ("bad_when", dict(capability_names=["api:openai"], when_spent="later",
                          owner_wait_seconds=5)),
        ("wallet_secret", dict(secret_names=["A"], capability_names=["api:openai"],
                               post_wallet=wallet)),
        ("wallet_total", dict(capability_names=["api:openai"], post_wallet=wallet,
                              max_calls=9)),
        ("actor_field", dict(secret_names=["A"], actor={"source": "x", "bogus": 1})),
        ("one_service_counts", dict(capability_names=["api:openai"],
                                    calls_per_service={"api:openai": 2})),
    ]


def scenario(root, trust, seed, side, now, providers, base):
    sign = signer(trust, seed, side, providers)
    ident = identity(side)
    out = {"created": [], "ids": []}
    cwd_a, cwd_b = os.path.join(base, "cwd_a"), os.path.join(base, "cwd_b")
    for name, kwargs in creation_cases(cwd_a):
        result = attempt(grants.create_run_grant, root, ident, now=now, owner_sign=sign,
                         **({"actor": ACTOR} if "actor" not in kwargs else {}), **kwargs)
        out["created"].append([name, result])
    ok = grants.list_run_grants(root, include_expired=True, include_revoked=True,
                                include_consumed=True, now=now)
    ids = [g["grant_id"] for g in ok]
    out["ids"] = ids
    index = {gid: i for i, gid in enumerate(ids)}
    out["listed"] = public(ok)
    by_name = {"secret_once": 0, "two_services": 1, "wallet": 2, "single_card": 3}

    def find(scope, run=None, ident_=ident, actor=ACTOR):
        found = grants.find_matching_run_grant(root, ident_, actor=actor, now=now, run=run,
                                               **scope)
        return None if found is None else index[found["grant_id"]]

    scopes = {"secret_once": dict(secret_names=["OPENAI_API_KEY"]),
              "two_services": dict(capability_names=["api:openai", "api:github"]),
              "wallet": dict(capability_names=["api:openai"]),
              "single_card": dict(capability_names=["api:openai"])}
    out["find"] = {name: find(scope) for name, scope in scopes.items()}
    dev = RunFacts(env_name="dev", secret_names=(), capability_names=("api:openai",))
    prod = RunFacts(env_name="prod", secret_names=(), capability_names=("api:openai",))
    out["find_run"] = [find(scopes["wallet"], dev), find(scopes["wallet"], prod),
                       find(scopes["secret_once"], actor={"source": "other"})]
    other = dict(ident, command_fingerprint=h(f"{side}:cmd2"))
    out["explain"] = [
        grants.explain_run_grant_mismatch(root, other, capability_names=["api:openai"],
                                          actor=ACTOR, cwd=cwd_a,
                                          argv=["python3", "app.py"], now=now),
        grants.explain_run_grant_mismatch(root, other, capability_names=["api:openai"],
                                          actor=ACTOR, cwd=cwd_b,
                                          argv=["python3", "app.py"], now=now),
        grants.explain_run_grant_mismatch(root, other, secret_names=["OTHER"], actor=ACTOR,
                                          cwd=cwd_a, argv=["python3", "app.py"], now=now),
        grants.explain_run_grant_mismatch(root, other, secret_names=["OTHER"], actor=ACTOR,
                                          cwd=cwd_b, argv=["ls"], now=now),
    ]
    steps = []

    def step(name, fn, *args, **kwargs):
        steps.append([name, attempt(fn, *args, **kwargs)])
        return steps[-1][1]

    admitted = step("admit_two", grants.admit_run_grant, root, ident,
                    capability_names=["api:openai", "api:github"], actor=ACTOR,
                    env_name="dev", now=now)
    token = None
    if "ok" in admitted:
        full = grants.admit_run_grant  # noqa: F841 - the token came from the real call
    # the raw token is stripped from the public result: take it from the ledger's issue
    raw = _last_token.get("token")
    token = raw

    def consume(name, cap, **kwargs):
        env = kwargs.pop("env_name", "dev")
        ident_ = kwargs.pop("identity", ident)
        step(name, capabilities.consume_capability_token, root, token, ident_, cap,
             actor=ACTOR, env_name=env, now=now, return_reason=True, require_parent=True,
             provider_config=providers.get(cap[len("api:"):]), **kwargs)

    consume("c_openai_1", "api:openai")
    consume("c_github", "api:github")
    consume("c_openai_2", "api:openai")
    consume("c_openai_3", "api:openai")
    consume("c_stripe", "api:stripe")
    consume("c_prod", "api:openai", env_name="prod")
    consume("c_other_cmd", "api:openai", identity=other)
    consume("c_inspect", "api:openai", charge=False, allow_spent=True)
    step("tokens", capabilities.list_capability_tokens, root, include_expired=True,
         include_consumed=True, include_revoked=True, now=now)
    token_id = _last_token.get("token_id")
    step("revoke_token", capabilities.revoke_capability_token, root, token_id, reason="done",
         now=now)
    consume("c_revoked", "api:openai")
    step("admit_two_again", grants.admit_run_grant, root, ident,
         capability_names=["api:openai", "api:github"], actor=ACTOR, env_name="dev", now=now)
    step("revoke_two", grants.revoke_run_grant, root, ids[by_name["two_services"]],
         reason="stop", now=now, mode="immediate")
    step("revoke_two_again", grants.revoke_run_grant, root, ids[by_name["two_services"]],
         now=now, mode="future")
    step("admit_two_revoked", grants.admit_run_grant, root, ident,
         capability_names=["api:openai", "api:github"], actor=ACTOR, env_name="dev", now=now)
    step("admit_secret", grants.admit_run_grant, root, ident, secret_names=["OPENAI_API_KEY"],
         actor=ACTOR, now=now)
    step("admit_secret_again", grants.admit_run_grant, root, ident,
         secret_names=["OPENAI_API_KEY"], actor=ACTOR, now=now)
    step("admit_wallet", grants.admit_run_grant, root, ident, capability_names=["api:openai"],
         actor=ACTOR, env_name="dev", now=now)
    token = _last_token.get("token")
    consume("w_r1", "api:openai", wallet_entry="api:openai/r1")
    consume("w_r0_a", "api:openai", wallet_entry="api:openai/r0")
    consume("w_r0_b", "api:openai", wallet_entry="api:openai/r0")
    consume("w_none", "api:openai")
    consume("w_wrong", "api:openai", wallet_entry="api:github/r1")
    step("listed_after", grants.list_run_grants, root, include_expired=True,
         include_revoked=True, include_consumed=True, now=now)
    step("prune", grants.prune_expired_run_grants, root, now=now)
    step("tokens_after", capabilities.list_capability_tokens, root, include_expired=True,
         include_consumed=True, include_revoked=True, now=now)
    out["steps"] = steps
    return out


_last_token = {}
_real_mint = capabilities._mint_capability_token


def _recording_mint(*args, **kwargs):
    result = _real_mint(*args, **kwargs)
    _last_token.clear()
    _last_token.update(result)
    return result


def open_session(root, nonce=None, providers=None):
    store = SecretStore(root, passphrase=PASS)
    store.trust = TrustContext.at_unlock(root, PASS, store.master_key)
    store.pin()
    if nonce is not None:
        store.trust.session_nonce = bytes.fromhex(nonce)
    store.trust.provider_snapshot = dict(providers or {})
    return store


def main():
    case = json.loads(sys.stdin.read())
    base, now, providers = case["base"], case["now"], case["providers"]
    if case["mode"] == "scenario":
        os.makedirs(os.path.join(base, "cwd_a"), exist_ok=True)
        os.makedirs(os.path.join(base, "cwd_b"), exist_ok=True)
        store = protected_store(os.path.join(base, "vault"))
        store.trust.provider_snapshot = dict(providers)
        trust = store.trust
        seed = owner_seed(store)
        capabilities._mint_capability_token = _recording_mint
        grants._mint_capability_token = _recording_mint
        with session_verifier(trust):
            results = scenario(store.root, trust, seed, "py", now, providers, base)
        facts = {"root": store.root, "seed": seed.hex(),
                 "local_approval_id": hx(trust.local_approval_id),
                 "location": hx(trust.location), "owner_key_id": trust.owner_key_id,
                 "session_nonce": hx(trust.session_nonce),
                 "signing_key": hx(trust.hmac_key()),
                 "state_key": hx(trust.grant_state_key),
                 "owner_public_key": hx(trust.owner_public_key)}
        print(json.dumps({"facts": facts, "results": results}))
        return
    store = open_session(case["root"], case["session_nonce"], providers)
    root = store.root
    with session_verifier(store.trust):
        stored = {g["grant_id"]: g for g in grants._read_store(root)["grants"]}
        valid = {gid: grants._valid_grant(root, stored[gid]) for gid in case["grant_ids"]}
        state = {gid: verify_grant_state_integrity(root, stored[gid])
                 for gid in case["grant_ids"]}
        tokens = [verify_token_integrity(root, t) for t in capabilities._read_store(root)["tokens"]
                  if t.get("command_fingerprint") == case["identity"]["command_fingerprint"]]
        found = grants.find_matching_run_grant(root, case["identity"], actor=ACTOR, now=now,
                                               **case["scope"])
        listed = grants.list_run_grants(root, include_expired=True, include_revoked=True,
                                        include_consumed=True, now=now)
    print(json.dumps({"valid": valid, "state": state, "tokens": tokens,
                      "found": None if found is None else found["grant_id"],
                      "listed_ids": [g["grant_id"] for g in listed]}))


if __name__ == "__main__":
    main()
