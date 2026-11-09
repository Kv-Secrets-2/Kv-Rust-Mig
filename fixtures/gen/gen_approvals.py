"""Stage 3b golden vectors for approval signing/verification, from kv-secrets 0.4.0.

Run with the reference venv from the kv-secrets checkout's parent:
  KV_SRC=~/repos/kv-secrets /var/tmp/kv-ref-venv/bin/python fixtures/gen/gen_approvals.py
Writes fixtures/v0.4.0/approvals.json. Deterministic: fixed seeds/keys, fixed artifact ids;
the only random value (the AES-GCM nonce of a sealed pause answer key) is recorded as data.
"""
import copy, hashlib, hmac, json, os, sys

sys.path.insert(0, os.path.expanduser(os.environ.get("KV_SRC", "~/repos/kv-secrets")))
from kv import approval_wire as wire, approval_signing as sig, approval_artifacts as art
from kv.trust import owner_public_key, owner_key_id

OUT = os.path.join(os.path.dirname(__file__), "..", "v0.4.0", "approvals.json")
SEED = bytes(range(32))
OTHER_SEED = bytes(range(32, 64))
LOCAL_ID = bytes(range(100, 116))
LOCATION = "/tmp/kv-fixture-project".encode()
SESSION_NONCE = bytes(range(200, 232))
HMAC_KEY = bytes(range(1, 33))
DAEMON_KEY = bytes(range(50, 82))
ANSWER_KEY = bytes(range(90, 122))


class Ctx:
    def __init__(self, protected, public_key):
        self.protected = protected
        self.owner_public_key = public_key


def h(b):
    return bytes(b).hex()


def canon_or_error(value):
    try:
        return {"ok": wire.canonical_json(value)}
    except (TypeError, ValueError) as exc:
        return {"error": str(exc)}


def sample(kind, i):
    if kind == "nonce":
        return bytes((i + k) % 256 for k in range(wire.NONCE_LEN))
    if kind == "bytes":
        return bytes([i % 256, 0, 255, 7])
    if kind == "text":
        return f"t{i}-\u00e9\U0001F511"
    if kind == "bool":
        return i % 2 == 0
    if isinstance(kind, tuple) and kind[0] == "enum":
        return kind[1 + i % (len(kind) - 1)]
    raise AssertionError(kind)


def sample_fields(schema):
    fields = {}
    for i, (name, kind) in enumerate(schema):
        if isinstance(kind, tuple) and kind[0] == "list":
            fields[name] = [tuple(sample(sub, i + j + n) for n, sub in enumerate(kind[1]))
                            for j in range(2)]
        else:
            fields[name] = sample(kind, i)
    return fields


def jsonable(value):
    if isinstance(value, (bytes, bytearray)):
        return {"hex": h(value)}
    if isinstance(value, (list, tuple)):
        return [jsonable(v) for v in value]
    return value


def kind_json(kind):
    return list(kind) if isinstance(kind, tuple) and kind[0] == "enum" else (
        ["list", [kind_json(k) for k in kind[1]]] if isinstance(kind, tuple) else kind)


def main():
    pub = owner_public_key(SEED)
    out = {"inputs": {"seed": h(SEED), "other_seed": h(OTHER_SEED), "local_approval_id": h(LOCAL_ID),
                      "location": h(LOCATION), "session_nonce": h(SESSION_NONCE),
                      "hmac_key": h(HMAC_KEY), "daemon_key": h(DAEMON_KEY), "answer_key": h(ANSWER_KEY)},
           "owner_public_key": h(pub), "owner_key_id": owner_key_id(pub, LOCAL_ID),
           "other_owner_public_key": h(owner_public_key(OTHER_SEED))}

    # canonical JSON
    cases = [None, True, False, 0, -1, 2**63, 10**30, "", "a\"b\\c\n\t\u0001", "\u00e9\u4e2d\U0001F511",
             [], {}, [1, [2, [3]]], {"b": 1, "a": {"d": [None, "x"], "c": True}, "\u00e9": 2, "Z": 3},
             1.5, {"x": [1, 2.0]}, {1: "int key"}]
    out["canonical_json"] = [{"input_repr": repr(c), "input": c if not isinstance(c, float) and not (
        isinstance(c, dict) and any(not isinstance(k, str) for k in c)) else None, **canon_or_error(c)}
        for c in cases]
    out["frame"] = [{"in": h(b), "out": h(wire.frame(b))} for b in (b"", b"kv", bytes(300))]

    # wire messages: every type
    msgs = []
    for msg_type, schema in wire.MESSAGE_FIELDS.items():
        fields = sample_fields(schema)
        tag = wire.mac(DAEMON_KEY, msg_type, fields)
        msgs.append({"type": msg_type, "schema": [[n, kind_json(k)] for n, k in schema],
                     "fields": {k: jsonable(v) for k, v in fields.items()},
                     "encoding": h(wire.encode(msg_type, fields)), "mac": h(tag),
                     "to_json": wire.to_json(msg_type, fields, tag)})
    out["wire_messages"] = msgs
    out["wire_limits"] = {"FRAME_LEN": wire.FRAME_LEN, "NONCE_LEN": wire.NONCE_LEN, "MAC_LEN": wire.MAC_LEN,
                          "MAX_FIELD_BYTES": wire.MAX_FIELD_BYTES, "MAX_LIST_ITEMS": wire.MAX_LIST_ITEMS}

    # owner-signed grant
    grant = {"grant_id": "grant_0001", "created_at_epoch": 1793500000, "expires_at_epoch": 1793503600,
             "created_from_run_id": "run_42", "command_fingerprint": "fp_abc", "script_kind": "python",
             "script_sha256": "0" * 64, "script_ref_hash": "1" * 64, "secret_names": ["OPENAI_API_KEY"],
             "capability_names": ["api:openai", "api:github"], "actor": {"name": "agent", "pid": 7},
             "risk_card": {"level": "medium", "notes": ["n\u00e9"]}, "calls_per_service": {"api:openai": 3,
             "api:github": 2}, "usage_mode": "reusable", "max_runs": 4,
             "session_nonce": h(SESSION_NONCE), "post_wallet": [{"rule": "api:openai/chat", "calls": 2}],
             "when_spent": "pause", "owner_wait_seconds": 120, "status": "approved"}
    fields = dict(request_id="req_1", request_digest="2" * 64, request_expires_at_epoch=1793501000,
                  local_approval_id=LOCAL_ID, location=LOCATION, owner_key_id=out["owner_key_id"],
                  environment="dev", network=False, network_reason=None, max_runs=4, calls_per_run=None,
                  provider_digests={"openai": "3" * 64, "github": "4" * 64}, session_nonce=SESSION_NONCE)
    payload = sig.owner_grant_payload(grant, artifact_id="owner_approval_" + "ab" * 12, **fields)
    signed = dict(grant, owner_approval={"version": 1, "signer": sig.SIGNER, "payload": payload,
                                         "signature": sig.sign_payload(SEED, payload).hex()})
    out["owner_grant"] = {"grant": grant, "payload": payload, "message": h(sig._message(payload)),
                          "signed_grant": signed}

    def mut(fn):
        g = copy.deepcopy(signed)
        fn(g)
        return g
    variants = {
        "valid": signed,
        "grant_field_changed": mut(lambda g: g.__setitem__("secret_names", ["OTHER"])),
        "signature_flipped": mut(lambda g: g["owner_approval"].__setitem__(
            "signature", ("0" if g["owner_approval"]["signature"][0] != "0" else "1") + g["owner_approval"]["signature"][1:])),
        "signed_optional_removed": mut(lambda g: g.pop("calls_per_service")),
        "reusable_max_runs_removed": mut(lambda g: g.pop("max_runs")),
        "post_rule_present": mut(lambda g: g.__setitem__("post_rule", "x")),
        "wrong_version": mut(lambda g: g["owner_approval"].__setitem__("version", 2)),
        "wrong_artifact_prefix": mut(lambda g: g["owner_approval"]["payload"].__setitem__("artifact_id", "approval_x")),
        "payload_not_object": mut(lambda g: g["owner_approval"].__setitem__("payload", [])),
        "signature_not_hex": mut(lambda g: g["owner_approval"].__setitem__("signature", "zz")),
        "status_changed_unsigned_field": mut(lambda g: g.__setitem__("status", "revoked")),
    }
    out["owner_grant_verify"] = [
        {"name": name, "key": key_name, "grant": g,
         "expected": sig.verified_owner_payload(key, g)}
        for name, g in variants.items()
        for key_name, key in (("owner", pub), ("other", owner_public_key(OTHER_SEED)))]
    out["owner_grant_payload_errors"] = []
    for name, override in (("network_not_bool", {"network": 0}), ("max_runs_zero", {"max_runs": 0}),
                           ("float_value", {"calls_per_run": 1.5})):
        try:
            sig.owner_grant_payload(grant, artifact_id="owner_approval_x", **dict(fields, **override))
            err = None
        except ValueError as exc:
            err = str(exc)
        out["owner_grant_payload_errors"].append({"name": name, "override": {k: v for k, v in override.items()}, "error": err})

    # permit
    facts = {"signer": sig.SIGNER, "permit_id": "permit_1", "method": "POST", "path": "/v1/x",
             "body_sha256": "5" * 64, "session_nonce": h(SESSION_NONCE), "expires_at_epoch": 1793501111}
    permit = sig.attach_permit_approval(facts, SEED)
    pv = {"valid": permit,
          "extra_key": dict(permit, extra=1),
          "signer_mismatch": dict(permit, signer="local-project-hmac-v1"),
          "facts_changed": dict(permit, payload=dict(facts, path="/v1/y")),
          "short_signature": dict(permit, signature=permit["signature"][:-2]),
          "version_bool": dict(permit, version=True)}
    out["permit"] = {"facts": facts, "message": h(sig._permit_message(facts)), "artifact": permit}
    out["permit_verify"] = [{"name": n, "protected": p, "key": kn, "artifact": a,
                             "expected": sig.verified_permit_payload(Ctx(p, k), a)}
                            for n, a in pv.items() for p in (True, False)
                            for kn, k in (("owner", pub), ("other", owner_public_key(OTHER_SEED)))]

    # pause answer / right / job
    pfacts = {"signer": sig.SIGNER, "job_id": "job_1", "pass_expires_at_epoch": 1793502000,
              "session_nonce": h(SESSION_NONCE)}
    answer = sig.attach_pause_answer(pfacts, SEED, decision="extend", add_calls=3, add_seconds=600,
                                     ends_at_epoch=1793502600)
    out["pause_answer"] = {"facts": pfacts, "artifact": answer, "message": h(sig._pause_message(answer["payload"])),
                           "end_cases": [{"pass_expires_at_epoch": e, "add_seconds": s, "now": n,
                                          "end": sig.pause_answer_end({"pass_expires_at_epoch": e}, s, now=n)}
                                         for e, s, n in ((1000, 60, 500), (1000, 60, 2000), (1000, 0, 0), (None, 30, 10))]}
    right_payload = {"signer": sig.SIGNER, "kind": sig.PAUSE_RIGHT_KIND, "local_approval_id": h(LOCAL_ID),
                     "location": h(LOCATION), "owner_key_id": out["owner_key_id"], "session_nonce": h(SESSION_NONCE),
                     "right_public_key": h(owner_public_key(OTHER_SEED)), "holder": "page",
                     "expires_at_epoch": 1793503000}
    right = sig.attach_pause_right(right_payload, SEED)
    rv = {"valid": right, "extra_payload_key": dict(right, payload=dict(right_payload, x=1)),
          "missing_payload_key": dict(right, payload={k: v for k, v in right_payload.items() if k != "holder"}),
          "answer_as_right": answer}
    av = {"valid": answer, "right_as_answer": right,
          "payload_changed": dict(answer, payload=dict(answer["payload"], add_calls=4))}
    out["pause_right"] = {"artifact": right, "message": h(sig._pause_right_message(right_payload))}
    out["pause_right_verify"] = [{"name": n, "protected": p, "artifact": a,
                                  "expected": sig.verified_pause_right(Ctx(p, pub), a)}
                                 for n, a in rv.items() for p in (True, False)]
    out["pause_answer_verify"] = [{"name": n, "protected": p, "artifact": a,
                                   "expected": sig.verified_pause_answer(Ctx(p, pub), a)}
                                  for n, a in av.items() for p in (True, False)]
    job = {"job_id": "job_1", "nonce": "6" * 32, "right": "7" * 64, "session_nonce": h(SESSION_NONCE),
           "signed_at": 1793501234}
    out["pause_job_message"] = {"fields": job, "message": h(sig.pause_job_message(job))}

    # pause answer key seal / proofs
    sealed = sig.seal_pause_answer_key(DAEMON_KEY, ANSWER_KEY, right_public_key="ab" * 32, session_nonce="cd" * 32)
    out["pause_seal"] = {"seal_key": h(sig._pause_seal_key(DAEMON_KEY)), "sealed": sealed,
                         "right_public_key": "ab" * 32, "session_nonce": "cd" * 32,
                         "opens": h(sig.open_pause_answer_key(DAEMON_KEY, sealed, right_public_key="ab" * 32,
                                                              session_nonce="cd" * 32)),
                         "wrong_session_opens": sig.open_pause_answer_key(DAEMON_KEY, sealed, right_public_key="ab" * 32,
                                                                          session_nonce="ce" * 32)}
    reply = {"status": "paused", "job_id": "job_1", "proof": "ignored", "calls_left": 2}
    proof_fields = sig.snapshot_proof_fields("9" * 32, reply)
    out["pause_proof"] = {"kind": "paused", "fields": {"job_id": "job_1", "n": 3},
                          "proof": sig.pause_answer_proof(ANSWER_KEY, "paused", {"job_id": "job_1", "n": 3}),
                          "snapshot_reply": reply, "snapshot_fields": proof_fields,
                          "proven_short_key": sig.pause_answer_proven(ANSWER_KEY[:31], "paused", {"job_id": "job_1", "n": 3},
                                                                      sig.pause_answer_proof(ANSWER_KEY, "paused", {"job_id": "job_1", "n": 3}))}

    # local HMAC artifacts (approval_artifacts)
    hgrant = {k: v for k, v in grant.items() if k not in ("post_wallet",)}
    hp = art._grant_payload(hgrant, artifact_id="approval_" + "cd" * 12)
    hb = art._canonical_json(hp)
    out["hmac_grant_artifact"] = {"grant": hgrant, "payload": hp, "payload_bytes": h(hb),
                                  "payload_sha256": hashlib.sha256(hb).hexdigest(),
                                  "signature": hmac.new(HMAC_KEY, hb, hashlib.sha256).hexdigest()}
    state_grant = dict(signed, status="admitted", admission_id="adm_1", admitted_run_id="run_9",
                       admitted_at_epoch=1793500500)
    sp = art._grant_state_payload(state_grant)
    out["grant_state"] = {"grant": state_grant, "payload": sp, "payload_bytes": h(art._canonical_json(sp)),
                          "integrity": hmac.new(HMAC_KEY, art._canonical_json(sp), hashlib.sha256).hexdigest(),
                          "approval_ref": list(art.grant_approval_ref(state_grant)),
                          "hmac_approval_ref": list(art.grant_approval_ref(dict(hgrant, approval_artifact={
                              "artifact_id": "approval_x", "payload_sha256": "8" * 64})))}
    token = {"token_id": "tok_1", "grant_id": "grant_0001", "calls": 3, "names": ["a", "\u00e9"]}
    tb = art._canonical_json({"type": "admitted_capability_v1", "record": token})
    out["token_integrity"] = {"record": token, "bytes": h(tb),
                              "integrity": hmac.new(HMAC_KEY, tb, hashlib.sha256).hexdigest()}
    req = {"request_id": "req_1", "status": "pending", "created_at_epoch": 1, "updated_at_epoch": 2,
           "expires_at_epoch": 3, "argv": ["python3", "app.py"], "cwd": "/p", "command_fingerprint": "fp",
           "script_kind": "python", "script_sha256": "0" * 64, "script_ref_hash": None,
           "secret_names": [], "capability_names": ["api:openai"], "actor": {"name": "a"}, "source": "mcp",
           "reason": "r\u00e9", "risk_level": "low", "risk_card": {}, "max_calls": 5, "environment": "dev",
           "network": False, "network_reason": None, "approved_grant_id": "g", "created_at": "x"}
    rp = art._approval_request_payload(req)
    out["request_integrity_payload"] = {"request": req, "payload": rp, "payload_bytes": h(art._canonical_json(rp))}
    out["request_digests"] = [
        {"name": "v1", "request": req, "digest": wire.request_content_digest(req)},
        {"name": "v2", "request": dict(req, calls_per_service={"api:openai": 2}),
         "digest": wire.request_content_digest(dict(req, calls_per_service={"api:openai": 2}))},
        {"name": "v3", "request": dict(req, recommended_ttl_seconds=900),
         "digest": wire.request_content_digest(dict(req, recommended_ttl_seconds=900))},
    ]
    prov = {"origin": "https://api.openai.com", "secret_name": "OPENAI_API_KEY",
            "rules": [{"id": "models", "method": "GET", "path": "/v1/models"}]}
    out["provider_digest"] = {"definition": prov, "digest": wire.provider_digest(prov)}
    out["signing_key_file"] = {"valid": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=\n",
                               "parsed": h(art.parse_signing_key(b"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=\n"))}

    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write("\n")
    print("wrote", OUT, len(msgs), "wire types,", len(out["owner_grant_verify"]), "grant verify cases")


main()
