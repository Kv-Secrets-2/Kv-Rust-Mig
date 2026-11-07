"""Report Python 0.4.0's grant normalization results for one JSON case set on stdin.

Each section is a list of inputs; each output is {"ok": value} or {"error": message}.
Input: {"identity": [any...], "scope": [any...], "actor": [any...],
        "actor_match": [[grant_actor, current_actor]...], "reason": [any...],
        "service_calls": [[names, max_calls, calls_per_service]...],
        "count": [any...], "seconds": [[value, now]...], "hash": [[value, required]...],
        "grant_id": [any...], "revoked": [grant...], "expired": [[record, now]...],
        "waiting": [[grant, now]...], "script_match": [[grant, identity]...], "iso": [epoch...]}
"""
import json
import sys

from kv import grants


def attempt(fn, *args):
    try:
        return {"ok": fn(*args)}
    except ValueError as error:
        return {"error": str(error)}


def main():
    case = json.loads(sys.stdin.read())
    out = {
        "identity": [attempt(grants._normalize_run_identity, v) for v in case["identity"]],
        "scope": [attempt(grants._normalize_scope_list, v, "secret_names") for v in case["scope"]],
        "actor": [attempt(grants._normalize_actor, v) for v in case["actor"]],
        "actor_match": [grants._actor_matches(g, c) for g, c in case["actor_match"]],
        "reason": [attempt(grants._normalize_reason, v) for v in case["reason"]],
        "service_calls": [attempt(grants.normalize_service_calls, n, m, p)
                          for n, m, p in case["service_calls"]],
        "count": [attempt(grants.check_count, v) for v in case["count"]],
        "seconds": [attempt(grants.check_seconds, v, "ttl_seconds", now)
                    for v, now in case["seconds"]],
        "hash": [attempt(lambda v, r: grants._validate_hash(v, "script_sha256", required=r), v, r)
                 for v, r in case["hash"]],
        "grant_id": [attempt(grants._normalize_grant_id, v) for v in case["grant_id"]],
        "revoked": [grants._is_revoked(g) for g in case["revoked"]],
        "expired": [grants._is_expired(r, now) for r, now in case["expired"]],
        "waiting": [grants._waiting_after_end(g, now) for g, now in case["waiting"]],
        "script_match": [grants._script_identity_matches(g, i) for g, i in case["script_match"]],
        "iso": [grants._iso(e) for e in case["iso"]],
    }
    json.dump(out, sys.stdout)


if __name__ == "__main__":
    main()
