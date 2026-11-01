import json
import sys
from types import SimpleNamespace

from kv.approval_signing import verified_owner_payload, verified_permit_payload


document = json.load(sys.stdin)
public_key = bytes.fromhex(document["public_key"])
assert verified_owner_payload(public_key, document["grant"]) is not None
context = SimpleNamespace(protected=True, owner_public_key=public_key)
assert verified_permit_payload(context, document["permit"]) is not None
print("PASS Rust owner grant and permit signatures verified by Python")
