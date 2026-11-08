"""Provider validation/default-policy oracle; no credentials or networking."""
import json
import sys
from kv.providers import validate_db_provider, validate_ssh_provider, build_provider_table
from kv.broker_policy import default_http_policy

data = json.load(sys.stdin)
print(json.dumps({
    "db": [validate_db_provider(v) for v in data["db"]],
    "ssh": [validate_ssh_provider(v) for v in data["ssh"]],
    "tables": [build_provider_table(None, config=v)[0] for v in data["tables"]],
    "default": default_http_policy(),
}))
