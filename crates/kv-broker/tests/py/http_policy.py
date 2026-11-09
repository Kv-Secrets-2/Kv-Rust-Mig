"""HTTP rule helper oracle, without a vault or network."""
import contextlib
import io
import json
import sys
from types import SimpleNamespace
from unittest.mock import patch
from kv.cli import (_http_policy_rule_from_args, _http_policy_route_label,
                    _valid_http_policy_entry)

data = json.load(sys.stdin)
rules = []
labels = []
for case in data["rules"]:
    args = SimpleNamespace(rule_id=case["id"], methods=case.get("methods"),
                           path=case.get("path"), path_prefix=case.get("path_prefix"),
                           query_keys=case.get("query_keys"), allowed_headers=case.get("allowed_headers"))
    stream = io.StringIO()
    try:
        with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            rule = _http_policy_rule_from_args(args)
        rules.append(rule)
        labels.append(_http_policy_route_label(rule))
    except SystemExit:
        line = next(line for line in stream.getvalue().splitlines() if "unsupported HTTP method:" in line)
        rules.append({"error": line[line.index("unsupported HTTP method:"):]})
        labels.append(None)
binding = []
for case in data["bindings"]:
    stream = io.StringIO()
    try:
        with patch("kv.cli._load_http_provider_for_policy", return_value=case["provider"]), contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            _valid_http_policy_entry(None, "test", case["entry"])
        binding.append(None)
    except SystemExit:
        line = next(line for line in stream.getvalue().splitlines() if "HTTP policy invalid for test:" in line)
        binding.append(line.split("HTTP policy invalid for test: ", 1)[1])
print(json.dumps({"rules": rules, "labels": labels, "bindings": binding}))
