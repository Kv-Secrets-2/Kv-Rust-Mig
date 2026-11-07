"""Report Python 0.4.0's wrap_argv / launch_facts for JSONL cases on stdin.

Each line fixes the host (method, bwrap path, environment incl. HOME) and the
run (argv, network, secrets_dir, cwd, protect_home, overlays, private_tmp,
cwd_bind_source, secrets_injected, reader). Each answer:
{"wrapped": [...] | null, "error": str | null, "facts": [sandboxed, network] | null}.
"""
import json
import os
import sys

from kv import sandbox


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        case = json.loads(line)
        os.environ.clear()
        os.environ.update(case["env"])
        sandbox._isolation_cache = case["method"]
        sandbox._bwrap_path_cache = case["bwrap"] or ""
        record = {"wrapped": None, "error": None, "facts": None}
        try:
            wrapped = sandbox.wrap_argv(
                case["argv"],
                network=case["network"],
                secrets_dir=case["secrets_dir"],
                cwd=case["cwd"],
                protect_home_credentials=case["protect_home"],
                readonly_file_overlays=[tuple(p) for p in case["overlays"]],
                private_tmp=case["private_tmp"],
                cwd_bind_source=case["cwd_bind_source"],
                secrets_injected=case["secrets_injected"],
                weak_flag_reader=case["reader"],
            )
            record["wrapped"] = wrapped
            sandboxed, network = sandbox.launch_facts(wrapped)
            record["facts"] = [sandboxed, network]
        except sandbox.RunRefusalError as exc:
            record["error"] = str(exc)
        sys.stdout.write(json.dumps(record, ensure_ascii=True) + "\n")


if __name__ == "__main__":
    main()
