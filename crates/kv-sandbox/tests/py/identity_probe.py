"""Report Python 0.4.0's run identity for one JSON case on stdin.

Input: {"cwd": str, "files": [...], "argvs": [[...]...], "modules": [...], "run_id": str,
        "scopes": [{"env_names": [...]|null, "secret_scope": any, "secrets_injected": bool}]}
Output: {"hashes": {path: sha|null}, "script_paths": [path|null...],
         "module_paths": [path|null...], "identities": [{...}...],
         "run_identities": [[{...} per scope] per argv]}
"""
import json
import sys

from kv import sandbox


def main():
    case = json.loads(sys.stdin.read())
    cwd = case["cwd"]
    out = {
        "hashes": {path: sandbox._hash_file(path) for path in case["files"]},
        "script_paths": [sandbox._script_file_path(argv, cwd=cwd) for argv in case["argvs"]],
        "module_paths": [sandbox.module_script_path(name, cwd) for name in case["modules"]],
        "identities": [sandbox._script_identity(argv, cwd=cwd) for argv in case["argvs"]],
        "run_identities": [
            [
                sandbox.build_run_identity(
                    argv, cwd=cwd, env_names=scope["env_names"],
                    secret_scope=scope["secret_scope"],
                    secrets_injected=scope["secrets_injected"], run_id=case["run_id"])
                for scope in case["scopes"]
            ]
            for argv in case["argvs"]
        ],
    }
    sys.stdout.write(json.dumps(out, sort_keys=True))


if __name__ == "__main__":
    main()
