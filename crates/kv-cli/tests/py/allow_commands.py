"""Owner command-policy comparisons on disposable vaults."""
import json
from pathlib import Path
import sys

from kv.config import (add_allowed_command, add_network_command, get_run_policy,
                       load_config, remove_allowed_command, save_config)

root = Path(sys.argv[1])
action = sys.argv[2]
if action == "seed-broad":
    config = load_config(root)
    config.setdefault("security", {})["allowed_commands"] = ["python3", "python3 app.py"]
    save_config(root, config)
elif action == "malformed":
    config = load_config(root)
    field = sys.argv[3]
    config.setdefault("security", {})[field] = 42 if field == "kv_run_policy" else [42]
    save_config(root, config)
elif action == "get":
    print(json.dumps(get_run_policy(root)))
else:
    operation = {"add": add_allowed_command, "remove": remove_allowed_command,
                 "network": add_network_command}[action]
    print(json.dumps(operation(root, sys.argv[3])))
