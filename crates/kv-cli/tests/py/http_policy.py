"""HTTP policy seed/repair operations on disposable parity vaults."""
from pathlib import Path
import sys
from kv.config import load_config, save_config

root = Path(sys.argv[1])
config = load_config(root)
action = sys.argv[2]
http = config.setdefault("broker_policy", {}).setdefault("http", {})
if action == "repair":
    http["github"]["rules"].append({"id": "broken", "methods": ["GET"], "path": "relative"})
elif action == "binding":
    http["github"]["origin"] = "https://1.1.1.1"
elif action == "bad-http":
    config["broker_policy"]["http"] = []
else:
    raise ValueError("unknown operation")
save_config(root, config)
