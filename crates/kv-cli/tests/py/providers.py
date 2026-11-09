"""Provider config mutations on disposable parity vaults."""
from pathlib import Path
import sys
from kv.config import load_config, save_config

root = Path(sys.argv[1])
config = load_config(root)
action = sys.argv[2]
if action == "invalid-provider":
    config.setdefault("providers", {})["broken"] = {
        "provider_type": "http", "base_url": "http://1.1.1.1", "secret_name": "TOKEN"
    }
    config.setdefault("broker_policy", {}).setdefault("http", {})["broken"] = {
        "origin": "http://1.1.1.1", "secret_name": "TOKEN", "rules": []
    }
elif action == "bad-policy":
    config["broker_policy"] = {"http": []}
elif action == "bad-providers":
    config["providers"] = []
elif action == "bad-entry":
    config["providers"] = {"broken": 42}
else:
    raise ValueError("unknown operation")
save_config(root, config)
