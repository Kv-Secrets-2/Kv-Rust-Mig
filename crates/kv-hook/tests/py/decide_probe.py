"""Reply of kv.hook's decision pipeline for each hook input on stdin (parity oracle).

Each input line is a PreToolUse JSON object; each output line is the JSON reply
`_decide` gives for it, in this process's working folder and environment.
"""
import json
import sys

from kv import hook


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        data = json.loads(line)
        reply = hook._decide(data)
        if isinstance(reply, str):  # _decide returns the line main() prints
            reply = json.loads(reply)
        sys.stdout.write(json.dumps(reply, ensure_ascii=True) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
