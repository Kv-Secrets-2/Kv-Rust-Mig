"""Report Python 0.4.0's classify_command for JSONL cases on stdin.

Each line: {"argv": [...], "allowed": [...] | null, "secrets": bool, "protected": bool}.
Each answer: {"allowed": bool, "mode": str, "reason": str, "handoff": obj|null,
              "session_reason": str, "hint": str, "effective": str}.
"""
import json
import sys

from kv import sandbox


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        case = json.loads(line)
        decision = sandbox.classify_command(
            case["argv"], case.get("allowed"), secrets_injected=case.get("secrets", True))
        record = {
            "allowed": decision.allowed,
            "mode": decision.mode,
            "reason": decision.reason,
            "handoff": decision.broker_handoff,
            "session_reason": sandbox.session_denial_reason(
                decision, case.get("protected", False)),
            "hint": sandbox.allowlist_hint_for_argv(case["argv"]),
            "effective": sandbox.effective_run_mode(decision.mode, case.get("count", 0)),
        }
        sys.stdout.write(json.dumps(record, ensure_ascii=True) + "\n")


if __name__ == "__main__":
    main()
