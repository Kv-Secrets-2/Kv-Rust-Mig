"""Report Python 0.4.0's risk-card results for one JSON case set on stdin.

Input: {"minimal": [{"run_identity": {...}, "secret_names": any, "capability_names": any,
                     "max_calls": any, "reason": str}...],
        "normalize": [any...], "summarize": [any...]}
Output: {"minimal": [card...], "normalize": [card...], "summarize": [[line...]...]}
"""
import json
import sys

from kv import risk_card


def attempt(fn, card):
    """Python raises on some malformed cards; report that instead of crashing the probe."""
    try:
        return fn(card)
    except Exception as error:  # noqa: BLE001 - the error type is the parity fact
        return {"python_error": type(error).__name__}


def main():
    case = json.loads(sys.stdin.read())
    minimal = []
    for item in case["minimal"]:
        kwargs = {}
        for key in ("secret_names", "capability_names", "max_calls", "reason"):
            if key in item:
                kwargs[key] = item[key]
        minimal.append(risk_card.minimal_risk_card(item["run_identity"], **kwargs))
    out = {
        "minimal": minimal,
        "normalize": [attempt(risk_card.normalize_risk_card, card) for card in case["normalize"]],
        "summarize": [attempt(risk_card.summarize_risk_card, card) for card in case["summarize"]],
    }
    json.dump(out, sys.stdout)


if __name__ == "__main__":
    main()
