import dataclasses
import json
import sys

from kv.request_records import RequestRecords


def run(ops):
    records = RequestRecords()
    results = []
    for op in ops:
        try:
            name = op["op"]
            if name == "reset":
                records = RequestRecords(op.get("bound"))
                result = None
            elif name == "record":
                result = dataclasses.asdict(records.record(op["request"], now=op["now"]))
            elif name == "get":
                result = records.get(op["id"], now=op["now"])
                if result is not None:
                    result = dataclasses.asdict(result)
            else:
                result = len(records)
            results.append({"ok": result})
        except Exception as error:
            results.append({"error": str(error), "type": type(error).__name__})
    return results


json.dump(run(json.load(sys.stdin)), sys.stdout)
