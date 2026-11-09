#!/usr/bin/env python3
"""Fail-closed Linux parity gate; see docs/migration/PARITY.md.

Build once with Cargo's workspace feature resolution, then run the exact fresh
test executables reported by Cargo. Independently require discovery, success
and a validated-Python marker for every declared comparison. No test filters or
skip switches are accepted. Native CI separately covers doctests/platforms.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "scripts/parity_inventory.json"


class GateError(RuntimeError):
    pass


def clean_environment(source):
    # Test bodies use both isolated and ordinary Python subprocesses. Neither
    # user site-packages nor inherited import overrides may replace the reference.
    env = {k: v for k, v in source.items() if not k.startswith("PYTHON")}
    env.update(PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1", CARGO_TERM_COLOR="never")
    return env


def capture(argv, *, cwd=ROOT, env=None, timeout=30, text=True):
    try:
        result = subprocess.run(argv, cwd=cwd, env=env, text=text, capture_output=True,
                                timeout=timeout, check=True)
    except (OSError, subprocess.SubprocessError) as error:
        raise GateError(f"command failed: {argv[0]}: {error}") from error
    return result.stdout


def load_inventory(path=INVENTORY):
    data = json.loads(Path(path).read_text())
    if data.get("schema_version") != 1:
        raise GateError("unsupported parity inventory schema")
    targets = data.get("targets", {})
    if not targets or any(not names or len(names) != len(set(names)) for names in targets.values()):
        raise GateError("inventory must contain nonempty, unique test lists")
    if sum(map(len, targets.values())) < data.get("minimum_comparisons", 1):
        raise GateError("parity inventory is below its reviewed minimum")
    return data


REFERENCE_PROBE = r'''
import hashlib, importlib.metadata, json, pathlib, sys
import kv, kv_mcp
roots = {"kv": pathlib.Path(kv.__file__).resolve().parent,
         "kv_mcp": pathlib.Path(kv_mcp.__file__).resolve().parent}
files = {}
for package, root in roots.items():
    for path in root.rglob("*.py"):
        files[package + "/" + path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
print(json.dumps({"python": list(sys.version_info[:3]), "executable": sys.executable,
    "distribution_version": importlib.metadata.version("kv-secrets"),
    "module_version": kv.__version__, "cryptography": importlib.metadata.version("cryptography"),
    "imports": {name: str(root) for name, root in roots.items()}, "files": files}))
'''


def check_reference_observation(observed, expected_files, version, requested_python, mode):
    runtime = tuple(observed.get("python", []))
    requested = tuple(int(part) for part in requested_python.split("."))
    if not requested or len(requested) > 3 or runtime[:len(requested)] != requested:
        raise GateError(f"Python runtime {runtime} does not match requested {requested_python}")
    if mode == "canonical" and runtime[:2] != (3, 10):
        raise GateError("canonical transcripts require Python 3.10")
    if runtime[:2] not in [(3, 10), (3, 11), (3, 12), (3, 13)]:
        raise GateError(f"unsupported reference runtime: {runtime}")
    if observed.get("distribution_version") != version or observed.get("module_version") != version:
        raise GateError("installed reference package/module version does not match the pin")
    actual = observed.get("files", {})
    if actual != expected_files:
        missing = sorted(set(expected_files) - set(actual))
        extra = sorted(set(actual) - set(expected_files))
        changed = sorted(k for k in expected_files.keys() & actual.keys() if expected_files[k] != actual[k])
        raise GateError(f"imported Python source differs from the pinned checkout: missing={missing}, extra={extra}, changed={changed}")


def pinned_source_hashes(repo, commit):
    # A clean status can hide working-tree edits marked assume-unchanged or
    # skip-worktree. Read immutable blobs from the pinned tree instead, and
    # disable replacement refs so local Git configuration cannot replace it.
    tree = capture(["git", "--no-replace-objects", "ls-tree", "-r", "-z", commit,
                    "--", "kv", "kv_mcp"], cwd=repo)
    expected = {}
    for entry in tree.split("\0"):
        if not entry:
            continue
        metadata, name = entry.split("\t", 1)
        if not name.endswith(".py"):
            continue
        mode, kind, object_id = metadata.split()
        if kind != "blob" or mode not in ("100644", "100755"):
            raise GateError(f"pinned Python source is not a regular file: {name}")
        source = capture(["git", "--no-replace-objects", "cat-file", "blob", object_id],
                         cwd=repo, text=False)
        expected[name] = hashlib.sha256(source).hexdigest()
    if not expected or "kv/__init__.py" not in expected or "kv_mcp/__init__.py" not in expected:
        raise GateError("reference package source inventory is incomplete")
    return expected


def attest_reference(repo, interpreter, inventory, requested_python, mode, env):
    repo = Path(repo).resolve()
    if not interpreter or not Path(interpreter).is_absolute() or not Path(interpreter).is_file():
        raise GateError("KV_PY_REF must name an existing absolute Python interpreter")
    head = capture(["git", "rev-parse", "HEAD"], cwd=repo).strip()
    if head != inventory["reference_commit"]:
        raise GateError(f"reference commit mismatch: {head}")
    if capture(["git", "status", "--porcelain", "--untracked-files=all"], cwd=repo).strip():
        raise GateError("reference checkout is dirty; install and test the pinned source unchanged")
    expected = pinned_source_hashes(repo, inventory["reference_commit"])
    observed = json.loads(capture([interpreter, "-I", "-c", REFERENCE_PROBE], env=env))
    check_reference_observation(observed, expected, inventory["reference_version"], requested_python, mode)
    return dict(observed, git_commit=head, source_files=len(expected))


def parse_discovery(text):
    names = re.findall(r"^(.+): test$", text, re.M)
    if len(names) != len(set(names)):
        raise GateError("duplicate discovered test name")
    return set(names)


def check_results(text, discovered, expected, returncode):
    if returncode:
        raise GateError(f"test executable failed with exit {returncode}")
    if "KV_PARITY_SKIP" in text:
        raise GateError("a Python comparison was skipped")
    results = re.findall(r"^test (.+?) \.\.\. (ok|FAILED|ignored(?:.*)?)$", text, re.M)
    names = [name for name, _ in results]
    if len(names) != len(set(names)) or set(names) != discovered:
        raise GateError("test completion inventory differs from discovery")
    if any(status != "ok" for _, status in results):
        raise GateError("a discovered test failed or was ignored")
    summaries = re.findall(r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; .*", text, re.M)
    if len(summaries) != 1 or tuple(map(int, summaries[0])) != (len(discovered), 0, 0):
        raise GateError("missing or inconsistent completed test summary")
    markers = re.findall(r"^KV_PARITY_TEST (.+)$", text, re.M)
    if Counter(markers) != Counter(expected):
        raise GateError(f"parity marker inventory mismatch: expected={sorted(expected)}, observed={sorted(markers)}")
    if not set(expected) <= discovered:
        raise GateError("expected comparison was filtered out or not discovered")
    return {"tests_passed": len(discovered), "comparisons": sorted(expected)}


def run_logged(argv, output, *, cwd=ROOT, env, timeout=900, stderr=None):
    """Bound the whole process group; keep large compiler/test output on disk."""
    with Path(output).open("w") as out:
        err = Path(stderr).open("w") if stderr else subprocess.STDOUT
        try:
            process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=out, stderr=err,
                                       stdin=subprocess.DEVNULL, start_new_session=True)
            try:
                return process.wait(timeout=timeout)
            except subprocess.TimeoutExpired as error:
                # The unreaped owned leader pins this process-group identity.
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                raise GateError(f"command exceeded {timeout}s: {argv[0]}") from error
        finally:
            if stderr:
                err.close()


def compiled_targets(messages, packages):
    targets = {}
    for line in messages.splitlines():
        record = json.loads(line)
        if record.get("reason") != "compiler-artifact" or not record.get("executable"):
            continue
        if not record.get("profile", {}).get("test"):
            continue
        package = packages.get(record["package_id"])
        if package is None:
            continue
        name = package["name"] + "/" + record["target"]["name"]
        value = {"executable": record["executable"], "cwd": str(Path(package["manifest_path"]).parent)}
        if name in targets and targets[name] != value:
            raise GateError(f"ambiguous Cargo test artifact: {name}")
        targets[name] = value
    if not targets:
        raise GateError("Cargo produced no test executables")
    return targets


def run_gate(args, report):
    if sys.platform != "linux":
        raise GateError("this mandatory inventory is a Linux gate; other platforms have separate native CI jobs")
    inventory = load_inventory()
    env = clean_environment(os.environ)
    interpreter = env.get("KV_PY_REF", "")
    report["reference"] = attest_reference(args.reference_repo, interpreter, inventory,
                                           args.python_version, args.mode, env)
    env.update(KV_PARITY_REQUIRED="1", KV_PARITY_MODE=args.mode, KV_PY_REF=interpreter)
    report["mode"] = args.mode
    report["rust_commit"] = capture(["git", "rev-parse", "HEAD"]).strip()
    report["rust_worktree_status"] = capture(["git", "status", "--porcelain"]).splitlines()
    report["rustc"] = capture(["rustc", "--version"], env=env).strip()
    metadata = json.loads(capture(["cargo", "metadata", "--no-deps", "--locked", "--format-version=1"], env=env))
    packages = {p["id"]: p for p in metadata["packages"] if p["id"] in metadata["workspace_members"]}
    build_log = args.output / "build.jsonl"
    if run_logged(["cargo", "test", "--release", "--workspace", "--locked", "--no-run", "--message-format=json"],
                  build_log, stderr=args.output / "build.stderr", env=env, timeout=1800):
        raise GateError("Cargo test build failed; see build.stderr")
    targets = compiled_targets(build_log.read_text(), packages)
    missing = set(inventory["targets"]) - targets.keys()
    if missing:
        raise GateError(f"expected parity targets were not built: {sorted(missing)}")
    failures = []
    report["targets"] = {}
    for target, artifact in sorted(targets.items()):
        expected = inventory["targets"].get(target, [])
        stem = target.replace("/", "--")
        discovery_log = args.output / (stem + ".list")
        test_log = args.output / (stem + ".log")
        try:
            if run_logged([artifact["executable"], "--list", "--color=never"], discovery_log,
                          cwd=artifact["cwd"], env=env, timeout=60):
                raise GateError("test discovery failed")
            discovered = parse_discovery(discovery_log.read_text())
            if not set(expected) <= discovered:
                raise GateError(f"expected parity tests missing from discovery: {sorted(set(expected) - discovered)}")
            status = run_logged([artifact["executable"], "--show-output", "--test-threads=1", "--color=never"],
                                test_log, cwd=artifact["cwd"], env=env)
            report["targets"][target] = check_results(test_log.read_text(), discovered, expected, status)
            print(f"PASS {target}: {len(discovered)} tests, {len(expected)} comparisons", flush=True)
        except GateError as error:
            report["targets"][target] = {"error": str(error)}
            failures.append(target)
            print(f"FAIL {target}: {error}", flush=True)
    if failures:
        raise GateError(f"failed targets: {', '.join(failures)}")
    # Reverse interoperability is a separate required Stage 1 gate.
    vector_dir = args.output / "rust-vectors"
    commands = [
        ("emit-vectors", ["cargo", "run", "--release", "--locked", "-p", "kv-crypto", "--example", "emit_rust_vectors", "--", str(vector_dir)]),
        ("reverse-crypto", [interpreter, "-I", str(ROOT / "fixtures/gen/check_rust_outputs.py"), str(vector_dir)]),
    ]
    if args.mode == "canonical":
        commands.append(("unicode-table", [interpreter, "-I", str(ROOT / "fixtures/gen/generate_python_digits.py"), "--check"]))
    report["extra_checks"] = {}
    for name, command in commands:
        status = run_logged(command, args.output / (name + ".log"), env=env)
        report["extra_checks"][name] = status
        if status:
            raise GateError(f"{name} failed with exit {status}")
        print(f"PASS {name}", flush=True)
    report["comparisons_passed"] = sum(len(t["comparisons"]) for t in report["targets"].values())
    if report["comparisons_passed"] < inventory["minimum_comparisons"]:
        raise GateError("completed comparisons below inventory floor")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-repo", required=True, type=Path)
    parser.add_argument("--python-version", required=True, help="expected major.minor or exact version")
    parser.add_argument("--mode", choices=("canonical", "semantic"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    report = {"status": "running", "started_at": datetime.now(timezone.utc).isoformat()}
    result_path = args.output / "report.json"
    result_path.write_text(json.dumps(report, indent=2) + "\n")
    try:
        run_gate(args, report)
        report["status"] = "passed"
    except (GateError, OSError, ValueError, KeyError) as error:
        report.update(status="failed", error=str(error))
        print(f"Parity gate failed: {error}", file=sys.stderr)
    finally:
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        result_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
