"""Negative controls for the gate's independent evidence checks (stdlib only)."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import venv

spec = importlib.util.spec_from_file_location("parity_gate", Path(__file__).with_name("parity_gate.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class InventoryControls(unittest.TestCase):
    GOOD = "test parity ... ok\n\nKV_PARITY_TEST parity\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s\n"

    def test_complete_evidence_passes(self):
        result = gate.check_results(self.GOOD, {"parity"}, ["parity"], 0)
        self.assertEqual(result["comparisons"], ["parity"])

    def test_success_without_comparison_marker_fails(self):
        with self.assertRaises(gate.GateError):
            gate.check_results(self.GOOD.replace("KV_PARITY_TEST parity\n", ""), {"parity"}, ["parity"], 0)

    def test_marker_without_success_fails(self):
        with self.assertRaises(gate.GateError):
            gate.check_results(self.GOOD.replace("test parity ... ok\n", ""), {"parity"}, ["parity"], 0)

    def test_filtered_expected_comparison_cannot_pass_zero_tests(self):
        text = "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0s\n"
        with self.assertRaises(gate.GateError):
            gate.check_results(text, set(), ["parity"], 0)

    def test_ignored_failed_duplicate_or_skipped_comparison_fails(self):
        for text in [self.GOOD.replace("... ok", "... ignored"),
                     self.GOOD.replace("... ok", "... FAILED"),
                     self.GOOD + "KV_PARITY_TEST parity\n",
                     self.GOOD + "KV_PARITY_TEST surprise\n",
                     self.GOOD + "KV_PARITY_SKIP hidden\n",
                     self.GOOD + "test parity ... ok\n",
                     self.GOOD.replace("1 passed", "2 passed")]:
            with self.subTest(text=text), self.assertRaises(gate.GateError):
                gate.check_results(text, {"parity"}, ["parity"], 0)

    def test_failed_command_cannot_be_rescued_by_passing_output(self):
        with self.assertRaises(gate.GateError):
            gate.check_results(self.GOOD, {"parity"}, ["parity"], 101)

    def test_discovery_requires_unique_names(self):
        self.assertEqual(gate.parse_discovery("parity: test\nhelper: test\n"), {"parity", "helper"})
        with self.assertRaises(gate.GateError):
            gate.parse_discovery("parity: test\nparity: test\n")

    def test_committed_inventory_has_a_reviewed_floor(self):
        inventory = gate.load_inventory()
        self.assertGreaterEqual(sum(map(len, inventory["targets"].values())), 35)


class ReferenceControls(unittest.TestCase):
    def observation(self):
        return {"python": [3, 10, 22], "distribution_version": "0.4.0",
                "module_version": "0.4.0", "files": {"kv/a.py": "abc"}}

    def test_runtime_package_and_actual_source_are_attested(self):
        gate.check_reference_observation(self.observation(), {"kv/a.py": "abc"}, "0.4.0", "3.10", "canonical")
        variants = [dict(self.observation(), python=[3, 12, 14]),
                    dict(self.observation(), distribution_version="0.5.0"),
                    dict(self.observation(), module_version="0.5.0"),
                    dict(self.observation(), files={}),
                    dict(self.observation(), files={"kv/a.py": "changed"}),
                    dict(self.observation(), files={"kv/a.py": "abc", "kv/extra.py": "new"})]
        for observed in variants:
            with self.subTest(observed=observed), self.assertRaises(gate.GateError):
                gate.check_reference_observation(observed, {"kv/a.py": "abc"}, "0.4.0", "3.10", "canonical")

    def test_canonical_mode_cannot_use_newer_python_even_when_requested(self):
        with self.assertRaises(gate.GateError):
            gate.check_reference_observation(dict(self.observation(), python=[3, 12, 14]),
                                             {"kv/a.py": "abc"}, "0.4.0", "3.12", "canonical")

    def test_import_overrides_are_removed_without_removing_network_trust(self):
        env = gate.clean_environment({"PYTHONPATH": "bad", "PYTHONHOME": "bad", "SSL_CERT_FILE": "ca", "HTTPS_PROXY": "proxy"})
        self.assertNotIn("PYTHONPATH", env)
        self.assertNotIn("PYTHONHOME", env)
        self.assertEqual(env["SSL_CERT_FILE"], "ca")
        self.assertEqual(env["HTTPS_PROXY"], "proxy")

    def test_real_gate_refuses_missing_empty_and_nonexistent_reference(self):
        with tempfile.TemporaryDirectory() as directory:
            for configured in [None, "", "/nonexistent/kv-parity-python"]:
                env = dict(os.environ)
                env.pop("KV_PY_REF", None)
                if configured is not None:
                    env["KV_PY_REF"] = configured
                result = subprocess.run([sys.executable, "-I", str(Path(gate.__file__)),
                                         "--reference-repo", directory, "--python-version", "3.10",
                                         "--mode", "canonical", "--output", directory],
                                        env=env, capture_output=True, text=True, timeout=15)
                self.assertNotEqual(result.returncode, 0)
                report = json.loads((Path(directory) / "report.json").read_text())
                self.assertEqual(report["status"], "failed")
                self.assertIn("KV_PY_REF", report["error"])

    def test_wrong_git_reference_is_rejected_before_import(self):
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(["git", "init", "-q", directory], check=True)
            subprocess.run(["git", "-C", directory, "-c", "user.name=Parity test", "-c", "user.email=parity@example.invalid",
                            "commit", "--allow-empty", "-qm", "unrelated reference"], check=True)
            with self.assertRaisesRegex(gate.GateError, "reference commit mismatch"):
                gate.attest_reference(directory, sys.executable, gate.load_inventory(), "3.10", "canonical", {})

    def test_hidden_editable_reference_edits_cannot_change_the_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "reference"
            repo.mkdir()
            original = b'__version__ = "0.4.0"\r\n'
            for package, content in [("kv", original), ("kv_mcp", b"# MCP package\n")]:
                (repo / package).mkdir()
                (repo / package / "__init__.py").write_bytes(content)
            (repo / ".gitignore").write_text("__pycache__/\n")
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "add", "."], cwd=repo, check=True)
            subprocess.run(["git", "-c", "user.name=Parity test", "-c", "user.email=parity@example.invalid",
                            "commit", "-qm", "pinned reference"], cwd=repo, check=True)
            commit = gate.capture(["git", "rev-parse", "HEAD"], cwd=repo).strip()
            inventory = {"reference_commit": commit, "reference_version": "0.4.0"}

            # A real isolated interpreter imports the checkout through an
            # editable .pth file. Minimal metadata keeps this control offline.
            environment = root / "venv"
            venv.EnvBuilder(with_pip=False).create(environment)
            interpreter = str(environment / "bin" / "python")
            site = Path(gate.capture([interpreter, "-I", "-c",
                                     "import sysconfig; print(sysconfig.get_path('purelib'))"]).strip())
            (site / "reference.pth").write_text(str(repo) + "\n")
            for package, version in [("kv-secrets", "0.4.0"), ("cryptography", "50.0.2")]:
                metadata = site / (package.replace("-", "_") + "-" + version + ".dist-info")
                metadata.mkdir()
                (metadata / "METADATA").write_text(
                    f"Metadata-Version: 2.1\nName: {package}\nVersion: {version}\n")
            env = gate.clean_environment(os.environ)
            version = f"{sys.version_info.major}.{sys.version_info.minor}"
            observed = gate.attest_reference(repo, interpreter, inventory, version, "semantic", env)
            self.assertEqual(observed["files"]["kv/__init__.py"], hashlib.sha256(original).hexdigest())

            for flag in ["assume-unchanged", "skip-worktree"]:
                with self.subTest(flag=flag):
                    subprocess.run(["git", "update-index", "--" + flag, "kv/__init__.py"], cwd=repo, check=True)
                    (repo / "kv/__init__.py").write_bytes(original + b"# hidden working-tree edit\n")
                    self.assertEqual(gate.capture(["git", "status", "--porcelain", "--untracked-files=all"], cwd=repo), "")
                    with self.assertRaisesRegex(gate.GateError, "imported Python source differs"):
                        gate.attest_reference(repo, interpreter, inventory, version, "semantic", env)
                    (repo / "kv/__init__.py").write_bytes(original)
                    subprocess.run(["git", "update-index", "--no-" + flag, "kv/__init__.py"], cwd=repo, check=True)


if __name__ == "__main__":
    unittest.main()
