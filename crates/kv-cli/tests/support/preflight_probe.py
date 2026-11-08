"""Byte-exact CLI transcripts; only the manifest's random run ID is masked."""
import ast
import errno
import fcntl
import json
import os
from pathlib import Path
import pty
import re
import select
import subprocess
import sys
import termios
import time

from kv.vault_origin import record_created
from kv.cli import build_parser

data = json.load(sys.stdin)
try:
    ast.parse("x\0")
except (ValueError, SyntaxError) as exc:
    nul_error = type(exc).__name__
root = Path(data["root"])
sources = [
    "pass", "import openai", "from kv.cap_client import api_call\napi_call('openai')",
    "api_call('openai')\napi_call('anthropic')", "c=OpenAI()\nc.chat()",
    "os.getenv('OPENAI_API_KEY')", "subprocess.run(['ssh','user@host'])",
    "Path('out').write_text('x')\nopen('log','w')", "x =",
    "for x in range(3):\n api_call('github')", "for x in xs:\n api_call('google')",
    "import anthropic\nanthropic.Anthropic()", "os.system('ssh remote')",
    "requests.get('https://example.com')", "match x:\n case 1: pass",
    "api_call(provider='openai')", "api_call('missing')",
]
for i, source in enumerate(sources):
    (root / f"s{i}.py").write_text(source)
(root / "nul.py").write_bytes(b"x=1\x00")
(root / "overflow.py").write_text(f"for x in range({10**400}):\n api_call('openai')")
(root / "infinity.py").write_text(f"for x in range({17 * 10**307}):\n api_call('openai')")
(root / "deep.py").write_text("x=" + "-" * 600 + "1")
(root / "loop-a").symlink_to("loop-b")
(root / "loop-b").symlink_to("loop-a")
(root / "odd'\u2028\x85file").write_text("pass")
project = root / "project"
secrets = project / ".secrets"
secrets.mkdir(parents=True, mode=0o700)
config = secrets / "config.json"
config.write_text(json.dumps({"security": {"kv_run_policy": "allowlist", "allowed_commands": ["python3 allowed.py"]}}))
config.chmod(0o600)
for name in ["allowed.py", "blocked.py"]:
    (project / name).write_text("api_call('openai')")
record_created(str(project))
error_projects = []
for name, value in [("attribute-error", {"security": None}),
                    ("type-error", {"security": {"kv_run_policy": "allowlist", "allowed_commands": None}}),
                    ("missing-config", None)]:
    path = root / name
    (path / ".secrets").mkdir(parents=True, mode=0o700)
    if value is not None:
        cfg = path / ".secrets/config.json"
        cfg.write_text(json.dumps(value))
        cfg.chmod(0o600)
    record_created(str(path))
    error_projects.append(path)

cases = [(f"script-{i}-{form}", ["preflight", *(["--json"] if form == "json" else []), "--", "python3", f"s{i}.py"], root, "same")
         for i in range(len(sources)) for form in ["text", "json"]]
extras = [
    ("help", ["preflight", "-h"]), ("top-help", ["-h"]), ("no-command", ["preflight"]),
    ("empty-separator", ["preflight", "--"]), ("double-separator", ["preflight", "--", "--"]),
    ("bad-ttl", ["preflight", "--request-ttl", "bad"]),
    ("hidden-bad-ttl", ["preflight", "--request-ttl", "bad\u2028\x85"]),
    ("negative-ttl", ["preflight", "--request-ttl", "-3", "python3", "s2.py"]),
    ("unicode-negative-ttl", ["preflight", "--request-ttl", "-٣", "python3", "s2.py"]),
    ("underscore-ttl", ["preflight", "--request-ttl", "1_000", "python3", "s2.py"]),
    ("negative-float-ttl", ["preflight", "--request-ttl", "-1."]),
    ("empty-ttl", ["preflight", "--request-ttl="]),
    ("help-value", ["preflight", "--help=x"]),
    ("attached-help-value", ["preflight", "-hfoo"]),
    ("big-ttl", ["preflight", "--request-ttl", str(10**200), "python3", "s2.py"]),
    ("unknown", ["preflight", "--wat"]), ("missing-option", ["preflight", "--cwd"]),
    ("flag-value", ["preflight", "--json=x"]), ("ambiguous", ["preflight", "--re"]),
    ("abbreviated", ["preflight", "--js", "python3", "s2.py"]),
    ("options-after-command", ["preflight", "python3", "s2.py", "--json"]),
    ("relative-cwd", ["preflight", "--cwd", "project", "python3", "allowed.py"]),
    ("absolute-cwd", ["preflight", "--cwd", str(project), "--json", "python3", "allowed.py"]),
    ("missing-cwd", ["preflight", "--cwd", "missing-directory", "--json", "python3", "app.py"]),
    ("blocked", ["preflight", "curl", "https://example.com"]),
    ("allowlist-blocked", ["preflight", "--cwd", str(project), "python3", "blocked.py"]),
    ("nul", ["preflight", "python3", "nul.py"]), ("overflow", ["preflight", "python3", "overflow.py"]),
    ("infinity-overflow", ["preflight", "python3", "infinity.py"]),
    ("identity-not-directory", ["preflight", "--cwd", str(root / "s0.py/child"), "python3", "app.py"]),
    ("identity-loop", ["preflight", "--cwd", str(root / "loop-a"), "python3", "app.py"]),
    ("identity-escaped-path", ["preflight", "--cwd", str(root / "odd'\u2028\x85file/child"), "python3", "app.py"]),
    ("hidden", ["preflight", "python3", "s2.py", "a\n世界", "a'\\b", ""]),
    ("long", ["preflight", "python3", "s2.py", "x" * 9000]),
    ("request-no-project", ["preflight", "--request", "python3", "s2.py"]),
    ("request-before-empty", ["preflight", "--request"]),
    ("metadata", ["preflight", "--env", "dev", "--source", "mcp", "--client", "codex", "--session-id", "1", "--reason", "test", "python3", "s2.py"]),
]
cases += [(name, argv, root, "same") for name, argv in extras]
cases += [(path.name, ["preflight", "--cwd", str(path), "python3", "app.py"], root, "same") for path in error_projects]
cases += [("depth", ["preflight", "python3", "deep.py"], root, "depth")]
cases += [("request-project", ["preflight", "--cwd", str(project), "--request", "python3", "allowed.py"], root, "request")]
cases += [("request-project-empty", ["preflight", "--cwd", str(project), "--request"], root, "request")]


def leader():
    os.setsid()
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


def run(prefix, argv, cwd, tty, colour):
    env = dict(os.environ, TERM="xterm-256color", NO_COLOR="" if colour else "1", COLUMNS="80")
    if not tty:
        p = subprocess.run(prefix + argv, cwd=cwd, env=env, capture_output=True, timeout=30)
        return p.returncode, p.stdout, p.stderr
    master, slave = pty.openpty()
    p = subprocess.Popen(prefix + argv, cwd=cwd, env=env, stdin=slave, stdout=slave, stderr=slave, preexec_fn=leader)
    os.close(slave)
    output = bytearray()
    deadline = time.monotonic() + 30
    try:
        while True:
            if time.monotonic() > deadline:
                p.kill()
                raise TimeoutError(argv)
            if not select.select([master], [], [], 0.1)[0]:
                if p.poll() is not None:
                    break
                continue
            try:
                chunk = os.read(master, 65536)
            except OSError as exc:
                if exc.errno != errno.EIO:
                    raise
                break
            if not chunk:
                break
            output.extend(chunk)
    finally:
        os.close(master)
        p.wait()
    return p.returncode, bytes(output), b""


def mask(result):
    return (result[0], *(re.sub(rb'("run_id": ")run_[a-f0-9]{24}(")', rb'\1RUN_ID\2', stream) for stream in result[1:]))


def error_result(message, tty, colour):
    red, reset = ("\x1b[38;2;255;100;100m", "\x1b[0m") if colour else ("", "")
    error = f"  {red}✗ {message}{reset}\n".encode()
    return (1, error.replace(b"\n", b"\r\n"), b"") if tty else (1, b"", error)


count = requests = nul_differences = runtime_differences = 0
failures = []
for tty in [False, True]:
    for colour in [False, True]:
        for name, argv, cwd, kind in cases:
            before = {str(p.relative_to(project)): p.read_bytes() for p in project.rglob("*") if p.is_file()}
            got = run([data["binary"]], argv, cwd, tty, colour)
            if kind == "request":
                requests += 1
                message = "kv preflight --request is not supported by this kv build yet; run kv preflight without --request"
                expected = error_result(message, tty, colour)
                assert got == expected, (name, tty, colour, got, expected)
                after = {str(p.relative_to(project)): p.read_bytes() for p in project.rglob("*") if p.is_file()}
                assert before == after, "--request wrote project state"
                continue
            want = run([sys.executable, "-I", "-m", "kv"], argv, cwd, tty, colour)
            if name == "help":
                reference_help = want
            if name == "attached-help-value" and want[0] == 0:
                assert want == reference_help
                legacy_error = run([sys.executable, "-I", "-m", "kv"], ["preflight", "--help=foo"], cwd, tty, colour)
                assert got == legacy_error and got[0] == 2, (got, legacy_error)
                runtime_differences += 1
                continue
            if name == "unknown" and want[0] == 1:
                branded = run([sys.executable, "-I", "-m", "kv"], ["unknown-preflight-command"], cwd, tty, colour)
                assert want == branded
                choices = next(action.choices for action in build_parser()._actions if action.choices)
                usage = "usage: kv [-h] [--version]\n          {" + ",".join(choices) + "}\n          ...\n"
                error = (usage + "kv: error: unrecognized arguments: --wat\n").encode()
                expected = (2, error.replace(b"\n", b"\r\n"), b"") if tty else (2, b"", error)
                assert got == expected, (got, expected)
                runtime_differences += 1
                continue
            if name in {"identity-not-directory", "identity-escaped-path"} and hasattr(os.path, "ALLOW_MISSING") and sys.version_info < (3, 13):
                candidate = root / ("s0.py" if name == "identity-not-directory" else "odd'\u2028\x85file")
                assert got == error_result(str(NotADirectoryError(errno.ENOTDIR, os.strerror(errno.ENOTDIR), str(candidate))), tty, colour)
                assert want == error_result(str(NotADirectoryError(errno.ENOTDIR, os.strerror(errno.ENOTDIR), str(candidate / "child"))), tty, colour)
                runtime_differences += 1
                continue
            if name == "nul" and nul_error == "SyntaxError":
                assert want[0] == 0 and b"Python script could not be parsed; estimates are incomplete." in want[1] and want[2] == b""
                assert got == error_result("source code string cannot contain null bytes", tty, colour), got
                nul_differences += 1
                continue
            if name == "top-help":
                assert got[0] == want[0] == 0 and got[2] == want[2] == b""
                delimiter = b"Use 'kv COMMAND --help' for per-command flags. Version: "
                gp, gs, gv = got[1].partition(delimiter)
                wp, ws, wv = want[1].partition(delimiter)
                assert gp == wp and gs == ws == delimiter
                assert b"kv preflight -- CMD" in gp and b"Report broker capability needs before approval" in gp
                ending = (b"\x1b[0m" if colour else b"") + (b"\r\n\r\n" if tty else b"\n\n")
                assert gv == data["version"].encode() + ending, gv
                assert wv == b"0.4.0" + ending, wv
                continue
            if kind == "depth":
                assert want[0] == 1 and b"recursion depth" in b"".join(want[1:]), want
                assert got == error_result("Python script is nested too deeply for static preflight", tty, colour), got
                continue
            if mask(got) != mask(want):
                failures.append((name, tty, colour, got, want))
                continue
            if name == "hidden":
                assert b"the line cannot be copied as is" in got[1]
            if name == "long":
                assert b"<this value is too long to be shown safely>" in got[1]
                assert b"The full command is too long to show here; kv preflight --json shows it, and kv preflight --request files it." in got[1]
            count += 1
assert not failures, failures
print(f"preflight CLI parity: {count} exact transcripts, {len(sources)} scripts, {requests} fail-closed requests; 4 depth differences; {nul_differences} version-specific NUL differences; {runtime_differences} argparse/resolver runtime differences; 4 help listings with distinct package-version footers; pipe/pty x plain/ANSI")
