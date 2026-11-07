#!/usr/bin/env python3
"""Run a command in a pty, answering prompts. usage: ptyrun.py [--cwd DIR] [--env K=V]... -- CMD ARGS -- 'regex=>answer' ...
Prints captured output to stdout; exit code = child exit code."""
import os, pty, re, select, subprocess, sys, time, fcntl, termios
def _lead():
    os.setsid()
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)
args = sys.argv[1:]
cwd = None; env = dict(os.environ)
while args and args[0] != "--":
    if args[0] == "--cwd": cwd = args[1]; args = args[2:]
    elif args[0] == "--env": k, v = args[1].split("=", 1); env[k] = v; args = args[2:]
    else: break
args = args[1:]
split = args.index("--") if "--" in args else len(args)
cmd, rules = args[:split], args[split+1:]
rules = [r.split("=>", 1) for r in rules]
m, s = pty.openpty()
proc = subprocess.Popen(cmd, stdin=s, stdout=s, stderr=s, cwd=cwd, env=env, close_fds=True, preexec_fn=_lead)
os.close(s)
buf = b""; seen = 0; out = b""
deadline = time.time() + 60
while True:
    r, _, _ = select.select([m], [], [], 0.2)
    if r:
        try:
            chunk = os.read(m, 65536)
        except OSError:
            break
        if not chunk: break
        buf += chunk; out += chunk
    for i, (pat, ans) in enumerate(rules):
        if i >= seen and re.search(pat.encode(), buf):
            os.write(m, ans.encode() + b"\n"); seen = i + 1; buf = b""
            break
    if proc.poll() is not None and not r:
        break
    if time.time() > deadline:
        proc.kill(); break
proc.wait()
sys.stdout.buffer.write(out)
sys.exit(proc.returncode)
