"""Bounded subprocess fixtures against the installed, pinned Python audit writer."""
import fcntl
import json
import os
from pathlib import Path
import sys
import time

from kv import audit

directory = Path(sys.argv[1])
mode = sys.argv[2]
audit.AUDIT_DIR = str(directory)
audit._deliver_via_reply = True


def wait_for(path):
    deadline = time.monotonic() + 25
    while not path.exists():
        if time.monotonic() >= deadline:
            raise TimeoutError("audit test gate was not released")
        time.sleep(0.005)


def snapshot():
    return {"health": audit.audit_health(), "chain": audit.verify_chain()}


if mode == "snapshot":
    result = snapshot()
elif mode == "emit":
    event, fields = json.loads(sys.argv[3])
    result = {"outcome": audit.emit(event, **fields), **snapshot()}
elif mode == "hold":
    name, ready, release = sys.argv[3:]
    fd = os.open(directory / name, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        Path(ready).write_text("locked")
        wait_for(Path(release))
    finally:
        os.close(fd)
    result = {"released": True}
elif mode in ("writer", "paused_append"):
    ready, release = map(Path, sys.argv[3:5])
    real_append = audit._audit_append
    first = True

    def gated_append(dir_fd, text):
        global first
        if first:
            first = False
            # emit already holds audit.lock and has read its predecessor hash.
            ready.write_text("append-ready")
            wait_for(release)
        return real_append(dir_fd, text)

    audit._audit_append = gated_append
    if mode == "writer":
        count = int(sys.argv[5])
        outcomes = [audit.emit("interop", writer="python", seq=seq)
                    for seq in range(1, count + 1)]
    else:
        outcomes = [audit.emit("paused_python", writer="python", seq=0)]
    result = {"outcomes": outcomes, **snapshot()}
elif mode == "missing_loss_bug":
    record = json.loads((directory / "audit-health.json").read_bytes())
    accepted = audit._health_record_valid(record)
    try:
        observed = {"snapshot": audit.audit_health()}
    except Exception as exc:
        observed = {"exception": {"type": type(exc).__name__, "args": list(exc.args)}}
    result = {"validator_accepted": accepted, **observed}
elif mode == "health_validation":
    health_path = directory / "audit-health.json"
    original = health_path.read_bytes()
    original_stat = health_path.lstat()
    names = sorted(path.name for path in directory.iterdir())
    before = audit.audit_health()
    probed_stat = health_path.lstat()
    assert health_path.read_bytes() == original
    assert (original_stat.st_ino, original_stat.st_mode, original_stat.st_nlink) == (
        probed_stat.st_ino, probed_stat.st_mode, probed_stat.st_nlink)
    assert sorted(path.name for path in directory.iterdir()) == names
    victim = directory.parent / "victim"
    victim.write_text("untouched")
    (directory / "audit.jsonl").symlink_to(victim)
    outcome = audit.emit("refused")
    source = directory.parent / "health-source"
    result = {"before": before, "outcome": outcome, "after": audit.audit_health(),
              "record": json.loads(health_path.read_bytes()),
              "victim": victim.read_text(),
              "source": source.read_text() if source.exists() else None}
elif mode == "fault_recovery":
    health = [audit.audit_health()]
    directory.mkdir(mode=0o700)
    victim = directory.parent / "victim"
    victim.write_text("untouched")
    log = directory / "audit.jsonl"
    log.symlink_to(victim)
    outcomes = []
    for _ in range(2):
        outcomes.append(audit.emit("refused"))
        health.append(audit.audit_health())
    warning = audit.take_audit_warning()
    warnings = [warning]
    audit.release_audit_warning(warning)
    warnings.extend([audit.take_audit_warning(), audit.take_audit_warning()])
    log.unlink()
    outcomes.append(audit.emit("recovered"))
    health.append(audit.audit_health())
    warnings.append(audit.take_audit_warning())
    log.unlink()
    log.symlink_to(victim)
    outcomes.append(audit.emit("refused_again"))
    health.append(audit.audit_health())
    log.unlink()
    outcomes.append(audit.emit("recovered_before_warning"))
    health.append(audit.audit_health())
    warnings.extend([audit.take_audit_warning(), audit.take_audit_warning()])
    result = {"health": health, "outcomes": outcomes, "warnings": warnings,
              "victim": victim.read_text()}
else:
    raise ValueError("unknown audit fixture mode")

print(json.dumps(result))
