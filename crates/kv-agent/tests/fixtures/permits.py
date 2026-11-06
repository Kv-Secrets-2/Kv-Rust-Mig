"""Real HTTPS and authenticated Python owner fixtures for ordinary API permits.

Only URL safety/DNS pinning is overridden. The daemon, owner verification,
request preparation, TLS, transport, and audit implementation remain real.
"""

import argparse
import copy
import http.server
import json
import os
from pathlib import Path
import ssl
import sys
import threading
import time
from urllib.parse import urlsplit

HOST = "permit-fixture.example"


def wait_for_file(path, seconds):
    deadline = time.monotonic() + seconds
    while not path.is_file():
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)
    return True


def run_server(certificate, key, observed, directory):
    directory, observed = Path(directory), Path(observed)
    observed_lock = threading.Lock()

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_POST(self):
            self.connection.settimeout(20)
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            with observed_lock:
                with observed.open("a", encoding="utf-8") as output:
                    output.write(json.dumps({
                        "method": self.command,
                        "path": self.path,
                        "headers": {k.lower(): v for k, v in self.headers.items()},
                        "body_hex": body.hex(),
                    }) + "\n")
                    output.flush()
            self.close_connection = True
            path = urlsplit(self.path).path
            if path == "/api/drop":
                return  # A real request was accepted; no HTTP response follows.
            if path == "/api/hold":
                if not wait_for_file(directory / "provider.release", 45):
                    raise AssertionError("fixture provider release timed out")
            body = b'{"ok":true}'
            try:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        do_GET = do_POST
        do_PUT = do_POST
        do_PATCH = do_POST
        do_DELETE = do_POST

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        server.socket = context.wrap_socket(server.socket, server_side=True)
        pending = directory / "server.port.pending"
        pending.write_text(str(server.server_port), encoding="ascii")
        pending.replace(directory / "server.port")
        server.serve_forever()


def run_daemon(root, passphrase, directory, mode="protected"):
    from kv import providers
    from kv.agent import run_agent
    from kv.config import get_default_env
    from kv.store import SecretStore
    from kv.trust import TrustContext

    directory = Path(directory)
    gate_lock = threading.Lock()
    entered = 0

    def safety(url):
        nonlocal entered
        if urlsplit(url).hostname != HOST:
            return False, "permit fixture only permits its public-shaped hostname", None
        if (directory / "safety.fail").exists():
            return False, "fixture rejected preflight", None
        if (directory / "safety.arm").exists():
            with gate_lock:
                entered += 1
                (directory / f"safety.entered.{entered}").write_text("entered")
            if not wait_for_file(directory / "safety.release", 30):
                return False, "permit fixture safety check timed out", None
            (directory / "safety.returned").write_text("returned")
        return True, "", "127.0.0.1"

    providers._check_url_safety = safety
    store = SecretStore(root, passphrase=passphrase)
    master = store.master_key
    store.pin()
    store.trust = TrustContext.at_unlock(root, None if mode == "unprotected" else passphrase, master)
    run_agent(store, get_default_env(root))


def owner(root, passphrase, command):
    from kv import approval_channel, approval_wire
    from kv.approval_render import render_permit_request
    from kv.owner_approval import PermitSigningContext, SigningRefused

    if command.get("action") == "unprotected":
        from kv.agent import agent_request
        from kv.owner_approval import prompt_unwrapped
        unwrapped = prompt_unwrapped(root, lambda *args, **kwargs: passphrase)
        try:
            challenge = os.urandom(approval_wire.NONCE_LEN)
            answer = agent_request("owner_channel", project_root=root, challenge=challenge.hex())
            fields = approval_channel.check_answer(answer, challenge, unwrapped)
            assert fields["mode"] == "unprotected"
            challenge = os.urandom(approval_wire.NONCE_LEN)
            answer = agent_request("owner_permit_register", project_root=root,
                                   challenge=challenge.hex(), permit={})
            try:
                approval_channel.check_answer(answer, challenge, unwrapped,
                                              expect="permit-register-ack-v1")
            except approval_channel.DaemonRefused as exc:
                code = exc.code
            else:
                raise AssertionError("unprotected session accepted registration")
        finally:
            unwrapped.discard_seed()
        try:
            context = PermitSigningContext.begin(root, lambda *args, **kwargs: passphrase)
        except SigningRefused:
            owner_refused = True
        else:
            context.close()
            raise AssertionError("owner accepted an unprotected daemon")
        return {"code": code, "owner_refused": owner_refused}

    context = PermitSigningContext.begin(root, lambda *args, **kwargs: passphrase)
    try:
        def register_result(artifact):
            challenge = os.urandom(approval_wire.NONCE_LEN)
            answer = context._send("owner_permit_register", challenge=challenge.hex(), permit=artifact)
            try:
                fields = approval_channel.check_answer(
                    answer, challenge, context._unwrapped, expect="permit-register-ack-v1")
            except approval_channel.DaemonRefused as exc:
                return {"code": exc.code}
            # The public owner method additionally binds IDs and payload digest.
            status = context.register_permit(artifact)
            assert fields["status"] in ("registered", "already-registered")
            assert status == "already-registered"
            return {"status": fields["status"]}

        action = command.get("action", "approve")
        if action == "register":
            return {"status": context.register_permit(command["permit"])}
        if action == "register_result":
            return register_result(command["permit"])
        record = context.permit_record(command["request_id"])
        rendered = "\n".join(render_permit_request(record))
        artifact = context.sign_permit(record)
        result = {"record": record, "permit": artifact, "rendered": rendered}
        if action == "approve":
            result["status"] = context.register_permit(artifact)
        elif action == "mutations":
            results = []
            for field, value in command["mutations"]:
                changed = copy.deepcopy(record)
                changed["facts"][field] = value
                response = register_result(context.sign_permit(changed))
                results.append({"field": field, **response})
            tampered = copy.deepcopy(artifact)
            tampered["payload"]["method"] = "DELETE"
            results.append({"field": "unsigned-tampering", **register_result(tampered)})
            result["results"] = results
        elif action != "record":
            raise AssertionError(f"unknown owner action {action}")
        return result
    finally:
        context.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=("server", "daemon", "owner", "audit"))
    parser.add_argument("arguments", nargs="*")
    args = parser.parse_args()
    if args.role == "server":
        run_server(*args.arguments)
    elif args.role == "daemon":
        run_daemon(*args.arguments)
    elif args.role == "owner":
        print(json.dumps(owner(*args.arguments, json.load(sys.stdin))))
    else:
        from kv.audit import verify_chain
        ok, details = verify_chain()
        print(json.dumps({"ok": ok, "details": details}))


if __name__ == "__main__":
    main()
