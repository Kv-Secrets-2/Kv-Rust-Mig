"""Local HTTPS and Python-daemon fixtures for daemon shutdown integration tests.

The Rust test supplies a temporary CA/server certificate and trusts that CA only
in its test caller. The Python daemon uses the parent's SSL_CERT_FILE. This
fixture's URL-safety override permits only loopback; it changes neither the
reference daemon's stop implementation nor its shutdown deadlines.
"""

import argparse
import http.server
import json
from pathlib import Path
import ssl
import sys
import threading
import time
from urllib.parse import urlsplit


def wait_for_file(path, seconds):
    deadline = time.monotonic() + seconds
    while not path.is_file():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.01, remaining))
    return True


def run_server(certificate, key, observed, directory):
    directory = Path(directory)
    observed = Path(observed)
    observed_lock = threading.Lock()

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_GET(self):
            with observed_lock:
                with observed.open("a", encoding="utf-8") as output:
                    output.write(json.dumps({
                        "path": self.path,
                        "authorization": self.headers.get("Authorization"),
                    }) + "\n")
                    output.flush()

            status = 200
            body = b'{"ok":true}'
            if urlsplit(self.path).path == "/api/hold":
                if not wait_for_file(directory / "provider.release", 60):
                    print("fixture provider release timed out", file=sys.stderr, flush=True)
                    status = 503
                    body = b'{"error":"fixture provider release timed out"}'

            self.close_connection = True
            try:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                # A bounded daemon stop can abandon its committed connection.
                pass

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        server.socket = context.wrap_socket(server.socket, server_side=True)
        pending = directory / "server.port.pending"
        pending.write_text(str(server.server_port) + "\n", encoding="ascii")
        pending.replace(directory / "server.port")
        server.serve_forever()


def run_daemon(root, passphrase, directory):
    from kv import providers
    from kv.agent import run_agent
    from kv.config import get_default_env
    from kv.store import SecretStore
    from kv.trust import TrustContext

    directory = Path(directory)

    def local_safety(url):
        parsed = urlsplit(url)
        if parsed.hostname != "127.0.0.1":
            return False, "test caller only permits 127.0.0.1", None
        if "/api/pending" in parsed.path:
            (directory / "safety.entered").write_text("entered\n", encoding="ascii")
            if not wait_for_file(directory / "safety.release", 30):
                print("fixture URL-safety release timed out", file=sys.stderr, flush=True)
                return False, "fixture URL-safety release timed out", None
            (directory / "safety.returned").write_text("returned\n", encoding="ascii")
        return True, "", "127.0.0.1"

    providers._check_url_safety = local_safety
    store = SecretStore(root, passphrase=passphrase)
    master = store.master_key
    store.pin()
    store.trust = TrustContext.at_unlock(root, passphrase, master)
    run_agent(store, get_default_env(root))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    roles = parser.add_subparsers(dest="role", required=True)
    server = roles.add_parser("server")
    for name in ("certificate", "key", "observed", "directory"):
        server.add_argument(name)
    daemon = roles.add_parser("daemon")
    for name in ("root", "passphrase", "directory"):
        daemon.add_argument(name)
    args = parser.parse_args()
    if args.role == "server":
        run_server(args.certificate, args.key, args.observed, args.directory)
    else:
        run_daemon(args.root, args.passphrase, args.directory)


if __name__ == "__main__":
    main()
