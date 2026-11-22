"""The local door to the NER TEE, for the DICOM application container.

Added 2026-11-23 (Kailash: DICOM should use the shared NER on the text it
extracts from the pixels and on free-text tags). The DICOM container runs on
this k-anon TEE and has no route to the NER TEE, and should not have one:
attestation, key pinning and the RA-TLS channel live here, in the enclave
manager, exactly as for the skald-fta stage. So the enclave manager serves a
Unix socket, which the skald-dicom compose file mounts at
/run/anamika-ner/ner.sock, and forwards each request to the NER TEE through
ner_client.spans_remote.

  POST /spans   {"texts", "minimum_confidence", "labels"} -> the NER TEE's reply
                (503 when the NER TEE can't be used; the container then takes
                its fallback, see DICOM-deidentifier app/shared_ner.py)
  GET  /health  {"status": "ok"}

Only local processes can reach a Unix socket; its directory is 0700, owned
by this service's user (the container runs as root). Nothing is logged but
status lines, nothing is written to disk.

k-anon nodes only, and only while ner_tee is enabled; the NER node and a
disabled config never open it, and a socket that is not there simply means
"no shared NER" to the container.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from lib import ner_client
from lib.config import config

DEFAULT_SOCKET = "/tmp/tee_ner/ner.sock"
MAX_BODY = 64 * 1024 * 1024
_server = None


def socket_path() -> str:
    return str(getattr(getattr(config, "ner_tee", None), "dicom_socket", "") or DEFAULT_SOCKET)


class _Handler(BaseHTTPRequestHandler):
    server_version = "anamika-ner-local/1"

    def log_message(self, fmt, *args):  # status lines only, never contents
        sys.stdout.write("NER local socket: %s\n" % (fmt % args))

    def address_string(self):
        return "local"

    def _reply(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path == "/health":
            self._reply(200, b'{"status": "ok"}')
        else:
            self._reply(404, b'{"error": "not found"}')

    def do_POST(self):  # noqa: N802
        if self.path != "/spans":
            return self._reply(404, b'{"error": "not found"}')
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            return self._reply(400, b'{"error": "missing or oversized body"}')
        body = self.rfile.read(length)
        try:
            reply = ner_client.spans_remote(body)
        except ner_client.NerUnavailable as e:
            print(f"NER local socket: NER TEE unavailable ({e})", flush=True)
            return self._reply(503, json.dumps({"error": "NER TEE unavailable"}).encode())
        except Exception as e:  # never take the enclave manager down over this
            print(f"NER local socket: {type(e).__name__}: {e}", flush=True)
            return self._reply(500, b'{"error": "internal error"}')
        self._reply(200, reply)


class _UnixServer(ThreadingHTTPServer):
    address_family = socket.AF_UNIX
    daemon_threads = True

    def server_bind(self):
        self.socket.bind(self.server_address)

    def get_request(self):
        conn, _ = self.socket.accept()
        return conn, ("local", 0)


def _prepare_dir(path: str) -> None:
    d = os.path.dirname(path)
    if os.path.isdir(d) and os.stat(d).st_uid != os.getuid():
        # docker creates a missing bind-mount source as root; take it back.
        subprocess.run(["sudo", "chown", f"{os.getuid()}:{os.getgid()}", d], check=False, capture_output=True)
    os.makedirs(d, mode=0o700, exist_ok=True)
    os.chmod(d, 0o700)
    if os.path.exists(path):
        os.remove(path)


def start() -> bool:
    """Open the socket if this node should. Returns whether it is serving.
    Never raises: a failure here only means DICOM runs without shared NER."""
    global _server
    if _server is not None:
        return True
    try:
        if not ner_client.remote_enabled():
            return False
        path = socket_path()
        _prepare_dir(path)
        _server = _UnixServer(path, _Handler)
        threading.Thread(target=_server.serve_forever, name="ner-local-socket", daemon=True).start()
        print(f"NER local socket for DICOM on {path}", flush=True)
        return True
    except Exception as e:
        print(f"NER local socket not started: {type(e).__name__}: {e}", flush=True)
        _server = None
        return False
