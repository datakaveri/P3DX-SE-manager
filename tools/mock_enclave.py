#!/usr/bin/env python3
"""
Local mock of the middleware + enclave for direct-upload development.

Implements the real crypto (via docs/reference/enclave_direct_upload.py) so the
browser path can be exercised end to end on localhost before any backend work
lands. The "pipeline" is a stub that copies the input through.

    python3 tools/mock_enclave.py --port 8787

Then point the UI at it by setting tee_url.url to http://localhost:8787 in
src/environments/environments.ts.

Auth is deliberately permissive here: any Bearer token is accepted and its
subject is derived from the JWT payload if present. Do not confuse this with the
real middleware, which must validate properly.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "enclave"))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

from enclave_direct_upload import (  # noqa: E402
    UploadError,
    UploadManager,
    write_output_container,
)

SCRATCH = tempfile.mkdtemp(prefix="mock-enclave-")
PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
MANAGER = UploadManager(PRIVATE_KEY, scratch_dir=SCRATCH)

# run_id -> {"path": encrypted container path, "filename": ..., "expires_at": ...}
OUTPUTS: dict[str, dict] = {}
RUN_STATE: dict[str, dict] = {}
LOCK = threading.Lock()


def public_key_pem() -> str:
    return PRIVATE_KEY.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def subject_from_bearer(header: str | None) -> str:
    """Best-effort sub extraction. The real middleware must verify the signature."""
    if not header or not header.lower().startswith("bearer "):
        return "anonymous"
    token = header.split(" ", 1)[1]
    parts = token.split(".")
    if len(parts) != 3:
        return f"token:{token[:16]}"
    try:
        payload = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
        return str(claims.get("sub") or claims.get("email") or "anonymous")
    except Exception:
        return f"token:{token[:16]}"


def run_pipeline(run_id: str, src_path: str, filename: str) -> None:
    """Stub for the real anonymisation pipeline: sleep, copy, encrypt, publish."""
    time.sleep(3)
    anonymised = os.path.join(SCRATCH, f"{run_id}.out")
    shutil.copyfile(src_path, anonymised)

    output_key, output_base_iv = MANAGER.output_key_for(run_id)
    container = os.path.join(SCRATCH, f"{run_id}.enc")
    stem, ext = os.path.splitext(filename)
    with open(container, "wb") as fh:
        write_output_container(
            anonymised, fh,
            run_id=run_id,
            output_key=output_key,
            output_base_iv=output_base_iv,
            filename=f"{stem}_anonymised{ext or '.csv'}",
            content_type="text/csv",
        )
    os.unlink(anonymised)
    MANAGER.release(run_id)

    with LOCK:
        OUTPUTS[run_id] = {
            "path": container,
            "filename": f"{stem}_anonymised{ext or '.csv'}",
            "bytes": os.path.getsize(container),
            "expires_at": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 2 * 3600)
            ),
        }
        RUN_STATE[run_id]["status"] = "success"
    print(f"[mock] run {run_id} complete -> {container}")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # -- helpers ---------------------------------------------------------- #

    def _cors(self) -> None:
        self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", "*"))
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Authorization, Content-Type, X-Chunk-SHA256",
        )
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Expose-Headers", "Content-Disposition, Content-Length")

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self._cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: int, description: str) -> None:
        self._json(status, {"title": "error", "description": description})

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        remaining = length
        buf = bytearray()
        while remaining > 0:
            block = self.rfile.read(min(remaining, 1 << 20))
            if not block:
                break
            buf.extend(block)
            remaining -= len(block)
        return bytes(buf)

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write(f"[mock] {self.address_string()} {fmt % args}\n")

    # -- routes ----------------------------------------------------------- #

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        sub = subject_from_bearer(self.headers.get("Authorization"))
        try:
            if path == "/enclave/upload/init":
                self._json(201, MANAGER.init(sub, json.loads(self._read_body())))
                return

            parts = path.strip("/").split("/")
            if len(parts) == 4 and parts[:2] == ["enclave", "upload"] and parts[3] == "complete":
                upload_id = parts[2]
                body = json.loads(self._read_body())
                result = MANAGER.complete(sub, upload_id, body["plaintext_sha256"])
                self._json(200, result)
                return

            if path == "/enclave/bundle/upload":
                self._read_body()
                # The real enclave decrypts the bundle to find the dataset ref.
                # The mock just runs the most recent completed upload.
                with LOCK:
                    candidates = [
                        s for s in MANAGER._sessions.values() if s.completed  # noqa: SLF001
                    ]
                if not candidates:
                    self._error(400, "No completed upload to run")
                    return
                session = max(candidates, key=lambda s: s.last_activity)
                with LOCK:
                    RUN_STATE[session.upload_id] = {"status": "processing"}
                threading.Thread(
                    target=run_pipeline,
                    args=(session.upload_id, session.scratch_path, session.filename),
                    daemon=True,
                ).start()
                self._json(200, {"title": "ok", "description": "bundle accepted"})
                return

            self._error(404, f"No such endpoint: {path}")
        except UploadError as e:
            self._error(e.status, e.description)
        except Exception as e:  # noqa: BLE001
            self._error(500, f"{type(e).__name__}: {e}")

    def do_PUT(self) -> None:
        path = urlparse(self.path).path
        sub = subject_from_bearer(self.headers.get("Authorization"))
        parts = path.strip("/").split("/")
        try:
            if len(parts) == 5 and parts[:2] == ["enclave", "upload"] and parts[3] == "chunk":
                result = MANAGER.put_chunk(
                    sub, parts[2], int(parts[4]),
                    self._read_body(),
                    self.headers.get("X-Chunk-SHA256", ""),
                )
                self._json(200, result)
                return
            self._error(404, f"No such endpoint: {path}")
        except UploadError as e:
            self._error(e.status, e.description)
        except Exception as e:  # noqa: BLE001
            self._error(500, f"{type(e).__name__}: {e}")

    def do_DELETE(self) -> None:
        path = urlparse(self.path).path
        sub = subject_from_bearer(self.headers.get("Authorization"))
        parts = path.strip("/").split("/")
        try:
            if len(parts) == 3 and parts[:2] == ["enclave", "upload"]:
                MANAGER.delete(sub, parts[2])
                self._json(200, {"title": "ok", "description": "deleted"})
                return
            self._error(404, f"No such endpoint: {path}")
        except UploadError as e:
            self._error(e.status, e.description)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path, query = parsed.path, parse_qs(parsed.query)
        sub = subject_from_bearer(self.headers.get("Authorization"))
        parts = path.strip("/").split("/")

        try:
            if len(parts) == 4 and parts[:2] == ["enclave", "upload"] and parts[3] == "status":
                self._json(200, MANAGER.status(sub, parts[2]))
                return

            if path == "/enclave/status":
                with LOCK:
                    if not RUN_STATE:
                        self._json(200, {"status": "processing"})
                        return
                    run_id = max(RUN_STATE, key=lambda r: RUN_STATE[r].get("t", 0))
                    state = RUN_STATE[run_id]
                    out = OUTPUTS.get(run_id)
                if state["status"] != "success" or not out:
                    self._json(200, {"status": "processing"})
                    return
                self._json(200, {
                    "status": "success",
                    "outputs": {
                        "direct": {
                            "outputBlobUrl": f"mock://output/{run_id}",
                            "filename": out["filename"],
                            "bytes": out["bytes"],
                            "expires_at": out["expires_at"],
                        }
                    },
                })
                return

            if path == "/enclave/output/download":
                url = (query.get("url") or [""])[0]
                run_id = url.rsplit("/", 1)[-1]
                with LOCK:
                    out = OUTPUTS.get(run_id)
                if not out or not os.path.exists(out["path"]):
                    self._error(404, "That output is no longer available.")
                    return
                size = os.path.getsize(out["path"])
                self.send_response(200)
                self._cors()
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(size))
                self.send_header(
                    "Content-Disposition", f'attachment; filename="{out["filename"]}.enc"'
                )
                self.end_headers()
                with open(out["path"], "rb") as fh:
                    shutil.copyfileobj(fh, self.wfile, length=1 << 20)
                return

            if path == "/enclave/jwt" or path == "/enclave/jwt/fresh":
                # The UI normally extracts the enclave public key from MAA
                # attestation claims. For local dev, hand it over directly.
                self._json(200, {"public_key_pem": public_key_pem()})
                return

            if path == "/enclave/public-key":
                self._json(200, {"public_key_pem": public_key_pem()})
                return

            if path == "/enclave/dev/attestation":
                # Synthetic MAA claims in the real shape, so the UI's production
                # extractPublicKeyFromJwtClaims() path runs unchanged. The claim
                # value is base64(base64-DER-body), which is what the real
                # attestation service publishes.
                der_b64 = "".join(
                    line for line in public_key_pem().splitlines()
                    if not line.startswith("-----")
                )
                now = int(time.time())
                self._json(200, {
                    "iss": "http://localhost-mock-enclave",
                    "iat": now,
                    "exp": now + 3600,
                    "x-ms-runtime": {
                        "client-payload": {
                            "public key": base64.b64encode(der_b64.encode()).decode(),
                        }
                    },
                })
                return

            self._error(404, f"No such endpoint: {path}")
        except UploadError as e:
            self._error(e.status, e.description)
        except Exception as e:  # noqa: BLE001
            self._error(500, f"{type(e).__name__}: {e}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8787)
    args = ap.parse_args()

    print(f"[mock] scratch  : {SCRATCH}")
    print(f"[mock] listening: http://localhost:{args.port}")
    print("[mock] enclave public key (paste into the UI if attestation is stubbed):")
    print(public_key_pem())
    ThreadingHTTPServer(("0.0.0.0", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
