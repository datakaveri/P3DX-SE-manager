"""The TLS listener that receives data keys from the middleware.

This is the enclave half of RA-TLS. The middleware will not send a data key over
an ordinary channel, because ordinary TLS proves only that the peer holds a
private key for some certificate — and here there is no CA that could ever have
seen this key, since it is generated inside the enclave, per run, and never
leaves.

So the certificate *is* the attestation's subject. This server:

    1. serves TLS with a self-signed certificate for the per-run keypair
    2. on POST /enclave/attest, mints an MAA token carrying a nonce the
       middleware chose and this enclave's public key
    3. on POST /enclave/key, accepts the plaintext data key

The nonce the middleware sends is `sha256(channel binding)` of the TLS session
it is talking on. It never travels — both ends derive it independently from the
finished handshake. So a token minted here is usable only on the connection that
requested it, and an attacker who terminates TLS himself and relays a genuine
token from elsewhere presents one whose nonce belongs to a different session.

**Why the key arrives in the clear.** It is tempting to re-wrap it under the
enclave's public key. That would be pure ceremony: the channel is already
encrypted to a key only this enclave holds, and the middleware has already
proven the peer is this enclave. Re-wrapping would encrypt it under the same key
twice.

Runs on a thread inside the enclave manager rather than as its own service, so
it shares the process that owns the keypair and cannot drift out of step with
it. The chunk-upload receiver stays on plain HTTP: those chunks are already
AEAD-encrypted under the key being delivered here, and a second TLS layer around
100 MB of ciphertext buys nothing.
"""

from __future__ import annotations

import base64
import json
import os
import threading
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

import ssl

PORT = int(os.getenv("RATLS_PORT", "4443"))

#: Set by `serve()`. A dict of the handlers the enclave manager wants exposed,
#: so this module does not import the manager and create a cycle.
_HOOKS: dict = {}

MAX_BODY_BYTES = 64 * 1024


class RaTlsHandler(BaseHTTPRequestHandler):
    # HTTP/1.1, so the connection persists between the two requests a dispatch
    # makes. This is load-bearing rather than a performance choice: the
    # middleware attests the channel and then deposits the key on it, and the
    # binding that authenticates the deposit belongs to *this* TLS session. Under
    # HTTP/1.0 the default would close the socket after the attestation and the
    # deposit would arrive on an unverified new one.
    protocol_version = "HTTP/1.1"

    # Quiet: the default logs every request to stderr, and these requests are
    # about key material. Nothing here should end up in a log file by accident.
    def log_message(self, fmt, *args):
        pass

    def _reply(self, status: int, payload: dict):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY_BYTES:
            raise ValueError("missing or oversized request body")
        return json.loads(self.rfile.read(length))

    def do_POST(self):
        try:
            if self.path == "/enclave/attest":
                self._attest()
            elif self.path == "/enclave/key":
                self._receive_key()
            else:
                self._reply(404, {"error": "no such endpoint"})
        except ValueError as e:
            self._reply(400, {"error": str(e)})
        except Exception as e:
            # Deliberately terse to the caller. The detail goes to the enclave's
            # own output; a response to a request whose body was key material is
            # not a good place to echo internal state.
            traceback.print_exc()
            self._reply(500, {"error": type(e).__name__})

    def _attest(self):
        """Mint a token for the nonce the middleware derived from this channel."""
        nonce = self._body().get("nonce", "")
        if not isinstance(nonce, str) or not (16 <= len(nonce) <= 128):
            raise ValueError("nonce must be a 16-128 character string")

        token = _HOOKS["attest"](nonce)
        self._reply(200, {"maa_jwt": token})

    def _receive_key(self):
        body = self._body()
        job_id = body.get("job_id", "")
        if not isinstance(job_id, str) or not job_id:
            raise ValueError("job_id is required")

        try:
            data_key = base64.b64decode(body["data_key"], validate=True)
        except (KeyError, ValueError, TypeError) as e:
            raise ValueError(f"data_key must be base64: {e}") from e
        if len(data_key) != 32:
            raise ValueError("data_key must be 32 bytes (AES-256)")

        output_key = None
        if body.get("output_key"):
            output_key = base64.b64decode(body["output_key"], validate=True)
            if len(output_key) != 32:
                raise ValueError("output_key must be 32 bytes (AES-256)")

        _HOOKS["receive_key"](job_id, data_key, output_key)
        self._reply(200, {"status": "accepted"})


class _ThreadingHTTPSServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    # Without this a restart inside the TIME_WAIT window fails to bind, and the
    # enclave comes back up with no way to receive a key — silently, because
    # everything else about it looks healthy.
    allow_reuse_address = True


def serve(cert_path: str, key_path: str, attest, receive_key, port: int = PORT):
    """Start the listener on a daemon thread. Returns the server.

    `attest(nonce) -> jwt` and `receive_key(job_id, data_key, output_key)` are
    supplied by the enclave manager, which owns the keypair and the job state.
    """
    _HOOKS["attest"] = attest
    _HOOKS["receive_key"] = receive_key

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # TLS 1.2 is the floor, but 1.3 is what will actually be negotiated with the
    # middleware's client — and the RFC 9266 exporter binding both ends rely on
    # is only defined for 1.3 in the way this design uses it.
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)

    server = _ThreadingHTTPSServer(("0.0.0.0", port), RaTlsHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)

    thread = threading.Thread(target=server.serve_forever, name="ratls", daemon=True)
    thread.start()
    print(f"RA-TLS listener on :{port} using the per-run enclave key", flush=True)
    return server
