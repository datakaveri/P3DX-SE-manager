#!/usr/bin/env python3
"""
End-to-end smoke test against the mock enclave (tools/mock_enclave.py).

Drives the full protocol exactly as the browser worker does — init, chunk PUTs,
status, complete, bundle, poll, download, decrypt — and asserts the bytes that
come back match what went in.

    python3 tools/mock_enclave.py --port 8787 &
    python3 tools/e2e_smoke.py --port 8787
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "enclave"))

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding  # noqa: E402

from enclave_direct_upload import (  # noqa: E402
    chunk_digest_root,
    encrypt_chunk,
    read_output_container,
)

TOKEN = "Bearer " + ".".join([
    base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("="),
    base64.urlsafe_b64encode(b'{"sub":"smoke-user"}').decode().rstrip("="),
    "sig",
])


def request(method: str, url: str, body: bytes | None = None,
            headers: dict | None = None) -> tuple[int, bytes, dict]:
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Authorization", TOKEN)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req) as res:
            return res.status, res.read(), dict(res.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--size", type=int, default=300_000)
    ap.add_argument("--chunk", type=int, default=131_072)
    args = ap.parse_args()
    base = f"http://localhost:{args.port}"

    status, body, _ = request("GET", f"{base}/enclave/public-key")
    assert status == 200, body
    public_key = serialization.load_pem_public_key(
        json.loads(body)["public_key_pem"].encode()
    )

    payload = bytes((i * 37 + 11) & 0xFF for i in range(args.size))
    dataset_key, output_key = os.urandom(32), os.urandom(32)
    base_iv, output_base_iv = os.urandom(12), os.urandom(12)
    total_chunks = -(-len(payload) // args.chunk)

    def wrap(raw: bytes) -> str:
        return base64.b64encode(public_key.encrypt(
            raw,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )).decode()

    status, body, _ = request(
        "POST", f"{base}/enclave/upload/init",
        json.dumps({
            "filename": "smoke.csv",
            "format": "csv",
            "content_type": "text/csv",
            "total_bytes": len(payload),
            "chunk_size": args.chunk,
            "total_chunks": total_chunks,
            "cipher": "AES-256-GCM",
            "key_wrap": "RSA-OAEP-SHA256",
            "wrapped_key": wrap(dataset_key),
            "base_iv": base64.b64encode(base_iv).decode(),
            "output_wrapped_key": wrap(output_key),
            "output_base_iv": base64.b64encode(output_base_iv).decode(),
        }).encode(),
        {"Content-Type": "application/json"},
    )
    assert status == 201, (status, body)
    upload_id = json.loads(body)["upload_id"]
    print(f"init      -> {upload_id} ({total_chunks} chunks)")

    digests = []
    for i in range(total_chunks):
        block = payload[i * args.chunk:(i + 1) * args.chunk]
        digest = hashlib.sha256(block).hexdigest()
        digests.append(digest)
        status, body, _ = request(
            "PUT", f"{base}/enclave/upload/{upload_id}/chunk/{i}",
            encrypt_chunk(dataset_key, base_iv, upload_id, i, total_chunks, block),
            {"Content-Type": "application/octet-stream", "X-Chunk-SHA256": digest},
        )
        assert status == 200, (status, body)
    print(f"chunks    -> {total_chunks} accepted")

    status, body, _ = request("GET", f"{base}/enclave/upload/{upload_id}/status")
    assert status == 200 and len(json.loads(body)["received_chunks"]) == total_chunks
    print("status    -> all chunks accounted for")

    # A tampered chunk must be rejected.
    bad = bytearray(encrypt_chunk(dataset_key, base_iv, upload_id, 0, total_chunks,
                                  payload[:args.chunk]))
    bad[10] ^= 0xFF
    status, _, _ = request(
        "PUT", f"{base}/enclave/upload/{upload_id}/chunk/0", bytes(bad),
        {"Content-Type": "application/octet-stream", "X-Chunk-SHA256": digests[0]},
    )
    assert status == 400, f"tampered chunk was accepted (status {status})"
    print("tamper    -> corrupted chunk correctly rejected")

    status, body, _ = request(
        "POST", f"{base}/enclave/upload/{upload_id}/complete",
        json.dumps({"plaintext_sha256": chunk_digest_root(digests)}).encode(),
        {"Content-Type": "application/json"},
    )
    assert status == 200, (status, body)
    print(f"complete  -> {json.loads(body)['dataset_ref']}")

    # A wrong root must be rejected.
    status, _, _ = request(
        "POST", f"{base}/enclave/upload/{upload_id}/complete",
        json.dumps({"plaintext_sha256": "00" * 32}).encode(),
        {"Content-Type": "application/json"},
    )
    assert status == 400, "a bad root digest was accepted"
    print("checksum  -> wrong root correctly rejected")

    status, body, _ = request(
        "POST", f"{base}/enclave/bundle/upload", b"{}", {"Content-Type": "application/json"}
    )
    assert status == 200, (status, body)
    print("bundle    -> accepted, pipeline running")

    output = None
    for _ in range(40):
        time.sleep(1)
        status, body, _ = request("GET", f"{base}/enclave/status")
        state = json.loads(body)
        if state.get("status") == "success":
            output = state["outputs"]["direct"]
            break
    assert output, "pipeline did not finish in time"
    print(f"poll      -> success ({output['filename']}, {output['bytes']} bytes)")

    url = urllib.parse.quote(output["outputBlobUrl"], safe="")
    status, container, _ = request("GET", f"{base}/enclave/output/download?url={url}")
    assert status == 200, (status, container)

    header, recovered = read_output_container(io.BytesIO(container), output_key)
    assert recovered == payload, "decrypted output does not match the original"
    print(f"download  -> decrypted {len(recovered)} bytes, integrity verified")

    # A wrong key must fail, not silently produce garbage.
    try:
        read_output_container(io.BytesIO(container), os.urandom(32))
        print("\nFAILED: output decrypted with the wrong key")
        return 1
    except Exception:
        print("wrong key -> correctly refused to decrypt")

    print("\nEnd-to-end smoke test passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
