#!/usr/bin/env python3
"""
Verifies that the enclave reference implementation can decrypt vectors produced
by the browser's real crypto helpers, and vice versa.

    bun run tools/crypto-interop-emit.ts > /tmp/vectors.json
    python3 tools/crypto_interop_verify.py /tmp/vectors.json

Exits non-zero on any mismatch.
"""

import base64
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "enclave"))

from enclave_direct_upload import (  # noqa: E402
    chunk_aad,
    chunk_digest_root,
    decrypt_chunk,
    derive_chunk_nonce,
    encrypt_chunk,
)


def b64d(value: str) -> bytes:
    return base64.b64decode(value)


def main(path: str) -> int:
    with open(path) as fh:
        v = json.load(fh)

    key = b64d(v["key"])
    base_iv = b64d(v["base_iv"])
    payload = b64d(v["payload"])
    session_id = v["session_id"]
    total_chunks = v["total_chunks"]
    failures = []

    # 1. Nonce derivation must agree exactly, including across byte carries.
    carry_iv = b"\xff" * 12
    for case in v["nonce_carry_vectors"]:
        expected = b64d(case["nonce"])
        actual = derive_chunk_nonce(carry_iv, case["index"])
        if expected != actual:
            failures.append(
                f"nonce[{case['index']}]: browser {expected.hex()} != enclave {actual.hex()}"
            )
    print(f"nonce derivation  -> {len(v['nonce_carry_vectors'])} vectors checked")

    # 2. AAD strings must agree byte-for-byte.
    for c in v["chunks"]:
        expected = c["aad"].encode()
        actual = chunk_aad(session_id, c["index"], total_chunks)
        if expected != actual:
            failures.append(f"aad[{c['index']}]: {expected!r} != {actual!r}")
    print(f"AAD encoding      -> {len(v['chunks'])} chunks checked")

    # 3. The enclave must decrypt what the browser encrypted.
    recovered = bytearray()
    digests = []
    for c in v["chunks"]:
        plaintext = decrypt_chunk(
            key, base_iv, session_id, c["index"], total_chunks, b64d(c["ciphertext"])
        )
        digest = hashlib.sha256(plaintext).hexdigest()
        if digest != c["digest"]:
            failures.append(f"digest[{c['index']}]: browser {c['digest']} != enclave {digest}")
        digests.append(digest)
        recovered.extend(plaintext)

    if bytes(recovered) != payload:
        failures.append("reassembled payload differs from the browser's original")
    print(f"browser -> enclave -> {len(payload)} bytes decrypted and reassembled")

    # 4. Root commitment must agree.
    root = chunk_digest_root(digests)
    if root != v["plaintext_sha256"]:
        failures.append(f"root digest: browser {v['plaintext_sha256']} != enclave {root}")
    print("root commitment   -> matches")

    # 5. And the reverse direction — what the enclave encrypts for the output
    #    container must be decryptable with the same parameters.
    for c in v["chunks"]:
        start = c["index"] * v["chunk_size"]
        block = payload[start:start + v["chunk_size"]]
        round_trip = decrypt_chunk(
            key, base_iv, session_id, c["index"], total_chunks,
            encrypt_chunk(key, base_iv, session_id, c["index"], total_chunks, block),
        )
        if round_trip != block:
            failures.append(f"enclave round trip failed on chunk {c['index']}")
    print("enclave -> browser -> round trip matches")

    if failures:
        print("\nFAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1

    print("\nBrowser and enclave crypto agree byte-for-byte.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/vectors.json"))
