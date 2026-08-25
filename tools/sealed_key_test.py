"""Tests for the sealed-key envelope and the keypair lifecycle.

Run:  python3 tools/sealed_key_test.py

There is no TPM on a developer machine or in CI, so `seal`/`unseal` are stubbed
with an in-memory store that reproduces the one behaviour that matters: unsealing
succeeds only if the policy value (PCR15) matches what it was at seal time.
Everything above that line — the AES envelope, idempotent generation, rotation,
fingerprint stability — is exercised for real.

What this cannot test is whether the tpm2-tools invocations in lib/sealed_key.py
are correct. That needs hardware; `tools/tpm_seal_check.py` does it on the VM.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib import sealed_key  # noqa: E402


# ── A vTPM stand-in ───────────────────────────────────────────────────────────

class FakeTpm:
    """Seals to memory, gated on a policy value the test controls.

    Deliberately does NOT persist across instances, mirroring the real property
    that sealed blobs are useless on another machine's TPM.
    """

    def __init__(self):
        self.pcr15 = "0" * 64
        self._store: dict[str, tuple[str, bytes]] = {}

    def seal(self, secret: bytes, pub_path: str, priv_path: str) -> None:
        if len(secret) > 128:
            raise sealed_key.SealingError("sensitive data exceeds 128 bytes")
        handle = os.path.basename(pub_path)
        self._store[handle] = (self.pcr15, secret)
        for path in (pub_path, priv_path):
            with open(os.open(path, os.O_WRONLY | os.O_CREAT, 0o600), "wb") as fh:
                fh.write(handle.encode())

    def unseal(self, pub_path: str, priv_path: str) -> bytes:
        handle = os.path.basename(pub_path)
        if handle not in self._store:
            raise sealed_key.SealingError("no such sealed object")
        sealed_at, secret = self._store[handle]
        if sealed_at != self.pcr15:
            raise sealed_key.SealingError("policy check failed: PCR15 has changed")
        return secret


def install_fake_tpm() -> FakeTpm:
    tpm = FakeTpm()
    sealed_key.seal = tpm.seal
    sealed_key.unseal = tpm.unseal
    sealed_key.tpm_available = lambda: True
    return tpm


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_envelope_round_trip():
    kek = os.urandom(32)
    pem = b"-----BEGIN RSA PRIVATE KEY-----\n" + os.urandom(1200) + b"\n-----END-----\n"
    blob = sealed_key.wrap_private_key(pem, kek)
    assert blob != pem, "the envelope must not store the key in the clear"
    assert sealed_key.unwrap_private_key(blob, kek) == pem
    print("envelope           -> round trip byte-identical")


def test_envelope_rejects_wrong_kek():
    pem = b"secret-key-material"
    blob = sealed_key.wrap_private_key(pem, os.urandom(32))
    try:
        sealed_key.unwrap_private_key(blob, os.urandom(32))
    except sealed_key.SealingError:
        print("envelope           -> wrong KEK rejected")
        return
    raise SystemExit("FAIL: the envelope opened under the wrong KEK")


def test_envelope_detects_tampering():
    """AES-GCM, not AES-CBC: a flipped bit must fail, not decrypt to garbage."""
    kek = os.urandom(32)
    blob = bytearray(sealed_key.wrap_private_key(b"secret-key-material", kek))
    blob[-1] ^= 0x01
    try:
        sealed_key.unwrap_private_key(bytes(blob), kek)
    except sealed_key.SealingError:
        print("envelope           -> tampered ciphertext rejected")
        return
    raise SystemExit("FAIL: tampered ciphertext was accepted")


def test_seal_and_load(tmp: str, tpm: FakeTpm):
    tpm.pcr15 = "a" * 64
    pem = b"-----BEGIN RSA PRIVATE KEY-----\n" + os.urandom(1200) + b"\n-----END-----\n"
    pub, priv, enc = (os.path.join(tmp, n) for n in ("kek.pub", "kek.priv", "pk.enc"))

    sealed_key.seal_private_key(pem, pub, priv, enc)
    assert pem not in open(enc, "rb").read(), "private key found in the clear on disk"
    assert oct(os.stat(enc).st_mode)[-3:] == "600", "sealed key file is not 0600"
    assert sealed_key.load_private_key(pub, priv, enc) == pem
    print("seal               -> private key recovered, absent from disk in clear")


def test_pcr_change_blocks_unseal(tmp: str, tpm: FakeTpm):
    """The property sealing exists for: a machine whose measured code changed
    cannot recover the key."""
    tpm.pcr15 = "b" * 64
    pem = b"private-key-pem"
    pub, priv, enc = (os.path.join(tmp, n) for n in ("k2.pub", "k2.priv", "pk2.enc"))
    sealed_key.seal_private_key(pem, pub, priv, enc)
    assert sealed_key.load_private_key(pub, priv, enc) == pem

    tpm.pcr15 = "c" * 64  # code changed -> PCR15 differs
    try:
        sealed_key.load_private_key(pub, priv, enc)
    except sealed_key.SealingError:
        print("seal               -> PCR15 change blocks unseal")
        return
    raise SystemExit("FAIL: the key unsealed after PCR15 changed")


def test_kek_fits_the_tpm_limit():
    """Why there is a KEK at all: TPM2_Create caps sensitive data at 128 bytes,
    so an RSA-2048 PEM (~1.7 KB) cannot be sealed directly."""
    pem = b"x" * 1700
    try:
        sealed_key.seal(pem, "/dev/null", "/dev/null")
    except sealed_key.SealingError:
        print("seal               -> oversized payload correctly refused")
        return
    raise SystemExit("FAIL: a 1700-byte payload was accepted for sealing")


def test_keypair_lifecycle(tmp: str, tpm: FakeTpm):
    """Idempotent generation, stable fingerprint, and rotation that changes it."""
    tpm.pcr15 = "d" * 64
    os.environ["BASE_DIR"] = tmp
    for name in ("lib.config", "P3DX_SDK"):
        sys.modules.pop(name, None)

    from lib.config import get_config
    import lib.config as config_module
    config_module.config = get_config()

    import P3DX_SDK
    P3DX_SDK.sealed_key = sealed_key

    assert not P3DX_SDK.keypair_exists()
    P3DX_SDK.generate_and_save_key_pair()
    assert P3DX_SDK.keypair_exists()

    first = P3DX_SDK.public_key_fingerprint()
    assert len(first) == 64

    # The reason this matters: a deploy used to destroy the keypair, which would
    # invalidate every data key the browser had wrapped for this enclave.
    P3DX_SDK.generate_and_save_key_pair()
    assert P3DX_SDK.public_key_fingerprint() == first, \
        "a second call rotated the key; wrapped data keys would be invalidated"
    print("lifecycle          -> generation is idempotent, fingerprint stable")

    # The public key file's exact shape is load-bearing: the attestation client
    # base64s it into the token payload and the browser re-armours it as PEM. A
    # stray marker or newline yields a PEM the browser cannot import, and the
    # only symptom is an encryption failure in the UI with nothing pointing here.
    raw = open(P3DX_SDK.config.get_path('public_key')).read()
    assert "-----" not in raw, f"public key file contains PEM markers: {raw[-40:]!r}"
    assert "\n" not in raw.strip(), "public key file must be a single line"
    import base64 as _b64
    der = _b64.b64decode(raw.strip(), validate=True)  # raises if not clean base64
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    load_der_public_key(der)  # raises unless it is a real SPKI
    assert _b64.b64encode(der).decode() == raw.strip()
    print("lifecycle          -> public key is bare single-line base64 DER")

    pem = P3DX_SDK.load_enclave_private_key_pem()
    assert b"PRIVATE KEY" in pem
    assert not os.path.exists(P3DX_SDK.config.get_path('private_key')), \
        "a plaintext private_key.pem exists alongside the sealed one"
    print("lifecycle          -> private key unseals; no plaintext PEM on disk")

    second = P3DX_SDK.rotate_key_pair()
    assert second != first, "rotation did not change the key"
    assert P3DX_SDK.load_key_generation()["generation"] == 1
    print("lifecycle          -> rotation changes the fingerprint")

    # A key sealed before rotation must not open after it, or rotation would be
    # cosmetic.
    tpm.pcr15 = "e" * 64
    try:
        P3DX_SDK.load_enclave_private_key_pem()
    except sealed_key.SealingError:
        print("lifecycle          -> post-rotation key still bound to PCR15")
        return
    raise SystemExit("FAIL: key unsealed under a changed PCR15 after rotation")


if __name__ == "__main__":
    tmp = tempfile.mkdtemp(prefix="sealed-key-test-")
    try:
        tpm = install_fake_tpm()
        test_envelope_round_trip()
        test_envelope_rejects_wrong_kek()
        test_envelope_detects_tampering()
        test_kek_fits_the_tpm_limit()
        test_seal_and_load(tmp, tpm)
        test_pcr_change_blocks_unseal(tmp, tpm)
        test_keypair_lifecycle(os.path.join(tmp, "base"), tpm)
        print("\nAll sealed-key tests passed.")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
