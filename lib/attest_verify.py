"""Verify another enclave's MAA attestation, from inside an enclave.

Added 2026-11-22 for the NER TEE: a k-anon TEE sends free text to a separate
NER TEE only after it has verified, itself, that the NER TEE is a genuine,
non-debuggable AMD SEV-SNP confidential VM running our code. This is the same
check the middleware's attest.py makes before it deposits a data key, ported
so it runs in the enclave's own Python environment, which has `cryptography`
but neither PyJWT nor pyOpenSSL. Installing packages into the production
enclave environment was ruled out: the current flow must not change.

What is checked, in order, failing closed:
  * the JWT signature, RS256/384/512 only, against the PINNED issuer's keys
    (never the token's own `jku`), plus issuer, expiry and not-before;
  * the guest is a genuine, azure-compliant, NON-debuggable SEV-SNP VM;
  * the nonce inside the signed client payload is the one the caller chose;
  * the enclave's public key, taken from inside the verified token;
  * identity against reference values, under a policy (see Policy).

Reference values and the policy (Kailash, 2026-11-22: "enforce our code and
images; log Azure's platform values", and "make sure the current flow doesn't
break"):
  * "pcr15" is the code measurement (P3DX_SDK.measure_enclave_manager_code_vtpm,
    deterministic since this change). Enforced when the policy says so.
  * "launch_measurement" and boot "pcrs" belong to Azure's firmware and our
    kernel. They change on Azure maintenance and kernel updates, so they are
    only ever logged.
  * mode "warn" logs a code mismatch instead of refusing. That is the rollout
    default; "enforce" is a separate later switch in config.yml.
"""

from __future__ import annotations

import base64
import hmac
import json
import os
import time
from dataclasses import dataclass, field

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

MAA_ISSUER = os.getenv("MAA_ISSUER", "https://sharedeus2.eus2.attest.azure.net")
JWKS_TTL_SECONDS = 3600
CLOCK_SKEW_SECONDS = 120
_HASHES = {"RS256": hashes.SHA256, "RS384": hashes.SHA384, "RS512": hashes.SHA512}
_jwks_cache: dict = {"keys": None, "at": 0.0}


class AttestationError(Exception):
    """The peer is not provably what it claims to be."""


@dataclass
class Policy:
    """What the caller expects of the peer, and how strictly."""

    pcr15: str = ""  # expected PCR15 (hex); empty = not published yet
    launch_measurement: str = ""  # logged only
    pcrs: dict = field(default_factory=dict)  # logged only
    mode: str = "warn"  # "warn" logs a code mismatch; "enforce" refuses


@dataclass
class Verified:
    public_key: str  # bare base64 DER SPKI, from inside the token
    pcr15: str
    launch_measurement: str
    nonce: str
    expires_at: int
    warnings: list


def _b64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64(s: str, what: str) -> bytes:
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4))
    except Exception as e:
        raise AttestationError(f"{what} is not valid base64: {e}") from e


def _hex(v: str) -> str:
    """PCR values come as "0xABC…" in tokens and bare "abc…" from tpm2 reads."""
    v = v.strip().lower()
    return v[2:] if v.startswith("0x") else v


def _same(a: str, b: str) -> bool:
    return hmac.compare_digest(_hex(a), _hex(b))


def _jwks(issuer: str) -> list:
    now = time.time()
    if _jwks_cache["keys"] is not None and now - _jwks_cache["at"] < JWKS_TTL_SECONDS:
        return _jwks_cache["keys"]
    url = f"{issuer.rstrip('/')}/certs"
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        keys = resp.json().get("keys") or []
    except Exception as e:
        raise AttestationError(f"could not fetch the issuer's keys from {url}: {e}") from e
    if not keys:
        raise AttestationError(f"{url} lists no keys")
    _jwks_cache.update(keys=keys, at=now)
    return keys


def _signing_key(kid: str, issuer: str):
    for entry in _jwks(issuer):
        if entry.get("kid") != kid:
            continue
        chain = entry.get("x5c") or []
        if not chain:
            raise AttestationError(f"issuer key {kid!r} has no certificate")
        return x509.load_der_x509_certificate(base64.b64decode(chain[0])).public_key()
    raise AttestationError(f"no key in the issuer's key set matches kid {kid!r}")


def _verified_claims(token: str, issuer: str) -> dict:
    if not isinstance(token, str) or token.count(".") != 2:
        raise AttestationError("not a well-formed JWT")
    head_b64, body_b64, sig_b64 = token.split(".")
    try:
        header = json.loads(_b64url(head_b64))
        claims = json.loads(_b64url(body_b64))
        signature = _b64url(sig_b64)
    except Exception as e:
        raise AttestationError(f"unreadable JWT: {e}") from e
    alg = header.get("alg")
    if alg not in _HASHES:  # blocks alg=none and HMAC confusion outright
        raise AttestationError(f"unacceptable signing algorithm {alg!r}")
    key = _signing_key(header.get("kid") or "", issuer)
    try:
        key.verify(signature, f"{head_b64}.{body_b64}".encode(), padding.PKCS1v15(), _HASHES[alg]())
    except Exception as e:
        raise AttestationError("JWT signature does not verify against the issuer's key") from e
    if claims.get("iss") != issuer:
        raise AttestationError(f"token issuer is {claims.get('iss')!r}, expected {issuer}")
    now = time.time()
    if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] + CLOCK_SKEW_SECONDS < now:
        raise AttestationError("token has expired or has no expiry")
    if isinstance(claims.get("nbf"), (int, float)) and claims["nbf"] - CLOCK_SKEW_SECONDS > now:
        raise AttestationError("token is not valid yet")
    return claims


def _check_isolation(claims: dict) -> dict:
    tee = claims.get("x-ms-isolation-tee")
    if not isinstance(tee, dict):
        raise AttestationError("token has no x-ms-isolation-tee claim; not a confidential VM")
    if tee.get("x-ms-attestation-type") != "sevsnpvm":
        raise AttestationError(f"attestation type is {tee.get('x-ms-attestation-type')!r}, expected 'sevsnpvm'")
    if tee.get("x-ms-compliance-status") != "azure-compliant-cvm":
        raise AttestationError(f"compliance status is {tee.get('x-ms-compliance-status')!r}")
    if tee.get("x-ms-sevsnpvm-is-debuggable") is True:
        raise AttestationError("the SNP guest is debuggable; its memory is not protected")
    return tee


def _payload(claims: dict) -> dict:
    payload = (claims.get("x-ms-runtime") or {}).get("client-payload")
    if not isinstance(payload, dict):
        raise AttestationError("token has no client-payload; the enclave published nothing")
    return payload


def _public_key(payload: dict) -> str:
    raw = payload.get("public key")
    if not raw:
        raise AttestationError("client-payload has no public key")
    inner = _b64(raw, "public key").decode("utf-8", "replace").strip()
    body = "".join(line for line in inner.splitlines() if not line.startswith("-----")).strip()
    if len(_b64(body, "public key body")) < 100:
        raise AttestationError("public key is too short to be an RSA SPKI")
    return body


def _pcr15(payload: dict) -> str:
    encoded = payload.get("tpm_values")
    if not encoded:
        return ""
    try:
        return str(json.loads(_b64(encoded, "tpm_values").decode("utf-8")).get("15") or "")
    except Exception:
        return ""


def verify(token: str, nonce: str, policy: Policy | None = None, issuer: str = MAA_ISSUER) -> Verified:
    """Verify `token` was minted just now, for `nonce`, by a genuine enclave
    running our code (as far as `policy` says). Raises AttestationError."""
    policy = policy or Policy()
    claims = _verified_claims(token, issuer)
    tee = _check_isolation(claims)
    payload = _payload(claims)

    raw_nonce = payload.get("nonce")
    seen = _b64(raw_nonce, "nonce").decode("utf-8", "replace").strip() if raw_nonce else ""
    if not seen or not hmac.compare_digest(seen, nonce):
        raise AttestationError("nonce mismatch: this attestation was not minted for this exchange")

    warnings = []
    pcr15 = _pcr15(payload)
    if policy.pcr15:
        if not pcr15 or not _same(pcr15, policy.pcr15):
            message = f"PCR15 {pcr15[:16] or 'missing'}… is not the published code measurement {policy.pcr15[:16]}…"
            if policy.mode == "enforce":
                raise AttestationError(message)
            warnings.append(message)
    else:
        warnings.append("no reference PCR15 published; the peer's code is not checked")
    launch = tee.get("x-ms-sevsnpvm-launchmeasurement", "")
    if policy.launch_measurement and not _same(launch, policy.launch_measurement):
        warnings.append("launch measurement differs from the reference (Azure firmware changes this; logged only)")
    actual_pcrs = claims.get("x-ms-azurevm-attested-pcr-values") or {}
    for name, want in (policy.pcrs or {}).items():
        if actual_pcrs.get(name) and not _same(str(actual_pcrs[name]), str(want)):
            warnings.append(f"{name} differs from the reference (boot state; logged only)")

    return Verified(
        public_key=_public_key(payload),
        pcr15=pcr15,
        launch_measurement=launch,
        nonce=seen,
        expires_at=int(claims["exp"]),
        warnings=warnings,
    )


def spki_b64_from_der_cert(der: bytes) -> str:
    """Bare base64 DER SPKI of a certificate, in the form enclaves publish."""
    from cryptography.hazmat.primitives import serialization

    cert = x509.load_der_x509_certificate(der)
    spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(spki).decode()
