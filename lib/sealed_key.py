"""Keep the enclave's RSA private key across deploys without leaving it in the
clear on disk.

Why this exists. The enclave used to mint a fresh keypair on every
`/enclave/deploy`, so a key only had to survive one job and living as a plaintext
PEM was survivable. Under the job queue the browser wraps its data key for a
*specific* enclave public key, possibly minutes before that enclave is chosen, so
the keypair has to outlive deploys — and a long-lived plaintext PEM on a disk
that is only VMGuestState-encrypted is a standing exposure.

How it works. The TPM cannot seal an RSA-2048 PEM directly: `TPM2_Create` caps
sensitive data at MAX_SYM_DATA, typically 128 bytes, and a PEM is ~1.7 KB. So we
seal a 32-byte key-encryption key (KEK) to the vTPM under a PCR15 policy, and
keep the private key on disk as AES-256-GCM ciphertext under that KEK. Unsealing
the KEK requires PCR15 to hold the same value it had at seal time.

    keys/kek.pub, keys/kek.priv    TPM-sealed KEK (policy-bound to PCR15)
    keys/private_key.enc          AES-256-GCM(KEK, private_key_pem)
    keys/public_key.pem           plaintext; it is public

**What this does and does not buy.** It binds the private key to *this VM's
vTPM*: a stolen or copied disk is useless without it, which is the main win. It
is *not* a strong integrity guarantee against a local root attacker — PCR15 is a
software self-measurement extended by this very code, so an attacker who can
modify the enclave manager can also modify what gets measured, and one who is
already root can read the unsealed key out of memory regardless. The real root of
trust for what is running remains the SEV-SNP launch measurement and secure boot.
Treat PCR15 sealing as defence in depth, not as the boundary.

PCR15 and not PCR11: PCR15 is the enclave-manager code hash, deterministic
across reboots, so the key unseals after every cold start. PCR11 carries the
*application* image digest and changes on every deploy — sealing to it would make
the key unrecoverable the first time someone ran a different application.
"""

from __future__ import annotations

import base64
import os
import subprocess
import tempfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#: Set to "off" to keep an unsealed PEM on disk. Development and CI only — there
#: is no TPM in a container or on a laptop. Logs loudly, because a production
#: enclave running this way has a plaintext long-lived private key on disk.
SEALING_MODE = os.getenv("KEY_SEALING", "on").lower()

#: PCR the KEK's unseal policy is bound to.
POLICY_PCR = os.getenv("KEY_SEALING_PCR", "15")

TPM_TIMEOUT = int(os.getenv("TPM_COMMAND_TIMEOUT", "30"))


class SealingError(RuntimeError):
    pass


def enabled() -> bool:
    return SEALING_MODE != "off"


def _tpm(args: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a tpm2-tools command. sudo to match the rest of the SDK's TPM use."""
    try:
        result = subprocess.run(
            ["sudo", *args], capture_output=True, timeout=TPM_TIMEOUT, **kwargs
        )
    except FileNotFoundError as e:
        raise SealingError(f"tpm2-tools not installed: {e}") from e
    except subprocess.TimeoutExpired as e:
        raise SealingError(f"{args[0]} timed out after {TPM_TIMEOUT}s") from e
    if result.returncode != 0:
        stderr = (result.stderr or b"").decode(errors="replace").strip()
        raise SealingError(f"{args[0]} failed: {stderr or 'unknown error'}")
    return result


def _primary_context(workdir: str) -> str:
    """Create the owner-hierarchy primary key used as the sealing parent.

    Regenerated on demand rather than persisted: `tpm2_createprimary` with a
    fixed template is deterministic from the owner seed, so the same VM always
    derives the same parent. One less file to keep in sync with the sealed blobs.
    """
    path = os.path.join(workdir, "primary.ctx")
    _tpm(["tpm2_createprimary", "-C", "o", "-g", "sha256", "-G", "rsa", "-c", path])
    return path


def _policy_digest(workdir: str) -> str:
    """Compute the PCR policy digest that will gate unsealing."""
    session = os.path.join(workdir, "policy.session")
    digest = os.path.join(workdir, "policy.digest")
    _tpm(["tpm2_startauthsession", "-S", session])
    try:
        _tpm(["tpm2_policypcr", "-S", session,
              "-l", f"sha256:{POLICY_PCR}", "-L", digest])
    finally:
        # Sessions are a scarce TPM resource and leak across process exits.
        _flush(session)
    return digest


def _take_ownership(path: str, mode: int = 0o600) -> None:
    """Claim a file tpm2-tools created under sudo.

    Every TPM command runs via sudo, so its output files land owned by root and
    the service user cannot even chmod them. Hand them back before anything else
    touches them, or the next run fails with EPERM on its own key material.
    """
    _tpm(["chown", f"{os.getuid()}:{os.getgid()}", path])
    os.chmod(path, mode)


def _flush(session_path: str) -> None:
    try:
        _tpm(["tpm2_flushcontext", session_path])
    except SealingError:
        pass
    try:
        os.unlink(session_path)
    except OSError:
        pass


def seal(secret: bytes, pub_path: str, priv_path: str) -> None:
    """Seal `secret` to the vTPM, gated on the current PCR15 value."""
    if len(secret) > 128:
        raise SealingError(
            f"cannot seal {len(secret)} bytes; TPM2_Create caps sensitive data at 128"
        )
    with tempfile.TemporaryDirectory(prefix="seal-") as workdir:
        primary = _primary_context(workdir)
        policy = _policy_digest(workdir)
        secret_file = os.path.join(workdir, "secret.bin")
        with open(os.open(secret_file, os.O_WRONLY | os.O_CREAT, 0o600), "wb") as fh:
            fh.write(secret)
        # Dropping `userwithauth` is what forces the policy path: with it set,
        # the object could be unsealed with an empty password and PCR15 would
        # gate nothing.
        _tpm(["tpm2_create", "-C", primary, "-u", pub_path, "-r", priv_path,
              "-L", policy, "-i", secret_file,
              "-a", "fixedtpm|fixedparent|noda|adminwithpolicy"])
    _take_ownership(pub_path)
    _take_ownership(priv_path)


def unseal(pub_path: str, priv_path: str) -> bytes:
    """Recover a sealed secret. Fails if PCR15 has changed since sealing."""
    with tempfile.TemporaryDirectory(prefix="unseal-") as workdir:
        primary = _primary_context(workdir)
        loaded = os.path.join(workdir, "kek.ctx")
        _tpm(["tpm2_load", "-C", primary, "-u", pub_path, "-r", priv_path, "-c", loaded])

        session = os.path.join(workdir, "unseal.session")
        _tpm(["tpm2_startauthsession", "--policy-session", "-S", session])
        try:
            _tpm(["tpm2_policypcr", "-S", session, "-l", f"sha256:{POLICY_PCR}"])
            result = _tpm(["tpm2_unseal", "-p", f"session:{session}", "-c", loaded])
        finally:
            _flush(session)
    return result.stdout


# ── Private-key envelope ──────────────────────────────────────────────────────
#
# AES-256-GCM under the sealed KEK. Stored as a single file: 12-byte nonce then
# ciphertext-with-tag.

_NONCE_BYTES = 12


def wrap_private_key(pem: bytes, kek: bytes) -> bytes:
    nonce = os.urandom(_NONCE_BYTES)
    return nonce + AESGCM(kek).encrypt(nonce, pem, b"p3dx-enclave-private-key")


def unwrap_private_key(blob: bytes, kek: bytes) -> bytes:
    if len(blob) <= _NONCE_BYTES:
        raise SealingError("sealed private key file is truncated")
    nonce, ciphertext = blob[:_NONCE_BYTES], blob[_NONCE_BYTES:]
    try:
        return AESGCM(kek).decrypt(nonce, ciphertext, b"p3dx-enclave-private-key")
    except Exception as e:
        raise SealingError(f"private key failed to decrypt under the sealed KEK: {e}") from e


def seal_private_key(pem: bytes, kek_pub: str, kek_priv: str, enc_path: str) -> None:
    """Seal a fresh KEK and write the private key encrypted under it."""
    kek = AESGCM.generate_key(bit_length=256)
    try:
        seal(kek, kek_pub, kek_priv)
        blob = wrap_private_key(pem, kek)
        fd = os.open(enc_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with open(fd, "wb") as fh:
            fh.write(blob)
            fh.flush()
            os.fsync(fh.fileno())
    finally:
        # Best effort; CPython gives no way to actually scrub a bytes object.
        del kek


def load_private_key(kek_pub: str, kek_priv: str, enc_path: str) -> bytes:
    """Unseal the KEK and return the private key PEM. Never touches disk."""
    try:
        kek = unseal(kek_pub, kek_priv)
    except SealingError as e:
        # By far the most common cause, and the raw tpm2_unseal output says
        # nothing useful about it: the enclave-manager code changed, so PCR15
        # no longer holds the value the KEK was sealed against.
        #
        # This is the sealing policy doing its job, not a fault. But it is
        # operationally sharp — any edit to a measured file strands the key —
        # so name the cause and the remedy instead of leaving a TPM error code.
        raise SealingError(
            f"could not unseal the private key: {e}\n"
            f"  Most likely the enclave-manager code changed since the key was "
            f"sealed, so PCR{POLICY_PCR} no longer matches the sealing policy.\n"
            f"  A sealed key does not survive a code change by design. Recover by "
            f"regenerating: delete kek.pub, kek.priv and private_key.enc from the "
            f"keys directory, restart the service, and re-attest. Any data key a "
            f"browser already wrapped for the old public key becomes unusable, so "
            f"drain the node first."
        ) from e
    with open(enc_path, "rb") as fh:
        return unwrap_private_key(fh.read(), kek)


def tpm_available() -> bool:
    """Whether this host can seal at all — used to fail fast at startup with a
    clear message rather than at the first deploy."""
    if not enabled():
        return False
    try:
        _tpm(["tpm2_pcrread", f"sha256:{POLICY_PCR}"])
        return True
    except SealingError:
        return False
