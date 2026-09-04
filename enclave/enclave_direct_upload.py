"""
Reference implementation of the enclave side of direct dataset upload/download.

This is the authoritative definition of the wire crypto. The browser
(src/utils/cryptoUtils.ts + DatasetUploadWorker/) is written to match it exactly;
if the two ever disagree, the round-trip self-test at the bottom of this file
fails, which is the point of having it.

Drop this module into the enclave and wire the five upload handlers plus the
output writer to it. It has no framework dependency — only `cryptography`.

    pip install cryptography

Run the self-test:

    python3 enclave_direct_upload.py
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import struct
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import BinaryIO

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --------------------------------------------------------------------------- #
# Limits. Mirror src/environments/environments.ts -> direct_upload.
# Sized for Standard_DC2as_v5 (2 vCPU / 8 GiB / no local temp disk).
# --------------------------------------------------------------------------- #

MB = 1024 * 1024

CHUNK_SIZE = 64 * MB
MAX_CHUNKS = 16
MAX_CHUNK_BYTES = CHUNK_SIZE + 64          # ciphertext + GCM tag + slack
# Per-format caps, enforced independently of the middleware — this is the side
# that cannot be bypassed. csv/json/dicom carry the raised 300 MB cap; the
# reassembled dataset and the output container both live in the /enclave/scratch
# tmpfs, grown to 2 GiB in the same deploy to hold them. excel and image stay at
# 25 MB, bounded by browser preview memory, not the transport. Keep this table
# in step with the middleware's MAX_TOTAL_BYTES.
MAX_TOTAL_BYTES_BY_FORMAT = {
    "csv": 300 * MB,
    "json": 300 * MB,
    "excel": 25 * MB,
    "dicom": 300 * MB,
    "image": 25 * MB,
}
MAX_CONCURRENT_SESSIONS_PER_USER = 1
SESSION_TTL_SECONDS = 30 * 60
OUTPUT_TTL_SECONDS = 2 * 60 * 60

# A caller-supplied session id becomes a filename in the scratch directory, so it
# is constrained to a UUID and nothing else. The middleware only ever sends a
# job_id, which is a uuid4, so this costs nothing and closes a path-traversal
# write.
SESSION_ID_RE = re.compile(r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
                           r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")

# Scratch MUST be tmpfs. DC2as_v5 has no local temp disk, so RAM is the only
# storage inside the SEV-SNP encrypted-memory boundary. Mount it size-capped so a
# bug cannot exhaust enclave RAM:
#     mount -t tmpfs -o size=1G,noexec,nosuid,nodev tmpfs /enclave/scratch
SCRATCH_DIR = os.environ.get("ENCLAVE_SCRATCH_DIR", "/enclave/scratch")

OUTPUT_MAGIC = b"SPIDROU1"


class UploadError(Exception):
    """Maps to a 4xx response. `status` is the HTTP code to return."""

    def __init__(self, status: int, description: str):
        super().__init__(description)
        self.status = status
        self.description = description


# --------------------------------------------------------------------------- #
# Wire crypto — must stay byte-identical to the browser.
# --------------------------------------------------------------------------- #


def derive_chunk_nonce(base_iv: bytes, index: int) -> bytes:
    """
    Per-chunk nonce = base_iv as a big-endian 96-bit integer, plus index.

    Browser equivalent: deriveChunkNonce() in src/utils/cryptoUtils.ts.

    A fresh random key per upload plus a unique index means (key, nonce) is never
    reused, which is the one thing AES-GCM must never do.
    """
    if len(base_iv) != 12:
        raise ValueError(f"base IV must be 12 bytes, got {len(base_iv)}")
    return ((int.from_bytes(base_iv, "big") + index) % (1 << 96)).to_bytes(12, "big")


def chunk_aad(session_id: str, index: int, total_chunks: int) -> bytes:
    """
    Binds a chunk to its position and session, so reordering, splicing, dropping
    or replaying a chunk from another upload fails decryption rather than
    silently corrupting the reassembled file.

    Browser equivalent: chunkAad().
    """
    return f"{session_id}:{index}:{total_chunks}".encode("utf-8")


def chunk_digest_root(chunk_digests_hex: list[str]) -> str:
    """
    Whole-file commitment: SHA-256 over the concatenated RAW per-chunk digests,
    in index order.

    Not a plain SHA-256 of the file because WebCrypto has no streaming digest —
    hashing the file directly would force the browser into a second full read
    purely to hash. This falls out of the single encryption pass it already makes.

    Browser equivalent: chunkDigestRoot().
    """
    joined = b"".join(bytes.fromhex(h) for h in chunk_digests_hex)
    return hashlib.sha256(joined).hexdigest()


def unwrap_key(private_key: rsa.RSAPrivateKey, wrapped_b64: str) -> bytes:
    """RSA-OAEP-SHA256 unwrap of a 32-byte AES key. Same scheme the config
    bundle already uses, so no new key material or attestation claims."""
    raw = private_key.decrypt(
        base64.b64decode(wrapped_b64),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    if len(raw) != 32:
        raise UploadError(400, "Wrapped key did not decrypt to a 32-byte AES key")
    return raw


def decrypt_chunk(key: bytes, base_iv: bytes, session_id: str, index: int,
                  total_chunks: int, body: bytes) -> bytes:
    """Body is ciphertext || 16-byte GCM tag. Raises on any tampering."""
    return AESGCM(key).decrypt(
        derive_chunk_nonce(base_iv, index),
        body,
        chunk_aad(session_id, index, total_chunks),
    )


def encrypt_chunk(key: bytes, base_iv: bytes, session_id: str, index: int,
                  total_chunks: int, plaintext: bytes) -> bytes:
    """Returns ciphertext || 16-byte GCM tag."""
    return AESGCM(key).encrypt(
        derive_chunk_nonce(base_iv, index),
        plaintext,
        chunk_aad(session_id, index, total_chunks),
    )


# --------------------------------------------------------------------------- #
# Upload session manager
# --------------------------------------------------------------------------- #


@dataclass
class UploadSession:
    upload_id: str
    user_sub: str
    filename: str
    fmt: str
    total_bytes: int
    chunk_size: int
    total_chunks: int
    dataset_key: bytes
    base_iv: bytes
    output_key: bytes
    output_base_iv: bytes
    scratch_path: str
    created_at: float
    last_activity: float
    received: dict[int, str] = field(default_factory=dict)   # index -> plaintext sha256
    completed: bool = False

    def zeroise(self) -> None:
        # Python cannot reliably wipe an immutable bytes object; rebinding at
        # least drops the reference so it becomes collectable. Use a bytearray
        # here if your threat model needs a real wipe.
        self.dataset_key = b""


class UploadManager:
    """
    In-memory session store. Keys live here and are NEVER written to disk.

    Reassembly writes each decrypted chunk to a preallocated file at
    offset index*chunk_size rather than accumulating in RAM. That makes chunk
    re-PUT idempotent (just rewrite the offset), avoids realloc-and-copy growth,
    and is what makes resume work.
    """

    def __init__(self, private_key: rsa.RSAPrivateKey, scratch_dir: str = SCRATCH_DIR):
        self._private_key = private_key
        self._scratch_dir = scratch_dir
        self._sessions: dict[str, UploadSession] = {}
        self._lock = threading.Lock()
        os.makedirs(scratch_dir, exist_ok=True)

    # -- init ------------------------------------------------------------- #

    def init(self, user_sub: str, body: dict) -> dict:
        # The caller may name the session, because the browser encrypted these
        # chunks before any enclave was chosen and baked that name into every
        # chunk's AAD ("{session_id}:{index}:{total_chunks}"). Minting a fresh
        # uuid here instead would make every chunk fail its AEAD check, with no
        # error that points at the cause.
        #
        # Validated first, and constrained to a UUID, because it becomes a
        # filename in the scratch directory further down. Absent, we mint our
        # own, so a direct caller with no queue in front of it still works.
        session_id = body.get("session_id")
        if session_id is not None:
            if not isinstance(session_id, str) or not SESSION_ID_RE.match(session_id):
                raise UploadError(400, "session_id must be a UUID")
            with self._lock:
                if session_id in self._sessions:
                    raise UploadError(409, "That session_id is already in use")

        fmt = str(body.get("format", "")).lower()
        if fmt not in MAX_TOTAL_BYTES_BY_FORMAT:
            raise UploadError(400, f"Unsupported format '{fmt}'")

        if body.get("cipher") != "AES-256-GCM":
            raise UploadError(400, "Only AES-256-GCM is supported")
        if body.get("key_wrap") != "RSA-OAEP-SHA256":
            raise UploadError(400, "Only RSA-OAEP-SHA256 key wrapping is supported")

        total_bytes = int(body.get("total_bytes", 0))
        chunk_size = int(body.get("chunk_size", 0))
        total_chunks = int(body.get("total_chunks", 0))

        if total_bytes <= 0:
            raise UploadError(400, "total_bytes must be positive")
        if total_bytes > MAX_TOTAL_BYTES_BY_FORMAT[fmt]:
            raise UploadError(
                413,
                f"{fmt.upper()} uploads are limited to "
                f"{MAX_TOTAL_BYTES_BY_FORMAT[fmt] // MB} MB",
            )
        if chunk_size <= 0 or chunk_size > CHUNK_SIZE:
            raise UploadError(400, f"chunk_size must be between 1 and {CHUNK_SIZE}")
        if total_chunks != -(-total_bytes // chunk_size):
            raise UploadError(400, "total_chunks does not match total_bytes / chunk_size")
        if total_chunks > MAX_CHUNKS:
            raise UploadError(400, f"Too many chunks (max {MAX_CHUNKS})")

        with self._lock:
            self._sweep_locked()
            live = [s for s in self._sessions.values()
                    if s.user_sub == user_sub and not s.completed]
            if len(live) >= MAX_CONCURRENT_SESSIONS_PER_USER:
                raise UploadError(429, "An upload is already in progress for this user")

        # Unwrap immediately so a bad key fails before 100 MB is on the wire.
        dataset_key = unwrap_key(self._private_key, body["wrapped_key"])
        output_key = unwrap_key(self._private_key, body["output_wrapped_key"])
        base_iv = base64.b64decode(body["base_iv"])
        output_base_iv = base64.b64decode(body["output_base_iv"])
        if len(base_iv) != 12 or len(output_base_iv) != 12:
            raise UploadError(400, "base_iv and output_base_iv must be 12 bytes")

        upload_id = session_id or str(uuid.uuid4())
        scratch_path = os.path.join(self._scratch_dir, f"{upload_id}.bin")
        with open(scratch_path, "wb") as fh:
            fh.truncate(total_bytes)          # sparse preallocation
        os.chmod(scratch_path, 0o600)

        now = time.time()
        session = UploadSession(
            upload_id=upload_id,
            user_sub=user_sub,
            filename=os.path.basename(str(body.get("filename", "dataset"))),
            fmt=fmt,
            total_bytes=total_bytes,
            chunk_size=chunk_size,
            total_chunks=total_chunks,
            dataset_key=dataset_key,
            base_iv=base_iv,
            output_key=output_key,
            output_base_iv=output_base_iv,
            scratch_path=scratch_path,
            created_at=now,
            last_activity=now,
        )
        with self._lock:
            self._sessions[upload_id] = session

        return {
            "upload_id": upload_id,
            "expires_at": _iso(now + SESSION_TTL_SECONDS),
        }

    # -- chunk ------------------------------------------------------------ #

    def put_chunk(self, user_sub: str, upload_id: str, index: int,
                  body: bytes, declared_digest: str) -> dict:
        session = self._require(user_sub, upload_id)

        if not 0 <= index < session.total_chunks:
            raise UploadError(400, f"Chunk index {index} is out of range")
        if len(body) > MAX_CHUNK_BYTES:
            raise UploadError(413, "Chunk is larger than the negotiated chunk size")

        try:
            plaintext = decrypt_chunk(
                session.dataset_key, session.base_iv, upload_id,
                index, session.total_chunks, body,
            )
        except Exception:
            # Deliberately opaque: a padding/auth oracle is a real risk here.
            raise UploadError(400, f"Chunk {index} failed authentication")

        expected = session.chunk_size if index < session.total_chunks - 1 else (
            session.total_bytes - index * session.chunk_size
        )
        if len(plaintext) != expected:
            raise UploadError(400, f"Chunk {index} has unexpected length")

        digest = hashlib.sha256(plaintext).hexdigest()
        if declared_digest and digest != declared_digest.lower():
            raise UploadError(400, f"Chunk {index} does not match its declared digest")

        # Write at offset — idempotent, so a retried or resumed chunk simply
        # overwrites, and never an in-RAM accumulator.
        with open(session.scratch_path, "r+b") as fh:
            fh.seek(index * session.chunk_size)
            fh.write(plaintext)

        session.received[index] = digest
        session.last_activity = time.time()

        return {
            "index": index,
            "received_chunks": len(session.received),
            "total_chunks": session.total_chunks,
        }

    # -- status / complete ------------------------------------------------ #

    def status(self, user_sub: str, upload_id: str) -> dict:
        session = self._require(user_sub, upload_id)
        return {
            "received_chunks": sorted(session.received.keys()),
            "total_chunks": session.total_chunks,
            "expires_at": _iso(session.last_activity + SESSION_TTL_SECONDS),
        }

    def complete(self, user_sub: str, upload_id: str, digest_root: str) -> dict:
        """Verify the whole-file commitment and close the session.

        `digest_root` is the chunk digest root — SHA-256 over the concatenated
        raw per-chunk digests — not a SHA-256 of the plaintext. This parameter
        was called `plaintext_sha256` for a while, which described neither what
        callers sent nor what this compares it against.
        """
        session = self._require(user_sub, upload_id)

        missing = [i for i in range(session.total_chunks) if i not in session.received]
        if missing:
            raise UploadError(400, f"Missing chunks: {missing[:10]}")

        actual_size = os.path.getsize(session.scratch_path)
        if actual_size != session.total_bytes:
            raise UploadError(400, "Reassembled size does not match total_bytes")

        root = chunk_digest_root([session.received[i] for i in range(session.total_chunks)])
        if root != digest_root.lower():
            raise UploadError(400, "Reassembled dataset does not match the client checksum")

        session.completed = True
        session.zeroise()
        session.last_activity = time.time()

        return {
            "dataset_ref": f"enclave://upload/{upload_id}",
            "bytes": session.total_bytes,
            "sha256_verified": True,
        }

    def delete(self, user_sub: str, upload_id: str) -> None:
        session = self._require(user_sub, upload_id)
        self._destroy(session)

    # -- pipeline integration --------------------------------------------- #

    def resolve_dataset_ref(self, user_sub: str, dataset_ref: str) -> str:
        """
        Called when the bundle's decrypted blobUrl starts with enclave://upload/.

        The user_sub check is essential: without it, user A could reference user
        B's upload_id and read their data.
        """
        prefix = "enclave://upload/"
        if not dataset_ref.startswith(prefix):
            raise UploadError(400, "Not an enclave upload reference")
        upload_id = dataset_ref[len(prefix):]
        session = self._require(user_sub, upload_id)
        if not session.completed:
            raise UploadError(409, "That upload has not finished yet")
        return session.scratch_path

    def output_key_for(self, upload_id: str) -> tuple[bytes, bytes]:
        session = self._sessions.get(upload_id)
        if session is None:
            raise UploadError(404, "Unknown upload session")
        return session.output_key, session.output_base_iv

    def release(self, upload_id: str) -> None:
        """Call once the pipeline has loaded the dataset — do not hold scratch
        (which is RAM) for the duration of the run."""
        session = self._sessions.get(upload_id)
        if session is not None:
            _unlink(session.scratch_path)

    # -- housekeeping ------------------------------------------------------ #

    def _require(self, user_sub: str, upload_id: str) -> UploadSession:
        with self._lock:
            self._sweep_locked()
            session = self._sessions.get(upload_id)
        if session is None:
            raise UploadError(404, "Unknown or expired upload session")
        if session.user_sub != user_sub:
            # Same message as "not found" so the endpoint isn't an existence oracle.
            raise UploadError(404, "Unknown or expired upload session")
        return session

    def _sweep_locked(self) -> None:
        cutoff = time.time() - SESSION_TTL_SECONDS
        for upload_id, session in list(self._sessions.items()):
            if session.last_activity < cutoff:
                self._destroy(session)

    def _destroy(self, session: UploadSession) -> None:
        _unlink(session.scratch_path)
        session.zeroise()
        self._sessions.pop(session.upload_id, None)


# --------------------------------------------------------------------------- #
# Output container
# --------------------------------------------------------------------------- #


def write_output_container(
    src_path: str,
    dst: BinaryIO,
    *,
    run_id: str,
    output_key: bytes,
    output_base_iv: bytes,
    filename: str,
    content_type: str,
    chunk_size: int = CHUNK_SIZE,
) -> dict:
    """
    Encrypt the pipeline's result into the container the browser expects, then
    upload `dst` to blob storage.

    Layout (all integers big-endian):

        magic       8 bytes   b"SPIDROU1"
        header_len  4 bytes   uint32
        header      header_len bytes, UTF-8 JSON
        per chunk:  4 bytes   uint32 ciphertext length
                    N bytes   ciphertext || 16-byte GCM tag

    The header must be written BEFORE the chunks but contains per-chunk digests,
    so this makes two passes over the source file. At <=100 MB on tmpfs that is
    cheap; if you ever need one pass, move chunk_digests into a trailer and have
    the browser seek — but the current browser reader expects them up front.
    """
    total_bytes = os.path.getsize(src_path)
    total_chunks = max(1, -(-total_bytes // chunk_size))

    digests: list[str] = []
    with open(src_path, "rb") as fh:
        while True:
            block = fh.read(chunk_size)
            if not block:
                break
            digests.append(hashlib.sha256(block).hexdigest())
    if not digests:
        digests = [hashlib.sha256(b"").hexdigest()]

    header = {
        "filename": filename,
        "content_type": content_type,
        "total_bytes": total_bytes,
        "chunk_size": chunk_size,
        "total_chunks": total_chunks,
        "base_iv": base64.b64encode(output_base_iv).decode("ascii"),
        "chunk_digests": digests,
        "plaintext_sha256": chunk_digest_root(digests),
        "run_id": run_id,
    }
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")

    dst.write(OUTPUT_MAGIC)
    dst.write(struct.pack(">I", len(header_bytes)))
    dst.write(header_bytes)

    with open(src_path, "rb") as fh:
        for index in range(total_chunks):
            block = fh.read(chunk_size)
            ciphertext = encrypt_chunk(
                output_key, output_base_iv, run_id, index, total_chunks, block
            )
            dst.write(struct.pack(">I", len(ciphertext)))
            dst.write(ciphertext)

    return header


def read_output_container(src: BinaryIO, output_key: bytes) -> tuple[dict, bytes]:
    """Inverse of write_output_container — used by the self-test and useful for
    debugging a real output blob outside the browser."""
    if src.read(8) != OUTPUT_MAGIC:
        raise ValueError("Not a SPIDEr output container")
    (header_len,) = struct.unpack(">I", src.read(4))
    header = json.loads(src.read(header_len).decode("utf-8"))
    base_iv = base64.b64decode(header["base_iv"])

    out = io.BytesIO()
    digests: list[str] = []
    for index in range(header["total_chunks"]):
        (ct_len,) = struct.unpack(">I", src.read(4))
        plaintext = AESGCM(output_key).decrypt(
            derive_chunk_nonce(base_iv, index),
            src.read(ct_len),
            chunk_aad(header["run_id"], index, header["total_chunks"]),
        )
        digest = hashlib.sha256(plaintext).hexdigest()
        if header["chunk_digests"][index] != digest:
            raise ValueError(f"chunk {index} digest mismatch")
        digests.append(digest)
        out.write(plaintext)

    if chunk_digest_root(digests) != header["plaintext_sha256"]:
        raise ValueError("root digest mismatch")
    return header, out.getvalue()


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _iso(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def _unlink(path: str) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def load_private_key(pem_path: str) -> rsa.RSAPrivateKey:
    with open(pem_path, "rb") as fh:
        key = serialization.load_pem_private_key(fh.read(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("Expected an RSA private key")
    return key


# --------------------------------------------------------------------------- #
# Self-test: full upload -> reassemble -> anonymise -> output -> decrypt cycle.
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    import tempfile

    scratch = tempfile.mkdtemp(prefix="enclave-selftest-")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    manager = UploadManager(private_key, scratch_dir=scratch)

    def wrap(raw: bytes) -> str:
        return base64.b64encode(
            public_key.encrypt(
                raw,
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
            )
        ).decode("ascii")

    # A dataset spanning several chunks, with a deliberately odd tail.
    chunk = 64 * 1024
    payload = os.urandom(chunk * 3 + 1234)

    dataset_key, output_key = os.urandom(32), os.urandom(32)
    base_iv, output_base_iv = os.urandom(12), os.urandom(12)
    total_chunks = -(-len(payload) // chunk)

    init = manager.init(
        "user-123",
        {
            "filename": "patients.csv",
            "format": "csv",
            "total_bytes": len(payload),
            "chunk_size": chunk,
            "total_chunks": total_chunks,
            "cipher": "AES-256-GCM",
            "key_wrap": "RSA-OAEP-SHA256",
            "wrapped_key": wrap(dataset_key),
            "base_iv": base64.b64encode(base_iv).decode(),
            "output_wrapped_key": wrap(output_key),
            "output_base_iv": base64.b64encode(output_base_iv).decode(),
        },
    )
    upload_id = init["upload_id"]
    print(f"init            -> {upload_id}")

    digests = []
    for i in range(total_chunks):
        block = payload[i * chunk:(i + 1) * chunk]
        digests.append(hashlib.sha256(block).hexdigest())
        manager.put_chunk(
            "user-123", upload_id, i,
            encrypt_chunk(dataset_key, base_iv, upload_id, i, total_chunks, block),
            digests[-1],
        )
    print(f"chunks          -> {total_chunks} accepted")

    # Out-of-order and repeated chunks must be accepted (that is what makes
    # retry and resume work).
    manager.put_chunk(
        "user-123", upload_id, 0,
        encrypt_chunk(dataset_key, base_iv, upload_id, 0, total_chunks, payload[:chunk]),
        digests[0],
    )

    # A chunk replayed at the wrong index must be rejected by the AAD binding.
    try:
        manager.put_chunk(
            "user-123", upload_id, 1,
            encrypt_chunk(dataset_key, base_iv, upload_id, 0, total_chunks, payload[:chunk]),
            digests[0],
        )
        raise SystemExit("FAIL: a chunk replayed at the wrong index was accepted")
    except UploadError:
        print("AAD binding     -> misplaced chunk correctly rejected")

    # Another user must not be able to touch this session.
    try:
        manager.status("user-999", upload_id)
        raise SystemExit("FAIL: cross-user access was allowed")
    except UploadError:
        print("ownership       -> cross-user access correctly rejected")

    result = manager.complete("user-123", upload_id, chunk_digest_root(digests))
    print(f"complete        -> {result['dataset_ref']} ({result['bytes']} bytes)")

    src = manager.resolve_dataset_ref("user-123", result["dataset_ref"])
    assert open(src, "rb").read() == payload, "reassembled dataset differs from source"
    print("reassembly      -> byte-identical to the original")

    # Pipeline runs here; pretend it produced this.
    anonymised = os.path.join(scratch, "out.csv")
    with open(anonymised, "wb") as fh:
        fh.write(payload[: chunk * 2 + 77])

    okey, oiv = manager.output_key_for(upload_id)
    container = os.path.join(scratch, "out.enc")
    with open(container, "wb") as fh:
        header = write_output_container(
            anonymised, fh,
            run_id=upload_id, output_key=okey, output_base_iv=oiv,
            filename="patients_anonymised.csv", content_type="text/csv",
            chunk_size=chunk,
        )
    print(f"output          -> {header['total_chunks']} chunks, {header['total_bytes']} bytes")

    with open(container, "rb") as fh:
        _, recovered = read_output_container(fh, output_key)
    assert recovered == open(anonymised, "rb").read(), "output round trip differs"
    print("output round    -> byte-identical after decrypt")

    manager.release(upload_id)

    # ----------------------------------------------------------------------- #
    # Caller-supplied session id.
    #
    # Under the job queue the browser encrypts before any enclave is chosen, so
    # the AAD is bound to the middleware's job_id. If init mints its own id
    # instead, every chunk fails its AEAD check with nothing pointing at why —
    # which is exactly why this is tested rather than assumed.
    # ----------------------------------------------------------------------- #

    job_id = str(uuid.uuid4())
    small = os.urandom(4096)
    dkey, okey2 = os.urandom(32), os.urandom(32)
    div, oiv2 = os.urandom(12), os.urandom(12)

    init = manager.init("user-123", {
        "session_id": job_id,
        "filename": "queued.csv", "format": "csv",
        "total_bytes": len(small), "chunk_size": len(small), "total_chunks": 1,
        "cipher": "AES-256-GCM", "key_wrap": "RSA-OAEP-SHA256",
        "wrapped_key": wrap(dkey), "base_iv": base64.b64encode(div).decode(),
        "output_wrapped_key": wrap(okey2),
        "output_base_iv": base64.b64encode(oiv2).decode(),
    })
    if init["upload_id"] != job_id:
        raise SystemExit(f"FAIL: init minted {init['upload_id']} instead of adopting {job_id}")
    print(f"session_id      -> adopted {job_id}")

    # The decisive check: ciphertext whose AAD was sealed under job_id must
    # decrypt, which it only can if the enclave reconstructs the same AAD.
    digest = hashlib.sha256(small).hexdigest()
    manager.put_chunk("user-123", job_id, 0,
                      encrypt_chunk(dkey, div, job_id, 0, 1, small), digest)
    manager.complete("user-123", job_id, chunk_digest_root([digest]))
    assert open(manager.resolve_dataset_ref("user-123",
                f"enclave://upload/{job_id}"), "rb").read() == small
    print("session_id AAD  -> chunks sealed under job_id decrypt correctly")
    manager.release(job_id)

    for bad in ("../../etc/passwd", "not-a-uuid", "", "a" * 36):
        try:
            manager.init("user-123", {"session_id": bad, "format": "csv",
                                      "total_bytes": 1, "chunk_size": 1, "total_chunks": 1,
                                      "cipher": "AES-256-GCM", "key_wrap": "RSA-OAEP-SHA256"})
            raise SystemExit(f"FAIL: session_id {bad!r} was accepted")
        except UploadError:
            pass
    print("session_id       -> non-UUID ids rejected (they become filenames)")

    print("\nAll self-tests passed.")
