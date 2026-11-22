"""NER TEE side: run skald-fta for one k-anon TEE's request.

Added 2026-11-22. Only active on a node started with NODE_ROLE=ner (the NER
confidential VM); every k-anon node ignores this module. The request arrives on
the RA-TLS listener, after the caller has attested this enclave and pinned its
TLS key, so the payload has crossed only an encrypted channel that ends inside
this enclave's memory.

One job at a time: the models take most of the VM's memory and a second
concurrent run would only slow both down. A request that arrives while one is
running gets NerBusy (HTTP 503), and the caller falls back to running
skald-fta locally.

Nothing persists. The payload, the container's input and its output live in a
work folder on the scratch tmpfs (RAM), removed in `finally` whatever happens.
The container runs with --network none: the models are baked into the image, so
the text has no way out except the reply.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import uuid

from lib.config import config

_lock = threading.Lock()


class NerBusy(RuntimeError):
    pass


class NerBadRequest(ValueError):
    pass


def _image() -> str:
    image = getattr(config.free_text_anonymization, "image", "")
    if not image:
        raise RuntimeError("config.yml declares no skald-fta image")
    return image


def _extract(payload: str, work: str) -> None:
    """config/<file> and data/<file> only, regular files, plain names."""
    with tarfile.open(payload, "r:gz") as tf:
        for m in tf.getmembers():
            parts = m.name.split("/")
            if (not m.isfile() or len(parts) != 2 or parts[0] not in ("config", "data")
                    or parts[1] in ("", ".", "..") or parts[1].startswith(".")):
                raise NerBadRequest(f"unexpected entry in the payload: {m.name!r}")
            with tf.extractfile(m) as src, open(os.path.join(work, *parts), "wb") as out:
                shutil.copyfileobj(src, out)


def _ram_dir() -> str | None:
    """Plaintext stays in memory: the scratch tmpfs, else /dev/shm."""
    for d in (getattr(config.paths, "scratch_dir", None), "/dev/shm"):
        if d and os.path.isdir(d):
            return d
    return None


def _remove(path: str) -> None:
    shutil.rmtree(path, ignore_errors=True)
    if os.path.exists(path):  # files the root container wrote
        subprocess.run(["sudo", "rm", "-rf", path], check=False, capture_output=True)


def run(payload_path: str, timeout: float | None = None) -> tuple[int, str]:
    """Run skald-fta over the payload. Returns (exit code, path of a tar.gz of
    everything it wrote to output/). The caller deletes the tar.gz."""
    if not _lock.acquire(blocking=False):
        raise NerBusy("a NER job is already running")
    scratch = _ram_dir()
    work = tempfile.mkdtemp(prefix="nerjob-", dir=scratch)
    name = f"ner-fta-{uuid.uuid4().hex[:12]}"
    try:
        for d in ("config", "data", "output"):
            os.makedirs(os.path.join(work, d))
        _extract(payload_path, work)
        if not os.listdir(os.path.join(work, "data")):
            raise NerBadRequest("the payload holds no data")
        timeout = timeout or float(getattr(config.free_text_anonymization, "timeout_seconds", 3600))
        cmd = [
            "docker", "run", "--rm", "--name", name, "--network", "none",
            "-v", f"{work}/config:/app/config:ro",
            "-v", f"{work}/data:/app/data",
            "-v", f"{work}/output:/app/output",
            _image(),
        ]
        print(f"NER job {name}: running skald-fta", flush=True)
        try:
            code = subprocess.run(cmd, stdout=sys.stdout, stderr=sys.stderr, timeout=timeout, check=False).returncode
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
            code = 124
        out = os.path.join(work, "output")
        # The container runs as root and leaves root-owned 0600 files; this
        # process (kanonTEE) has to read them to send them back.
        subprocess.run(["sudo", "chown", "-R", f"{os.getuid()}:{os.getgid()}", out],
                       check=False, capture_output=True)
        fd, result = tempfile.mkstemp(prefix="nerresult-", suffix=".tgz", dir=scratch)
        os.close(fd)
        with tarfile.open(result, "w:gz") as tf:
            for f in sorted(os.listdir(out)):
                path = os.path.join(out, f)
                if os.path.isfile(path) and not os.path.islink(path):
                    tf.add(path, arcname=f)
        print(f"NER job {name}: exit {code}", flush=True)
        return code, result
    finally:
        _remove(work)
        _lock.release()


# ── /ner/spans: the span service for DICOM (added 2026-11-23) ────────────────
#
# Kailash: DICOM should use the shared NER too, "on extracted text + if there
# are any remarks tags which need NER". The DICOM container masks text itself
# (boxes on the image, values in tags), so it needs WHERE the personal data
# is, not a rewritten file, and it asks once per DICOM file, so a model load
# per request (~8 s) would cost minutes per folder. One warm container
# therefore serves it: the same pinned skald-fta image, running
# lib/ner_service.py (measured into PCR15 with the rest of the code, mounted
# read-only), with --network none and only a Unix socket, on the scratch tmpfs,
# as its way in or out. It starts on the first request and lives as long as the
# VM (which the middleware deallocates after 15 idle minutes).
#
# It does not take the /ner/run lock: the two use separate containers and the
# VM has room for both, and a long FHIR job must not stall a DICOM batch.

import http.client
import json
import socket
import time

SPANS_CONTAINER = "ner-spans"
SPANS_READY_SECONDS = 240  # first start: container up + models loaded (~10 s measured)
MAX_SPANS_BYTES = 64 * 1024 * 1024
_spans_lock = threading.Lock()


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._path)
        self.sock = sock


def _unix_request(path: str, method: str, url: str, body: bytes | None, timeout: float):
    conn = _UnixHTTPConnection(path, timeout)
    try:
        conn.request(method, url, body=body, headers={"Content-Type": "application/json"} if body else {})
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def _spans_socket() -> str:
    base = _ram_dir() or "/dev/shm"
    return os.path.join(base, "ner-spans", "ner.sock")


def _spans_ready(sock_path: str) -> bool:
    try:
        status, raw = _unix_request(sock_path, "GET", "/health", None, 5)
        return status == 200 and bool(json.loads(raw).get("ready"))
    except Exception:
        return False


def _ensure_spans_service() -> str:
    """The socket of a running, model-loaded span service; started if needed."""
    sock_path = _spans_socket()
    if _spans_ready(sock_path):
        return sock_path
    with _spans_lock:
        if _spans_ready(sock_path):
            return sock_path
        sock_dir = os.path.dirname(sock_path)
        subprocess.run(["docker", "rm", "-f", SPANS_CONTAINER], capture_output=True, check=False)
        _remove(sock_dir)
        os.makedirs(sock_dir, mode=0o700)
        service = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ner_service.py")
        cmd = [
            "docker", "run", "-d", "--rm", "--name", SPANS_CONTAINER, "--network", "none",
            "-v", f"{sock_dir}:/sock",
            "-v", f"{service}:/svc/ner_service.py:ro",
            "--entrypoint", "python", _image(),
            "/svc/ner_service.py", "--serve-unix", "/sock/ner.sock",
        ]
        started = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if started.returncode != 0:
            raise RuntimeError(f"could not start the span service: {started.stderr.strip()[:300]}")
        print("NER span service: starting (models loading)", flush=True)
        deadline = time.monotonic() + SPANS_READY_SECONDS
        while time.monotonic() < deadline:
            if _spans_ready(sock_path):
                print("NER span service: ready", flush=True)
                return sock_path
            time.sleep(2)
        subprocess.run(["docker", "rm", "-f", SPANS_CONTAINER], capture_output=True, check=False)
        raise RuntimeError("the span service did not become ready")


def spans(body: bytes) -> tuple[int, bytes]:
    """Forward one POST /spans request (JSON, see lib/ner_service.py) to the
    span service. Returns (HTTP status, response body). The text is never
    logged or written to disk here."""
    if not body or len(body) > MAX_SPANS_BYTES:
        raise NerBadRequest("missing or oversized span request")
    try:
        json.loads(body)
    except ValueError as e:
        raise NerBadRequest(f"span request is not JSON: {e}") from e
    sock_path = _ensure_spans_service()
    return _unix_request(sock_path, "POST", "/spans", body, timeout=600)
