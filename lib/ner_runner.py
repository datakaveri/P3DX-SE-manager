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
