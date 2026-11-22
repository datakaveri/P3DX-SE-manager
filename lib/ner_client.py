"""Run the skald-fta (NER) stage on the NER TEE instead of locally.

Added 2026-11-22. Kailash's design: a sixth confidential VM, booted only when a
job needs NER, holds the NER models; the k-anon TEE that runs the job attests
it and sends it the free text over RA-TLS. Two rules shape everything here:

1. **The current flow must not break.** Every failure (NER TEE off, still
   booting past the wait, attestation refused, an error, a malformed reply)
   raises NerUnavailable before a single file is written to output/, and the
   caller then runs skald-fta locally exactly as before. Falling back is also
   the safe direction for privacy: the text simply never leaves this enclave.

2. **Only what NER needs crosses.** For a CSV input, only the free-text columns
   (plus a row number) are sent, and the cleaned columns are merged back here
   into the original file. A FHIR Bundle is sent whole: skald-fta's FHIR mode
   uses the bundle's own names and identifiers to find them in the text.

The channel: TLS to the NER TEE's RA-TLS listener, which presents a
self-signed certificate for its per-run key. Before anything is sent:
  * POST /enclave/attest with a fresh random nonce we choose;
  * verify the MAA token (lib/attest_verify: signature, issuer, genuine
    non-debuggable SEV-SNP, the nonce, the code measurement under the policy);
  * check the certificate's public key IS the key inside the verified token.
Only the attested enclave holds that private key, so only it can have
completed this TLS session. (The middleware additionally binds the nonce to
the TLS exporter; that needs pyOpenSSL, which this environment does not have.
With a fresh nonce plus the key pin, a relay cannot read or alter the text.)
"""

from __future__ import annotations

import csv
import hashlib
import http.client
import io
import json
import os
import secrets
import shutil
import socket
import ssl
import sys
import tarfile
import tempfile
import time

from lib import attest_verify
from lib.config import config

ROW_KEY = "__anamika_ner_row"


class NerUnavailable(RuntimeError):
    """The NER TEE could not be used; the caller runs skald-fta locally."""


def _setting(name, default=None):
    return getattr(getattr(config, "ner_tee", None), name, default)


def remote_enabled() -> bool:
    return bool(_setting("enabled", False)) and bool(_setting("host"))


def _policy() -> attest_verify.Policy:
    ref = _setting("reference", {}) or {}
    return attest_verify.Policy(
        pcr15=str(ref.get("pcr15") or ""),
        launch_measurement=str(ref.get("launch_measurement") or ""),
        pcrs=dict(ref.get("pcrs") or {}),
        mode=str(_setting("attestation_mode", "warn")),
    )


# ── payload ──────────────────────────────────────────────────────────────────


def _single_csv(data_dir: str):
    names = [n for n in os.listdir(data_dir) if os.path.isfile(os.path.join(data_dir, n))]
    return os.path.join(data_dir, names[0]) if len(names) == 1 and names[0].lower().endswith(".csv") else None


def _reduced_csv(src: str, columns: list, dest: str) -> list:
    """Write only the free-text columns (plus a row number) of `src` to `dest`.
    Returns the columns found. Raises ValueError when the file can't be read
    as UTF-8 CSV with those columns: the caller then sends the file whole."""
    csv.field_size_limit(sys.maxsize)
    with open(src, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        idx = [header.index(c) for c in columns if c in header]
        if not idx:
            raise ValueError("none of the free-text columns are in the file")
        with open(dest, "w", newline="", encoding="utf-8") as out:
            w = csv.writer(out)
            w.writerow([ROW_KEY] + [header[i] for i in idx])
            for n, row in enumerate(reader):
                w.writerow([n] + [row[i] if i < len(row) else "" for i in idx])
    return [header[i] for i in idx]


def _merge_csv(original: str, cleaned: str, dest: str) -> None:
    """The original CSV with its free-text columns replaced by the cleaned ones."""
    csv.field_size_limit(sys.maxsize)
    with open(cleaned, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        head = next(reader)
        if not head or head[0] != ROW_KEY:
            raise NerUnavailable("the cleaned file has no row numbers")
        cols = head[1:]
        cleaned_rows = {int(r[0]): r[1:] for r in reader if r}
    with open(original, newline="", encoding="utf-8") as f, open(dest, "w", newline="", encoding="utf-8") as out:
        reader = csv.reader(f)
        header = next(reader)
        pos = [header.index(c) for c in cols]
        w = csv.writer(out)
        w.writerow(header)
        for n, row in enumerate(reader):
            if n not in cleaned_rows:
                raise NerUnavailable(f"the cleaned file is missing row {n}")
            row = list(row) + [""] * (len(header) - len(row))
            for p, value in zip(pos, cleaned_rows[n]):
                row[p] = value
            w.writerow(row)


def _build_payload(fta_config_dir: str, data_dir: str, block: dict, work: str):
    """tar.gz of config/ and data/ for the NER TEE. Returns (path, reduced_from)."""
    reduced_from = None
    stage = os.path.join(work, "send")
    os.makedirs(os.path.join(stage, "data"))
    shutil.copytree(fta_config_dir, os.path.join(stage, "config"))
    src = _single_csv(data_dir)
    columns = block.get("columns") or []
    if src and columns:
        try:
            _reduced_csv(src, list(columns), os.path.join(stage, "data", os.path.basename(src)))
            reduced_from = src
        except (ValueError, UnicodeDecodeError, StopIteration) as e:
            print(f"NER TEE: sending the input whole ({e})", flush=True)
            shutil.rmtree(os.path.join(stage, "data"))
            os.makedirs(os.path.join(stage, "data"))
    if reduced_from is None:
        for name in os.listdir(data_dir):
            path = os.path.join(data_dir, name)
            if os.path.isfile(path):
                shutil.copy2(path, os.path.join(stage, "data", name))
    payload = os.path.join(work, "payload.tgz")
    with tarfile.open(payload, "w:gz") as tf:
        for top in ("config", "data"):
            for name in sorted(os.listdir(os.path.join(stage, top))):
                tf.add(os.path.join(stage, top, name), arcname=f"{top}/{name}")
    shutil.rmtree(stage)
    return payload, reduced_from


def _safe_extract(tgz: str, dest: str) -> list:
    """Regular files with plain names only; nothing else is accepted back."""
    names = []
    with tarfile.open(tgz, "r:gz") as tf:
        for m in tf.getmembers():
            name = m.name
            if not m.isfile() or "/" in name or name in ("", ".", "..") or name.startswith("."):
                raise NerUnavailable(f"refusing an unexpected entry in the NER reply: {name!r}")
            with tf.extractfile(m) as src, open(os.path.join(dest, name), "wb") as out:
                shutil.copyfileobj(src, out)
            names.append(name)
    return names


# ── channel ──────────────────────────────────────────────────────────────────


def _connect(host: str, port: int, wait: float, timeout: float) -> http.client.HTTPSConnection:
    """TLS to the NER TEE, waiting up to `wait` seconds for it to finish booting."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # trusted only after the attestation below
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    deadline = time.monotonic() + wait
    last = None
    while True:
        conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=timeout)
        try:
            conn.connect()
            return conn
        except (OSError, ssl.SSLError) as e:
            last = e
            conn.close()
        if time.monotonic() >= deadline:
            raise NerUnavailable(f"NER TEE at {host}:{port} not reachable: {last}")
        time.sleep(5)


def _attest(conn: http.client.HTTPSConnection) -> attest_verify.Verified:
    nonce = secrets.token_hex(32)
    conn.request("POST", "/enclave/attest", body=json.dumps({"nonce": nonce}),
                 headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    body = resp.read()
    if resp.status != 200:
        raise NerUnavailable(f"NER TEE would not attest: HTTP {resp.status}")
    try:
        token = json.loads(body)["maa_jwt"]
        verified = attest_verify.verify(token, nonce, _policy())
    except attest_verify.AttestationError as e:
        raise NerUnavailable(f"NER TEE attestation rejected: {e}") from e
    except Exception as e:
        raise NerUnavailable(f"NER TEE attestation unusable: {e}") from e
    presented = attest_verify.spki_b64_from_der_cert(conn.sock.getpeercert(binary_form=True))
    if presented != verified.public_key:
        raise NerUnavailable("the NER TEE's TLS key is not the attested key; nothing was sent")
    for w in verified.warnings:
        print(f"NER TEE attestation (logged, not enforced): {w}", flush=True)
    return verified


def run_remote(fta_config_dir: str, data_dir: str, out_dir: str, block: dict, staged_name: str,
               timeout: float) -> int:
    """Run skald-fta on the NER TEE. Returns its exit code, with its output
    files written into `out_dir` exactly as a local run would leave them.
    Raises NerUnavailable, having written nothing, whenever it can't."""
    if not remote_enabled():
        raise NerUnavailable("ner_tee is not enabled")
    host, port = str(_setting("host")), int(_setting("port", 4443))
    scratch = getattr(config.paths, "scratch_dir", None) or tempfile.gettempdir()
    work = tempfile.mkdtemp(prefix="ner-", dir=scratch if os.path.isdir(scratch) else None)
    try:
        payload, reduced_from = _build_payload(fta_config_dir, data_dir, block, work)
        conn = _connect(host, port, float(_setting("wait_seconds", 180)), float(timeout) + 120)
        try:
            verified = _attest(conn)
            print(f"NER TEE {host}:{port} attested (PCR15 {verified.pcr15[:16]}…); sending "
                  f"{'free-text columns only' if reduced_from else 'the input'}", flush=True)
            size = os.path.getsize(payload)
            with open(payload, "rb") as body:
                conn.request("POST", "/ner/run", body=body, headers={
                    "Content-Type": "application/gzip", "Content-Length": str(size)})
                resp = conn.getresponse()
            result = os.path.join(work, "result.tgz")
            with open(result, "wb") as f:
                shutil.copyfileobj(resp, f)
            if resp.status != 200:
                raise NerUnavailable(f"NER TEE run failed: HTTP {resp.status}")
            try:
                exit_code = int(resp.getheader("X-NER-Exit-Code", ""))
            except ValueError as e:
                raise NerUnavailable("NER TEE reply has no exit code") from e
        finally:
            conn.close()

        got = os.path.join(work, "got")
        os.makedirs(got)
        names = _safe_extract(result, got)
        # Prepare everything before touching out_dir, so a failure here still
        # leaves the local fallback a clean output/.
        if reduced_from and staged_name in names:
            merged = os.path.join(work, "merged.csv")
            _merge_csv(reduced_from, os.path.join(got, staged_name), merged)
            shutil.move(merged, os.path.join(got, staged_name))
        for name in names:
            shutil.copy2(os.path.join(got, name), os.path.join(out_dir, name))
        print(f"NER TEE returned {len(names)} file(s), exit code {exit_code}", flush=True)
        return exit_code
    except NerUnavailable:
        raise
    except Exception as e:
        raise NerUnavailable(f"{type(e).__name__}: {e}") from e
    finally:
        shutil.rmtree(work, ignore_errors=True)
