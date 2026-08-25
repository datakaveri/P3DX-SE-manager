"""
Process-wide UploadManager for the direct dataset upload endpoints.

The manager holds unwrapped AES keys and session state in memory only (see
enclave/enclave_direct_upload.py) — it MUST stay a single instance for the
lifetime of this process. gunicorn runs this app with --workers 1 for exactly
this reason: a second worker would have its own empty session dict, so a
chunk PUT landing on the "wrong" worker would fail with a spurious "Unknown
or expired upload session".
"""

import glob
import json
import os
import sys
import threading
import time

from cryptography.hazmat.primitives import serialization

from lib.config import config
from enclave.enclave_direct_upload import (
    UploadManager,
    UploadError,
    write_output_container,
)

_lock = threading.Lock()
_manager = None
_manager_key_fingerprint = None
_sweeper_started = False

# How often the background sweeper checks for idle sessions. Independent of
# SESSION_TTL_SECONDS (30 min, enforced inside UploadManager itself) — this
# just bounds how long an idle session can outlive its TTL before something
# actually goes and collects it, for the case where no other request happens
# to touch the manager in the meantime.
_SWEEP_INTERVAL_SECONDS = 300


def _scratch_dir():
    configured = getattr(config.direct_upload, "scratch_dir", None)
    return configured or os.environ.get("ENCLAVE_SCRATCH_DIR", "/enclave/scratch")


def _sweep_stray_scratch_files(scratch_dir):
    """
    Remove every leftover upload artifact in scratch_dir. Called ONLY right
    before constructing a brand-new UploadManager (process startup, or a live
    key rotation) — at that exact moment the new manager's session dict is
    guaranteed empty, so any file already on disk is provably orphaned: no
    in-memory session anywhere references it, and sessions never survive a
    process restart by design (the AES keys are memory-only, so a restarted
    process could not resume them even if it tried).

    This is what actually closes the restart-orphan gap: UploadManager's own
    TTL sweep only ever knows about sessions it currently holds in memory, so
    it has no way to discover files left behind by a process that no longer
    exists.
    """
    for pattern in ("*.bin", "*.meta.json", "*.out.enc"):
        for stray in glob.glob(os.path.join(scratch_dir, pattern)):
            try:
                os.unlink(stray)
            except OSError:
                pass


def _run_background_sweeper():
    while True:
        time.sleep(_SWEEP_INTERVAL_SECONDS)
        try:
            manager = get_manager()
        except UploadError:
            continue  # keys not generated yet -- nothing to sweep
        except Exception:
            continue  # never let the sweeper thread die
        try:
            with manager._lock:  # noqa: SLF001 -- _sweep_locked() assumes the caller holds this
                manager._sweep_locked()  # noqa: SLF001 -- no public equivalent; see stage_for_pipeline()
        except Exception:
            continue


def get_manager():
    """Return the current UploadManager, (re)creating it if the enclave's RSA
    keypair has changed since it was last built (e.g. after a redeploy), or
    if this is the first call in this process.

    A key rotation makes every existing session unusable anyway — the browser
    wrapped its AES keys for the OLD public key — so dropping them is correct,
    not just convenient. Either way (fresh process or rotation), any files
    already in scratch_dir are swept first — see _sweep_stray_scratch_files.
    """
    global _manager, _manager_key_fingerprint, _sweeper_started

    # Keyed on the public key's fingerprint rather than the private key file's
    # mtime. The private key is normally a sealed blob whose mtime says nothing
    # useful, and a fingerprint answers the actual question — "is this still the
    # same keypair?" — instead of a proxy for it.
    import P3DX_SDK  # deferred: P3DX_SDK imports this module at load time

    if not P3DX_SDK.keypair_exists():
        raise UploadError(503, "TEE keys not yet generated — attest before uploading")

    fingerprint = P3DX_SDK.public_key_fingerprint()
    with _lock:
        if _manager is None or _manager_key_fingerprint != fingerprint:
            scratch_dir = _scratch_dir()
            os.makedirs(scratch_dir, exist_ok=True)
            _sweep_stray_scratch_files(scratch_dir)
            private_key = serialization.load_pem_private_key(
                P3DX_SDK.load_enclave_private_key_pem(), password=None
            )
            _manager = UploadManager(private_key, scratch_dir=scratch_dir)
            _manager_key_fingerprint = fingerprint
        if not _sweeper_started:
            threading.Thread(target=_run_background_sweeper, name="direct-upload-sweeper", daemon=True).start()
            _sweeper_started = True
        return _manager


def _meta_path(scratch_dir, upload_id):
    return os.path.join(scratch_dir, f"{upload_id}.meta.json")


def stage_for_pipeline(user_sub, dataset_ref):
    """
    Verify the caller owns the referenced upload, then write a small metadata
    sidecar (original filename, format) next to the scratch file.

    This is the ownership check from backend-changes-direct-upload.md §2.5,
    called from upload_encrypted_bundle() at bundle-upload time — the only
    point where the bundle-uploader's user_sub and this in-memory manager are
    both available together. The deploy_enclave.py subprocess that later
    actually reads the dataset has neither: it runs as a separate process
    with no access to this module's state, and it has no per-request caller
    identity of its own. So it reads the plaintext straight off the shared
    tmpfs path (no key needed — the dataset key was already consumed during
    chunk reassembly) and reads this sidecar for the filename/format it has
    no other way to learn. Ownership is enforced exactly once, here, before
    the subprocess ever starts.

    Raises UploadError if the caller does not own the session or it has not
    finished uploading — the bundle upload should be rejected outright.
    """
    manager = get_manager()
    scratch_path = manager.resolve_dataset_ref(user_sub, dataset_ref)  # ownership + completed check

    upload_id = dataset_ref[len("enclave://upload/"):]
    # UploadManager exposes resolve_dataset_ref() and output_key_for() but no
    # public accessor for filename/format. Reading the "private" _sessions
    # dict here — in our own integration layer, not in the vendored module —
    # avoids modifying enclave_direct_upload.py, which must stay byte-for-byte
    # identical to the checksummed reference copy.
    session = manager._sessions.get(upload_id)  # noqa: SLF001
    meta = {
        "filename": session.filename if session else "dataset",
        "format": session.fmt if session else "csv",
    }
    meta_path = _meta_path(os.path.dirname(scratch_path), upload_id)
    with open(meta_path, "w") as f:
        json.dump(meta, f)
    os.chmod(meta_path, 0o600)

    return scratch_path


def read_staged_meta(scratch_dir, upload_id):
    """Pure filesystem read of the sidecar stage_for_pipeline() wrote — safe
    to call from any process, including the deploy subprocess. Does not touch
    the in-memory UploadManager."""
    try:
        with open(_meta_path(scratch_dir, upload_id)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _get_fetch_data():
    """Mirrors P3DX_SDK._get_fetch_data()'s lazy sys.path/import pattern
    locally, rather than importing P3DX_SDK, to avoid a module-load-time
    import cycle (P3DX_SDK's own module-level code already runs before this
    module would be imported from it)."""
    fetch_data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Fetch_data")
    if fetch_data_dir not in sys.path:
        sys.path.insert(0, fetch_data_dir)
    import fetch_data
    return fetch_data


def _output_blob_base_url():
    account_container = str(getattr(config.direct_upload, "output_container", ""))
    account, _, container = account_container.partition("/")
    if not account or not container:
        raise UploadError(500, "direct_upload.output_container is not configured as 'account/container'")
    return f"https://{account}.blob.core.windows.net/{container}"


def _write_direct_status(outputs_direct, manifest=None):
    outputs = {"direct": outputs_direct}
    if manifest is not None:
        outputs["manifest"] = manifest
    status_payload = {
        "status": "success",
        "application": "direct-upload",
        "outputs": outputs,
    }
    status_path = config.get_path('status')
    os.makedirs(os.path.dirname(status_path), exist_ok=True)
    # The SKALD container runs as root inside Docker and may have already
    # written a status.json of its own into this bind-mounted directory (e.g.
    # its own error report) — this process runs as a non-root user, so it can
    # unlink a root-owned file in a directory it owns, but cannot open one for
    # writing in place. Remove-then-create sidesteps that; see the identical
    # fix in P3DX_SDK._write_dicom_status for the same root cause.
    try:
        if os.path.exists(status_path):
            os.remove(status_path)
    except OSError:
        pass
    with open(status_path, "w") as f:
        json.dump(status_payload, f, indent=2)
    try:
        os.chmod(status_path, 0o644)
    except OSError:
        pass


def finalize_output(upload_id, output_path, filename, content_type, manifest=None):
    """
    Encrypt the pipeline's result under the browser-held output key and
    upload it — the one operation that MUST happen in this process, since
    output_key never leaves UploadManager's in-memory session (see
    backend-changes-direct-upload.md §2.6). The deploy_enclave.py subprocess
    that produced `output_path` calls this over loopback and receives only a
    completion result, never the key.

    `manifest` is the already-stripped DICOM manifest (tags_touched /
    redacted_regions summary) when the underlying dataset is DICOM, passed
    straight through from P3DX_SDK._upload_direct_output. It carries no PHI
    of its own (see _read_stripped_manifest), so it's safe to fold into the
    status payload verbatim; without it the DICOM output UI panel that reads
    that summary would have nothing to show for a direct-mode run.

    `output_path` is attacker-shaped input arriving over an HTTP body — even
    though this route is meant to be host-internal only, it is validated to
    resolve inside config.paths.tee_output regardless, so a compromised or
    misrouted caller cannot use this as an arbitrary-file-read/exfiltration
    primitive (encrypt-then-upload-anything, decryptable by whoever holds
    this upload_id's output_key).
    """
    output_dir_real = os.path.realpath(config.paths.tee_output)
    resolved = os.path.realpath(output_path) if output_path else ""
    if not resolved or not (resolved == output_dir_real or resolved.startswith(output_dir_real + os.sep)):
        raise UploadError(400, "output_path must be inside the pipeline's output directory")
    if not os.path.isfile(resolved):
        raise UploadError(400, f"output_path does not exist: {output_path}")

    manager = get_manager()
    output_key, output_base_iv = manager.output_key_for(upload_id)  # raises UploadError(404) if unknown

    scratch_dir = _scratch_dir()
    container_path = os.path.join(scratch_dir, f"{upload_id}.out.enc")
    with open(container_path, "wb") as fh:
        header = write_output_container(
            resolved, fh,
            run_id=upload_id, output_key=output_key, output_base_iv=output_base_iv,
            filename=filename, content_type=content_type,
        )
    os.chmod(container_path, 0o600)

    fetch_data = _get_fetch_data()
    blob_url = f"{_output_blob_base_url()}/{upload_id}.enc"
    try:
        fetch_data.upload_blob(blob_url, container_path)
    finally:
        try:
            os.unlink(container_path)
        except OSError:
            pass

    # The input scratch file is normally already gone (the subprocess deletes
    # it right after staging into tee_input_data — see Fetch_data/fetch_data.py).
    # release() is a safe no-op if so; it exists as a backstop, not the
    # primary cleanup path.
    manager.release(upload_id)

    ttl_seconds = int(getattr(config.direct_upload, "output_ttl_seconds", 7200))
    result = {
        "outputBlobUrl": blob_url,
        "filename": filename,
        "bytes": header["total_bytes"],
        "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + ttl_seconds)),
    }
    _write_direct_status(result, manifest=manifest)
    return result
