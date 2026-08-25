#!/usr/bin/env python3
"""Fetch and decrypt data from Azure Blob Storage using Managed Identity."""

import os
import json
import shutil
import sys
import traceback
from pathlib import Path
from email.utils import formatdate
from urllib.parse import urlparse
import requests

_parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)
from P3DX_SDK import create_fernet_cipher
from lib.config import config

# ===============================
# Managed Identity + Azure helpers
# ===============================

def get_mi_token(resource):

    url = config.azure.imds_url
    params = {
        "api-version": "2019-08-01",
        "resource": resource
    }
    headers = {"Metadata": "true"}

    r = requests.get(url, params=params, headers=headers, timeout=5)
    r.raise_for_status()
    return r.json()["access_token"]


def download_blob(url, output_path):
    token = get_mi_token(config.azure.storage_resource)
    headers = {
        "Authorization": f"Bearer {token}",
        "x-ms-version": "2020-10-02",
        "x-ms-date": formatdate(usegmt=True)
    }

    r = requests.get(url, headers=headers, timeout=30)
    r.raise_for_status()

    with open(output_path, "wb") as f:
        f.write(r.content)


def fetch_fernet_key_from_kv(secret_url):
    """Fetch Fernet key from Azure Key Vault using Managed Identity."""
    token = get_mi_token(config.azure.vault_resource)
    headers = {"Authorization": f"Bearer {token}"}

    r = requests.get(f"{secret_url}?api-version=7.4", headers=headers, timeout=10)
    r.raise_for_status()
    return r.json()["value"].encode()


def upload_blob(blob_url, file_path):
    """Upload file to Azure Blob Storage using Managed Identity."""
    token = get_mi_token(config.azure.storage_resource)
    headers = {
        "Authorization": f"Bearer {token}",
        "x-ms-version": "2020-10-02",
        "x-ms-date": formatdate(usegmt=True),
        "x-ms-blob-type": "BlockBlob",
        "Content-Type": "application/octet-stream"
    }

    with open(file_path, "rb") as f:
        file_content = f.read()

    # Use PUT method for blob upload
    r = requests.put(blob_url, headers=headers, data=file_content, timeout=30)
    r.raise_for_status()
    return r.status_code in (201, 202)


_IMAGE_CONFIG_FILENAME = "pipeline_config.json"


def read_output_format(default="csv"):
    """Determine the output format ('dicom', 'image', 'csv', …).

    Checks the app config delivered in the bundle (tee_input_config) first,
    then falls back to DPconfig.json which the /run re-run endpoints stamp.
    """
    # 1) Bundle-delivered app config (what the container reads).
    cfg_dir = config.paths.tee_input_config
    try:
        for name in sorted(os.listdir(cfg_dir)):
            if name.endswith(".json"):
                with open(os.path.join(cfg_dir, name)) as f:
                    data = json.load(f)
                fmt = str(data.get("format", "")).strip().lower()
                if fmt:
                    return fmt
                # skald-image's config carries no "format" key of its own
                # (see pipeline_config.json's contract) — the reserved
                # filename is the only signal that this is an image job.
                if name == _IMAGE_CONFIG_FILENAME:
                    return "image"
    except (OSError, ValueError):
        pass

    # 2) Fallback: DPconfig.json (set by /run/*_pipeline re-runs).
    try:
        with open(config.get_path('config_file')) as f:
            fmt = str(json.load(f).get("format", "")).strip().lower()
        if fmt:
            return fmt
    except (OSError, ValueError):
        pass

    return default


def decrypt_file(encrypted_path, fernet_key_bytes, output_path):
    """Decrypt file using Fernet key bytes."""
    try:
        cipher = create_fernet_cipher(fernet_key_bytes)
    except Exception as e:
        raise ValueError(f"Failed to create Fernet cipher: {e}")

    # Read encrypted file
    with open(encrypted_path, 'rb') as f:
        encrypted_data = f.read()
    
    # Decrypt using Fernet
    try:
        plaintext = cipher.decrypt(encrypted_data)
    except Exception as e:
        raise ValueError(f"Fernet decryption failed: {e}. Check if correct key is being used or file is corrupted.")
    
    # Save decrypted file
    # Check if output_path exists as a directory and remove it
    if os.path.exists(output_path) and os.path.isdir(output_path):
        shutil.rmtree(output_path)
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'wb') as f:
        f.write(plaintext)
    
    os.chmod(output_path, 0o600)

_FORMAT_EXTENSIONS = {"csv": ".csv", "json": ".json", "excel": ".xlsx", "dicom": ".dcm"}


def _stage_direct_upload_input(dataset_url, output_dir, output_format):
    """
    Direct-upload mode: the dataset was already reassembled, plaintext, in
    the enclave's tmpfs scratch directory by /enclave/upload/* — ownership was
    verified once, synchronously, when the bundle carrying this reference was
    uploaded (see lib/direct_upload.stage_for_pipeline). No Azure Blob
    download and no Key Vault fetch happen for this path; the AES key that
    protected the chunks in transit was already consumed during reassembly and
    never leaves the enclave manager process — this subprocess never sees it.

    NOTE: this copies the plaintext dataset from tmpfs onto
    config.paths.tee_input_data, which is host disk on this deployment, not
    tmpfs — closing that gap means moving the pipeline's I/O directories to
    tmpfs too, which is a separate, not-yet-decided question. This does not
    introduce a NEW exposure relative to the status quo: every other flow in
    this codebase (Azure Blob tabular, DICOM) already stages plaintext at this
    same host-disk path. It just falls short of this feature's own "RAM only"
    goal until that follow-up lands.
    """
    from lib import direct_upload as _du

    upload_id = dataset_url[len("enclave://upload/"):]
    scratch_dir = _du._scratch_dir()
    scratch_path = os.path.join(scratch_dir, f"{upload_id}.bin")
    if not os.path.exists(scratch_path):
        raise FileNotFoundError(
            f"Direct-upload dataset not found at {scratch_path}. "
            "The upload session may have expired or already been consumed."
        )

    meta = _du.read_staged_meta(scratch_dir, upload_id)
    original_name = meta.get("filename") or "dataset"
    fmt = meta.get("format") or output_format
    stem, orig_ext = os.path.splitext(original_name)
    ext = _FORMAT_EXTENSIONS.get(fmt, orig_ext or ".dat")
    filename = (stem or "dataset") + ext

    os.makedirs(output_dir, exist_ok=True)
    dest_path = os.path.join(output_dir, filename)
    shutil.copyfile(scratch_path, dest_path)
    os.chmod(dest_path, 0o600)

    # Free the tmpfs copy now — only the disk-side copy the pipeline is about
    # to read is needed from here on. The metadata sidecar is left in place;
    # the later output-upload step (P3DX_SDK._upload_direct_output) still
    # needs it to name the result, and it is cleaned up there.
    os.remove(scratch_path)

    print(f"Direct-upload dataset staged: {scratch_path} -> {dest_path}")


_IMAGE_INPUT_EXTENSIONS = (".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".webp")


def _validate_and_normalize_image_config():
    """Enforce skald-image's two security boundaries against the decrypted
    pipeline_config.json before the container ever starts, and normalize the
    high_thresh/low_thresh JSON-int/float ambiguity.

    temp_dir must stay under /tmp: any path under /app/output would write the
    unredacted source image onto the volume that leaves the enclave.
    ocr must stay false: true writes recognised plate text to a plaintext CSV
    on the output volume, so plate numbers would survive redaction in
    readable form. Both are rejected outright — never silently corrected —
    since a client that got these wrong (or was tampered with) should not
    have its job quietly reinterpreted.
    """
    cfg_path = os.path.join(config.paths.tee_input_config, _IMAGE_CONFIG_FILENAME)
    with open(cfg_path) as f:
        cfg = json.load(f)

    temp_dir = os.path.normpath(str(cfg.get("temp_dir", "/tmp/skald-image")))
    if temp_dir != "/tmp" and not temp_dir.startswith("/tmp" + os.sep):
        raise ValueError(
            f"skald-image pipeline_config.json: temp_dir must stay under /tmp, "
            f"got {cfg.get('temp_dir')!r}"
        )

    if bool(cfg.get("ocr", False)):
        raise ValueError(
            "skald-image pipeline_config.json: ocr must be false — OCR output "
            "is never permitted to leave the TEE"
        )

    # JSON has no int/float distinction, so a UI that emits 500/100 (not
    # 500.0/100.0) round-trips through json.loads as Python ints. Coerce here
    # so the container never has to special-case the wire format.
    changed = False
    for key in ("high_thresh", "low_thresh"):
        value = cfg.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            cfg[key] = float(value)
            changed = True
    if changed:
        with open(cfg_path, "w") as f:
            json.dump(cfg, f, indent=2)
        os.chmod(cfg_path, 0o600)


def fetch_and_decrypt_tee():
    """Fetch encrypted data from Azure Blob Storage and decrypt using Key Vault secret."""
    encrypted_path = os.path.join(config.paths.tee_input_data, "dataset.enc")
    output_dir = config.paths.tee_input_data
    urls_path = Path(config.get_path('decrypted_urls'))

    output_format = read_output_format()

    if output_format == "image":
        _validate_and_normalize_image_config()

    if not urls_path.exists():
        raise FileNotFoundError(
            f"decrypted_urls.json not found at {urls_path}. "
            "Ensure bundle decryption completed successfully."
        )

    # Read decrypted URLs from bundle
    with open(urls_path, "r") as f:
        urls = json.load(f)

    # Validate required URLs
    if "blobUrl" not in urls or "keyVaultUrl" not in urls:
        raise ValueError(
            "decrypted_urls.json must contain 'blobUrl' and 'keyVaultUrl'"
        )

    dataset_url = urls["blobUrl"]
    keyvault_url = urls["keyVaultUrl"]

    if dataset_url.startswith("enclave://upload/"):
        _stage_direct_upload_input(dataset_url, output_dir, output_format)
        print("\nDirect-upload dataset staged from tmpfs scratch; "
              "skipping Azure Blob download and Key Vault fetch entirely")
        return

    print("=" * 60)
    print("Fetching and Decrypting Data (TEE + Managed Identity)")
    print("=" * 60)
    print(f"Blob URL: {dataset_url}")
    print(f"Key Vault URL: {keyvault_url}")

    # Download encrypted blob
    print("\nDownloading encrypted dataset from blob storage...")
    download_blob(dataset_url, encrypted_path)
    print(f"Downloaded to: {encrypted_path}")

    # Fetch Fernet key from Key Vault
    print("\nFetching Fernet key from Key Vault...")
    fernet_key = fetch_fernet_key_from_kv(keyvault_url)
    print("Fernet key retrieved successfully")

    # Determine output filename (parse path only, ignoring any query string)
    filename = os.path.basename(urlparse(dataset_url).path)
    if filename.endswith(".enc"):
        filename = filename[:-4]
    # Preserve whatever extension the blob name already carries (e.g.
    # "healthcare_multi.xlsx.enc" -> "healthcare_multi.xlsx") — SKALD picks its
    # reader purely from the extension, so overwriting a real .xlsx/.json with
    # .csv hands the binary/JSON bytes to the CSV reader and it fails on the
    # first non-UTF-8 byte. Only fall back to a format-appropriate extension
    # when the blob name carries none at all (legacy blobs named e.g. just
    # "dataset.enc"). DICOM input must stay .dcm so the container reads it as
    # an image, not a CSV. skald-image input must keep an image extension so
    # the container's `ext` allow-list picks it up from input_dir.
    if output_format == "dicom":
        if not filename.endswith(".dcm"):
            filename += ".dcm"
    elif output_format == "image":
        if not filename.lower().endswith(_IMAGE_INPUT_EXTENSIONS):
            filename += ".png"
    elif not filename.lower().endswith((".csv", ".json", ".xlsx", ".xls")):
        filename += _FORMAT_EXTENSIONS.get(output_format, ".csv")

    output_path = os.path.join(output_dir, filename)
    
    # Decrypt file
    print(f"\nDecrypting dataset...")
    decrypt_file(encrypted_path, fernet_key, output_path)
    print(f"Decrypted data saved to: {output_path}")

    # Cleanup temporary encrypted file
    os.remove(encrypted_path)
    print("\n" + "=" * 60)
    print("Data fetch and decryption completed successfully")
    print("=" * 60)

    # The real anonymised output is produced later by the pipeline container
    # and uploaded post-run by P3DX_SDK.encrypt_and_upload_output() (Step 11),
    # which reads from tee_output — never from here. This function's only job
    # is staging the decrypted input for the container to read; it must not
    # upload anything itself, since the only file available at this point is
    # the raw, not-yet-anonymised input.

if __name__ == '__main__':
    try:
        fetch_and_decrypt_tee()
    except Exception as e:
        print(f"\nERROR: {e}")
        traceback.print_exc()
        exit(1)



