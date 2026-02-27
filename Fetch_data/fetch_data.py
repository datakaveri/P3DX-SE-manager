#!/usr/bin/env python3
"""Fetch and decrypt data from Azure Blob Storage using Managed Identity."""

import os
import json
import shutil
import sys
import traceback
from pathlib import Path
from email.utils import formatdate

import requests

# ===============================
# Managed Identity + Azure helpers
# ===============================

def get_mi_token(resource):

    url = "http://169.254.169.254/metadata/identity/oauth2/token"
    params = {
        "api-version": "2019-08-01",
        "resource": resource
    }
    headers = {"Metadata": "true"}

    r = requests.get(url, params=params, headers=headers, timeout=5)
    r.raise_for_status()
    return r.json()["access_token"]


def download_blob(url, output_path):
    token = get_mi_token("https://storage.azure.com/")
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
    token = get_mi_token("https://vault.azure.net")
    headers = {"Authorization": f"Bearer {token}"}

    r = requests.get(f"{secret_url}?api-version=7.4", headers=headers, timeout=10)
    r.raise_for_status()
    return r.json()["value"].encode()


def upload_blob(blob_url, file_path):
    """Upload file to Azure Blob Storage using Managed Identity."""
    token = get_mi_token("https://storage.azure.com/")
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


def decrypt_file(encrypted_path, fernet_key_bytes, output_path):
    """Decrypt file using Fernet key bytes."""
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__))))
    from PPDX_SKALD import create_fernet_cipher

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

def encrypt_file(input_path, fernet_key_bytes, encrypted_output_path):
    """Encrypt file using Fernet key bytes."""
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__))))
    from PPDX_SKALD import create_fernet_cipher

    try:
        cipher = create_fernet_cipher(fernet_key_bytes)
    except Exception as e:
        raise ValueError(f"Failed to create Fernet cipher: {e}")

    with open(input_path, 'rb') as f:
        plaintext = f.read()

    encrypted_data = cipher.encrypt(plaintext)

    os.makedirs(os.path.dirname(encrypted_output_path), exist_ok=True)
    with open(encrypted_output_path, 'wb') as f:
        f.write(encrypted_data)

    os.chmod(encrypted_output_path, 0o600)


def fetch_and_decrypt_tee():
    """Fetch encrypted data from Azure Blob Storage and decrypt using Key Vault secret."""
    encrypted_path = "/tmp/dataset.enc"
    output_dir = "/tmp/tee_input/data"
    urls_path = Path("/tmp/urls/decrypted_urls.json")

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

    # Determine output filename
    filename = os.path.basename(dataset_url)
    if filename.endswith(".enc"):
        filename = filename[:-4]
    if not filename.endswith(".csv"):
        filename += ".csv"

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

    # --------------------------------------------------
    # Encrypt processed output and upload to output blob
    # --------------------------------------------------

    print("\nEncrypting output file before upload...")

    encrypted_output_path = output_path + ".enc"

    encrypt_file(output_path, fernet_key, encrypted_output_path)

    print(f"Encrypted output saved to: {encrypted_output_path}")

    if "outputContainerUrl" not in urls:
        raise ValueError("Missing 'outputContainerUrl' in decrypted_urls.json")

    output_container_url = urls["outputContainerUrl"].rstrip("/")
    
    # Extract filename from encrypted output path
    blob_filename = os.path.basename(encrypted_output_path)
    
    # Construct full blob URL: container_url/blob_filename
    output_blob_url = f"{output_container_url}/{blob_filename}"

    print(f"\nUploading encrypted output to blob: {output_blob_url}")
    upload_blob(output_blob_url, encrypted_output_path)

    print("Encrypted output uploaded successfully")

    # Optional cleanup
    os.remove(encrypted_output_path)

if __name__ == '__main__':
    try:
        fetch_and_decrypt_tee()
    except Exception as e:
        print(f"\nERROR: {e}")
        traceback.print_exc()
        exit(1)



