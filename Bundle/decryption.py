#!/usr/bin/env python3
"""Decryption script for encrypted JSON bundles."""

import json
import base64
import hmac
import hashlib
import os
import shutil
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def base64url_decode(data: str) -> bytes:
    """Decode base64url string to bytes."""
    padding = len(data) % 4
    if padding:
        data += '=' * (4 - padding)
    return base64.b64decode(data.replace('-', '+').replace('_', '/'))


def decrypt_fernet_token(token_b64url: str, fernet_key: bytes) -> bytes:
    """Decrypt Fernet token and return plaintext bytes."""
    token = base64url_decode(token_b64url)
    
    if len(token) < 57:
        raise ValueError(f"Token too short: {len(token)} bytes")
    
    if token[0] != 0x80:
        raise ValueError(f"Invalid Fernet version: {token[0]:#x}")
    
    iv = token[9:25]
    hmac_signature = token[-32:]
    ciphertext = token[25:-32]
    encryption_key = fernet_key[:16]
    signing_key = fernet_key[16:32]
    
    expected_hmac = hmac.new(signing_key, token[:-32], hashlib.sha256).digest()
    if not hmac.compare_digest(hmac_signature, expected_hmac):
        raise ValueError("HMAC verification failed")
    
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except ValueError as e:
        raise ValueError(f"AES-CBC decryption failed: {e}")
    
    if not plaintext:
        raise ValueError("Decrypted plaintext is empty")
    
    padding_length = plaintext[-1]
    if 1 <= padding_length <= 16:
        if all(b == padding_length for b in plaintext[-padding_length:]):
            plaintext = plaintext[:-padding_length]
    
    return plaintext


def decrypt_rsa_wrapped_key(wrapped_key_b64: str, private_key_path: str, password: bytes = None) -> bytes:
    """Decrypt RSA-OAEP wrapped Fernet key."""
    ciphertext = base64.b64decode(wrapped_key_b64)
    
    with open(private_key_path, 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=password, backend=default_backend())
    
    fernet_key = private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    
    if len(fernet_key) != 32:
        raise ValueError(f"Invalid key length: {len(fernet_key)} bytes")
    
    return fernet_key


def decrypt_bundle(bundle_path: str, private_key_path: str, output_dir: str = None, key_password: str = None, debug: bool = False):
    """
    Decrypt the bundle and save decrypted files and URLs.
    
    Args:
        bundle_path: Path to encrypted JSON bundle file
        private_key_path: Path to RSA private key file (PEM format)
        output_dir: Directory to save decrypted files (default: same directory as bundle)
        key_password: Password for encrypted private key (if applicable)
        debug: Print debug information about bundle structure
    """
    with open(bundle_path, 'r') as f:
        data = json.load(f)
    if 'bundle' in data:
        bundle = data['bundle']
    else:
        bundle = data
    
    if debug:
        print("="*60)
        print("DEBUG: Bundle Structure")
        print("="*60)
        print(json.dumps(bundle, indent=2, default=str))
        print("="*60)
        print()
    
    bundle_version = bundle.get('version')
    if bundle_version and bundle_version != '1.0':
        print(f"Warning: Bundle version {bundle_version} (expected 1.0)")
    
    payload = bundle.get('payload', {})
    if not payload:
        raise ValueError(f"Missing payload in bundle: {list(bundle.keys())}")
    
    metadata = bundle.get('metadata', {})
    wrapped_key = payload.get('wrappedKey')
    if not wrapped_key:
        raise ValueError(f"Missing wrappedKey in payload: {list(payload.keys())}")
    
    encrypted_files = payload.get('encryptedFiles', {})
    encrypted_urls = payload.get('encryptedUrls', {})
    
    if not encrypted_files and not encrypted_urls:
        raise ValueError(f"Missing encryptedFiles and encryptedUrls in payload: {list(payload.keys())}")
    
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    else:
        output_dir = os.path.dirname(os.path.abspath(bundle_path))
    
    print(f"Decrypting bundle: {bundle_path}")
    print(f"Output directory: {output_dir}")
    print(f"Bundle timestamp: {bundle.get('timestamp', 'N/A')}")
    print()
    
    print("Step 1: Decrypting Fernet key...")
    password_bytes = key_password.encode('utf-8') if key_password else None
    fernet_key = decrypt_rsa_wrapped_key(wrapped_key, private_key_path, password_bytes)
    print(f"Fernet key decrypted ({len(fernet_key)} bytes)")
    
    file_names = metadata.get('fileNames', {})
    original_sizes = metadata.get('originalSizes', {})
    decrypted_files = {}
    decrypted_urls = {}
    
    # Decrypt config file
    if 'config' in encrypted_files:
        print(f"\nStep 2: Decrypting config file...")
        try:
            encrypted_token = encrypted_files['config']
            decrypted_data = decrypt_fernet_token(encrypted_token, fernet_key)
            
            expected_size = original_sizes.get('config')
            if expected_size and len(decrypted_data) != expected_size:
                print(f"Warning: Size mismatch: {len(decrypted_data)} vs {expected_size} bytes")
            
            original_filename = file_names.get('config', 'generated-config.json')
            output_folder = '/tmp/tee_input/config'
            os.makedirs(output_folder, exist_ok=True)
            output_path = os.path.join(output_folder, original_filename)
            
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            os.chmod(output_path, 0o600)
            
            decrypted_files['config'] = {
                'path': output_path,
                'size': len(decrypted_data),
                'original_filename': original_filename
            }
            
            print(f"Config decrypted successfully")
            print(f"  Saved to: {output_path}")
            print(f"  Size: {len(decrypted_data)} bytes")
            
        except Exception as e:
            raise ValueError(f"Failed to decrypt config: {e}")
    
    # Decrypt encrypted URLs
    if encrypted_urls:
        print(f"\nStep 3: Decrypting encrypted URLs...")
        for url_type in ['blobUrl', 'keyVaultUrl', 'outputContainerUrl']:
            if url_type in encrypted_urls:
                try:
                    encrypted_token = encrypted_urls[url_type]
                    decrypted_url = decrypt_fernet_token(encrypted_token, fernet_key).decode('utf-8')
                    decrypted_urls[url_type] = decrypted_url
                    print(f"  {url_type}: {decrypted_url}")
                except Exception as e:
                    raise ValueError(f"Failed to decrypt {url_type}: {e}")
        
        # Save decrypted URLs to a JSON file
        if decrypted_urls:
            urls_dir = '/tmp/urls'
            os.makedirs(urls_dir, exist_ok=True)
            urls_output_path = os.path.join(urls_dir, 'decrypted_urls.json')
            with open(urls_output_path, 'w') as f:
                json.dump(decrypted_urls, f, indent=2)
            os.chmod(urls_output_path, 0o600)
            print(f"\n  Decrypted URLs saved to: {urls_output_path}")
    
    print("\n" + "="*60)
    print("Decryption Summary")
    print("="*60)
    for file_type, info in decrypted_files.items():
        print(f"  {file_type}: {info['path']} ({info['size']} bytes)")
    if decrypted_urls:
        print(f"\n  Decrypted URLs:")
        for url_type, url in decrypted_urls.items():
            print(f"    {url_type}: {url}")
    print("="*60)
    
    return {
        'files': decrypted_files,
        'urls': decrypted_urls
    }
