#!/usr/bin/env python3
"""Decryption script for encrypted JSON bundles."""

import json
import base64
import struct
import hmac
import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


def base64url_decode(data: str) -> bytes:
    """Decode base64url string to bytes."""
    padding = len(data) % 4
    if padding:
        data += '=' * (4 - padding)
    return base64.b64decode(data.replace('-', '+').replace('_', '/'))


def base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url string."""
    return base64.b64encode(data).decode('utf-8').rstrip('=').replace('+', '-').replace('/', '_')


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
    Decrypt the entire bundle and save decrypted files.
    
    Args:
        bundle_path: Path to encrypted JSON bundle file
        private_key_path: Path to RSA private key file (PEM format)
        output_dir: Directory to save decrypted files (default: same directory as bundle)
        key_password: Password for encrypted private key (if applicable)
        debug: Print debug information about bundle structure
    """
    with open(bundle_path, 'r') as f:
        data = json.load(f)
    
    # Handle nested JSON structure where bundle is stored as string
    # Can be: {'bundle': '...'} or {'bundle': {'bundle': '...'}}
    if 'bundle' in data:
        bundle_value = data['bundle']
        
        if isinstance(bundle_value, str):
            # Bundle is a JSON string, parse it
            bundle = json.loads(bundle_value)
            if debug:
                pass
        elif isinstance(bundle_value, dict):
            # Bundle is a dict - check if it has another 'bundle' key
            if 'bundle' in bundle_value and isinstance(bundle_value['bundle'], str):
                # Double nested: {'bundle': {'bundle': '...'}}
                bundle = json.loads(bundle_value['bundle'])
                if debug:
                    pass
            else:
                # Bundle is already a dict with the actual bundle data
                bundle = bundle_value
                if debug:
                    print("Detected nested JSON structure (dict)")
        else:
            bundle = data
    else:
        # No 'bundle' key, use data directly
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
    
    payload = bundle.get('payload', bundle if 'encryptedFiles' in bundle else {})
    if not payload:
        raise ValueError(f"Missing payload in bundle: {list(bundle.keys())}")
    
    metadata = bundle.get('metadata', {})
    wrapped_key = payload.get('wrappedKey') or bundle.get('wrappedKey') or bundle.get('encryptedFernetKey')
    if not wrapped_key:
        raise ValueError(f"Missing wrappedKey: {list(payload.keys())}")
    
    encrypted_files = payload.get('encryptedFiles', {})
    if not encrypted_files:
        encrypted_files = {k: payload[k] for k in ['sshKey', 'symmetricKey', 'config'] if k in payload}
        if not encrypted_files:
            raise ValueError(f"Missing encryptedFiles: {list(payload.keys())}")
    
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
    output_folders = {
        'sshKey': '/tmp/SSH_key',
        'symmetricKey': '/tmp/Symmetric_key',
        'config': '/tmp/SKALD_input/config'
    }
    
    decrypted_files = {}
    
    for file_type in ['sshKey', 'symmetricKey', 'config']:
        if file_type not in encrypted_files:
            print(f"Warning: {file_type} not found in encrypted files, skipping...")
            continue
        
        print(f"\nStep 2.{file_type}: Decrypting {file_type}...")
        try:
            encrypted_token = encrypted_files[file_type]
            decrypted_data = decrypt_fernet_token(encrypted_token, fernet_key)
            
            expected_size = original_sizes.get(file_type)
            if expected_size and len(decrypted_data) != expected_size:
                print(f"Size mismatch: {len(decrypted_data)} vs {expected_size} bytes")
            
            output_folder = output_folders.get(file_type)
            original_filename = file_names.get(file_type, f'{file_type}.decrypted')
            
            if output_folder:
                os.makedirs(output_folder, exist_ok=True)
                output_path = os.path.join(output_folder, original_filename)
            else:
                output_path = os.path.join(output_dir, original_filename)
                
                if os.path.exists(output_path):
                        import shutil
                (shutil.rmtree if os.path.isdir(output_path) else os.remove)(output_path)
            
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            os.chmod(output_path, 0o600)
            
            decrypted_files[file_type] = {
                'path': output_path,
                'size': len(decrypted_data),
                'original_filename': original_filename,
                'folder': output_folder if output_folder else output_dir
            }
            
            print(f"{file_type} decrypted successfully")
            print(f"  Saved to: {output_path}")
            print(f"  Size: {len(decrypted_data)} bytes")
            
            # Special handling for config file: rename to kconfig_beneficiary.json for SKALD
            if file_type == 'config' and output_folder == '/tmp/SKALD_input/config':
                skald_config_path = os.path.join(output_folder, 'kconfig_beneficiary.json')
                if os.path.exists(skald_config_path):
                    os.remove(skald_config_path)
                os.rename(output_path, skald_config_path)
                decrypted_files[file_type]['path'] = skald_config_path
                print(f"  Renamed to: {skald_config_path} (SKALD expected filename)")
                
                # Also copy to /tmp/SKALD_input/ so it mounts to /app/kconfig_beneficiary.json in Docker
                skald_root_config_path = '/tmp/SKALD_input/kconfig_beneficiary.json'
                import shutil
                shutil.copy2(skald_config_path, skald_root_config_path)
                print(f"  Copied to: {skald_root_config_path} (for Docker mount to /app/)")
            
        except Exception as e:
            raise ValueError(f"Failed to decrypt {file_type}: {e}")
    
    print("\n" + "="*60)
    print("Decryption Summary")
    print("="*60)
    for file_type, info in decrypted_files.items():
        print(f"  {file_type}: {info['path']} ({info['size']} bytes)")
    print("="*60)
    

def extract_bundle_from_encrypted_json(encrypted_json_path: str) -> str:
    """Extract nested bundle JSON if present."""
    with open(encrypted_json_path, 'r') as f:
        data = json.load(f)
    
    if 'bundle' in data and isinstance(data['bundle'], str):
        bundle_dir = os.path.dirname(os.path.abspath(encrypted_json_path))
        bundle_json_path = os.path.join(bundle_dir, 'bundle.json')
        with open(bundle_json_path, 'w') as f:
            json.dump(json.loads(data['bundle']), f, indent=2)
        return bundle_json_path
    return encrypted_json_path



