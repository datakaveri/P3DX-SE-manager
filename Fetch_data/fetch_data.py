#!/usr/bin/env python3
"""Fetch and decrypt data from remote host via SSH."""

import os
import glob
import base64
import shutil
import subprocess
from pathlib import Path
from cryptography.fernet import Fernet


def find_file_in_dir(directory, extension=None):
    """Find first file in directory, optionally matching extension."""
    if not os.path.exists(directory):
        raise FileNotFoundError(f"Directory not found: {directory}")
    
    files = glob.glob(os.path.join(directory, '*'))
    files = [f for f in files if os.path.isfile(f)]
    
    if extension:
        files = [f for f in files if f.endswith(extension)]
    
    if not files:
        raise FileNotFoundError(f"No {'matching ' if extension else ''}files found in {directory}")
    
    return files[0]


def decrypt_file(encrypted_path, key_path, output_path):
    """Decrypt Fernet encrypted file using Fernet key."""
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__))))
    from PPDX_SKALD import create_fernet_cipher
    
    with open(key_path, 'rb') as f:
        key_data = f.read().strip()
    
    try:
        cipher = create_fernet_cipher(key_data)
    except Exception as e:
        raise ValueError(f"Failed to create Fernet cipher: {e}. Key format may be invalid.")
    
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


def fetch_and_decrypt(config_path=None):
    """Main function to fetch and decrypt data."""
    import json
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__))))
    from PPDX_SKALD import load_config_file, find_ssh_key, build_ssh_command, build_scp_command
    
    if config_path is None:
        config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "DPconfig.json")
    config = load_config_file(config_path)
    
    ssh_host = config["ssh_host"]
    ssh_user = config["ssh_user"]
    remote_data_dir = config["remote_data_dir"]
    
    ssh_key_dir = "/tmp/SSH_key"
    symmetric_key_dir = "/tmp/Symmetric_key"
    output_dir = "/tmp/SKALD_input/input_file"
    
    print("="*60)
    print("Fetching and Decrypting Data")
    print("="*60)
    
    ssh_key_path = find_file_in_dir(ssh_key_dir)
    print(f"Found SSH key: {ssh_key_path}")
    
    with open(ssh_key_path, 'rb') as f:
        key_content = f.read(100)
        if not key_content or key_content.startswith(b'\x00' * 10):
            raise ValueError(f"SSH key file appears corrupted (contains null bytes): {ssh_key_path}")
        if b'BEGIN' not in key_content and b'PRIVATE' not in key_content:
            raise ValueError(f"SSH key file doesn't appear to be a valid private key: {ssh_key_path}")
    
    symmetric_key_path = find_file_in_dir(symmetric_key_dir)
    print(f"Found symmetric key: {symmetric_key_path}")
    
    os.chmod(ssh_key_path, 0o600)
    
    result = subprocess.run(['ssh-keygen', '-l', '-f', ssh_key_path], capture_output=True, text=True, timeout=5)
    if result.returncode != 0:
        raise ValueError(f"Invalid SSH key format: {result.stderr.strip()}")
    
    print(f"\nConnecting to {ssh_user}@{ssh_host}...")
    
    ssh_cmd = build_ssh_command(ssh_key_path, ssh_user, ssh_host, f'ls -1 {remote_data_dir}*.enc 2>/dev/null | head -1')
    
    try:
        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            raise RuntimeError(f"SSH command failed: {result.stderr}")
        
        remote_enc_file = result.stdout.strip()
        if not remote_enc_file:
            raise FileNotFoundError(f"No .enc files found in {remote_data_dir}")
        
        print(f"Found encrypted file: {remote_enc_file}")
        
        local_enc_file = "/tmp/temp_encrypted.enc"
        
        print(f"\nDownloading {remote_enc_file}...")
        scp_cmd = build_scp_command(ssh_key_path, ssh_user, ssh_host, remote_enc_file, local_enc_file, is_upload=False)
        
        result = subprocess.run(scp_cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            raise RuntimeError(f"SCP download failed: {result.stderr}")
        
        print(f"Downloaded to {local_enc_file}")
        
        # Extract filename from remote path and convert .enc to .csv
        remote_filename = os.path.basename(remote_enc_file)
        if remote_filename.endswith('.enc'):
            # Remove .enc extension
            csv_filename = remote_filename[:-4]
            # If it doesn't already end with .csv, add it
            if not csv_filename.endswith('.csv'):
                csv_filename = csv_filename + '.csv'
        else:
            # If no .enc extension, use original name but ensure .csv extension
            base_name = os.path.splitext(remote_filename)[0]
            csv_filename = base_name + '.csv' if not base_name.endswith('.csv') else base_name
        
        output_file_path = os.path.join(output_dir, csv_filename)
        
        print(f"\nDecrypting file...")
        file_size = os.path.getsize(local_enc_file)
        print(f"  Encrypted file size: {file_size} bytes")
        print(f"  Output file: {csv_filename}")
        
        decrypt_file(local_enc_file, symmetric_key_path, output_file_path)
        print(f"Decrypted and saved to {output_file_path}")
        
        os.remove(local_enc_file)
        print(f"Cleaned up temporary file")
        
        print("\n" + "="*60)
        print("Success!")
        print(f"Decrypted file: {output_file_path}")
        print(f"File size: {os.path.getsize(output_file_path)} bytes")
        print("="*60)
        
    except subprocess.TimeoutExpired:
        raise RuntimeError("Connection timeout - check network and SSH access")
    except Exception as e:
        if os.path.exists("/tmp/temp_encrypted.enc"):
            os.remove("/tmp/temp_encrypted.enc")
        raise


if __name__ == '__main__':
    try:
        fetch_and_decrypt()
    except Exception as e:
        print(f"\nERROR: {e}")
        exit(1)

