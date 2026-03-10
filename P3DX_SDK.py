import os
import sys
import subprocess
import json
import base64
import urllib.parse
import time
import shutil
import re
import hashlib
import secrets
from pathlib import Path

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.fernet import Fernet

# Ensure Bundle directory is in path for decryption import
_script_dir = os.path.dirname(os.path.abspath(__file__))
_bundle_dir = os.path.join(_script_dir, 'Bundle')
_fetch_data_dir = os.path.join(_script_dir, 'Fetch_data')
if _bundle_dir not in sys.path:
    sys.path.insert(0, _bundle_dir)
from decryption import decrypt_bundle

# Lazy import for fetch_data
_fetch_data_module = None


def _get_fetch_data():
    """Import fetch_data once; required due to circular dependency."""
    global _fetch_data_module
    if _fetch_data_module is None:
        if _fetch_data_dir not in sys.path:
            sys.path.insert(0, _fetch_data_dir)
        import fetch_data as _fetch_data_module
    return _fetch_data_module


def load_config_file(config_path="DPconfig.json"):
    """Load configuration from JSON file."""
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")
    
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        return config
    except Exception as e:
        raise ValueError(f"Failed to load config from {config_path}: {e}")


def create_fernet_cipher(key_data):
    """Create Fernet cipher from key data, handling various key formats."""
    try:
        return Fernet(key_data)
    except Exception:
        key_str = key_data.decode('utf-8', errors='ignore').strip()
        if len(key_str) == 44:
            decoded = base64.b64decode(key_str)
            key = base64.urlsafe_b64encode(decoded)
            return Fernet(key)
        elif len(key_data) == 32:
            key = base64.urlsafe_b64encode(key_data)
            return Fernet(key)
        else:
            raise ValueError(f"Invalid key format: {len(key_data)} bytes")




def pull_compose_file(url, filename="docker-compose.yml"):
    """Download a docker-compose file from the given URL."""
    try:
        response = requests.get(url)
        response.raise_for_status()
        with open(filename, "wb") as file:
            file.write(response.content)
        print(f"Downloaded content from '{url}' and saved to '{filename}'")
    except requests.exceptions.RequestException as exc:
        print(f"Error downloading content: {exc}")


def extract_docker_image_from_compose(compose_file="docker-compose.yml"):
    """Extract docker image name from docker-compose.yml file."""
    if not os.path.exists(compose_file):
        raise FileNotFoundError(f"Docker compose file not found: {compose_file}")
    
    with open(compose_file, 'r') as f:
        content = f.read()
    
    match = re.search(r'^\s*image:\s*([^\s\n#]+)', content, re.MULTILINE)
    if match:
        return match.group(1).strip()
    else:
        raise ValueError("Could not extract docker image from docker-compose.yml")




def generate_and_save_key_pair():
    """Generate RSA key pair and save to keys/ directory."""
    public_key_file = "public_key.pem"
    private_key_file = "private_key.pem"

    os.makedirs("keys", exist_ok=True)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
        .split("\n")[1:-1]
    )

    private_key_bytes = (
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        .decode()
    )

    with open(os.path.join("keys", public_key_file), "w") as public_key_out:
        public_key_out.write("".join(public_key))

    with open(os.path.join("keys", private_key_file), "w") as private_key_out:
        private_key_out.write("".join(private_key_bytes))

    print("Public and private keys generated and saved successfully in the 'keys' folder!")

    # Strip PEM markers
    with open(os.path.join("keys", public_key_file), "r") as file:
        lines = file.readlines()
    cleaned_lines = [line.split("----")[0] if "----" in line else line for line in lines]
    with open(os.path.join("keys", public_key_file), "w") as file:
        file.writelines(cleaned_lines)

    print("Private key generated and saved successfully")


def pull_docker_image(app_name):
    """Pull a Docker image."""
    print("Pulling docker image")
    subprocess.run(["docker", "pull", app_name])


def hash_docker_image(image):
    """Returns SHA256 digest from RepoDigest or computes from docker inspect JSON."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format={{index .RepoDigests 0}}", image],
            capture_output=True, text=True, check=True, timeout=10
        )
        match = re.search(r'sha256:([a-f0-9]{64})', result.stdout)
        if match:
            return match.group(1)
    except Exception:
        pass
    result = subprocess.run(
        ["docker", "inspect", image], capture_output=True, text=True, check=True, timeout=10
    )
    return hashlib.sha256(json.dumps(json.loads(result.stdout)[0], sort_keys=True).encode()).hexdigest()


def save_image_hash(image_hash, path="keys/image_hash.txt"):
    with open(path, "w") as f:
        f.write(image_hash)


def hash_enclave_manager_code(base_dir="/home/kanonTEE/P3DX-SE-manager"):
    """
    Deterministically hash enclave manager code directory.
    """
    sha256_digest = hashlib.sha256()

    # Files to include in hash (deterministic order)
    files_to_hash = []
    
    for root, dirs, files in os.walk(base_dir):
        # Sort for deterministic order
        dirs.sort()
        files.sort()
        
        # Skip certain directories
        skip_dirs = {'.git', '__pycache__', '.mono', 'keys', 'node_modules', '.pytest_cache'}
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        
        for fname in files:
            # Only hash source code and config files
            if fname.endswith((".py", ".sh", ".json", ".service", ".md", ".txt", ".yaml", ".yml")):
                # Skip files in keys directory and other excluded paths
                if 'keys' in root or '.git' in root or '__pycache__' in root:
                    continue
                path = os.path.join(root, fname)
                files_to_hash.append(path)
    
    # Sort files for deterministic hashing
    files_to_hash.sort()
    
    # Hash each file's content
    for file_path in files_to_hash:
        try:
            with open(file_path, "rb") as f:
                file_content = f.read()
            # Include relative path in hash to ensure file location matters
            rel_path = os.path.relpath(file_path, base_dir)
            sha256_digest.update(rel_path.encode('utf-8'))
            sha256_digest.update(file_content)
        except Exception as e:
            print(f"Warning: Could not hash {file_path}: {e}")
    
    return sha256_digest.hexdigest()


def save_code_hash(code_hash, path="keys/code_hash.txt"):
    """Save enclave manager code hash to file."""
    with open(path, "w") as f:
        f.write(code_hash)


def _is_pcr15_extended():
    """Check if PCR 15 has already been extended."""
    try:
        result = subprocess.run(
            ["sudo", "tpm2_pcrread", "sha256:15"],
            capture_output=True, text=True, check=False, timeout=5
        )
        if result.returncode != 0:
            return False
        # Parse output: "    15 : 0x<64 hex chars>" - PCR 15 value
        match = re.search(r"15\s*:\s*0x([a-fA-F0-9]{64})", result.stdout)
        if match:
            value = match.group(1).lower()
            return value != "0" * 64
        return False
    except Exception:
        return False


def measure_enclave_manager_code_vtpm(base_dir="/home/kanonTEE/P3DX-SE-manager"):
    """
    Hash enclave manager code directory and extend to PCR 15 .
    """
    if _is_pcr15_extended():
        print("Enclave manager code already extended to PCR 15.")
    else:
        print(f"Hashing enclave manager code directory: {base_dir}")
        code_hash = hash_enclave_manager_code(base_dir)
        
        if code_hash:
            print(f"SHA256 digest for enclave manager code is: {code_hash}")
            save_code_hash(code_hash)
            
            extend_result = subprocess.run(
                ["sudo", "tpm2_pcrextend", f"15:sha256={code_hash}"],
                capture_output=True, text=True, check=False
            )
            if extend_result.returncode == 0:
                print("Enclave manager code hash extended successfully to PCR 15.")
            else:
                err = extend_result.stderr.strip() or extend_result.stdout.strip() or "Unknown error"
                print(f"Warning: Failed to extend to PCR 15: {err}")


def measureDockervTPM(link):
    """Extend image digest to PCR 11.
    """
    sha256_digest = hash_docker_image(link)
    if sha256_digest:
        print(f"SHA256 digest for image '{link}' is: {sha256_digest}")
        extend_result = subprocess.run(
            ["sudo", "tpm2_pcrextend", f"11:sha256={sha256_digest}"],
            capture_output=True, text=True, check=False
        )
        if extend_result.returncode == 0:
            print("Measurement extended successfully to PCR 11.")
        else:
            err = extend_result.stderr.strip() or extend_result.stdout.strip() or "Unknown error"
            print(f"Warning: Failed to extend to PCR 11: {err}")


def generate_nonce(size=32):
    """Generate a cryptographically secure random nonce."""
    nonce = secrets.token_bytes(size)
    return base64.urlsafe_b64encode(nonce).decode("utf-8")


def save_nonce(nonce, path="keys/deployment_nonce.txt"):
    with open(path, "w") as f:
        f.write(nonce)


def extend_nonce_to_pcr8(nonce, pcr_file_path="keys/pcr_values.json"):
    """Extend nonce hash into PCR 8.
    """
    nonce_hash = hashlib.sha256(nonce.encode()).hexdigest()
    extend_result = subprocess.run(
        ["sudo", "tpm2_pcrextend", f"8:sha256={nonce_hash}"],
        capture_output=True, text=True, check=False
    )
    if extend_result.returncode == 0:
        print("Nonce extended successfully to PCR 8.")
    else:
        err = extend_result.stderr.strip() or extend_result.stdout.strip() or "Unknown error"
        print(f"Warning: Failed to extend nonce to PCR 8: {err}")

    pcr_values = {}
    try:
        result = subprocess.run(
            ["sudo", "tpm2_pcrread", "sha256:0,1,2,3,4,5,6,7,8,11,15"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n")[1:]:
                parts = line.split(":")
                if len(parts) == 2:
                    pcr_values[parts[0].strip()] = parts[1].strip()
            with open(pcr_file_path, "w") as f:
                f.write(json.dumps(pcr_values))
            print(f"PCR values written to {pcr_file_path} (PCRs 0-8, 11, 15)")
        else:
            err = result.stderr.strip() if result.stderr else "tpm2_pcrread not available"
            print(f"Warning: Error reading PCR values: {err}")
    except Exception as exc:
        print(f"Warning: Error writing pcr_values.json: {exc}")


def execute_guest_attestation():
    """Run guest attestation sample app to generate a JWT."""
    script_dir = os.path.dirname(__file__)
    commands_folder = os.path.join(
        script_dir, "guest_attestation/cvm-attestation-sample-app"
    )
    original_cwd = os.getcwd()
    jwt_file = os.path.join(script_dir, "keys", "jwt-response.txt")
    
    try:
        if not os.path.exists(commands_folder):
            raise RuntimeError(f"Guest attestation folder not found: {commands_folder}")
        
        os.chdir(commands_folder)
        result = subprocess.run(
            ["python3", "generate-token.py"],
            capture_output=True,
            text=True,
            check=False
        )
        
        stdout_info = result.stdout.strip() if result.stdout else ""
        stderr_info = result.stderr.strip() if result.stderr else ""
        
        if result.returncode != 0:
            error_msg = stderr_info if stderr_info else stdout_info
            if not error_msg:
                error_msg = f"Process exited with code {result.returncode}"
            raise RuntimeError(f"Guest attestation failed: {error_msg}")
        
        if not os.path.exists(jwt_file):
            resolved_path = os.path.abspath("../../keys/jwt-response.txt")
            error_details = []
            if stdout_info:
                error_details.append(f"stdout: {stdout_info}")
            if stderr_info:
                error_details.append(f"stderr: {stderr_info}")
            if not error_details:
                error_details.append("No output captured")
            
            error_msg = (
                f"JWT file was not created. Expected: {jwt_file}, "
                f"Resolved from script dir: {resolved_path}. "
                f"Script output: {'; '.join(error_details)}"
            )
            
            if "Error executing command" in stdout_info or stderr_info:
                error_msg += (
                    f" The AttestationClient command failed. "
                    f"Please check if AttestationClient is executable and if the nonce file exists."
                )
            
            raise RuntimeError(error_msg)
        
    finally:
        os.chdir(original_cwd)


def call_set_state_endpoint(state, address):
    """Helper to call the enclave setstate endpoint."""
    endpoint_url = urllib.parse.urljoin(address, "/enclave/setstate")
    payload = {"state": state}
    response = requests.post(endpoint_url, json=payload)
    print(response.text)


def setState(title, description, step, maxSteps, address):
    """Update enclave state via the manager endpoint."""
    state = {
        "title": title,
        "description": description,
        "step": step,
        "maxSteps": maxSteps
    }
    call_set_state_endpoint(state, address)


def ensure_tee_folders():
    """Create TEE folders if they don't exist and clean old files."""
    folders = [
        '/tmp/tee_input/data',
        '/tmp/tee_input/config',
        '/tmp/tee_output',
        '/tmp/urls'
    ]
    
    for folder in folders:
        if os.path.exists(folder):
            # Remove old files but keep directory
            for item in os.listdir(folder):
                item_path = os.path.join(folder, item)
                if os.path.isfile(item_path):
                    os.remove(item_path)
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)
        else:
            os.makedirs(folder, exist_ok=True)
        print(f"Ensured folder exists: {folder}")


def get_jwt_from_file():
    """Read JWT from jwt-response.txt file."""
    jwt_file = "keys/jwt-response.txt"
    if not os.path.exists(jwt_file):
        raise FileNotFoundError(f"JWT file not found: {jwt_file}")
    with open(jwt_file, 'r') as f:
        return f.read().strip()


def send_jwt_to_ui(jwt, address):
    """Send JWT to UI endpoint for polling."""
    endpoint_url = urllib.parse.urljoin(address, "/enclave/jwt")
    payload = {"jwt": jwt}
    response = requests.post(endpoint_url, json=payload)
    if response.status_code == 200:
        print("JWT sent to UI successfully")
        return True
    else:
        print(f"Failed to send JWT to UI: {response.status_code} - {response.text}")
        return False


def wait_for_bundle_from_ui(address, timeout=300):
    """Poll UI endpoint for encrypted bundle."""
    endpoint_url = urllib.parse.urljoin(address, "/enclave/bundle")
    start_time = time.time()
    
    print(f"Waiting for bundle from UI (timeout: {timeout}s)...")
    while time.time() - start_time < timeout:
        try:
            response = requests.get(endpoint_url, timeout=5)
            if response.status_code == 200:
                bundle_data = response.json()
                if bundle_data.get('bundle'):
                    print("Bundle received from UI")
                    return bundle_data
            elif response.status_code == 404:
                # No bundle yet, continue polling
                time.sleep(2)
                continue
            else:
                print(f"Unexpected status: {response.status_code}")
                time.sleep(2)
        except requests.exceptions.RequestException as e:
            time.sleep(2)
            continue
    
    raise TimeoutError(f"Timeout waiting for bundle from UI after {timeout} seconds")


def save_bundle_to_file(bundle_data, bundle_path="Bundle/encrypted.json"):
    """Save bundle data to file."""
    os.makedirs(os.path.dirname(bundle_path), exist_ok=True)
    with open(bundle_path, 'w') as f:
        json.dump(bundle_data, f, indent=2)
    print(f"Bundle saved to: {bundle_path}")
    return bundle_path


def decrypt_bundle_tee(bundle_path, private_key_path):
    """Decrypt bundle using decryption.py logic."""
    print("Decrypting bundle...")
    decrypt_bundle(bundle_path, private_key_path)
    print("Bundle decrypted successfully")


def fetch_and_decrypt_data(config_path="DPconfig.json"):
    """Fetch encrypted data from Azure Blob Storage and decrypt using fetch_data.py logic."""
    fetch_data = _get_fetch_data()
    print("Fetching and decrypting data from Azure Blob Storage...")
    fetch_data.fetch_and_decrypt_tee()
    print("Data fetched and decrypted successfully")


def run_docker_containers():
    """Start docker containers in detached mode and follow logs live."""
    print("Stopping existing containers...", flush=True)
    subprocess.run(["sudo", "docker-compose", "down"], capture_output=True, text=True)
    
    print("Starting containers in detached mode...", flush=True)
    start_result = subprocess.run(
        ["sudo", "docker-compose", "up", "--build", "-d"],
        capture_output=True,
        text=True
    )
    if start_result.returncode != 0:
        print(f"ERROR: Docker Compose 'up' failed with exit code {start_result.returncode}", flush=True)
        print(f"Stderr: {start_result.stderr}", flush=True)
        print(f"Stdout: {start_result.stdout}", flush=True)
        raise RuntimeError(f"Application failed to start. Check logs for details.")
    
    print("Containers started. Following container logs live...", flush=True)
    print("="*60, flush=True)
    print("CONTAINER LOGS (live):", flush=True)
    print("="*60, flush=True)
    
    log_process = subprocess.Popen(
        ["sudo", "docker-compose", "logs", "-f"],
        stdout=sys.stdout,
        stderr=sys.stderr,
        text=True,
        bufsize=1
    )
    
    log_process.wait()
    
    ps_result = subprocess.run(
        ["sudo", "docker-compose", "ps", "-q"],
        capture_output=True,
        text=True
    )
    if ps_result.returncode == 0 and ps_result.stdout.strip():
        ps_status = subprocess.run(
            ["sudo", "docker-compose", "ps"],
            capture_output=True,
            text=True
        )
        print("\n" + "="*60, flush=True)
        print("Container Status:", flush=True)
        print(ps_status.stdout, flush=True)
    
    print("\n" + "="*60, flush=True)
    print("Application execution complete. Output saved to /tmp/tee_output", flush=True)


def encrypt_and_upload_output(config_path="DPconfig.json"):
    """Encrypt all files in output folder and upload to Azure Blob Storage."""
    fetch_data = _get_fetch_data()
    output_dir = "/tmp/tee_output"
    urls_path = Path("/tmp/urls/decrypted_urls.json")

    if not urls_path.exists():
        raise FileNotFoundError(
            f"decrypted_urls.json not found at {urls_path}. "
            "Cannot determine upload location without decrypted URLs."
        )
    
    with open(urls_path, "r") as f:
        urls = json.load(f)
    
    if "keyVaultUrl" not in urls:
        raise ValueError("keyVaultUrl not found in decrypted_urls.json")
    
    keyvault_url = urls["keyVaultUrl"]
    
    if "outputContainerUrl" not in urls:
        raise ValueError("outputContainerUrl not found in decrypted_urls.json")
    
    container_base_url = urls["outputContainerUrl"].rstrip("/")
    
    print("Fetching encryption key from Key Vault...")
    fernet_key = fetch_data.fetch_fernet_key_from_kv(keyvault_url)
    cipher = create_fernet_cipher(fernet_key)
    
    if not os.path.exists(output_dir):
        raise FileNotFoundError(f"Output directory not found: {output_dir}")
    
    output_files = [
        os.path.join(output_dir, f)
        for f in os.listdir(output_dir)
        if os.path.isfile(os.path.join(output_dir, f))
    ]
    
    if not output_files:
        raise FileNotFoundError(f"No files found in output directory: {output_dir}")
    
    print(f"Found {len(output_files)} file(s) to encrypt and upload")
    
    # Upload each encrypted file
    for output_file in output_files:
        print(f"Encrypting {output_file}...")
        with open(output_file, 'rb') as f:
            plaintext = f.read()
        
        encrypted_data = cipher.encrypt(plaintext)
        
        encrypted_filename = os.path.basename(output_file) + '.enc'
        temp_encrypted = f"/tmp/{encrypted_filename}"
        with open(temp_encrypted, 'wb') as f:
            f.write(encrypted_data)
        
        upload_blob_url = f"{container_base_url}/{encrypted_filename}"
        print(f"Uploading to blob storage: {upload_blob_url}...")
        
        try:
            fetch_data.upload_blob(upload_blob_url, temp_encrypted)
            print(f"Successfully uploaded {encrypted_filename}")
        except Exception as e:
            print(f"Failed to upload {encrypted_filename}: {e}")
            raise
        
        os.remove(temp_encrypted)
    
    print("Output encryption and upload complete")


def get_app_status():
    """Read status.json and return to UI
    
    Returns:
        dict: Status response with one of:
            - {"status": "processing", "message": "..."} if status.json doesn't exist yet
            - status.json content as-is on success/error (app controls structure)
    """
    status_file = "/tmp/tee_output/status.json"
    
    if not os.path.exists(status_file):
        return {
            "status": "processing",
            "message": "Application is still running. Status will be available once processing completes."
        }
    
    try:
        with open(status_file, 'r', encoding='utf-8') as f:
            status_data = json.load(f)
        return status_data
    except json.JSONDecodeError as e:
        return {
            "status": "error",
            "error": {
                "code": "JSON_PARSE_ERROR",
                "message": "Failed to parse status.json",
                "details": str(e)
            }
        }
    except Exception as e:
        return {
            "status": "error",
            "error": {
                "code": "UNEXPECTED_ERROR",
                "message": "Unexpected error reading status",
                "details": str(e)
            }
        }


def restart_enclave_manager():
    """Restart the enclave manager systemd service."""
    print("Restarting enclavemanager service...", flush=True)
    result = subprocess.run(
        ["sudo", "systemctl", "restart", "enclavemanager.service"],
        capture_output=True,
        text=True
    )
    if result.returncode == 0:
        print("enclavemanager service restarted successfully", flush=True)
        # Give service a moment to fully restart
        time.sleep(2)
    else:
        print(f"Warning: Failed to restart enclavemanager service: {result.stderr}", flush=True)
