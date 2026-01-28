import os
import sys
import subprocess
import json
import base64
import gzip
import tarfile
import urllib.parse
import time
import shutil
import glob
import re
import csv
import hashlib

import requests
import _pickle as pickle
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.fernet import Fernet


def load_config_file(config_path="DPconfig.json"):
    """Load configuration from JSON file."""
    ssh_config_path = "/tmp/SSH_config/ssh-config.json"
    base_config = {}
    
    # Load base config if it exists
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                base_config = json.load(f)
        except Exception as e:
            print(f"Warning: Failed to load base config from {config_path}: {e}")
    
    # Load SSH config from bundle if available
    ssh_config_loaded = False
    if os.path.exists(ssh_config_path):
        try:
            with open(ssh_config_path, 'r') as f:
                ssh_config = json.load(f)
            print(f"Using SSH config from encrypted bundle: {ssh_config_path}")
            # Merge SSH config into base config (SSH config takes precedence)
            base_config.update(ssh_config)
            ssh_config_loaded = True
        except Exception as e:
            print(f"Warning: Failed to load SSH config from bundle: {e}, using base config only")
    
    # Validate required SSH parameters if SSH operations will be performed
    required_ssh_params = ['ssh_host', 'ssh_user', 'remote_data_dir', 'remote_output_dir']
    missing_params = [param for param in required_ssh_params if param not in base_config]
    
    if missing_params:
        if ssh_config_loaded:
            raise KeyError(f"Missing required SSH parameters in bundle config: {missing_params}")
        elif os.path.exists(config_path):
            raise KeyError(f"Missing required SSH parameters in {config_path}: {missing_params}")
        else:
            raise FileNotFoundError(
                f"SSH config not found at {ssh_config_path} and base config not found at {config_path}. "
                f"Missing required parameters: {missing_params}"
            )
    
    # Return base config if SSH config not available
    if base_config:
        return base_config
    
    raise FileNotFoundError(f"Config file not found: {config_path} and SSH config not available")


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


def find_ssh_key(ssh_key_dir="/tmp/SSH_key"):
    """Find SSH key file in directory and set permissions."""
    ssh_key_files = glob.glob(os.path.join(ssh_key_dir, '*'))
    if not ssh_key_files:
        raise FileNotFoundError(f"No SSH key found in {ssh_key_dir}")
    ssh_key_path = ssh_key_files[0]
    os.chmod(ssh_key_path, 0o600)
    return ssh_key_path


def build_ssh_command(ssh_key_path, ssh_user, ssh_host, remote_command):
    """Build SSH command with standard options."""
    return [
        'ssh',
        '-i', ssh_key_path,
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'ConnectTimeout=10',
        f'{ssh_user}@{ssh_host}',
        remote_command
    ]


def build_scp_command(ssh_key_path, ssh_user, ssh_host, source_path, dest_path, is_upload=True):
    """Build SCP command with standard options.
    
    Args:
        ssh_key_path: Path to SSH private key
        ssh_user: SSH username
        ssh_host: SSH hostname/IP
        source_path: Source file path (local if uploading, remote if downloading)
        dest_path: Destination path (remote if uploading, local if downloading)
        is_upload: True for upload (local->remote), False for download (remote->local)
    """
    if is_upload:
        remote_path = f'{ssh_user}@{ssh_host}:{dest_path}'
        return [
            'scp',
            '-i', ssh_key_path,
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            source_path,
            remote_path
        ]
    else:
        remote_path = f'{ssh_user}@{ssh_host}:{source_path}'
        return [
            'scp',
            '-i', ssh_key_path,
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            remote_path,
            dest_path
        ]


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


def hash_enclave_manager_code(base_dir="/home/kanonTEE/P3DX-SE-manager"):
    """
    Deterministically hash enclave manager code directory.
    Stable unless code changes.
    """
    import hashlib, os

    sha256_digest = hashlib.sha256()

    for root, dirs, files in os.walk(base_dir):
        dirs.sort()
        files.sort()

        for fname in files:
            if fname.endswith((".py", ".sh", ".json", ".service")):
                path = os.path.join(root, fname)
                with open(path, "rb") as f:
                    sha256_digest.update(f.read())
    # if sha256_digest:
    #     print(f"SHA256 digest for enclave manager code '{link}' is: {sha256_digest}")
    #     extend_result = subprocess.run(
    #         ["sudo", "tpm2_pcrextend", f"14:sha256={sha256_digest}"],
    #         capture_output=True, text=True, check=False
    #     )
    #     if extend_result.returncode == 0:
    #         print("Measurement extended successfully to PCR 14.")
    #     else:
    #         err = extend_result.stderr.strip() or extend_result.stdout.strip() or "Unknown error"
    #         print(f"Warning: Failed to extend to PCR 14: {err}")

    return sha256_digest.hexdigest()

def measure_enclave_manager_vtpm():
    """
    Extend enclave manager code hash into PCR 14 exactly once.
    """
    guard_file = "/home/kanonTEE/P3DX-SE-manager/keys/pcr14_extended"

    if os.path.exists(guard_file):
        print("PCR 14 already extended — skipping")
        return

    code_hash = hash_enclave_manager_code()
    print(f"Extending enclave manager code hash to PCR 14: {code_hash}")

    result = subprocess.run(
        ["sudo", "tpm2_pcrextend", f"14:sha256={code_hash}"],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        err = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"PCR 14 extend failed: {err}")
    
    pcr_values = {}
    pcr_file_path = os.path.join("keys", "pcr_values.json")

    try:
        result = subprocess.run(
            ["sudo", "tpm2_pcrread", "sha256:0,1,2,3,4,5,6,7,8,14,15"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n")[1:]:
                parts = line.split(":")
                if len(parts) == 2:
                    pcr_values[parts[0].strip()] = parts[1].strip()
            print("PCR values read from TPM successfully!")
        else:
            err = result.stderr.strip() if result.stderr else "tpm2_pcrread not available"
            print(f"Warning: Error reading PCR values: {err}")
    except Exception as exc:
        print(f"Warning: Error reading PCR values: {exc}")

    with open(guard_file, "w") as f:
        f.write(code_hash)
    if os.path.exists(guard_file):
        with open(guard_file, "r") as f:
            code_hash = f.read().strip()
        if code_hash and "14" not in pcr_values:
            pcr_values["14"] = f"0x{code_hash}"
        
    with open(pcr_file_path, "w") as file:
        file.write(json.dumps(pcr_values))
    print(f"PCR values written to {pcr_file_path} ({len(pcr_values)} entries)")

    print("PCR 14 successfully extended")


def generate_and_save_key_pair():
    """Generate RSA key pair, save to keys/, and return the private key object."""
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

    with open("keys/private_key.pem", "r") as pem_file:
        private_key_pem = pem_file.read()
        print("Using Private Key to Decrypt data")
    key = RSA.import_key(private_key_pem)
    return key


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


def measureDockervTPM(link):
    """Extend image digest to PCR 15, read PCR values, and save to pcr_values.json."""
    pcr_values = {}
    pcr_file_path = os.path.join("keys", "pcr_values.json")
    
    sha256_digest = hash_docker_image(link)
    if sha256_digest:
        print(f"SHA256 digest for image '{link}' is: {sha256_digest}")
        extend_result = subprocess.run(
            ["sudo", "tpm2_pcrextend", f"15:sha256={sha256_digest}"],
            capture_output=True, text=True, check=False
        )
        if extend_result.returncode == 0:
            print("Measurement extended successfully to PCR 15.")
        else:
            err = extend_result.stderr.strip() or extend_result.stdout.strip() or "Unknown error"
            print(f"Warning: Failed to extend to PCR 15: {err}")
    
    try:
        result = subprocess.run(
            ["sudo", "tpm2_pcrread", "sha256:0,1,2,3,4,5,6,7,8,14,15"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n")[1:]:
                parts = line.split(":")
                if len(parts) == 2:
                    pcr_values[parts[0].strip()] = parts[1].strip()
            print("PCR values read from TPM successfully!")
        else:
            err = result.stderr.strip() if result.stderr else "tpm2_pcrread not available"
            print(f"Warning: Error reading PCR values: {err}")
    except Exception as exc:
        print(f"Warning: Error reading PCR values: {exc}")
    
    image_hash_path = os.path.join("keys", "image_hash.txt")
    if os.path.exists(image_hash_path):
        with open(image_hash_path, "r") as f:
            image_hash = f.read().strip()
        if image_hash and "15" not in pcr_values:
            pcr_values["15"] = f"0x{image_hash}"
    
    with open(pcr_file_path, "w") as file:
        file.write(json.dumps(pcr_values))
    print(f"PCR values written to {pcr_file_path} ({len(pcr_values)} entries)")


def generate_nonce(size=32):
    import secrets, base64
    nonce = secrets.token_bytes(size)
    return base64.urlsafe_b64encode(nonce).decode("utf-8")


def save_nonce(nonce, path="keys/deployment_nonce.txt"):
    with open(path, "w") as f:
        f.write(nonce)

def extend_nonce_to_vtpm(nonce, pcr=14):
    nonce_hash = hashlib.sha256(nonce.encode()).hexdigest()
    result = subprocess.run([
        "sudo", "tpm2_pcrextend",
        f"{pcr}:sha256={nonce_hash}"
    ], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        error_msg = result.stderr.strip() if result.stderr else result.stdout.strip()
        if not error_msg:
            error_msg = f"Process exited with code {result.returncode}"
        raise RuntimeError(f"Failed to extend nonce to vTPM: {error_msg}")

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


def getTokenFromAPD(jwt_file, config, dataset, rs_url):
    """Send JWT to APD for verification and return the access token."""
    apd_url = config["apd_url"]
    headers = {
        "clientId": config["clientId"],
        "clientSecret": config["clientSecret"],
        "Content-Type": config["Content-Type"],
    }

    with open("keys/" + jwt_file, "r") as file:
        token = file.read().strip()

    context = {"jwtMAA": token, "dataset_name": dataset, "rs_url": rs_url}
    data = {
        "itemId": config["itemId"],
        "itemType": config["itemType"],
        "role": config["role"],
        "context": context,
    }
    r = requests.post(apd_url, headers=headers, data=json.dumps(data))
    if r.status_code == 200:
        print("Token verified and Token recieved.")
        jsonResponse = r.json()
        token = jsonResponse.get("results").get("accessToken")
        print(token)
        return token
    print("Token verification failed.", r.text)
    sys.exit()


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


def pullconfig(url, token, key):
    """Pull and decrypt DP application config from resource server."""
    print("Pulling DP application config from RS..")
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        print(f"Failed to download file. Status code: {response.status_code}")
        return

    loadedDict = pickle.loads(response.content)
    print("Data downloaded successfully")
    
    encryptedKey = base64.b64decode(loadedDict["encryptedKey"])
    decryptor = PKCS1_OAEP.new(key)
    plainKey = decryptor.decrypt(encryptedKey)
    print("Symmetric key decrypted using the enclave's private RSA key.")
    
    fernetKey = Fernet(plainKey)
    decryptedConfig = fernetKey.decrypt(loadedDict["encConfig"])
    print("Config decrypted")

    decryptedConfigDict = json.loads(decryptedConfig.decode("utf-8"))
    config_path = os.path.expanduser("/tmp/DPinput/config")
    os.makedirs(config_path, exist_ok=True)
    config_file = os.path.join(config_path, "config.json")
    with open(config_file, "w") as json_file:
        json.dump(decryptedConfigDict, json_file, indent=4)
    print("Decrypted config written to tmp/DPinput/config")


def getChunkFromResourceServer(n, url, token):
    """Fetch encrypted chunk n from the resource server."""
    rs_url = f"{url}{n}"
    headers = {"Authorization": f"Bearer {token}"}
    print(rs_url)
    response = requests.get(rs_url, headers=headers)
    if response.status_code == 200:
        print("Token authenticated and Encrypted data recieved.")
        return pickle.loads(response.content)
    print(response.text)
    return None


def decryptChunk(loadedDict, n, key):
    """Decrypt one chunk and write it to /tmp/DPinput."""
    print("Decrypting chunk..")
    encryptedKey = base64.b64decode(loadedDict["encryptedKey"])
    decryptor = PKCS1_OAEP.new(key)
    plainKey = decryptor.decrypt(encryptedKey)
    fernetKey = Fernet(plainKey)
    decryptedData = fernetKey.decrypt(loadedDict["encData"])

    temp_dir = os.path.expanduser("/tmp/DPinput")
    decrypted_data_folder = os.path.join(temp_dir, "encrypted_data")
    extracted_data_folder = os.path.join(temp_dir, "inputdata")
    os.makedirs(decrypted_data_folder, exist_ok=True)
    os.makedirs(extracted_data_folder, exist_ok=True)

    decrypted_data_path = os.path.join(decrypted_data_folder, f"outfile{n}.gz")
    if os.path.exists(decrypted_data_path):
        os.remove(decrypted_data_path)
    with open(decrypted_data_path, "wb") as f:
        f.write(decryptedData)

    with gzip.open(decrypted_data_path, "rb") as file:
        data = file.read().decode("utf-8")
        json_data = json.loads(data)

    outfile_path = os.path.join(extracted_data_folder, f"data{n}.json")
    with open(outfile_path, "w", encoding="utf-8") as outfile:
        outfile.write("[\n")
        for i, record in enumerate(json_data):
            json_record = json.dumps(record, indent=4)
            outfile.write(json_record + (",\n" if i < len(json_data) - 1 else "\n"))
        outfile.write("]\n")


def dataChunkN(n, url, access_token, key):
    """Pull and decrypt chunk n; return 1 on success else 0."""
    loadedDict = getChunkFromResourceServer(n, url, access_token)
    if not loadedDict:
        return 0
    decryptChunk(loadedDict, n, key)
    return 1


def getInferenceFernetKey(key, url, access_token):
    """Retrieve the Fernet key for encrypting inference output."""
    print("Getting the inference Fernet key..")
    print("Accessing: ", url)
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        print("Token authenticated and pickle file recieved.")
        loadedDict = pickle.loads(response.content)
        print(loadedDict.keys())
        b64encryptedKey = loadedDict["encryptedKey"]
    else:
        print(response.text)
        return None

    print("The b64encryptedKey is: ", b64encryptedKey)
    encrypted_inference_key = base64.b64decode(b64encryptedKey)
    decryptor = PKCS1_OAEP.new(key)
    return decryptor.decrypt(encrypted_inference_key)


def encryptInference(inference_key):
    """Package and encrypt inference output located in /tmp/DPoutput."""
    print("Encrypting inference")
    output_file = os.path.expanduser("/tmp/DPoutput/concat_output.json")
    config_dir = os.path.expanduser("/tmp/DPinput/config")

    with open(output_file, "r") as f:
        concat_output = json.load(f)

    files = os.listdir(config_dir)
    if len(files) != 1:
        raise Exception(f"Expected exactly one file in {config_dir}, but found {len(files)} files.")

    config_file_path = os.path.join(config_dir, files[0])
    with open(config_file_path, "r") as f:
        config = json.load(f)
    concat_output["dataset"] = config["data_type"]

    with open(output_file, "w") as f:
        json.dump(concat_output, f, indent=4)

    inference_file = os.path.expanduser("/tmp/DPoutput/inference.json")
    os.rename(output_file, inference_file)
    print(f"File renamed and saved as {inference_file}")

    print("Encrypting the output file")
    tarball = "pipelineOutput.tar"
    tar = tarfile.open(tarball, "w")
    tar.add(inference_file, arcname="inference.json")
    tar.close()

    fernet = Fernet(inference_key)
    with open(tarball, "r+b") as dataFile:
        enc_inference = fernet.encrypt(dataFile.read())

    pickled_data = pickle.dumps({
        "encInference": enc_inference,
        "tarName": "pipelineOutput.tar"
    })
    os.remove(tarball)
    return pickled_data


def sendInference(inference, access_token, url):
    """Send encrypted inference to the resource server."""
    print("Sending the inference to: ", url)
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.post(url, headers=headers, data=inference)
    if response.status_code == 200:
        print("Success!")
    else:
        print("Request failed with status code:", response.status_code)
    print(response.text)


def ensure_skald_folders():
    """Create SKALD folders if they don't exist and clean old files."""
    folders = [
        '/tmp/SKALD_input/input_file',
        '/tmp/SKALD_input/config',
        '/tmp/SKALD_output',
        '/tmp/SKALD_keys',
        '/tmp/SSH_key',
        '/tmp/Symmetric_key'
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


def decrypt_bundle_skald(bundle_path, private_key_path):
    """Decrypt bundle using decryption.py logic."""
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'Bundle'))
    from decryption import decrypt_bundle
    
    print("Decrypting bundle...")
    decrypt_bundle(bundle_path, private_key_path)
    print("Bundle decrypted successfully")


def fetch_and_decrypt_data(config_path="DPconfig.json"):
    """Fetch encrypted data from remote server and decrypt using fetch_data.py logic."""
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'Fetch_data'))
    from fetch_data import fetch_and_decrypt
    
    print("Fetching and decrypting data from remote server...")
    fetch_and_decrypt(config_path)
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
        raise RuntimeError(f"SKALD application failed to start. Check logs for details.")
    
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
    print("Application execution complete. Output saved to /tmp/SKALD_output", flush=True)


def encrypt_inference_skald(config_path="DPconfig.json"):
    """Encrypt inference output and upload to remote server."""
    config = load_config_file(config_path)
    
    remote_host = config["ssh_host"]
    remote_user = config["ssh_user"]
    remote_output_dir = config["remote_output_dir"]
    
    symmetric_key_path = "/tmp/Symmetric_key"
    output_dir = "/tmp/SKALD_output"
    
    if os.path.isdir(symmetric_key_path):
        key_files = glob.glob(os.path.join(symmetric_key_path, '*'))
        if not key_files:
            raise FileNotFoundError(f"No key files found in {symmetric_key_path}")
        symmetric_key_path = key_files[0]
    
    with open(symmetric_key_path, 'rb') as f:
        key_data = f.read().strip()
    
    cipher = create_fernet_cipher(key_data)
    
    required_files = ["generalized.csv", "symmetric_keys.json"]
    output_files = []
    
    for filename in required_files:
        file_path = os.path.join(output_dir, filename)
        if os.path.exists(file_path):
            output_files.append(file_path)
        else:
            raise FileNotFoundError(f"Required file not found: {file_path}")
    
    print(f"Found {len(output_files)} required file(s)")
    
    ssh_key_path = find_ssh_key()
    
    for output_file in output_files:
        print(f"Encrypting {output_file}...")
        with open(output_file, 'rb') as f:
            plaintext = f.read()
        
        encrypted_data = cipher.encrypt(plaintext)
        
        encrypted_filename = os.path.basename(output_file) + '.enc'
        temp_encrypted = f"/tmp/{encrypted_filename}"
        with open(temp_encrypted, 'wb') as f:
            f.write(encrypted_data)
        
        remote_path = f"{remote_output_dir}/{encrypted_filename}"
        print(f"Uploading to {remote_user}@{remote_host}:{remote_path}...")
        
        scp_cmd = build_scp_command(ssh_key_path, remote_user, remote_host, temp_encrypted, remote_path)
        
        result = subprocess.run(scp_cmd, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            print(f"Uploaded {encrypted_filename}")
        else:
            print(f"Failed to upload {encrypted_filename}: {result.stderr}")
        
        os.remove(temp_encrypted)
    
    print("Inference encryption and upload complete")


def get_skald_status_and_preview():
    """Read status.json and return either CSV preview (success) or error details (failure).
    
    Returns:
        dict: Status response with one of:
            - {"status": "processing"} if status.json doesn't exist yet
            - {"status": "success", "preview": [...], "preview_count": int, "outputs": {...}} on success
            - {"status": "error", "error": {...}} on failure
    """
    status_file = "/tmp/SKALD_output/status.json"
    csv_file = "/tmp/SKALD_output/generalized.csv"
    
    if not os.path.exists(status_file):
        return {
            "status": "processing",
            "message": "SKALD application is still running. Status will be available once processing completes."
        }
    
    try:
        with open(status_file, 'r', encoding='utf-8') as f:
            status_data = json.load(f)
        
        if status_data.get("status") == "success":
            if not os.path.exists(csv_file):
                return {
                    "status": "error",
                    "error": {
                        "code": "CSV_FILE_NOT_FOUND",
                        "message": "CSV file not found",
                        "details": f"CSV file does not exist: {csv_file}"
                    }
                }
            
            csv_rows = []
            try:
                with open(csv_file, 'r', encoding='utf-8') as f:
                    csv_reader = csv.DictReader(f)
                    for i, row in enumerate(csv_reader):
                        if i >= 10:
                            break
                        csv_rows.append(row)
            except Exception as e:
                return {
                    "status": "error",
                    "error": {
                        "code": "CSV_READ_ERROR",
                        "message": "Failed to read CSV file",
                        "details": str(e)
                    }
                }
            
            return {
                "status": "success",
                "preview": csv_rows,
                "preview_count": len(csv_rows),
                "outputs": status_data.get("outputs", {})
            }
        
        elif status_data.get("status") == "error":
            return {
                "status": "error",
                "error": status_data.get("error", {})
            }
        
        else:
            return {
                "status": "error",
                "error": {
                    "code": "UNKNOWN_STATUS",
                    "message": "Unknown status in status.json",
                    "details": f"Status field has unexpected value: {status_data.get('status')}"
                }
            }
    
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
    import subprocess
    import time
    
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
