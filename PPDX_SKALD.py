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
    with open(config_path, 'r') as f:
        return json.load(f)


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
    """
    Returns SHA256 hash of the docker image config + layers
    """
    import subprocess
    import json
    import hashlib

    result = subprocess.run(
        ["docker", "inspect", image],
        capture_output=True,
        text=True,
        check=True
    )

    image_json = json.loads(result.stdout)[0]
    image_bytes = json.dumps(image_json, sort_keys=True).encode()

    return hashlib.sha256(image_bytes).hexdigest()


def save_image_hash(image_hash, path="keys/image_hash.txt"):
    with open(path, "w") as f:
        f.write(image_hash)


def measureDockervTPM(link):
    """Measure docker image digest into vTPM and save PCR values."""
    try:
        print(f"Fetching SHA256 digest for Docker image '{link}'...")
        repo_name, tag = link.split(":")
        response = requests.get(
            f"https://registry.hub.docker.com/v2/repositories/{repo_name}/tags/{tag}"
        )
        if response.status_code == 200:
            sha256_digest = response.json()["images"][0]["digest"].replace("sha256:", "")
            print(f"SHA256 digest for image '{link}' is: {sha256_digest}")
            print("Extending the measurement to PCR 15 using TPM2 tools...")
            subprocess.run(["sudo", "tpm2_pcrextend", f"15:sha256={sha256_digest}"])
            print("Measurement extended successfully to PCR 15.")
        else:
            print(f"Error: Image '{link}' not found.")
    except Exception as exc:
        print("Error:", exc)

    try:
        command = ["sudo", "tpm2_pcrread", "sha256:0,1,2,3,4,5,6,7,8,15"]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode == 0:
            pcr_values = {}
            for line in result.stdout.strip().split("\n")[1:]:
                parts = line.split(":")
                if len(parts) == 2:
                    pcr_values[parts[0].strip()] = parts[1].strip()
            with open(os.path.join("keys", "pcr_values.json"), "w") as file:
                file.write(json.dumps(pcr_values))
            print("PCR values written to file successfully!")
        else:
            print(f"Error reading PCR values: {result.stderr}")
    except Exception as exc:
        print("Error:", exc)


def extend_image_hash_to_vtpm(image_hash, pcr=14):
    subprocess.run(
        ["sudo", "tpm2_pcrextend", f"{pcr}:sha256={image_hash}"],
        check=True
    )


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
