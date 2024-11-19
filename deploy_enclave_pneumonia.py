import subprocess
import os
import PPDX_SDK
import sys
import json
import shutil
import time
import psutil
import logging
from datetime import datetime

# Simulate sourcing external scripts -  
# You'd integrate the necessary functions from setState.sh and profilingStep.sh here 


def load_config(filename):
    """Loads configuration data from a JSON file."""
    try:
        with open(filename, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        raise FileNotFoundError(f"Configuration file '{filename}' not found.")
    except json.JSONDecodeError:
        raise ValueError(f"Invalid JSON format in configuration file '{filename}'.")

def box_out(message):
    """Prints a box around a message using text characters."""

    lines = message.splitlines()  # Split message into lines
    max_width = max(len(line) for line in lines)  # Find longest line

    # Top border
    print("+" + "-" * (max_width + 2) + "+")

    # Content with padding
    for line in lines:
        print("| " + line.ljust(max_width) + " |")

    # Bottom border
    print("+" + "-" * (max_width + 2) + "+")


def remove_profiling_file():
    if os.path.exists("profiling.json"):
        os.remove("profiling.json")

def remove_files():
    file_path = os.path.join('.','docker-compose.yml')
    if os.path.exists(file_path):
        os.remove(file_path)
        print(f"Removed file: {file_path}")
    else:
        print(f"File not found: {file_path}")

    folder_path = os.path.join('.', 'keys')
    if os.path.exists(folder_path):
        shutil.rmtree(folder_path)
        print(f"Removed folder and contents: {folder_path}")
    else:
        print(f"Folder not found: {folder_path}")

    # Define and remove '/tmp/inputdata' if it exists
    folder_path = os.path.join('/tmp', 'inputdata')
    if os.path.exists(folder_path):
        shutil.rmtree(folder_path)
        print(f"Removed folder and contents: {folder_path}")
    else:
        print(f"Folder not found: {folder_path}")

    # Recreate the folder
    os.makedirs(folder_path)
    print(f"Recreated folder: {folder_path}")

    # Give 'a+x' permissions to the folder
    os.chmod(folder_path, 0o755)  # '755' gives rwxr-xr-x (a+x)
    print(f"Set a+x permissions on folder: {folder_path}")

    # Define and remove '/tmp/output' if it exists
    folder_path = os.path.join('/tmp', 'output')
    if os.path.exists(folder_path):
        shutil.rmtree(folder_path)
        print(f"Removed folder and contents: {folder_path}")
    else:
        print(f"Folder not found: {folder_path}")

    # Recreate the folder
    os.makedirs(folder_path)
    print(f"Recreated folder: {folder_path}")

    # Give 'a+x' permissions to the folder
    os.chmod(folder_path, 0o755)  # '755' gives rwxr-xr-x (a+x)
    print(f"Set a+x permissions on folder: {folder_path}")

# Start the main process
if __name__ == "__main__":
    config_file = "config_file_pneumonia.json"
    config = load_config(config_file)  # Loads configuration into a dictionary
    address = config["enclaveManagerAddress"]
    
    #PPDX_SDK.profiling_steps('Application Start', 0)
    #remove_profiling_file()
    remove_files()

    if len(sys.argv) < 2:
        print("Error: Missing GitHub raw link argument.")
        print("Usage: sudo python3 deploy_enclave.py <github_raw_link>")
        sys.exit(1)  # Exit with an error code

    github_raw_link = sys.argv[1]
    if not github_raw_link.startswith("https://raw.githubusercontent.com/"):
        print("Error: Invalid GitHub raw link format.")
        sys.exit(1)

    # Step 1 - Pulling docker compose & extracting docker image link
    box_out("Pulling Docker Compose from GitHub...")
    PPDX_SDK.pull_compose_file(github_raw_link)
    print('Extracting docker link...')
    link = subprocess.check_output(["sudo", "docker", "compose", "config", "--images"]).decode().strip()
    print("Image information:", link)

    # Step 3 - Docker image pulling
    box_out("Pulling docker image...")
    PPDX_SDK.pull_docker_image(link)
    print("Pulled docker image")

    # Step 2 - Key generation
    box_out("Generating and saving key pair...")
    PPDX_SDK.setState("TEE Attestation & Authorisation", "Step 2",2,5,address)
    PPDX_SDK.generate_and_save_key_pair()

    # Step 4 - Measuring image and storing in vTPM
    box_out("Measuring Docker image into vTPM...")
    PPDX_SDK.measureDockervTPM(link)
    print("Measured and stored in vTPM")

    # Step 5 - Send VTPM & public key to MAA & get attestation token
    box_out("Guest Attestation Executing...")
    PPDX_SDK.execute_guest_attestation()
    print("Guest Attestation complete. JWT received from MAA")

    # Step 6 - Send the JWT to APD
    box_out("Sending JWT to APD for verification...")
    token=PPDX_SDK.getAttestationToken(config)
    print("Access token received from APD")

    # Step 7 - Getting data
    box_out("Getting files from RS...")
    PPDX_SDK.setState("Getting data into Secure enclave","Step 3",3,5,address)
    PPDX_SDK.getFileFromResourceServer(token)

    box_out("Decrypting & storing files...")
    PPDX_SDK.decryptFile()
    print("Files decrypted and stored in /tmp/inputdata")

    # Executing the application in the docker
    box_out("Running the Application...")
    PPDX_SDK.setState("Running pneumonia detection application", "Step 4",4,5,address)
    subprocess.run(["sudo", "docker", "compose", 'up'])

    PPDX_SDK.setState("Secure Execution Complete", "Step 5", 5, 5, address)
    print('DONE')
    print('Output saved to /tmp/output')