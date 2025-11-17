import json
import os
import subprocess
import shutil
import sys


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
    lines = message.splitlines()
    max_width = max(len(line) for line in lines)

    # Top border
    print("+" + "-" * (max_width + 2) + "+")

    # Content with padding
    for line in lines:
        print("| " + line.ljust(max_width) + " |")

    # Bottom border
    print("+" + "-" * (max_width + 2) + "+")


def validate_github_link(github_raw_link):
    """Validate GitHub raw link format and exit if invalid."""
    if not github_raw_link.startswith("https://raw.githubusercontent.com/"):
        print("Error: Invalid GitHub raw link format.")
        sys.exit(1)


def remove_docker_compose():
    """Remove docker-compose.yml file if it exists."""
    file_path = os.path.join('.', 'docker-compose.yml')
    if os.path.exists(file_path):
        os.remove(file_path)
        print(f"Removed file: {file_path}")
    else:
        print(f"File not found: {file_path}")


def remove_keys_folder():
    """Remove keys folder if it exists."""
    folder_path = os.path.join('.', 'keys')
    if os.path.exists(folder_path):
        shutil.rmtree(folder_path)
        print(f"Removed folder and contents: {folder_path}")
    else:
        print(f"Folder not found: {folder_path}")


def pull_and_extract_docker_image(sdk, github_raw_link):
    """
    Step 1: Pull docker compose file and extract docker image link.
    
    Args:
        sdk: The SDK module (PPDX_SDK or PPDX_SDK_DP)
        github_raw_link: GitHub raw URL for docker-compose file
        
    Returns:
        str: Docker image link
    """
    box_out("Pulling Docker Compose from GitHub...")
    sdk.pull_compose_file(github_raw_link)
    print('Extracting docker link...')
    link = subprocess.check_output(["sudo", "docker", "compose", "config", "--images"]).decode().strip()
    print("Image information:", link)
    return link


def generate_keys(sdk, address):
    """
    Step 2: Generate and save key pair with state update.
    
    Args:
        sdk: The SDK module (PPDX_SDK or PPDX_SDK_DP)
        address: Enclave manager address
        
    Returns:
        Key pair (if SDK returns it, else None)
    """
    box_out("Generating and saving key pair...")
    sdk.setState("TEE Attestation & Authorisation", "Step 2", 2, 5, address)
    key = sdk.generate_and_save_key_pair()
    return key


def pull_docker_image(sdk, link):
    """
    Step 3: Pull docker image.
    
    Args:
        sdk: The SDK module (PPDX_SDK or PPDX_SDK_DP)
        link: Docker image link
    """
    box_out("Pulling docker image...")
    sdk.pull_docker_image(link)
    print("Pulled docker image")


def measure_docker_vtpm(sdk, link):
    """
    Step 4: Measure Docker image into vTPM.
    
    Args:
        sdk: The SDK module (PPDX_SDK or PPDX_SDK_DP)
        link: Docker image link
    """
    box_out("Measuring Docker image into vTPM...")
    sdk.measureDockervTPM(link)
    print("Measured and stored in vTPM")


def execute_attestation(sdk):
    """
    Step 5: Execute guest attestation.
    
    Args:
        sdk: The SDK module (PPDX_SDK or PPDX_SDK_DP)
    """
    box_out("Guest Attestation Executing...")
    sdk.execute_guest_attestation()
    print("Guest Attestation complete. JWT received from MAA")


def get_token_from_apd(sdk, config):
    """
    Step 6: Send JWT to APD for verification.
    
    Args:
        sdk: The SDK module
        config: Configuration dictionary
        
    Returns:
        Access token
    """
    box_out("Sending JWT to APD for verification...")
    token = sdk.getAttestationToken(config)
    print("Access token received from APD")
    return token


def get_data_state_update(sdk, address):
    """
    Update state for getting data into secure enclave.
    
    Args:
        sdk: The SDK module (PPDX_SDK or PPDX_SDK_DP)
        address: Enclave manager address
    """
    box_out("Getting files from RS...")
    sdk.setState("Getting data into Secure enclave", "Step 3", 3, 5, address)


def run_docker_application(sdk, address, message="Running the Application..."):
    """
    Run the docker compose application.
    
    Args:
        sdk: The SDK module (PPDX_SDK or PPDX_SDK_DP)
        address: Enclave manager address
        message: Custom message for setState
    """
    box_out(message)
    sdk.setState(message, "Step 4", 4, 5, address)
    subprocess.run(["sudo", "docker", "compose", 'up'])


def final_state_update(sdk, address, message="Secure Execution Complete"):
    """
    Final state update for completion.
    
    Args:
        sdk: The SDK module (PPDX_SDK or PPDX_SDK_DP)
        address: Enclave manager address
        message: Completion message
    """
    sdk.setState(message, "Step 5", 5, 5, address)
    print('DONE')
