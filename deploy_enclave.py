import subprocess
import os
import PPDX_SDK
import sys
import json
import shutil
import argparse

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
    
    folder_path = os.path.join('/tmp', 'FCoutput')
    if os.path.exists(folder_path):
        shutil.rmtree(folder_path)
        print(f"Removed folder and contents: {folder_path}")
    else:
        print(f"Folder not found: {folder_path}")
    
    # make FCoutput folder
    os.makedirs('/tmp/FCoutput', exist_ok=True)

    folder_path = os.path.join('/tmp', 'FCcontext')
    if os.path.exists(folder_path):
        shutil.rmtree(folder_path)
        print(f"Removed folder and contents: {folder_path}")
    else:
        print(f"Folder not found: {folder_path}")

    # make contextFolder folder if it does not exist
    os.makedirs('/tmp/FCcontext', exist_ok=True)

    folder_path = os.path.join('/tmp', 'FCinput')
    if os.path.exists(folder_path):
        shutil.rmtree(folder_path)
        print(f"Removed folder and contents: {folder_path}")
    else:
        print(f"Folder not found: {folder_path}")

    # make contextFolder folder if it does not exist
    os.makedirs('/tmp/FCinput', exist_ok=True)

    folder_path = os.path.join('.', 'keys')
    if os.path.exists(folder_path):
        shutil.rmtree(folder_path)
        print(f"Removed folder and contents: {folder_path}")
    else:
        print(f"Folder not found: {folder_path}")


# Start the main process
if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('docker_compose_url', type=str, help='The Docker Compose URL')
    parser.add_argument('json_context', type=str, help='The JSON context as a string')

    args = parser.parse_args()
    github_raw_link = args.docker_compose_url
    json_context_str = args.json_context

    try:
        context = json.loads(json_context_str)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")


    config_file = "config.json"
    config = load_config(config_file)
    address = config["address"]

    remove_files()

    if len(sys.argv) < 2:
        print("Error: Missing GitHub raw link argument.")
        print("Usage: sudo python3 deploy_enclave.py <github_raw_link>")
        sys.exit(1)  # Exit with an error code

    if not github_raw_link.startswith("https://raw.githubusercontent.com/"):
        print("Error: Invalid GitHub raw link format.")
        sys.exit(1)

    ppb_number = context["ppb_number"]

    folder_path = os.path.expanduser("/tmp/FCcontext")
    file_path = os.path.join(folder_path, "context.json")

    with open(file_path, 'w') as file:
        json.dump(context, file, indent=4)


    # Step 1 - Pulling docker compose & extracting docker image link
    box_out("Pulling Docker Compose from GitHub...")
    PPDX_SDK.pull_compose_file(github_raw_link)
    print('Extracting docker link...')
    link = subprocess.check_output(["sudo", "docker", "compose", "config", "--images"]).decode().strip()
    print("Image information:", link)

    # Step 2 - Docker image pulling
    box_out("Pulling docker image...")
    PPDX_SDK.pull_docker_image(link)
    print("Pulled docker & got sha digest")

    # Step 4 - Key generation
    box_out("Generating and saving key pair...")
    PPDX_SDK.setState("TEE Attestation & Authorisation", "Step 2",2,5,address)
    PPDX_SDK.generate_and_save_key_pair()
    print("Key pair generated and saved")

    # Step 5 - storing image digest in vTPM
    box_out("Measuring Docker image into vTPM...")
    PPDX_SDK.measureDockervTPM(link)
    print("Measured and stored in vTPM")

    # Step 6 - Send VTPM & public key to MAA & get attestation token
    box_out("Guest Attestation Executing...")
    PPDX_SDK.execute_guest_attestation()
    print("Guest Attestation complete. JWT received from MAA")

    # Step 7 - Send the JWT to APD
    box_out("Sending JWT to APD for verification...")
    attestationToken = PPDX_SDK.getAttestationToken(config)
    print("Attestation token received from APD")

    # Call APD for getting ADEX data access token
    print("Getting ADEX data access token")
    adexDataToken = PPDX_SDK.getADEXDataAccessTokens(config)

    # Call APD for getting Rythabandhu data access token
    print("Getting Rytabandhu consent token")
    farmerDataToken = PPDX_SDK.getFarmerDataToken(config, ppb_number)

    # Step 8 - Getting files from RS
    box_out("Getting files from RS...")
    PPDX_SDK.setState("Getting data into Secure enclave","Step 3",3,5,address)

    # getting files from ADEX
    PPDX_SDK.getSOFDataFromADEX(config, adexDataToken)
    PPDX_SDK.getYieldDataFromADEX(config, adexDataToken)
    PPDX_SDK.getAPMCDataFromADEX(config, adexDataToken)

    # getting Rytabandhu farmer data
    PPDX_SDK.getFarmerData(config, ppb_number, farmerDataToken, attestationToken)

    # Executing the application  
    box_out("Running the Application...")
    PPDX_SDK.setState("Computing farmer credit amount in TEE", "Step 4",4,5,address)
    subprocess.run(["sudo", "docker", "compose", 'up'])

    PPDX_SDK.setState("Secure Computation Complete", "Step 5", 5, 5, address)