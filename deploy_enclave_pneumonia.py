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
import common_utils



# Simulate sourcing external scripts -  
# You'd integrate the necessary functions from setState.sh and profilingStep.sh here 


def remove_profiling_file():
    if os.path.exists("profiling.json"):
        os.remove("profiling.json")


def remove_files():
    common_utils.remove_docker_compose()
    common_utils.remove_keys_folder()

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
    config = common_utils.load_config(config_file)  # Loads configuration into a dictionary
    address = config["enclaveManagerAddress"]

    #PPDX_SDK.profiling_steps('Application Start', 0)
    #remove_profiling_file()
    remove_files()

    if len(sys.argv) < 2:
        print("Error: Missing GitHub raw link argument.")
        print("Usage: sudo python3 deploy_enclave.py <github_raw_link>")
        sys.exit(1)  # Exit with an error code

    github_raw_link = sys.argv[1]
    common_utils.validate_github_link(github_raw_link)

    # Step 1 - Pulling docker compose & extracting docker image link
    link = common_utils.pull_and_extract_docker_image(PPDX_SDK, github_raw_link)

    # Step 3 - Docker image pulling
    common_utils.pull_docker_image(PPDX_SDK, link)

    # Step 2 - Key generation
    common_utils.generate_keys(PPDX_SDK, address)

    # Step 4 - Measuring image and storing in vTPM
    common_utils.measure_docker_vtpm(PPDX_SDK, link)

    # Step 5 - Send VTPM & public key to MAA & get attestation token
    common_utils.execute_attestation(PPDX_SDK)

    # Step 6 - Send the JWT to APD
    token = common_utils.get_token_from_apd(PPDX_SDK, config)

    # Step 7 - Getting data
    common_utils.get_data_state_update(PPDX_SDK, address)
    PPDX_SDK.getFileFromResourceServer(token)

    common_utils.box_out("Decrypting & storing files...")
    PPDX_SDK.decryptFile()
    print("Files decrypted and stored in /tmp/inputdata")

    # Executing the application in the docker
    common_utils.run_docker_application(PPDX_SDK, address, "Running pneumonia detection application")

    common_utils.final_state_update(PPDX_SDK, address, "Secure Execution Complete")
    print('Output saved to /tmp/output')