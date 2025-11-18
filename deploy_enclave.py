import subprocess
import os
import PPDX_SDK
import sys
import json
import shutil
import argparse
import common_utils


# Simulate sourcing external scripts -  
# You'd integrate the necessary functions from setState.sh and profilingStep.sh here 


def remove_profiling_file():
    if os.path.exists("profiling.json"):
        os.remove("profiling.json")


def remove_files():
    common_utils.remove_docker_compose()

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

    common_utils.remove_keys_folder()


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
    config = common_utils.load_config(config_file)
    address = config["address"]

    remove_files()

    if len(sys.argv) < 2:
        print("Error: Missing GitHub raw link argument.")
        print("Usage: sudo python3 deploy_enclave.py <github_raw_link>")
        sys.exit(1)  # Exit with an error code

    common_utils.validate_github_link(github_raw_link)

    ppb_number = context["ppb_number"]

    folder_path = os.path.expanduser("/tmp/FCcontext")
    file_path = os.path.join(folder_path, "context.json")

    with open(file_path, 'w') as file:
        json.dump(context, file, indent=4)

    # Step 1 - Pulling docker compose & extracting docker image link
    link = common_utils.pull_and_extract_docker_image(PPDX_SDK, github_raw_link)

    # Step 2 - Docker image pulling
    common_utils.pull_docker_image(PPDX_SDK, link)

    # Step 4 - Key generation
    common_utils.generate_keys(PPDX_SDK, address)

    # Step 5 - storing image digest in vTPM
    common_utils.measure_docker_vtpm(PPDX_SDK, link)

    # Step 6 - Send VTPM & public key to MAA & get attestation token
    common_utils.execute_attestation(PPDX_SDK)

    # Step 7 - Send the JWT to APD
    common_utils.box_out("Sending JWT to APD for verification...")
    attestationToken = PPDX_SDK.getAttestationToken(config)
    print("Attestation token received from APD")

    # Call APD for getting ADEX data access token
    print("Getting ADEX data access token")
    adexDataToken = PPDX_SDK.getADEXDataAccessTokens(config)

    # Call APD for getting Rythabandhu data access token
    print("Getting Rytabandhu consent token")
    farmerDataToken = PPDX_SDK.getFarmerDataToken(config, ppb_number)

    # Step 8 - Getting files from RS
    common_utils.get_data_state_update(PPDX_SDK, address)

    # getting files from ADEX
    PPDX_SDK.getSOFDataFromADEX(config, adexDataToken)
    PPDX_SDK.getYieldDataFromADEX(config, adexDataToken)
    PPDX_SDK.getAPMCDataFromADEX(config, adexDataToken)

    # getting Rytabandhu farmer data
    PPDX_SDK.getFarmerData(config, ppb_number, farmerDataToken, attestationToken)

    # Executing the application  
    common_utils.run_docker_application(PPDX_SDK, address, "Computing farmer credit amount in TEE")

    common_utils.final_state_update(PPDX_SDK, address, "Secure Computation Complete")