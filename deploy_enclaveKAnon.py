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

    folder_path = os.path.join('/tmp', 'arx_input')
    if os.path.exists(folder_path):
        shutil.rmtree(folder_path)
        print(f"Removed folder and contents: {folder_path}")
    else:
        print(f"Folder not found: {folder_path}")
        
    os.makedirs(folder_path)
    print("Created input folder")

    config_path = os.path.join(folder_path, "config")
    os.makedirs(config_path)

    encdata_path = os.path.join(folder_path, "encrypted_data")
    os.makedirs(encdata_path)

    inputdata_path = os.path.join(folder_path, "input_file")
    os.makedirs(inputdata_path)

    folder_path = os.path.join('/tmp', 'arx_output')
    if os.path.exists(folder_path):
        shutil.rmtree(folder_path)
        print(f"Removed folder and contents: {folder_path}")
    else:
        print(f"Folder not found: {folder_path}")

    os.makedirs(folder_path)
    print("Created output folder")

# Start the main process
if __name__ == "__main__":
    print("In DP script main")
    if len(sys.argv) < 2:
        print("Error: Missing arguments.")
        sys.exit(1)  # Exit with an error code

    dataset = sys.argv[1]
    rs_url = sys.argv[2]
    github_raw_link = sys.argv[3]

    # Validate the link
    if not github_raw_link.startswith("https://raw.githubusercontent.com/"):
        print("Error: Invalid GitHub raw link format.")
        sys.exit(1)

    remove_files()

    config_file = "DPconfig.json"
    config = load_config(config_file)  # Loads configuration into a dictionary
    address = config["enclaveManagerAddress"]

    inference_url = f"{rs_url}/inference/{dataset}"
    inferencekey_url = f"{rs_url}/key/{dataset}"
    data_url = f"{rs_url}/data/{dataset}/"
    config_url = f"{rs_url}/config/{dataset}"

    # Step 1 - Pulling docker compose & extracting docker image link
    print("\nStep 1")
    box_out("Pulling Docker Compose from GitHub...")
    PPDX_SDK.pull_compose_file(github_raw_link)
    print('Extracting docker link...')
    link = subprocess.check_output(["sudo", "docker", "compose", "config", "--images"]).decode().strip()
    print("Image information:", link)

    # Step 2 - Key generation
    print("\nStep 2") 
    box_out("Generating and saving key pair...")
    PPDX_SDK.setState("TEE Attestation & Authorisation", "Step 2",2,5,address)
    key=PPDX_SDK.generate_and_save_key_pair()

    # Step 3 - Docker image pulling
    print("\nStep 3")
    box_out("Pulling docker image...")
    PPDX_SDK.pull_docker_image(link)
    print("Pulled docker")

    # Step 4 - Measuring image and storing in vTPM
    print("\nStep 4")
    box_out("Measuring Docker image into vTPM...")
    PPDX_SDK.measureDockervTPM(link)
    print("Measured and stored in vTPM")

    # Step 5 - Send VTPM & public key to MAA & get attestation token
    print("\nStep 5")
    box_out("Guest Attestation Executing...")
    PPDX_SDK.execute_guest_attestation()
    print("Guest Attestation complete. JWT received from MAA: ")

    # Step 6 - Send the JWT to APD
    print("\nStep 6")
    box_out("Sending JWT to APD for verification...")
    token=PPDX_SDK.getTokenFromAPD('jwt-response.txt', config, dataset, rs_url)
    print("Access token received from APD")

    # Step 7 - Pulling config file from RS: 
    print("\nStep 7")
    box_out("Pulling DP application config")
    PPDX_SDK.setState("Getting data into Secure enclave","Step 3",3,5,address)
    PPDX_SDK.pullconfig_KAnon(config_url, token, key)
    print("Config pulled & stored")

    # Step 8 - Pulling chunks, decrypting & storing 
    print("\nStep 8")
    box_out("Getting files from RS, decrypting and storing locally...")
    count=0
    lengthList=[]
    while True:
        count=count+1
        print("The lengthList is: ", lengthList)

        ret =  PPDX_SDK.dataChunkN_KAnon(count, data_url, token, key)
        if (ret==0):
            print ("Error retrieveing chunk. Assuming no more chunks..")
            break
        lengthList.append(count)

    total_chunks = len(lengthList)
    print("TOTAL chunks stored :", total_chunks)

    # Executing the application in the docker
    print("\nStep 9")
    box_out("Running the Application...")
    PPDX_SDK.setState("Performing secure de-identification in TEE", "Step 4",4,5,address)
    subprocess.run(["sudo", "docker", "compose", 'up'])
    print('Output saved to /tmp/output')

    print("\nStep 10")
    print("Getting inference encryption key from RS..")
    inference_key=PPDX_SDK.getInferenceFernetKey(key, inferencekey_url, token)
    print("Got back inference key: ", inference_key)

    print("\nStep 11")
    print("Encrypting Inference using inference key")
    inference=PPDX_SDK.encryptInference_KAnon(inference_key)
    print("Inference encrypted")

    print("\nStep 12")
    print("Sending encrypted inference to RS")
    PPDX_SDK.sendInference(inference, token, inference_url)
    print("Inference sent to RS")

    print('DONE')
    PPDX_SDK.setState("Secure Computation Complete", "Step 5", 5, 5, address)