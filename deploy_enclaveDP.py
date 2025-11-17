import subprocess
import os
import PPDX_SDK_DP
import sys
import json
import shutil
import time
import psutil
import logging
from datetime import datetime
import common_utils


def remove_files():
    common_utils.remove_docker_compose()
    common_utils.remove_keys_folder()

    folder_path = os.path.join('/tmp', 'DPinput')
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

    inputdata_path = os.path.join(folder_path, "inputdata")
    os.makedirs(inputdata_path)

    folder_path = os.path.join('/tmp', 'DPoutput')
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
    common_utils.validate_github_link(github_raw_link)

    remove_files()

    config_file = "DPconfig.json"
    config = common_utils.load_config(config_file)  # Loads configuration into a dictionary
    address = config["enclaveManagerAddress"]

    inference_url = f"{rs_url}/inference/{dataset}"
    inferencekey_url = f"{rs_url}/key/{dataset}"
    data_url = f"{rs_url}/data/{dataset}/"
    config_url = f"{rs_url}/config/{dataset}"

    # Step 1 - Pulling docker compose & extracting docker image link
    print("\nStep 1")
    link = common_utils.pull_and_extract_docker_image(PPDX_SDK_DP, github_raw_link)

    # Step 2 - Key generation
    print("\nStep 2") 
    key = common_utils.generate_keys(PPDX_SDK_DP, address)

    # Step 3 - Docker image pulling
    print("\nStep 3")
    common_utils.pull_docker_image(PPDX_SDK_DP, link)

    # Step 4 - Measuring image and storing in vTPM
    print("\nStep 4")
    common_utils.measure_docker_vtpm(PPDX_SDK_DP, link)

    # # Step 5 - Send VTPM & public key to MAA & get attestation token
    # print("\nStep 5")
    # common_utils.execute_attestation(PPDX_SDK_DP)

    # # Step 6 - Send the JWT to APD
    # print("\nStep 6")
    # common_utils.box_out("Sending JWT to APD for verification...")
    # token = PPDX_SDK_DP.getTokenFromAPD('jwt-response.txt', config, dataset, rs_url)
    # print("Access token received from APD")

    # Step 7 - Pulling config file from RS: 
    print("\nStep 7")
    common_utils.box_out("Pulling DP application config")
    common_utils.get_data_state_update(PPDX_SDK_DP, address)
    PPDX_SDK_DP.pullconfig(config_url, token, key)
    print("Config pulled & stored")

    # Step 8 - Pulling chunks, decrypting & storing 
    print("\nStep 8")
    common_utils.box_out("Getting files from RS, decrypting and storing locally...")
    count=0
    lengthList=[]
    while True:
        count=count+1
        print("The lengthList is: ", lengthList)

        ret =  PPDX_SDK_DP.dataChunkN(count, data_url, token, key)
        if (ret==0):
            print ("Error retrieveing chunk. Assuming no more chunks..")
            break
        lengthList.append(count)

    total_chunks = len(lengthList)
    print("TOTAL chunks stored :", total_chunks)

    # Executing the application in the docker
    print("\nStep 9")
    common_utils.run_docker_application(PPDX_SDK_DP, address, "Performing secure de-identification in TEE")
    print('Output saved to /tmp/output')

    print("\nStep 10")
    print("Getting inference encryption key from RS..")
    inference_key=PPDX_SDK_DP.getInferenceFernetKey(key, inferencekey_url, token)
    print("Got back inference key: ", inference_key)

    print("\nStep 11")
    print("Encrypting Inference using inference key")
    inference=PPDX_SDK_DP.encryptInference(inference_key)
    print("Inference encrypted")

    print("\nStep 12")
    print("Sending encrypted inference to RS")
    PPDX_SDK_DP.sendInference(inference, token, inference_url)
    print("Inference sent to RS")

    print('DONE')
    common_utils.final_state_update(PPDX_SDK_DP, address, "Secure Computation Complete")