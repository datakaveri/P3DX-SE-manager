#!/usr/bin/env python3
import os
import sys
import subprocess
import json
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import Crypto
from Crypto.PublicKey import RSA
import base64
import hashlib
import json
import requests
import _pickle as pickle
from Crypto.Cipher import PKCS1_OAEP
from cryptography.fernet import Fernet
import tarfile
import urllib.parse
import datetime
import psutil
import gzip
import csv
import shutil
import json


def pull_compose_file(url, filename='docker-compose.yml'):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for bad responses (4xx or 5xx)

        with open(filename, 'wb') as file:
            file.write(response.content)
        
        print(f"Downloaded content from '{url}' and saved to '{filename}'")
    
    except requests.exceptions.RequestException as e:
        print(f"Error downloading content: {e}")

def pull_docker_image(app_name):
    # Pull Docker image
    print("Pulling docker image")
    subprocess.run(["docker", "pull", app_name])


# Generate Public-Private Key Pair
def generate_and_save_key_pair():
    public_key_file='public_key.pem'
    private_key_file='private_key.pem'
    # Create 'keys' folder if it doesn't exist
    if not os.path.exists('keys'):
        os.makedirs('keys')

    # Generate a new RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Get the public key
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode().split('\n')[1:-1]  # Remove BEGIN and END headers

    # Get the private key
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()   # Remove BEGIN and END headers

    # Write the public key to a file
    with open(os.path.join('keys', public_key_file), "w") as public_key_out:
        public_key_out.write(''.join(public_key))

    # Write the private key to a file
    with open(os.path.join('keys', private_key_file), "w") as private_key_out:
        private_key_out.write(''.join(private_key_bytes))

    print("Public and private keys generated and saved successfully in the 'keys' folder!")

    # Remove the end tags from both files
    with open(os.path.join('keys', public_key_file), 'r') as file:
        lines = file.readlines()

    new_lines = []
    for line in lines:
        if '----' not in line:
            new_lines.append(line)
        else:
            new_lines.append(line.split('----')[0])

    with open(os.path.join('keys', public_key_file), 'w') as file:
        file.writelines(new_lines)


def measureDockervTPM(link):
    try:
        docker_image = link
        
        print(f"Fetching SHA256 digest for Docker image '{docker_image}'...")
        repo_name, tag = docker_image.split(':')
        # Query Docker Hub API to get image info
        response = requests.get(f"https://registry.hub.docker.com/v2/repositories/{repo_name}/tags/{tag}")
        if response.status_code == 200:
            data = response.json()
            sha256_digest = data['images'][0]['digest'].replace('sha256:', '')
            print(f"SHA256 digest for image '{docker_image}' is: {sha256_digest}")

            print("Extending the measurement to PCR 15 using TPM2 tools...")
            # Extend the measurement to PCR 15 using TPM2 tools
            subprocess.run(['sudo', 'tpm2_pcrextend', f'15:sha256={sha256_digest}'])
            print("Measurement extended successfully to PCR 15.")
        else:
            print(f"Error: Image '{docker_image}' not found.")
    except Exception as e:
        print("Error:", e)

    try:
        pcr_values = {}
        # Run tpm2_pcrread command to get the PCR values
        command = ['sudo', 'tpm2_pcrread', 'sha256:0,1,2,3,4,5,6,7,8,15']
        result = subprocess.run(command, capture_output=True, text=True)
        
        # Check if the command was successful
        if result.returncode == 0:

            output_lines = result.stdout.strip().split('\n')
            for line in output_lines[1:]:  # Skip the first line (sha256:)
                parts = line.split(':')
                if len(parts) == 2:
                    pcr_number = parts[0].strip()
                    pcr_value = parts[1].strip()
                    pcr_values[pcr_number] = pcr_value
                else:
                    print("Unexpected output format:", line)
            json_string = json.dumps(pcr_values)

            with open(os.path.join('keys', 'pcr_values.json'), 'w') as file:
                file.write(json_string)
            print("PCR values written to file successfully!")
        else:
            print(f"Error reading PCR values: {result.stderr}")
    except Exception as e:
        print("Error:", e)  

def execute_guest_attestation():
    # Get the directory of the current script
    script_dir = os.path.dirname(__file__)

    commands_folder = os.path.join(script_dir, "guest_attestation/cvm-attestation-sample-app")

    # Change directory to the specified folder
    os.chdir(commands_folder)

    # Execute the command to generate token
    subprocess.run(["python3", "generate-token.py"])

    # Change directory back to the original directory
    os.chdir(script_dir)


#APD verifies quote and releases token
def getAttestationToken(config):

    auth_server_url= config["apd_url"]
    headers={'clientId': "73599b23-6550-4f01-882d-a2db75ba24ba", 'clientSecret': "15a874120135e4eed4782c8b51385649fee55562", 'Content-Type': config["Content-Type"]}

    with open('keys/jwt-response.txt', 'r') as file:
        token = file.read().strip()

    context={
                "jwtMAA": token
            }

    data={
            "itemId": "8bdebc63-ccb0-4930-bdbb-60ea9d7f7599",
            "itemType": config["itemType"],
            "role": config["role"],
            "context": context
         }
    dataJson=json.dumps(data)
    r= requests.post(auth_server_url,headers=headers,data=dataJson)

    if(r.status_code==200):
        print("Attestation Token verified and Token recieved.")
        jsonResponse=r.json()
        token=jsonResponse.get('results').get('accessToken')
        #print(token)
        return token
    else:
        print("Attestation Token fetching failed.", r.text)
        with open("output/output.json", "w") as f:
            # make status code 900 & status as "Error" to indicate that the process has failed
            json.dump({"status_code": "900", "status": "TEE Attestation error"}, f)


# ADEX SPECIFIC FUNCTIONS
def getADEXDataAccessTokens(config):
    auth_server_url=config["auth_server_url"]
    headers = {
        "clientId": config["clientId"],
        "clientSecret": config["clientSecret"],
        "Content-Type": "application/json"
    }
    data = {
        "itemId": config["adex_url"],
        "itemType": "resource_server",
        "role": config["role"]
    }

    dataJson = json.dumps(data)
    r = requests.post(auth_server_url, headers=headers, data=dataJson)

    if r.status_code == 200:
        print("ADEX Data access Token verified and Token recieved.")
        jsonResponse = r.json()
        token = jsonResponse.get('results').get('accessToken')
        #print(token)
        return token
    else:
        print("ADEX data access Token fetching failed.", r.text)

def getFarmerDataToken(config, ppb_number):

    auth_server_url=config["auth_server_url"]
    headers={'clientId': config["clientId"], 'clientSecret': config["clientSecret"], 'Content-Type': config["Content-Type"]}

    context = {
        "ppbNumber": ppb_number
    }
    data={
        "itemId": config["FarmerData_itemID"],
        "itemType": config["itemType"],
        "role": config["role"],
        "context": context
    }
    
    dataJson=json.dumps(data)
    r= requests.post(auth_server_url,headers=headers,data=dataJson)

    if(r.status_code==200):
        print("Rytabandhu Consent Token verified and Token recieved.")
        jsonResponse=r.json()
        token=jsonResponse.get('results').get('accessToken')
        #print(token)
        return token 
    else:
        print("Farmer data access Token fetching failed.", r.text)
    

#Send token to resource server for verification & get encrypted images  
def getSOFDataFromADEX(config, token):
    rs_url = config["SOF_url"]
    headers = {
        "token": token,
        "Content-Type": "application/json"  
    }
    rs=requests.get(rs_url,headers=headers)
    if rs.status_code == 200:
        print("SOF data fetched successfully.")

        # extract the results dictionary from response & store it in SOF_data.json in data folder
        jsonResponse = rs.json()
        results = jsonResponse.get('results')
        filtered_data = [item for item in results if item['evaluationYear'] == "2024-2025"]

        # if SOF_data.csv exists, delete it
        # store in /tmp/FCinput directory as SOF_data.csv
        folder_path = os.path.expanduser("/tmp/FCinput")
        file_path = os.path.join(folder_path, "SOF_data.csv")
        with open(file_path, 'w', newline='') as csvfile:
            # Define the CSV field names
            fieldnames = ['Crop', 'maxSOF']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for item in filtered_data:
                writer.writerow({'Crop': item['cropNameCommon'], 'maxSOF': item['maxSOF']})
        print("SOF data written to SOF_data.csv file.")
    else:
        print(f"Failed to fetch SOF data. Status code: {rs.status_code}")
        print(f"Response content: {rs.text}")

def getYieldDataFromADEX(config, token):
    rs_url = config["Yield_url"]
    headers = {
        "token": token,
        "Content-Type": "application/json"  
    }
    rs=requests.get(rs_url,headers=headers)
    if rs.status_code == 200:
        print("Yield data fetched successfully.")

        # extract the results dictionary from response & store it in SOF_data.json in data folder
        jsonResponse = rs.json()
        results = jsonResponse.get('results')
        # with open('data/Yield_data.json', 'w') as file:
        #     json.dump(results, file)
        filtered_data = [item for item in results if item['year'] == 2024]

        folder_path = os.path.expanduser("/tmp/FCinput")
        file_path = os.path.join(folder_path, "Yield_data.csv")
        with open(file_path, 'w', newline='') as csvfile:
            # Define the CSV field names
            fieldnames = ['district', 'crop', 'season', 'yield']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for item in filtered_data:
                writer.writerow({'district' : item['districtName'], 'crop': item['commodityName'], 'season': item['cropSeason'], 'yield': item['targetYield']})
            print("Yield data written to Yield_data.csv file.")
    else:
        print(f"Failed to fetch Yield data. Status code: {rs.status_code}")
        print(f"Response content: {rs.text}")

def getAPMCDataFromADEX(config, token):
    rs_url = config["APMC_url"]
    headers = {
        "token": token,
        "Content-Type": "application/json"  
    }
    rs=requests.get(rs_url,headers=headers)
    if rs.status_code == 200:
        print("APMC data fetched successfully.")

        # extract the results dictionary from response & store it in SOF_data.json in data folder
        jsonResponse = rs.json()
        results = jsonResponse.get('results')
        # with open('data/APMC_data.json', 'w') as file:
        #     json.dump(results, file)
        filtered_data = [item for item in results if item['year'] == 2025]

        folder_path = os.path.expanduser("/tmp/FCinput")
        file_path = os.path.join(folder_path, "APMC_data.csv")
        with open(file_path, 'w', newline='') as csvfile:
            # Define the CSV field names
            fieldnames = ['district', 'crop', 'season', 'price']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for item in filtered_data:
                writer.writerow({'district' : item['districtName'], 'crop': item['commodityName'], 'season': item['cropSeason'], 'price': item['totalPrice']})
        print("APMC data written to APMC_data.csv file.")
    else:
        print(f"Failed to fetch APMC data. Status code: {rs.status_code}")
        print(f"Response content: {rs.text}")


def getFarmerData(config, ppb_number, farmer_data_token, attestation_token):
    # Define the URL and parameters
    url = config["rs_proxy_url"]
    params = {
        "id": "c5422a0f-e60f-48e4-9d1e-1fa4b1714900",
        "q": f"Ppbno=={ppb_number}",
        "time": "2023-06-25T12:01:05Z",
        "endtime": "2024-06-01T12:01:05Z",
        "timerel": "during"
    }

    # Define the headers
    headers = {
        "Consent-Token": farmer_data_token, 
        "Enclave-Token": attestation_token
    }

    try:
        # Make the GET request
        response = requests.get(url, headers=headers, params=params)

        # Check if the request was successful
        if response.status_code == 200:
            print("Farmer data fetched successfully.")
            
            folder_path = os.path.expanduser("/tmp/FCinput")
            file_path = os.path.join(folder_path, "farmer_data.json")

            # Write the response content to a file
            with open(file_path, "wb") as file:
                file.write(response.content)
            print("Farmer data written to farmer_data.json file.")
        else:
            print(f"Failed to fetch farmer data. Status code: {response.status_code}")
            print(f"Response content: {response.text}")

    except requests.exceptions.RequestException as e:
        print(f"An error occurred while making the request: {e}")



# PNEUMONIA/YOLO SPECIFIC FUNCTIONS
#Send token to resource server for verification & get encrypted images  
def getFileFromResourceServer(token):
    rs_url = "https://authenclave.iudx.io/resource_server/encrypted.store"
    rs_headers={'Authorization': f'Bearer {token}'}
    rs=requests.get(rs_url,headers=rs_headers)
    if rs.status_code == 200:
        print("Token authenticated and Encrypted images received.")
        loadedDict = pickle.loads(rs.content)
        # Write the loadedDict to a file
        with open("loadedDict.pkl", "wb") as file:
            pickle.dump(loadedDict, file)
        print("loadedDict written to loadedDict.pkl file.")
    else:
        print("Token authentication failed.",rs.text)
        sys.exit()

#Decrypt images recieved using enclave's private key
def decryptFile():
    print("In decryptFile")
    
    with open('keys/private_key.pem', "r") as pem_file:
        private_key = pem_file.read()
        print('Using Private Key to Decrypt data')
    
    key = RSA.import_key(private_key)

    # Read the loadedDict from the file
    with open("loadedDict.pkl", "rb") as file:
        loadedDict = pickle.load(file)
    b64encryptedKey=loadedDict["encryptedKey"]
    encData=loadedDict["encData"]
    encryptedKey=base64.b64decode(b64encryptedKey)
    decryptor = PKCS1_OAEP.new(key)
    plainKey=decryptor.decrypt(encryptedKey)
    print("Symmetric key decrypted using the enclave's private RSA key.")
    fernetKey = Fernet(plainKey)
    decryptedData = fernetKey.decrypt(encData)

    temp_dir = os.path.expanduser("/tmp")

    decrypted_data_path = os.path.join(temp_dir, "decryptedData.tar.gz")
    extracted_data_path = os.path.join(temp_dir, "inputdata")

    # Remove existing content from the data paths if they exist
    for data_path in [decrypted_data_path, extracted_data_path]:
        if os.path.exists(data_path):
            if os.path.isdir(data_path):
                shutil.rmtree(data_path)
            else:
                os.remove(data_path)

    # Create the directories if they don't exist
    os.makedirs(extracted_data_path, exist_ok=True)
    # Write the decrypted data to a file
    with open(decrypted_data_path, "wb") as f:
        f.write(decryptedData)
    print("Data written")
    # Extract the contents of the tar.gz file
    tar=tarfile.open(decrypted_data_path)
    tar.extractall(extracted_data_path)
    print("Images decrypted.",os.listdir(extracted_data_path))
    print("Images stored in tmp directory")




#function to set state of enclave
def setState(title,description,step,maxSteps,address):
    state= {"title":title,"description":description,"step":step,"maxSteps":maxSteps}
    call_set_state_endpoint(state, address)

#function to call set state endpoint
def call_set_state_endpoint(state, address):
    #define enpoint url
    endpoint_url=urllib.parse.urljoin(address, '/enclave/setstate')

    #create Json payload
    payload = { "state": state }
    #create POST request
    r = requests.post(endpoint_url, json=payload)

    #print response
    print(r.text)

