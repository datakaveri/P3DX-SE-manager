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
from collections import OrderedDict

def pull_compose_file(url, filename='docker-compose.yml'):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for bad responses (4xx or 5xx)

        with open(filename, 'wb') as file:
            file.write(response.content)
        
        print(f"Downloaded content from '{url}' and saved to '{filename}'")
    
    except requests.exceptions.RequestException as e:
        print(f"Error downloading content: {e}")

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

    #reading private key 
    with open('keys/private_key.pem', "r") as pem_file:
        private_key = pem_file.read()
        print('Using Private Key to Decrypt data')
    key = RSA.import_key(private_key)

    return key

def pull_docker_image(app_name):
    # Docker login
    # print("Logging in to docker hub")
    # subprocess.run(["sudo", "docker", "login"])
    #Pull Docker image
    print("Pulling docker image")
    subprocess.run(["docker", "pull", app_name])
    #subprocess.run(["sudo", "docker", "pull", app_name])

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
            # Write the PCR values to a text file
            # with open(os.path.join('keys', 'pcr_values.txt'), 'w') as file:
            #     for pcr_number, pcr_value in pcr_values.items():
            #         file.write(f"{pcr_number}: {pcr_value}\n")
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
def getTokenFromAPD(jwt_file, config, dataset, rs_url):
    apd_url=config["apd_url"]
    headers={'clientId': config["clientId"], 'clientSecret': config["clientSecret"], 'Content-Type': config["Content-Type"]}

    with open('keys/'+jwt_file, 'r') as file:
        token = file.read().strip()

    context={
                "jwtMAA": token,
                "dataset_name" : dataset,
                "rs_url": rs_url
            }

    data={
            "itemId": config["itemId"],
            "itemType": config["itemType"],
            "role": config["role"],
            "context": context
         }
    dataJson=json.dumps(data)
    r= requests.post(apd_url,headers=headers,data=dataJson)
    if(r.status_code==200):
        print("Token verified and Token recieved.")
        jsonResponse=r.json()
        token=jsonResponse.get('results').get('accessToken')
        print(token)
        return token
    else:
        print("Token verification failed.", r.text)
        sys.exit() 

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


#DP Functions:

def pullconfig(url, token, key):
    print("Pulling DP application config from RS..")
    access_token=token
    rs_url=url

    auth = "Bearer {access_token}".format(access_token=access_token)
    headers = {'Authorization': auth }

    response = requests.get(rs_url, headers=headers)
    if response.status_code == 200:
        loadedDict = pickle.loads(response.content)
        print("Data downloaded successfully")

        b64encryptedKey=loadedDict["encryptedKey"]
        encConfig=loadedDict["encConfig"]
        encryptedKey=base64.b64decode(b64encryptedKey)
        decryptor = PKCS1_OAEP.new(key)
        plainKey=decryptor.decrypt(encryptedKey)
        print("Symmetric key decrypted using the enclave's private RSA key.")

        fernetKey = Fernet(plainKey)
        decryptedConfig = fernetKey.decrypt(encConfig)
        print("Config decrypted")

        decryptedConfigStr = decryptedConfig.decode('utf-8')
        decryptedConfigDict = json.loads(decryptedConfigStr)

        config_path = os.path.expanduser("/tmp/DPinput/config")
        config_file = os.path.join(config_path, "config.json")

        with open(config_file, 'w') as json_file:
            json.dump(decryptedConfigDict, json_file, indent=4)
        print("Decrypted config written to tmp/DPinput/config")
    else:
        print(f"Failed to download file. Status code: {response.status_code}")


def dataChunkN(n, url, access_token, key):
    count=n
    loadedDict=getChunkFromResourceServer(count, url, access_token)
    if loadedDict:
        decryptChunk(loadedDict, count, key)
        return 1
    else:
        return 0 
    
def getChunkFromResourceServer (n,url,token):
    rs_headers={'Authorization': f'Bearer {token}'}
    rs_url = f"{url}{n}"
    print(rs_url)
    rs=requests.get(rs_url,headers=rs_headers)
    if(rs.status_code==200):
        print("Token authenticated and Encrypted data recieved.")
        loadedDict=pickle.loads(rs.content)
        return loadedDict
    else:
        print(rs.text)
        return None

def decryptChunk(loadedDict, n, key):
    print("Decrypting chunk..")
    b64encryptedKey=loadedDict["encryptedKey"]
    encData=loadedDict["encData"]
    encryptedKey=base64.b64decode(b64encryptedKey)
    decryptor = PKCS1_OAEP.new(key)
    plainKey=decryptor.decrypt(encryptedKey)

    fernetKey = Fernet(plainKey)
    decryptedData = fernetKey.decrypt(encData)

    temp_dir = os.path.expanduser("/tmp/DPinput")
    decrypted_data_folder = os.path.join(temp_dir, "encrypted_data")
    extracted_data_folder = os.path.join(temp_dir, "inputdata")

    if not os.path.exists(extracted_data_folder):
        os.makedirs(extracted_data_folder)
    if not os.path.exists(decrypted_data_folder):
        os.makedirs(decrypted_data_folder)

    decrypted_data_path = os.path.join(decrypted_data_folder, f"outfile{n}.gz")
    
    if os.path.exists(decrypted_data_path):
        os.remove(decrypted_data_path)

    with open(decrypted_data_path, "wb") as f:
        f.write(decryptedData)

    with gzip.open(decrypted_data_path, 'rb') as file:
        data = file.read().decode('utf-8')
        json_data = json.loads(data)
    
    outfile_path = os.path.join(extracted_data_folder, f"data{n}.json")

    with open(outfile_path, 'w', encoding='utf-8') as outfile:
        outfile.write('[\n')
        for i, record in enumerate(json_data):
            json_record = json.dumps(record, indent=4)  # Convert the record to a JSON string with indentation
            if i < len(json_data) - 1:
                outfile.write(json_record + ',\n')  # Write the JSON string with a comma
            else:
                outfile.write(json_record + '\n')  # Last record, no comma
        outfile.write(']\n')


def getInferenceFernetKey(key, url, access_token):
    print ("Getting the inference Fernet key..")
    print("Accessing: ", url)   
    rs_headers={'Authorization': f'Bearer {access_token}'}
    rs_url = url
    rs=requests.get(rs_url,headers=rs_headers)

    if(rs.status_code==200):
        print("Token authenticated and pickle file recieved.")
        loadedDict=pickle.loads(rs.content)
        print(loadedDict.keys())
        b64encryptedKey=loadedDict["encryptedKey"]
    else:
        print(rs.text)
        return None
    
    print("The b64encryptedKey is: ", b64encryptedKey)

    encrypted_inference_key=base64.b64decode(b64encryptedKey)

    decryptor = PKCS1_OAEP.new(key)
    plain_inferenceKey=decryptor.decrypt(encrypted_inference_key)
    return plain_inferenceKey


def encryptInference(inference_key):
    print("Encrypting inference")
    output_file = os.path.expanduser("/tmp/DPoutput/concat_output.json")
    config_dir = os.path.expanduser("/tmp/DPinput/config")

    with open(output_file, 'r') as f:
        concat_output = json.load(f)

    files = os.listdir(config_dir)
    if len(files) != 1:
        raise Exception(f"Expected exactly one file in {config_dir}, but found {len(files)} files.")
        
    config_file = files[0]
    config_file_path = os.path.join(config_dir, config_file)

    with open(config_file_path, 'r') as f:
        config = json.load(f)

    concat_output["dataset"] = config["data_type"]

    with open(output_file, 'w') as f:
        json.dump(concat_output, f, indent=4)
    
    inference_file = os.path.expanduser("/tmp/DPoutput/inference.json")
    os.rename(output_file, inference_file)
    print(f"File renamed and saved as {inference_file}")

    print("Encrypting the output file")
    tarball = "pipelineOutput.tar"
    tar = tarfile.open(tarball, "w")
    tar.add(inference_file, arcname="inference.json")
    tar.close()

    fernet_key_bytes = inference_key
    fernet = Fernet(fernet_key_bytes)

    #encrypt the tarball
    dataFile = open(tarball, "r+b")
    inference_data = dataFile.read()
    enc_inference = fernet.encrypt(inference_data)
    
    data = {"encInference": enc_inference, "tarName": "pipelineOutput.tar"}
    pickled_data = pickle.dumps(data)
    os.remove(tarball)

    return pickled_data

def sendInference(inference, access_token, url):
    #send inference to RS
    print("Sending the inference to: ", url)

    auth = "Bearer {access_token}".format(access_token=access_token)
    headers = {'Authorization': auth }

    #Make the POST request with headers
    response = requests.post(url, headers=headers, data=inference)

    # Check the response
    if response.status_code == 200:
        print('Success!')
    else:
        print('Request failed with status code:', response.status_code)
    print(response.text)

    # #TESTING
    # while True:
    #     response = requests.post(url, headers=headers, data=inference)
    #     if(response.status_code==200):
    #         print("SUCCESS!!")
    #         break
    #     else:
    #         print("Request failed with status code: ", response.status_code)
    #         print(response.text)
    # print("DONE")



# K-Anon (ARX) FUNCTIONS

def decryptChunk_KAnon(loadedDict, n, key):
    print("Decrypting chunk..")
    b64encryptedKey=loadedDict["encryptedKey"]
    encData=loadedDict["encData"]
    encryptedKey=base64.b64decode(b64encryptedKey)
    decryptor = PKCS1_OAEP.new(key)
    plainKey=decryptor.decrypt(encryptedKey)

    fernetKey = Fernet(plainKey)
    decryptedData = fernetKey.decrypt(encData)

    temp_dir = os.path.expanduser("/tmp/arx_input")
    decrypted_data_folder = os.path.join(temp_dir, "encrypted_data")
    extracted_data_folder = os.path.join(temp_dir, "input_file")

    if not os.path.exists(extracted_data_folder):
        os.makedirs(extracted_data_folder)
    if not os.path.exists(decrypted_data_folder):
        os.makedirs(decrypted_data_folder)

    decrypted_data_path = os.path.join(decrypted_data_folder, f"outfile{n}.gz")
    
    if os.path.exists(decrypted_data_path):
        os.remove(decrypted_data_path)

    with open(decrypted_data_path, "wb") as f:
        f.write(decryptedData)

    with gzip.open(decrypted_data_path, 'rb') as file:
        data = file.read().decode('utf-8')
        json_data = json.loads(data)
    
    outfile_path = os.path.join(extracted_data_folder, f"data{n}.csv")

    # Open the CSV file for writing
    with open(outfile_path, 'w', newline='', encoding='utf-8') as csvfile:
        # Get the fieldnames (column headers) from the keys of the first record
        fieldnames = json_data[0].keys() if json_data else []

        # Create a CSV DictWriter object
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        # Write the header row (column names)
        writer.writeheader()

        # Write each record as a row in the CSV
        for record in json_data:
            writer.writerow(record)


def encryptInference_KAnon(inference_key):
    print("Encrypting inference")
    output_file = os.path.expanduser("/tmp/arx_output/response.json")
    config_dir = os.path.expanduser("/tmp/arx_input/config")

    with open(output_file, 'r') as f:
        concat_output = json.load(f)

    files = os.listdir(config_dir)
    if len(files) != 1:
        raise Exception(f"Expected exactly one file in {config_dir}, but found {len(files)} files.")
        
    config_file = files[0]
    config_file_path = os.path.join(config_dir, config_file)

    with open(config_file_path, 'r') as f:
        config = json.load(f)

    concat_output["dataset"] = config["data_type"]

    with open(output_file, 'w') as f:
        json.dump(concat_output, f, indent=4)
    
    inference_file = os.path.expanduser("/tmp/arx_output/inference.json")
    os.rename(output_file, inference_file)
    print(f"File renamed and saved as {inference_file}")

    print("Encrypting the output file")
    tarball = "pipelineOutput.tar"
    tar = tarfile.open(tarball, "w")
    tar.add(inference_file, arcname="inference.json")
    tar.close()

    fernet_key_bytes = inference_key
    fernet = Fernet(fernet_key_bytes)

    #encrypt the tarball
    dataFile = open(tarball, "r+b")
    inference_data = dataFile.read()
    enc_inference = fernet.encrypt(inference_data)
    
    data = {"encInference": enc_inference, "tarName": "pipelineOutput.tar"}
    pickled_data = pickle.dumps(data)
    os.remove(tarball)

    return pickled_data

def dataChunkN_KAnon(n, url, access_token, key):
    count=n
    loadedDict=getChunkFromResourceServer(count, url, access_token)
    if loadedDict:
        decryptChunk_KAnon(loadedDict, count, key)
        return 1
    else:
        return 0 
    

def pullconfig_KAnon(url, token, key):
    print("Pulling DP application config from RS..")
    access_token=token
    rs_url=url

    auth = "Bearer {access_token}".format(access_token=access_token)
    headers = {'Authorization': auth }

    response = requests.get(rs_url, headers=headers)
    if response.status_code == 200:
        loadedDict = pickle.loads(response.content)
        print("Data downloaded successfully")

        b64encryptedKey=loadedDict["encryptedKey"]
        encConfig=loadedDict["encConfig"]
        encryptedKey=base64.b64decode(b64encryptedKey)
        decryptor = PKCS1_OAEP.new(key)
        plainKey=decryptor.decrypt(encryptedKey)
        print("Symmetric key decrypted using the enclave's private RSA key.")

        fernetKey = Fernet(plainKey)
        decryptedConfig = fernetKey.decrypt(encConfig)
        print("Config decrypted")

        decryptedConfigStr = decryptedConfig.decode('utf-8')
        decryptedConfigDict = json.loads(decryptedConfigStr)

        config_path = os.path.expanduser("/tmp/arx_input/config")
        config_file = os.path.join(config_path, "config.json")

        with open(config_file, 'w') as json_file:
            json.dump(decryptedConfigDict, json_file, indent=4)
        print("Decrypted config written to tmp/DPinput/config")
    else:
        print(f"Failed to download file. Status code: {response.status_code}")