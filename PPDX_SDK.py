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

#AMD:
# 1. generate key pair - DONE
# 2. measure docker & store in vTPM
# 3. combine public key & vTPM report & send to MAA & return jwt token
# 4. send attestation token (public key embedded) to APD & get back access token
# rest steps are same
# steps 3 & 4 : use hardcoded token
# docker compose 

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
    ).decode().split('\n')[1:-1]  # Remove BEGIN and END headers

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
            new_lines.append(line.split('----')[0] + '\n')

    with open(os.path.join('keys', public_key_file), 'w') as file:
        file.writelines(new_lines)

    with open(os.path.join('keys', private_key_file), 'r') as file:
        lines = file.readlines()

    new_lines = []
    for line in lines:
        if '----' not in line:
            new_lines.append(line)
        else:
            new_lines.append(line.split('----')[0] + '\n')

    with open(os.path.join('keys', private_key_file), 'w') as file:
        file.writelines(new_lines)

def pull_docker_image(app_name):
    # Docker login
    subprocess.run(["sudo", "docker", "login"])
    # Pull Docker image
    if app_name=="YOLO":
        subprocess.run(["sudo", "docker", "pull", "kaushalkirpekar/yolo_docker3"])  


def measureDockervTPM(link):
    try:
        docker_image = link
        
        print(f"Fetching SHA256 digest for Docker image '{docker_image}'...")
        # Query Docker Hub API to get image info
        response = requests.get(f"https://registry.hub.docker.com/v2/repositories/{docker_image}/tags/latest")
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
        command = ['sudo', 'tpm2_pcrread', 'sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15']
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
            
            # Write the PCR values to a text file
            with open(os.path.join('keys', 'pcr values.txt'), 'w') as file:
                for pcr_number, pcr_value in pcr_values.items():
                    file.write(f"{pcr_number}: {pcr_value}\n")
                    
            print("PCR values written to file successfully!")
        else:
            print(f"Error reading PCR values: {result.stderr}")
    except Exception as e:
        print("Error:", e)

# def read_tpm_pcr():
#     try:
#         pcr_values = {}
#         # Run tpm2_pcrread command to get the PCR values
#         command = ['sudo', 'tpm2_pcrread', 'sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15']
#         result = subprocess.run(command, capture_output=True, text=True)
        
#         # Check if the command was successful
#         if result.returncode == 0:
#             output_lines = result.stdout.strip().split('\n')
#             for line in output_lines[1:]:  # Skip the first line (sha256:)
#                 parts = line.split(':')
#                 if len(parts) == 2:
#                     pcr_number = parts[0].strip()
#                     pcr_value = parts[1].strip()
#                     pcr_values[pcr_number] = pcr_value
#                 else:
#                     print("Unexpected output format:", line)
            
#             # Write the PCR values to a text file
#             with open(os.path.join('keys', 'pcr values.txt'), 'w') as file:
#                 for pcr_number, pcr_value in pcr_values.items():
#                     file.write(f"{pcr_number}: {pcr_value}\n")
                    
#             print("PCR values written to file successfully!")
#         else:
#             print(f"Error reading PCR values: {result.stderr}")
#     except Exception as e:
#         print("Error:", e)


# SGX 
#generate quote to be sent to APD for verification
def generateQuote():
    key = RSA.generate(2048)
    publicKey=key.publickey().export_key(format='DER')
    #print("Public key generated: " ,publicKey)
    #privateKey=key.export_key(format='DER')
    b64publicKey=base64.b64encode(publicKey)
    sha= hashlib.sha512(publicKey).hexdigest()
    shaBytes=bytearray.fromhex(sha)
    with open("/dev/attestation/user_report_data", "wb") as f:
        f.write(shaBytes)
    with open("/dev/attestation/quote", "rb") as f:
        quote = f.read()
    print("Quote generated.")
    #print("Quote: ",quote)
    return quote,b64publicKey, key

#APD verifies quote and releases token
def getTokenFromAPD(quote,b64publicKey,config):
    apd_url=config["apd_url"]
    headers={'clientId': config["clientId"], 'clientSecret': config["clientSecret"], 'Content-Type': config["Content-Type"]}
    b64quote=base64.b64encode(quote)
    context={
                "sgxQuote":b64quote.decode("utf-8"),
                "publicKey":b64publicKey.decode("utf-8")
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
        print("Quote verified and Token recieved.")
        jsonResponse=r.json()
        token=jsonResponse.get('results').get('accessToken')
        #print(token)
        return token
    else:
        print("Quote verification failed.", r.text)
        sys.exit() 



#Send token to resource server for verification & get encrypted images  
def getFileFromResourceServer(token,rs_url):
    rs_headers={'Authorization': f'Bearer {token}'}
    rs=requests.get(rs_url,headers=rs_headers)
    if(rs.status_code==200):
        print("Token authenticated and Encrypted images recieved.")
        loadedDict=pickle.loads(rs.content)
        return loadedDict
    else:
        print("Token authentication failed.",rs.text)
        sys.exit()

#Decrypt images recieved using enclave's private key
def decryptFile(loadedDict,key):
    b64encryptedKey=loadedDict["encryptedKey"]
    encData=loadedDict["encData"]
    encryptedKey=base64.b64decode(b64encryptedKey)
    decryptor = PKCS1_OAEP.new(key)
    plainKey=decryptor.decrypt(encryptedKey)
    print("Symmetric key decrypted using the enclave's private RSA key.")
    fernetKey = Fernet(plainKey)
    decryptedData = fernetKey.decrypt(encData)
    with open('/tmp/decryptedData.tar.gz', "wb") as f:
        f.write(decryptedData)
    tar=tarfile.open("/tmp/decryptedData.tar.gz")
    tar.extractall('/inputdata')
    print("Images decrypted.",os.listdir('/inputdata'))

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

#profiling function: timestamp, step description
def profiling_steps(description, stepno):
    with open("profiling.json", "r") as file:
        data = json.load(file)
    timestamp_str = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    step = {
        "step"+str(stepno): {
            "description": description,
            "timestamp": timestamp_str
        }
    }
    data["stepsProfile"].append(step)
    with open("profiling.json", "w") as file:
        json.dump(data, file, indent=4)

#profiling: input images
def profiling_inputImages():
    with open("profiling.json", "r") as file:
        data = json.load(file)
    extracted_directory = '/inputdata'
    files_in_directory = os.listdir(extracted_directory)
    image_extensions = ['.jpg', '.jpeg']
    image_count = 0
    for file_name in files_in_directory:
        if any(file_name.lower().endswith(ext) for ext in image_extensions):
            image_count += 1

    data["input"]["images"] = image_count
    with open("profiling.json", "w") as file:
        json.dump(data, file, indent=4)

def profiling_totalTime():
    print("Profiling total time...")
    with open("profiling.json", "r") as file:
        data = json.load(file)
    timestamp_step1 = None
    timestamp_step10 = None
    
    for step in data["stepsProfile"]:
        step_label = list(step.keys())[0]  # Extract the step label, e.g., "step1"
        step_data = list(step.values())[0]  # Extract the step data   
        if step_label == "step1":
            timestamp_step1 = step_data["timestamp"]
        elif step_label == "step10":
            timestamp_step10 = step_data["timestamp"]

    # Check if both timestamps were found
    if timestamp_step1 is not None and timestamp_step10 is not None:
        from datetime import datetime
        time_format = "%Y-%m-%dT%H:%M:%SZ"
        dt_step1 = datetime.strptime(timestamp_step1, time_format)
        dt_step10 = datetime.strptime(timestamp_step10, time_format)

        # Calculate the time difference
        time_difference_seconds = (dt_step10 - dt_step1).total_seconds()
        minutes = int(time_difference_seconds // 60)
        seconds = int(time_difference_seconds % 60)

        data["totalTime"] = {"minutes": minutes, "seconds": seconds}

        with open("profiling.json", "w") as output_file:
            json.dump(data, output_file, indent=4)

    print("Final Profiling completed.")


#Chunk Functions:
def dataChunkN(n, url, access_token, key):
    loadedDict=getChunkFromResourceServer(n, url, access_token)
    if loadedDict:
        decryptChunk(loadedDict, key)
        return 1
    else:
        return 0 
    
def getChunkFromResourceServer (n,url,token):
    print("Getting chunk from the resource server..")
    rs_headers={'Authorization': f'Bearer {token}'}
    rs_url = f"{url}{n}"
    print(rs_url)
    rs=requests.get(rs_url,headers=rs_headers)
    if(rs.status_code==200):
        print("Token authenticated and Encrypted images recieved.")
        loadedDict=pickle.loads(rs.content)
        #print(loadedDict.keys())
        return loadedDict
    else:
        print(rs.text)
        return None

def decryptChunk(loadedDict,key):
    print("Decrypting chunk..")
    b64encryptedKey=loadedDict["encryptedKey"]
    encData=loadedDict["encData"]
    encryptedKey=base64.b64decode(b64encryptedKey)
    decryptor = PKCS1_OAEP.new(key)
    plainKey=decryptor.decrypt(encryptedKey)
    print("Symmetric key decrypted using the enclave's private RSA key.")
    fernetKey = Fernet(plainKey)
    decryptedData = fernetKey.decrypt(encData)
    print(os.listdir("../"))
    with open('../inputdata/outfile.gz', "wb") as f:
        f.write(decryptedData)
    print("Chunk decrypted and saved in /inputdata/outfile.gz.")


#Chunk Functions for Healthcare:
def dataChunkHealthcare(n, url, access_token, key, file_name):
    loadedArray = getChunkFromResourceServerHealthcare(n, url, access_token, file_name)
    if loadedArray:
        data_arrays_count=decryptArrayHealthcare(loadedArray, key,file_name,n)
        return 1, data_arrays_count
    else:
        return 0, 0
    
def getChunkFromResourceServerHealthcare (n,url,token,file_name):
    print("Getting chunk from the resource server..")
    rs_headers = {'Authorization': f'Bearer {token}'}
    url = url + file_name + "/"
    rs_url = f"{url}{n}"
    print(rs_url)
    rs = requests.get(rs_url, headers=rs_headers)
    if rs.headers['content-type'] == 'application/json':
        try:
            loadedArray = rs.json()
        except json.JSONDecodeError:
            print("Unable to decode response content as JSON.")
    else:
        loadedArray = rs.content
    if loadedArray==b'Chunk not found!':
        print("No more chunks to retrieve.")
        return None
    return loadedArray

def decryptArrayHealthcare(loadedArray,key,file_name,file_number):
    print("Decrypting chunk..")
    loaded_dict = pickle.loads(loadedArray)
    b64encryptedKey = loaded_dict["encryptedKey"]
    encData = loaded_dict["encData"]
    encryptedKey = base64.b64decode(b64encryptedKey)
    decryptor = PKCS1_OAEP.new(key)
    plainKey = decryptor.decrypt(encryptedKey)
    print("Symmetric key decrypted using the enclave's private RSA key.")
    fernetKey = Fernet(plainKey)
    decryptedData = fernetKey.decrypt(encData)
    decompressed_data = gzip.decompress(decryptedData)
    json_data = json.loads(decompressed_data) 
    rows = [list(item.values()) for item in json_data]

    header = [
        "age", "sex", "cp", "trestbps", "chol", "fbs", "restecg", 
        "thalach", "exang", "oldpeak", "slope", "ca", "thal", "target"
    ]
    file_name = file_name
    # Write the data to a CSV file
    output_file = f'./diseaseDetection/data/{file_name}{file_number}'
    print("Output file:", output_file)
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(header)
        writer.writerows(rows)

    print(f"Chunk decrypted and saved in output file.")

    #calculate number of data arrays in output file
    with open(output_file, "r") as file:
        reader = csv.reader(file)
        data_arrays_count = len(list(reader)) - 1
        
    print("Number of data arrays in output file:", data_arrays_count)
    return data_arrays_count

def profiling_inputchunks(count, data_arrays_total):
    with open("profiling.json", "r") as file:
        data = json.load(file)
    data["input"] = {"chunks": count, "no_of_data_arrays": data_arrays_total}
    with open("profiling.json", "w") as file:
        json.dump(data, file, indent=4)