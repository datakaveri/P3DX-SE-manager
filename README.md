# Intel SGX Enclave Manager

##Enclave Manager:
Enclave is a trusted execution environment (TEE) embedded in a process. The enclave manager is a server that provides communication between the enclave and the APD.

## Enclave Manager Endpoints:

1. Deploy Enclave (/enclave/deploy): This takes as input github repo link, branch, and name & ID of enclave, and brings the enclave up and runs the application inside it.
2. Inference (/enclave/inference): The enclave will send back the inference to the task manager, after it is done running the application.
3. Get State (/enclave/state): This will return a json object of the current state of the application, its description and the step it's currently on.
4. Set State (/enclave/setstate): This will post a json object containing current state of the application, its description, the step it's currently on and the maximum number of steps.

## Steps to Run Server
1. create virtual environment.
      `python -m venv .env enclaveManager`__
2. source the virtual environment.
      `source ~/.env/enclaveManager/bin/activate`
3. install the dependencies from requirements.txt.
      `pip3 install -r requirements.txt`
4. Then clone the current repo and save it in home directory as sgx-enclave-manager.
      `git clone git@github.com:datakaveri/sgx-enclave-manager.git`

The enclave manager server can be accessed in two different ways:

### As a systemd service (publicly)

The enclave manager server runs publicly as a systemd service (enclavemanager). These endpoints can be run on the following domain: https://enclave-manager-sgx.iudx.io/ . It has the endpoints mentioned above. It requires basic authentication.

Steps:
1. Move the systemd services to /etc/systemd/system.
   `cp ~/sgx-enclave-manager/systemd_services/enclavemanager.service /etc/systemd/system`
   `cp ~/sgx-enclave-manager/systemd_services/enclave-manager-rev-tun.service /etc/systemd/system`
2. start the services.
   `sudo systemctl start enclavemanager.service`
   `sudo systemctl start enclave-manager-rev-tun.service`
3. Access endpoints on https://enclave-manager-sgx.iudx.io/ .

### Locally
The enclave manager server can be run locally on http://127.0.0.1:4000 or http://192.168.1.199:4000 for remote access. Steps:

1. Run the following commands in terminal.
   `cd sgx-enclave-manager`
   `./em.sh`
2. The server is now running on localhost and the endpoints can be accessed using Postman.
