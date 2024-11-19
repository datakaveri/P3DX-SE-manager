# AMD SEV Enclave Manager

##Enclave Manager:
Enclave is a trusted execution environment (TEE) embedded in a process. The enclave manager is a server that provides communication between the enclave and the APD.

## Enclave Manager Endpoints:

1. Deploy Enclave (/enclave/deploy): This takes as input github repo link, branch, and name & ID of enclave, and brings the enclave up and runs the application inside it.
2. Inference (/enclave/inference): The enclave will send back the inference to the task manager, after it is done running the application.
3. Get State (/enclave/state): This will return a json object of the current state of the application, its description and the step it's currently on.

## How to Dockerize applications for running inside AMD CVM

1. Clone the repository into the VM/your personal device, go into the application directory and add the Dockerfile
2. Creat a Github PAT (with write & delete packages permission)
3. Then login to the Github Container Registry
      `export token=<your_PAT>`
      `echo $token | docker login ghcr.io -u <Github_Username> --password-stdin`
   It should say login succeeded.
4. Build the docker image using the following command:
      `sudo docker build -t <image_name> . `
5. Tag the image
      `docker tag <image_name> ghcr.io/datakaveri/<package_name>`
6. Push the image
      `docker push ghcr.io/datakaveri/<package_name>:<tag>`

   
