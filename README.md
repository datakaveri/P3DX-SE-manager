# Intel SGX Enclave Manager

We will have the following endpoints:

1. Deploy Enclave: This will bring the enclave up and run the application inside it.
2. Inference: The enclave will send back the inference to the task manager, after it is done running the application.
3. Get State: This will return a json object of the current state of the application, its description and the step it's currently on.
4. Set State: This will pass a json object containing current state of the application, its description, the step it's currently on and the maximum number of steps.

These endpoints can be run using the following domain: https://enclave-manager-sgx.iudx.io/
It requires basic authentication.

The server runs as a systemd service
To check status (if active & running):

> sudo systemctl status enclavemanager.service

To start service:

> sudo systemctl start enclavemanager.service

To stop service:

> sudo systemctl stop enclavemanager.service

To restart service (after any changes or if getting error):

> sudo service enclavemanager restart
