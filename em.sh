#~/bin/bash

echo Starting Enclave Manager for Intel SGX

export FLASK_APP=enclave-manager.py
export FLASK_ENV=development
export FLASK_RUN_PORT=4000
export FLASK_RUN_HOST=0.0.0.0
flask run 
