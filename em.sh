#~/bin/bash

echo Starting Enclave Manager for Intel SGX

#virtualenv env
source /home/iudx/.env/enclaveManager/bin/activate
pip3 install -r requirements.txt

export FLASK_APP=enclave-manager-server4.py
export FLASK_ENV=development
export FLASK_RUN_PORT=4000
export FLASK_RUN_HOST=0.0.0.0
flask run 
