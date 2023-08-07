#~/bin/bash

echo Starting EnclaveManager modified for tokenized workflow

#virtualenv env
source activate
#pip3 install -r requirements.txt
export FLASK_APP=enclave-manager-server4.py
export FLASK_ENV=development
export FLASK_RUN_PORT=4000
export FLASK_RUN_HOST=0.0.0.0
flask run 
#--host=0.0.0.0 --port=5000
#sudo -E env PATH=$PATH flask run --host=0.0.0.0 --port=80
