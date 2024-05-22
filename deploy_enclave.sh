#!/bin/bash
source ./setState.sh
source ./profilingStep.sh
if [ -f "profiling.json" ]; then
    rm "profiling.json"
fi

#step 1
echo "Step 1"
echo "Starting Confidential Computing"
# call_setstate_endpoint "Starting confidential computing.." 10 1 "Starting confidential computing"
# profiling_func 1 "Starting confidential computing" 

function box_out()
{
  local s="$*"
  tput setaf 3
  echo " -${s//?/-}-
| ${s//?/ } |
| $(tput setaf 4)$s$(tput setaf 3) |
| ${s//?/ } |
 -${s//?/-}-"
  tput sgr 0
}

box_out 'Deploying enclave... (no root mode)'

#STEP 1
echo "Step 1"
box_out "Generating and saving key pair..."
python3 - <<END
import PPDX_SDK

# Call the generate_and_save_keypair function
PPDX_SDK.generate_and_save_key_pair()
END

#step 2
echo "Step 2"
# call_setstate_endpoint "Pulling docker image." 10 2 "Pulling docker image"
# profiling_func 2 "Pulling docker image"
box_out "Pulling docker image..."
python3 - <<END
import PPDX_SDK

# Pulling Docker Image
PPDX_SDK.pull_docker_image('kaushalkirpekar/yolo_docker3')
END
echo "Pulled docker"


echo "Step 3"
#measure docker image & put it inside VTPM 
box_out "Measuring docker image into vTPM..."
python3 - <<END
import PPDX_SDK

#Measuring and storing in vTPM
PPDX_SDK.measureDockervTPM('kaushalkirpekar/yolo_docker3')
END
echo "Measured and stored in vTPM"


echo "Step 4" 
#send VTPM & public key to MAA & get attestation token
box_out "Guest Attestation Executing..."
python3 - <<END
import PPDX_SDK

#Measuring and storing in vTPM
PPDX_SDK.execute_guest_attestation('kaushalkirpekar/yolo_docker3')
END
echo "Guest Attestation complete. JWT received from MAA"

echo "Step 5"
#send attestation token (with public key) to APD & 
# get access token (with public key)
box_out "Sending JWT to APD for verification"

python3 - <<END
import PPDX_SDK

token = PPDX_SDK.getTokenFromAPD('jwt-response.txt', 'config_file.json')
with open('keys/r_token.txt', "w") as token_file:
  token_file.write(token)
END
echo "Access token received from APD"


echo "Step 6"
# send access token to RS for verification & get images
box_out "Getting files from RS"

python3 - <<END
import PPDX_SDK

with open('keys/r_token.txt', "r") as token_file:
  token = token_file.read().strip()
# Call the function
PPDX_SDK.getFileFromResourceServer(token)
END

echo "Step 7"
# Decrypt the recieved images & store in temp directory
box_out "Decrypting & storing files"
sudo python3 - <<END
import PPDX_SDK

# Call the function
PPDX_SDK.decryptFile()
END

echo "Step 8"
sudo docker run kaushalkirpekar/yolo_docker3
echo "DONE"
# Run docker on images in temp directory & write output in temp directory