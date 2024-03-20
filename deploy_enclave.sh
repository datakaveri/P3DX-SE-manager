#!/bin/bash
source ./setState.sh
source ./profilingStep.sh
chmod a+x deploy_enclave.sh
if [ -f "profiling.json" ]; then
    rm "profiling.json"
fi

#step 1
echo "Step 1"
echo "Starting Confidential Computing"
call_setstate_endpoint "Starting confidential computing.." 10 1 "Starting confidential computing"
profiling_func 1 "Starting confidential computing" 

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

APP_NAME = $1

box_out 'Deploying enclave... (no root mode)'

echo $1 

#this code assumes that ~/pulledcode is present
#this code assumes that $3 is the name of the branch you want

#step 2
echo "Step 2"
call_setstate_endpoint "Pulling docker image." 10 2 "Pulling docker image"
profiling_func 2 "Pulling docker image"

sudo docker login
sudo docker pull kaushalkirpekar/yolo_docker3 

echo "Pulled docker"

echo "Step 3" 
# measure docker image 

#Enclave has been deployed. Call build script
#. ~/pulledcode/$REPO/b.sh

box_out 'Running application inside enclave..'
#call run script
#. /home/iudx/pulledcode/$REPO/r.sh