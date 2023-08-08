#!/bin/bash

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

#box_out  'Starting externally accessible EnclaveManager-server..'
#./em.sh &

URL=$1
REPO=$2
BRANCH=$3
ID=$4
NAME=$5

echo
echo
echo
echo

box_out 'Deploying enclave... (no root mode)'

echo $1 $2 $3 $4 $5

#this code assumes that ~/pulledcode is present
#this code assumes that $3 is the name of the branch you want

#first, remove everything in that directory..

box_out 'Clearing ~/pulledcode'

cd ~/pulledcode
rm -rf *

#Now do a git pull there

echo Adding ssh key...
eval $(ssh-agent -s)
ssh-add /home/iudx/.ssh/iudx_cloud

box_out 'Cloning into ~/pulledcode'

g=$(git clone $URL)
echo $g

echo $2 >> /home/iudx/pulledcode/dirname.txt

box_out 'Switching branch..'
echo Switching to.. $BRANCH of $REPO
cd /home/iudx/pulledcode/$REPO

g=$(git checkout $BRANCH)
echo $g

#Now do the measurements...
#sudo -u iudx /home/iudx/pulledcode/nitro-enclaves/enclavemanager/get_enclave_measurements.sh
#echo $cmd

echo "Deployed enclave ID $ID, URL $URL, BRANCH $BRANCH"

#Enclave has been deployed. Now run application inside it:

box_out 'Building application..'
#call build script
sh /home/iudx/pulledcode/sgx-yolo-app/build.sh

box_out 'Running application inside enclave..'
#call run script
sh /home/iudx/pulledcode/sgx-yolo-app/run.sh