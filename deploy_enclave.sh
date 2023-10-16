#!/bin/bash
source ./setState.sh
source ./profilingStep.sh
chmod a+x memory.py
chmod a+x deploy_enclave.sh
if [ -f "profiling.json" ]; then
    rm "profiling.json"
fi

#step 1
echo "Step 1"
memory_usage=$(python3 -c 'import memory; print(memory.measure_memory_usage())')
echo "Memory usage: $memory_usage"

echo "Starting Confidential Computing"
call_setstate_endpoint "Starting confidential computing.." 10 1 "Starting confidential computing"

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

#step 1 done
echo "Step 1 done"
memory_usage_2=$(python3 -c 'import memory; print(memory.measure_memory_usage())') 
echo "Memory usage: $memory_usage_2"

total_memory_usage=$(echo "$memory_usage_2 - $memory_usage" | bc -l)
echo "Total Memory usage: $total_memory_usage"
profiling_func 1 "Starting confidential computing" "$total_memory_usage"

#this code assumes that ~/pulledcode is present
#this code assumes that $3 is the name of the branch you want

#step 2
echo "Step 2"
memory_usage_3=$(python3 -c 'import memory; print(memory.measure_memory_usage())')
echo "Memory usage: $memory_usage_3"

#calling setstate endpoint (step 2)
call_setstate_endpoint "Pulling code." 10 2 "Pulling code"

#first, remove everything in that directory..
box_out 'Clearing ~/pulledcode'

cd ~/pulledcode
rm -rf *


#Now add ssh key and then do a git pull
echo Adding ssh key...
eval $(ssh-agent -s)
ssh-add ~/.ssh/iudx_cloud


#make sure SSH key is deployed
box_out 'Cloning into ~/pulledcode'

g=$(git clone $URL)
echo $g

echo $2 >> ~/pulledcode/dirname.txt

#step 2 completed
echo "Step 2 done"
cd ~/sgx-enclave-manager
memory_usage_4=$(python3 -c 'import memory; print(memory.measure_memory_usage())')
echo "Memory usage: $memory_usage_4"

total_memory_usage_2=$(echo "$memory_usage_4 - $memory_usage_3" | bc -l)
echo "Total Memory usage: $total_memory_usage_2"
profiling_func 2 "Pulling code" "$total_memory_usage_2"

box_out 'Switching branch..'
echo Switching to.. $BRANCH of $REPO
cd ~/pulledcode/$REPO

g=$(git checkout $BRANCH)
echo $g

echo "Deployed enclave ID $ID, URL $URL, BRANCH $BRANCH"
echo $REPO

#Enclave has been deployed. Call build script
. ~/pulledcode/$REPO/b.sh

box_out 'Running application inside enclave..'
#call run script
. /home/iudx/pulledcode/$REPO/r.sh