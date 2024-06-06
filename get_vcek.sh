#!/bin/bash

curl -H Metadata:true http://169.254.169.254/metadata/THIM/amd/certification > vcek
cat ./vcek | jq -r '.vcekCert , .certificateChain' > ./vcek.pem
