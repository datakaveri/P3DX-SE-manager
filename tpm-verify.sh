#!/bin/bash

# Execute tpm2_readpublic command
echo "Executing tpm2_readpublic command..."
tpm2_readpublic -c 0x81000003 -f pem -o outputfile.pem
if [ $? -eq 0 ]; then
    echo "tpm2_readpublic command executed successfully."
    echo "Public key successfully extracted and stored in output.pem"
else
    echo "Error: Failed to execute tpm2_readpublic command."
    exit 1
fi

# Extract nonce from outputfile.pem
#nonce=$(openssl x509 -pubkey -noout -in outputfile.pem | openssl rsa -pubin -outform DER 2>/dev/null | openssl dgst -sha256 -binary | xxd -p -c 32)
sleep 2

# Execute tpm2_quote command
echo "Executing tpm2_quote command..."
# tpm2_quote -c 0x81000003 -l sha256:15,16,22 -q $nonce -m message_output_file.msg -s signature_output_file.sig -o PCR_output_file.pcrs -g sha256
tpm2_quote -c 0x81000003 -l sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 -m message_output_file.msg -s signature_output_file.sig -o PCR_output_file.pcrs -g sha256
if [ $? -eq 0 ]; then
    echo "tpm2_quote command executed successfully."
    echo "TPM quote generated containing pcr 0-15"
    echo "Binary file message_output_file.msg, signature_output_file.sig and PCR_output_file.pcrs have been generated for verification purposes"
else
    echo "Error: Failed to execute tpm2_quote command."
    exit 1
fi

sleep 2

# Execute tpm2_checkquote command
echo "Executing tpm2_checkquote command..."
# tpm2_checkquote -u outputfile.pem -m message_output_file.msg -s signature_output_file.sig -f PCR_output_file.pcrs -g sha256 -q $nonce
tpm2_checkquote -u outputfile.pem -m message_output_file.msg -s signature_output_file.sig -f PCR_output_file.pcrs -g sha256
if [ $? -eq 0 ]; then
    echo "tpm2_checkquote command executed successfully."
    echo "TPM report containing pcrs has been verified with the signature"
else
    echo "Error: Failed to execute tpm2_checkquote command."
    exit 1
fi

