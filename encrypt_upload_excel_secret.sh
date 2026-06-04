#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
trap 'echo "ERROR: Script failed at line ${LINENO}: ${BASH_COMMAND}" >&2' ERR
export AWS_PAGER=""

# ============================================================
# Local Excel encryption + AES key stored in AWS Secrets Manager
# ============================================================

BUCKET="s3-dev-catalogue-tanuh-135663523795-ap-south-1-an"
PREFIX="cross-cloud-secret-proof"
REGION="ap-south-1"

PLAINTEXT_FILE="file_example_XLS_10.xls"
CIPHERTEXT_FILE="file_example_XLS_10.xls.enc"
MANIFEST_FILE="encryption_manifest_secret.json"

SECRET_NAME="azure-oidc/excel-aes-key"
SECRET_PAYLOAD_FILE="secret_payload_tmp.json"

cleanup_secret_payload() {
  rm -f "$SECRET_PAYLOAD_FILE"
}
trap cleanup_secret_payload EXIT

echo "============================================================"
echo "1. Checking prerequisites"
echo "============================================================"

command -v aws >/dev/null 2>&1 || { echo "ERROR: aws CLI not found"; exit 1; }
command -v python >/dev/null 2>&1 || { echo "ERROR: python not found"; exit 1; }

if [ ! -f "$PLAINTEXT_FILE" ]; then
  echo "ERROR: plaintext file not found: $PLAINTEXT_FILE"
  exit 1
fi

python - << 'EOF'
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:
    raise SystemExit(
        "ERROR: Python package 'cryptography' is missing.\n"
        "Install it using: pip install cryptography"
    )
EOF

echo "Plaintext file found: $PLAINTEXT_FILE"
cleanup_secret_payload

echo
echo "============================================================"
echo "2. Confirming current AWS identity"
echo "============================================================"

aws sts get-caller-identity --output json

echo
echo "============================================================"
echo "3. Encrypting Excel locally using AES-256-GCM"
echo "============================================================"

python - << EOF
import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

plaintext_file = "$PLAINTEXT_FILE"
ciphertext_file = "$CIPHERTEXT_FILE"
manifest_file = "$MANIFEST_FILE"

bucket = "$BUCKET"
prefix = "$PREFIX"
region = "$REGION"
secret_name = "$SECRET_NAME"

# Generate local AES-256 key.
aes_key = os.urandom(32)
aes_key_b64 = base64.b64encode(aes_key).decode("utf-8")

with open(plaintext_file, "rb") as f:
    plaintext = f.read()

original_sha256 = hashlib.sha256(plaintext).hexdigest()

# AES-GCM recommended nonce size is 12 bytes.
nonce = os.urandom(12)
nonce_b64 = base64.b64encode(nonce).decode("utf-8")

aad = f"{bucket}/{prefix}/{plaintext_file}".encode("utf-8")

aesgcm = AESGCM(aes_key)
ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

with open(ciphertext_file, "wb") as f:
    f.write(ciphertext)

ciphertext_sha256 = hashlib.sha256(ciphertext).hexdigest()

manifest = {
    "version": 1,
    "created_utc": datetime.now(timezone.utc).isoformat(),
    "proof_type": "SecretsManagerStoredAESKey",
    "algorithm": "AES-256-GCM",
    "region": region,
    "bucket": bucket,
    "prefix": prefix,
    "plaintext_filename": plaintext_file,
    "ciphertext_filename": ciphertext_file,
    "manifest_filename": manifest_file,
    "secret_name": secret_name,
    "nonce_b64": nonce_b64,
    "aad": aad.decode("utf-8"),
    "original_sha256": original_sha256,
    "ciphertext_sha256": ciphertext_sha256,
    "plaintext_size_bytes": len(plaintext),
    "ciphertext_size_bytes": len(ciphertext)
}

with open(manifest_file, "w") as f:
    json.dump(manifest, f, indent=2)

secret_payload = {
    "aes_key_b64": aes_key_b64,
    "algorithm": "AES-256-GCM",
    "created_utc": manifest["created_utc"],
    "plaintext_filename": plaintext_file,
    "ciphertext_filename": ciphertext_file,
    "original_sha256": original_sha256
}

with open("$SECRET_PAYLOAD_FILE", "w") as f:
    json.dump(secret_payload, f, indent=2)

# Best-effort local variable cleanup.
aes_key = b"\\x00" * 32

print("Local encryption succeeded.")
print("Original SHA256:", original_sha256)
print("Ciphertext SHA256:", ciphertext_sha256)
print("Wrote:", ciphertext_file)
print("Wrote:", manifest_file)
print("Wrote temporary secret payload: $SECRET_PAYLOAD_FILE")
EOF

echo
echo "============================================================"
echo "4. Creating or updating AES key in AWS Secrets Manager"
echo "============================================================"

if describe_error=$(aws secretsmanager describe-secret \
  --secret-id "$SECRET_NAME" \
  --region "$REGION" \
  2>&1 >/dev/null); then

  echo "Secret already exists. Updating secret value."

  aws secretsmanager put-secret-value \
    --secret-id "$SECRET_NAME" \
    --secret-string "file://$SECRET_PAYLOAD_FILE" \
    --region "$REGION" \
    --output json >/dev/null

else
  case "$describe_error" in
    *ResourceNotFoundException*)
      echo "Secret does not exist. Creating new secret."

      aws secretsmanager create-secret \
        --name "$SECRET_NAME" \
        --description "AES-256 key for Azure OIDC encrypted Excel proof" \
        --secret-string "file://$SECRET_PAYLOAD_FILE" \
        --region "$REGION" \
        --output json >/dev/null
      ;;
    *AccessDenied*|*AccessDeniedException*|*UnauthorizedOperation*)
      echo "ERROR: Access denied while checking Secrets Manager secret: $SECRET_NAME" >&2
      exit 1
      ;;
    *)
      echo "ERROR: Could not check Secrets Manager secret: $SECRET_NAME" >&2
      echo "$describe_error" >&2
      exit 1
      ;;
  esac
fi

echo "AES key stored in AWS Secrets Manager as: $SECRET_NAME"

echo
echo "============================================================"
echo "5. Removing temporary local secret payload"
echo "============================================================"

cleanup_secret_payload
echo "Deleted temporary secret payload file."

echo
echo "============================================================"
echo "6. Uploading encrypted Excel and manifest to S3"
echo "============================================================"

aws s3 cp "$CIPHERTEXT_FILE" "s3://$BUCKET/$PREFIX/$CIPHERTEXT_FILE" --region "$REGION"
aws s3 cp "$MANIFEST_FILE" "s3://$BUCKET/$PREFIX/$MANIFEST_FILE" --region "$REGION"

echo
echo "============================================================"
echo "7. Verifying uploaded S3 artifacts"
echo "============================================================"

aws s3 ls "s3://$BUCKET/$PREFIX/" --region "$REGION"

echo
echo "============================================================"
echo "Secret-based encryption upload completed"
echo "============================================================"
echo "S3 contains:"
echo "- s3://$BUCKET/$PREFIX/$CIPHERTEXT_FILE"
echo "- s3://$BUCKET/$PREFIX/$MANIFEST_FILE"
echo
echo "Secrets Manager contains:"
echo "- $SECRET_NAME"
echo
echo "Proof summary:"
echo "- Encrypted Excel and manifest uploaded to S3."
echo "- AES key stored only in AWS Secrets Manager."
echo "- No AES key file or encrypted DEK was uploaded to S3."
