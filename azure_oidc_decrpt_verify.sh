#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
trap 'echo "ERROR: Script failed at line ${LINENO}: ${BASH_COMMAND}" >&2' ERR
export AWS_PAGER=""

echo "============================================================"
echo "Azure OIDC + Secrets Manager AES Key + Local Excel Decryption"
echo "============================================================"

BUCKET="s3-dev-catalogue-tanuh-135663523795-ap-south-1-an"
PREFIX="cross-cloud-secret-proof"
REGION="ap-south-1"

ROLE_ARN="arn:aws:iam::135663523795:role/AzureCrossCloudTEEAssumeRole"
ROLE_SESSION_NAME="azure-oidc-secret-excel-proof"
DURATION_SECONDS="3600"
AZURE_TOKEN_RESOURCE="https://management.azure.com/"
AZURE_CLIENT_ID=""
EXPECTED_SECRET_NAME="azure-oidc/excel-aes-key"
KEEP_SECRET_EVIDENCE="${KEEP_SECRET_EVIDENCE:-false}"

TOKEN_RESPONSE_FILE="azure_token_response.json"
WEB_IDENTITY_TOKEN_FILE="web_identity_token.jwt"
STS_CREDS_FILE="aws_oidc_creds.json"

CIPHERTEXT_FILE="file_example_XLS_10.xls.enc"
MANIFEST_FILE="encryption_manifest_secret.json"
SECRET_RESPONSE_FILE="secret_value_response.json"
DECRYPTED_FILE="azure_secret_decrypted_file_example_XLS_10.xls"
VM_METADATA_FILE="vm_metadata.json"

cleanup_secret_files() {
  if [[ "${KEEP_SECRET_EVIDENCE}" != "true" ]]; then
    rm -f "$TOKEN_RESPONSE_FILE" "$WEB_IDENTITY_TOKEN_FILE" "$STS_CREDS_FILE" "$SECRET_RESPONSE_FILE"
  fi
}
trap cleanup_secret_files EXIT

s3_copy_required() {
  local key="$1"
  local destination="$2"
  local head_error

  if ! head_error=$(aws s3api head-object \
    --bucket "$BUCKET" \
    --key "$key" \
    --region "$REGION" \
    --output json \
    2>&1 >/dev/null); then
    case "$head_error" in
      *"(404)"*|*"Not Found"*|*"NoSuchKey"*)
        echo "ERROR: Required S3 object is missing: s3://$BUCKET/$key" >&2
        ;;
      *"(403)"*|*"Forbidden"*|*"AccessDenied"*)
        echo "ERROR: Access denied for required S3 object: s3://$BUCKET/$key" >&2
        ;;
      *)
        echo "ERROR: Could not check required S3 object: s3://$BUCKET/$key" >&2
        echo "$head_error" >&2
        ;;
    esac
    exit 1
  fi

  aws s3 cp "s3://$BUCKET/$key" "$destination" --region "$REGION"
}

echo
echo "============================================================"
echo "1. Checking prerequisites"
echo "============================================================"

command -v aws >/dev/null 2>&1 || { echo "ERROR: aws CLI not found"; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "ERROR: curl not found"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 not found"; exit 1; }

echo "AWS CLI: $(aws --version)"

python3 - << 'EOF'
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:
    raise SystemExit(
        "ERROR: Python package 'cryptography' is missing.\n"
        "Install it using: pip3 install --user cryptography"
    )
EOF

echo "Prerequisites OK."

echo
echo "============================================================"
echo "2. Reading Azure VM metadata"
echo "============================================================"

curl --silent --show-error --fail \
  --connect-timeout 2 --max-time 5 --retry 2 \
  --noproxy "*" \
  -H "Metadata:true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
  -o "$VM_METADATA_FILE"

python3 - "$VM_METADATA_FILE" << 'EOF'
import json
import sys
d=json.load(open(sys.argv[1]))
c=d.get("compute", {})
print("VM name:", c.get("name"))
print("Resource group:", c.get("resourceGroupName"))
print("Location:", c.get("location"))
print("VM size:", c.get("vmSize"))
print("Security type:", c.get("securityProfile", {}).get("securityType"))
EOF

echo
echo "============================================================"
echo "3. Getting Azure managed identity token"
echo "============================================================"

TOKEN_ARGS=(
  --get
  --data-urlencode "api-version=2018-02-01"
  --data-urlencode "resource=${AZURE_TOKEN_RESOURCE}"
)

if [[ -n "$AZURE_CLIENT_ID" ]]; then
  TOKEN_ARGS+=(--data-urlencode "client_id=${AZURE_CLIENT_ID}")
fi

curl --silent --show-error --fail \
  --connect-timeout 2 --max-time 10 --retry 2 \
  --noproxy "*" \
  -H "Metadata:true" \
  "${TOKEN_ARGS[@]}" \
  "http://169.254.169.254/metadata/identity/oauth2/token" \
  -o "$TOKEN_RESPONSE_FILE"

python3 - << EOF
import json
d=json.load(open("$TOKEN_RESPONSE_FILE"))
open("$WEB_IDENTITY_TOKEN_FILE","w").write(d["access_token"])
print("Saved web identity token:", "$WEB_IDENTITY_TOKEN_FILE")
print("client_id:", d.get("client_id"))
print("resource:", d.get("resource"))
print("expires_on:", d.get("expires_on"))
EOF

echo
echo "============================================================"
echo "4. Decoding JWT claims for proof"
echo "============================================================"

python3 - << EOF
import base64, json
tok=open("$WEB_IDENTITY_TOKEN_FILE").read().strip()
payload=tok.split(".")[1] + "=" * (-len(tok.split(".")[1]) % 4)
claims=json.loads(base64.urlsafe_b64decode(payload))
for k in ["iss", "aud", "sub", "appid", "azp", "tid", "oid", "xms_mirid"]:
    print(k + ":", claims.get(k))
EOF

echo
echo "============================================================"
echo "5. Assuming AWS role using Azure OIDC token"
echo "============================================================"

aws sts assume-role-with-web-identity \
  --role-arn "$ROLE_ARN" \
  --role-session-name "$ROLE_SESSION_NAME" \
  --web-identity-token "file://$WEB_IDENTITY_TOKEN_FILE" \
  --duration-seconds "$DURATION_SECONDS" \
  --region "$REGION" \
  --output json > "$STS_CREDS_FILE"

python3 - << EOF
import json
d=json.load(open("$STS_CREDS_FILE"))
print("AssumeRoleWithWebIdentity succeeded")
print("Assumed role ARN:", d["AssumedRoleUser"]["Arn"])
print("Provider:", d.get("Provider"))
print("Audience:", d.get("Audience"))
print("Subject:", d.get("SubjectFromWebIdentityToken"))
print("Expiration:", d["Credentials"]["Expiration"])
EOF

echo
echo "============================================================"
echo "6. Exporting temporary AWS credentials"
echo "============================================================"

export AWS_ACCESS_KEY_ID="$(python3 -c "import json;print(json.load(open('$STS_CREDS_FILE'))['Credentials']['AccessKeyId'])")"
export AWS_SECRET_ACCESS_KEY="$(python3 -c "import json;print(json.load(open('$STS_CREDS_FILE'))['Credentials']['SecretAccessKey'])")"
export AWS_SESSION_TOKEN="$(python3 -c "import json;print(json.load(open('$STS_CREDS_FILE'))['Credentials']['SessionToken'])")"
export AWS_DEFAULT_REGION="$REGION"

echo "Temporary AWS credentials exported for this script process."

echo
echo "============================================================"
echo "7. Verifying AWS caller identity"
echo "============================================================"

aws sts get-caller-identity --output json

echo
echo "============================================================"
echo "8. Downloading encrypted Excel and manifest from S3"
echo "============================================================"

s3_copy_required "$PREFIX/$CIPHERTEXT_FILE" "$CIPHERTEXT_FILE"
s3_copy_required "$PREFIX/$MANIFEST_FILE" "$MANIFEST_FILE"

ls -lh "$CIPHERTEXT_FILE" "$MANIFEST_FILE"

echo
echo "============================================================"
echo "9. Reading AES key from AWS Secrets Manager"
echo "============================================================"

SECRET_NAME="$(python3 - "$MANIFEST_FILE" "$EXPECTED_SECRET_NAME" << 'EOF'
import json
import sys

manifest_file = sys.argv[1]
expected_secret_name = sys.argv[2]

with open(manifest_file, "r") as f:
    m = json.load(f)

if "aes_key_b64" in m or "aes_key" in m:
    raise SystemExit("ERROR: Manifest must not contain AES key material")

secret_name = m.get("secret_name")
if secret_name != expected_secret_name:
    raise SystemExit(
        f"ERROR: Manifest secret_name {secret_name!r} does not match expected secret {expected_secret_name!r}"
    )

print(secret_name)
EOF
)"

echo "Secret name from manifest: $SECRET_NAME"

if ! secret_error=$(aws secretsmanager get-secret-value \
  --secret-id "$SECRET_NAME" \
  --region "$REGION" \
  --output json \
  2>&1 > "$SECRET_RESPONSE_FILE"); then
  case "$secret_error" in
    *AccessDenied*|*AccessDeniedException*)
      echo "ERROR: Access denied reading Secrets Manager secret: $SECRET_NAME" >&2
      ;;
    *ResourceNotFoundException*)
      echo "ERROR: Secrets Manager secret not found: $SECRET_NAME" >&2
      ;;
    *)
      echo "ERROR: Could not read Secrets Manager secret: $SECRET_NAME" >&2
      echo "$secret_error" >&2
      ;;
  esac
  exit 1
fi

echo "Secret value retrieved from AWS Secrets Manager."
echo "Secret response saved privately."

echo
echo "============================================================"
echo "10. Decrypting Excel locally and verifying SHA256"
echo "============================================================"

python3 - << EOF
import base64
import binascii
import hashlib
import json
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ciphertext_file = "$CIPHERTEXT_FILE"
manifest_file = "$MANIFEST_FILE"
secret_response_file = "$SECRET_RESPONSE_FILE"
decrypted_file = "$DECRYPTED_FILE"

with open(manifest_file, "r") as f:
    manifest = json.load(f)

if "aes_key_b64" in manifest or "aes_key" in manifest:
    raise SystemExit("ERROR: Manifest must not contain AES key material")

with open(secret_response_file, "r") as f:
    secret_response = json.load(f)

secret_string = secret_response.get("SecretString")
if not secret_string:
    raise SystemExit("ERROR: SecretString missing from Secrets Manager response")

try:
    secret_payload = json.loads(secret_string)
    aes_key = base64.b64decode(secret_payload["aes_key_b64"], validate=True)
except (KeyError, json.JSONDecodeError, binascii.Error) as exc:
    raise SystemExit(f"ERROR: Invalid secret payload: {exc}") from exc

if len(aes_key) != 32:
    raise SystemExit(f"ERROR: Expected 32-byte AES-256 key, got {len(aes_key)} bytes")

nonce = base64.b64decode(manifest["nonce_b64"], validate=True)
if len(nonce) != 12:
    raise SystemExit(f"ERROR: Expected 12-byte AES-GCM nonce, got {len(nonce)} bytes")

aad = manifest["aad"].encode("utf-8")

with open(ciphertext_file, "rb") as f:
    ciphertext = f.read()

actual_ciphertext_sha256 = hashlib.sha256(ciphertext).hexdigest()
expected_ciphertext_sha256 = manifest["ciphertext_sha256"]

print("Expected ciphertext SHA256:", expected_ciphertext_sha256)
print("Actual ciphertext SHA256:", actual_ciphertext_sha256)

if actual_ciphertext_sha256 != expected_ciphertext_sha256:
    raise SystemExit("ERROR: Ciphertext SHA256 mismatch before decrypt")

aesgcm = AESGCM(aes_key)
try:
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
except InvalidTag as exc:
    raise SystemExit("ERROR: AES-GCM authentication failed; ciphertext, nonce, AAD, or AES key is wrong") from exc

actual_plaintext_sha256 = hashlib.sha256(plaintext).hexdigest()
expected_plaintext_sha256 = manifest["original_sha256"]

with open(decrypted_file, "wb") as f:
    f.write(plaintext)

print("Local AES-256-GCM decryption succeeded.")
print("Expected original SHA256:", expected_plaintext_sha256)
print("Actual decrypted SHA256:", actual_plaintext_sha256)
print("Hash match:", actual_plaintext_sha256 == expected_plaintext_sha256)
print("Decrypted file written:", decrypted_file)
print("Decrypted file size bytes:", len(plaintext))

if actual_plaintext_sha256 != expected_plaintext_sha256:
    raise SystemExit("ERROR: Decrypted Excel hash does not match original")

aes_key = b"\\x00" * 32
EOF

cleanup_secret_files
if [[ "${KEEP_SECRET_EVIDENCE}" == "true" ]]; then
  echo "Secret-bearing token, STS, and Secrets Manager response files retained because KEEP_SECRET_EVIDENCE=true."
else
  echo "Secret-bearing token, STS, and Secrets Manager response files deleted."
  echo "Set KEEP_SECRET_EVIDENCE=true before running only if you intentionally need to retain them."
fi

echo
echo "============================================================"
echo "11. File type check"
echo "============================================================"

file "$DECRYPTED_FILE" || true
ls -lh "$DECRYPTED_FILE"

echo
echo "============================================================"
echo "Secret-based final proof completed"
echo "============================================================"
echo "Proof summary:"
echo "- Azure VM metadata was read through IMDS."
echo "- Azure VM obtained managed identity token."
echo "- AWS STS accepted Azure OIDC token."
echo "- Azure assumed AWS role without static AWS keys."
echo "- Azure downloaded encrypted Excel and manifest from S3."
echo "- Azure retrieved AES key from AWS Secrets Manager."
echo "- No AES key file was stored in S3."
echo "- Manifest did not contain AES key material."
echo "- Ciphertext SHA256 was verified before decrypt."
echo "- Azure decrypted Excel locally with AES-256-GCM using manifest AAD."
echo "- SHA256 hash of decrypted Excel matched original hash."
echo "- Proof is Azure managed-identity based OIDC federation with AWS Secrets Manager key retrieval and local AES-GCM decryption."
echo "- Security type was reported from VM metadata; this script does not prove TEE-attested or confidential VM key release."
