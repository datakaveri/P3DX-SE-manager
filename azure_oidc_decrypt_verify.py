#!/usr/bin/env python3
"""
Azure managed identity OIDC -> AWS STS -> S3/Secrets Manager -> AES-GCM decrypt proof.

This script is intended to run inside an Azure VM with managed identity enabled.
It proves Azure managed-identity based OIDC federation with AWS Secrets Manager
key retrieval and local AES-GCM decryption.

It does not prove TEE-attested secret release or confidential VM key release.
"""

from __future__ import annotations

import atexit
import base64
import binascii
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

try:
    import boto3
    import botocore
    import requests
    from botocore.config import Config
    from botocore.exceptions import BotoCoreError, ClientError
    from cryptography import __version__ as CRYPTOGRAPHY_VERSION
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError as exc:
    print(f"ERROR: Missing Python dependency: {exc}", file=sys.stderr)
    print("Install dependencies with: pip3 install --user boto3 requests cryptography", file=sys.stderr)
    sys.exit(1)


# -----------------------------
# Demo configuration
# -----------------------------
BUCKET = "s3-dev-catalogue-tanuh-135663523795-ap-south-1-an"
PREFIX = "cross-cloud-secret-proof"
REGION = "ap-south-1"

ROLE_ARN = "arn:aws:iam::135663523795:role/AzureCrossCloudTEEAssumeRole"
ROLE_SESSION_NAME = "azure-oidc-secret-excel-proof"
DURATION_SECONDS = 3600

CIPHERTEXT_FILE = "file_example_XLS_10.xls.enc"
MANIFEST_FILE = "encryption_manifest_secret.json"
DECRYPTED_FILE = "azure_secret_decrypted_file_example_XLS_10.xls"
EXPECTED_SECRET_NAME = "azure-oidc/excel-aes-key"

# Azure IMDS configuration
IMDS_ENDPOINT = "http://169.254.169.254"
IMDS_INSTANCE_API_VERSION = "2021-02-01"
IMDS_TOKEN_API_VERSION = "2018-02-01"
AZURE_TOKEN_RESOURCE = "https://management.azure.com/"
AZURE_CLIENT_ID = os.environ.get("AZURE_CLIENT_ID", "").strip()

# Evidence files. These contain secrets unless removed.
VM_METADATA_FILE = Path("vm_metadata.json")
TOKEN_RESPONSE_FILE = Path("azure_token_response.json")
WEB_IDENTITY_TOKEN_FILE = Path("web_identity_token.jwt")
STS_CREDS_FILE = Path("aws_oidc_creds.json")
SECRET_RESPONSE_FILE = Path("secret_value_response.json")

KEEP_SECRET_EVIDENCE = os.environ.get("KEEP_SECRET_EVIDENCE", "").lower() == "true"
SECRET_BEARING_FILES = [
    TOKEN_RESPONSE_FILE,
    WEB_IDENTITY_TOKEN_FILE,
    STS_CREDS_FILE,
    SECRET_RESPONSE_FILE,
]

SAFE_JWT_CLAIMS = ["iss", "aud", "sub", "appid", "azp", "tid", "oid", "xms_mirid"]
FORBIDDEN_MANIFEST_FIELDS = {
    "aes_key",
    "aes_key_b64",
    "secretstring",
    "secret_string",
    "dek",
    "dek_b64",
    "plaintext_dek",
    "plaintext_dek_b64",
    "encrypted_dek",
    "encrypted_dek_b64",
    "key_material",
    "key_b64",
}


class ProofError(Exception):
    """Expected proof failure with a safe user-facing message."""


def section(title: str) -> None:
    print()
    print("=" * 60)
    print(title)
    print("=" * 60)


def json_default(value: Any) -> str:
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def unlink_if_exists(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def write_text_private(path: Path, value: str) -> None:
    unlink_if_exists(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(value)


def write_bytes_private(path: Path, value: bytes) -> None:
    unlink_if_exists(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(value)


def write_json_private(path: Path, value: Any) -> None:
    write_text_private(path, json.dumps(value, indent=2, default=json_default))


def cleanup_secret_files() -> None:
    if KEEP_SECRET_EVIDENCE:
        return
    for path in SECRET_BEARING_FILES:
        unlink_if_exists(path)


atexit.register(cleanup_secret_files)


def check_prerequisites() -> None:
    section("1. Checking prerequisites")
    print(f"Python: {sys.version.split()[0]}")
    print(f"boto3: {boto3.__version__}")
    print(f"botocore: {botocore.__version__}")
    print(f"requests: {requests.__version__}")
    print(f"cryptography: {CRYPTOGRAPHY_VERSION}")
    print("AWS CLI is not required; this Python version uses boto3.")
    print("Prerequisites OK.")


def imds_get(path: str, params: dict[str, str], purpose: str, timeout: tuple[float, float]) -> dict[str, Any]:
    session = requests.Session()
    session.trust_env = False  # Same intent as curl --noproxy "*" for IMDS.
    url = f"{IMDS_ENDPOINT}{path}"
    headers = {"Metadata": "true"}
    last_error: Exception | None = None

    for attempt in range(1, 4):
        try:
            response = session.get(url, headers=headers, params=params, timeout=timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as exc:
            last_error = exc
            if attempt < 3:
                time.sleep(0.5 * attempt)
                continue
        except json.JSONDecodeError as exc:
            raise ProofError(f"ERROR: IMDS returned invalid JSON while {purpose}: {exc}") from exc

    raise ProofError(f"ERROR: IMDS unavailable while {purpose}: {last_error}") from last_error


def read_vm_metadata() -> dict[str, Any]:
    section("2. Reading Azure VM metadata")
    metadata = imds_get(
        "/metadata/instance",
        {"api-version": IMDS_INSTANCE_API_VERSION},
        "reading Azure VM metadata",
        timeout=(2, 5),
    )
    write_json_private(VM_METADATA_FILE, metadata)

    compute = metadata.get("compute", {})
    print("VM name:", compute.get("name"))
    print("Resource group:", compute.get("resourceGroupName"))
    print("Location:", compute.get("location"))
    print("VM size:", compute.get("vmSize"))
    print("Security type:", compute.get("securityProfile", {}).get("securityType"))
    return metadata


def get_managed_identity_token() -> str:
    section("3. Getting Azure managed identity token")
    params = {
        "api-version": IMDS_TOKEN_API_VERSION,
        "resource": AZURE_TOKEN_RESOURCE,
    }
    if AZURE_CLIENT_ID:
        params["client_id"] = AZURE_CLIENT_ID

    token_response = imds_get(
        "/metadata/identity/oauth2/token",
        params,
        "requesting Azure managed identity token",
        timeout=(2, 10),
    )
    if "access_token" not in token_response:
        safe_keys = ", ".join(sorted(token_response.keys()))
        raise ProofError(f"ERROR: Managed identity token response did not contain access_token. Keys: {safe_keys}")

    access_token = str(token_response["access_token"])
    write_json_private(TOKEN_RESPONSE_FILE, token_response)
    write_text_private(WEB_IDENTITY_TOKEN_FILE, access_token)

    print("Saved web identity token:", WEB_IDENTITY_TOKEN_FILE)
    print("client_id:", token_response.get("client_id"))
    print("resource:", token_response.get("resource"))
    print("expires_on:", token_response.get("expires_on"))
    return access_token


def decode_jwt_claims(token: str) -> None:
    section("4. Decoding JWT claims for proof")
    parts = token.split(".")
    if len(parts) < 2:
        raise ProofError("ERROR: Token does not look like a JWT")

    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProofError(f"ERROR: Could not decode JWT payload: {exc}") from exc

    for key in SAFE_JWT_CLAIMS:
        print(f"{key}: {claims.get(key)}")


def boto_config() -> Config:
    return Config(region_name=REGION, retries={"max_attempts": 3, "mode": "standard"})


def assume_role_with_web_identity(token: str) -> dict[str, Any]:
    section("5. Assuming AWS role using Azure OIDC token")
    print("Role ARN:", ROLE_ARN)
    print("Session name:", ROLE_SESSION_NAME)

    sts = boto3.client("sts", region_name=REGION, config=boto_config())
    try:
        response = sts.assume_role_with_web_identity(
            RoleArn=ROLE_ARN,
            RoleSessionName=ROLE_SESSION_NAME,
            WebIdentityToken=token,
            DurationSeconds=DURATION_SECONDS,
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "Unknown")
        message = exc.response.get("Error", {}).get("Message", str(exc))
        raise ProofError(f"ERROR: STS AssumeRoleWithWebIdentity failed ({code}): {message}") from exc
    except BotoCoreError as exc:
        raise ProofError(f"ERROR: STS AssumeRoleWithWebIdentity failed: {exc}") from exc

    write_json_private(STS_CREDS_FILE, response)
    print("AssumeRoleWithWebIdentity succeeded")
    print("Assumed role ARN:", response["AssumedRoleUser"]["Arn"])
    print("Provider:", response.get("Provider"))
    print("Audience:", response.get("Audience"))
    print("Subject:", response.get("SubjectFromWebIdentityToken"))
    print("Expiration:", response["Credentials"]["Expiration"])
    return response


def session_from_sts(sts_response: dict[str, Any]) -> boto3.Session:
    section("6. Preparing temporary AWS credential session")
    credentials = sts_response["Credentials"]
    print("Temporary AWS credentials loaded into this Python process only.")
    print("AWS secret access key and session token are not printed.")
    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=REGION,
    )


def verify_caller_identity(session: boto3.Session) -> None:
    section("7. Verifying AWS caller identity")
    sts = session.client("sts", region_name=REGION, config=boto_config())
    try:
        identity = sts.get_caller_identity()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "Unknown")
        message = exc.response.get("Error", {}).get("Message", str(exc))
        raise ProofError(f"ERROR: get-caller-identity failed ({code}): {message}") from exc

    safe_identity = {key: identity.get(key) for key in ["UserId", "Account", "Arn"]}
    print(json.dumps(safe_identity, indent=2))


def s3_error_message(exc: ClientError, key: str) -> str:
    error = exc.response.get("Error", {})
    code = str(error.get("Code", "Unknown"))
    message = str(error.get("Message", exc))
    location = f"s3://{BUCKET}/{key}"
    if code in {"404", "NoSuchKey", "NotFound"}:
        return f"ERROR: Required S3 object is missing: {location}"
    if code in {"403", "AccessDenied", "AccessDeniedException"}:
        return f"ERROR: Access denied for required S3 object: {location}"
    return f"ERROR: Could not access S3 object {location} ({code}): {message}"


def download_required_s3_object(s3: Any, key: str, destination: Path) -> None:
    try:
        s3.head_object(Bucket=BUCKET, Key=key)
    except ClientError as exc:
        raise ProofError(s3_error_message(exc, key)) from exc

    try:
        s3.download_file(BUCKET, key, str(destination))
        os.chmod(destination, 0o600)
    except ClientError as exc:
        raise ProofError(s3_error_message(exc, key)) from exc
    except OSError as exc:
        raise ProofError(f"ERROR: Could not write downloaded file {destination}: {exc}") from exc

    print(f"Downloaded: s3://{BUCKET}/{key} -> {destination} ({destination.stat().st_size} bytes)")


def download_artifacts(session: boto3.Session) -> None:
    section("8. Downloading encrypted Excel and manifest from S3")
    s3 = session.client("s3", region_name=REGION, config=boto_config())
    download_required_s3_object(s3, f"{PREFIX}/{CIPHERTEXT_FILE}", Path(CIPHERTEXT_FILE))
    download_required_s3_object(s3, f"{PREFIX}/{MANIFEST_FILE}", Path(MANIFEST_FILE))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_manifest_string(manifest: dict[str, Any], key: str) -> str:
    value = manifest.get(key)
    if not isinstance(value, str) or not value:
        raise ProofError(f"ERROR: Manifest field {key!r} is missing or invalid")
    return value


def check_manifest_for_key_material(value: Any, path: str = "manifest") -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = str(key).lower()
            if normalized in FORBIDDEN_MANIFEST_FIELDS or "dek" in normalized:
                raise ProofError(f"ERROR: Manifest must not contain AES key material: field {path}.{key}")
            check_manifest_for_key_material(nested, f"{path}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            check_manifest_for_key_material(nested, f"{path}[{index}]")


def load_and_validate_manifest() -> tuple[dict[str, Any], bytes, bytes]:
    section("9. Validating manifest and ciphertext hash")
    try:
        manifest = json.loads(Path(MANIFEST_FILE).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ProofError(f"ERROR: Manifest file not found: {MANIFEST_FILE}") from exc
    except json.JSONDecodeError as exc:
        raise ProofError(f"ERROR: Manifest is invalid JSON: {exc}") from exc

    if not isinstance(manifest, dict):
        raise ProofError("ERROR: Manifest must be a JSON object")

    check_manifest_for_key_material(manifest)

    algorithm = require_manifest_string(manifest, "algorithm")
    if algorithm != "AES-256-GCM":
        raise ProofError(f"ERROR: Manifest algorithm must be AES-256-GCM, got {algorithm!r}")

    secret_name = require_manifest_string(manifest, "secret_name")
    if secret_name != EXPECTED_SECRET_NAME:
        raise ProofError(
            f"ERROR: Manifest secret_name {secret_name!r} does not match expected secret {EXPECTED_SECRET_NAME!r}"
        )

    nonce_b64 = require_manifest_string(manifest, "nonce_b64")
    try:
        nonce = base64.b64decode(nonce_b64, validate=True)
    except binascii.Error as exc:
        raise ProofError(f"ERROR: Manifest nonce_b64 is invalid base64: {exc}") from exc
    if len(nonce) != 12:
        raise ProofError(f"ERROR: Expected 12-byte AES-GCM nonce, got {len(nonce)} bytes")

    aad_value = require_manifest_string(manifest, "aad")
    aad = aad_value.encode("utf-8")

    expected_ciphertext_sha256 = require_manifest_string(manifest, "ciphertext_sha256")
    actual_ciphertext_sha256 = sha256_file(Path(CIPHERTEXT_FILE))
    print("Expected ciphertext SHA256:", expected_ciphertext_sha256)
    print("Actual ciphertext SHA256:", actual_ciphertext_sha256)
    if actual_ciphertext_sha256 != expected_ciphertext_sha256:
        raise ProofError("ERROR: Ciphertext SHA256 mismatch before decrypt")

    require_manifest_string(manifest, "original_sha256")
    print("Manifest validation succeeded.")
    print("Ciphertext SHA256 verified before decrypt.")
    return manifest, nonce, aad


def get_secret_value(session: boto3.Session, secret_name: str) -> dict[str, Any]:
    section("10. Reading AES key from AWS Secrets Manager")
    print("Secret name from manifest:", secret_name)
    secrets = session.client("secretsmanager", region_name=REGION, config=boto_config())
    try:
        response = secrets.get_secret_value(SecretId=secret_name)
    except ClientError as exc:
        error = exc.response.get("Error", {})
        code = str(error.get("Code", "Unknown"))
        message = str(error.get("Message", exc))
        if code in {"AccessDenied", "AccessDeniedException"}:
            raise ProofError(f"ERROR: Access denied reading Secrets Manager secret: {secret_name}") from exc
        if code == "ResourceNotFoundException":
            raise ProofError(f"ERROR: Secrets Manager secret not found: {secret_name}") from exc
        raise ProofError(f"ERROR: Could not read Secrets Manager secret {secret_name} ({code}): {message}") from exc
    except BotoCoreError as exc:
        raise ProofError(f"ERROR: Could not read Secrets Manager secret {secret_name}: {exc}") from exc

    write_json_private(SECRET_RESPONSE_FILE, response)
    print("Secret value retrieved from AWS Secrets Manager.")
    print("Secret response saved privately.")
    return response


def decode_aes_key(secret_response: dict[str, Any]) -> bytes:
    secret_string = secret_response.get("SecretString")
    if not secret_string:
        raise ProofError("ERROR: SecretString missing from Secrets Manager response")

    try:
        secret_payload = json.loads(secret_string)
    except json.JSONDecodeError as exc:
        raise ProofError(f"ERROR: Invalid secret payload JSON: {exc}") from exc

    if not isinstance(secret_payload, dict):
        raise ProofError("ERROR: Invalid secret payload: expected JSON object")

    try:
        aes_key = base64.b64decode(secret_payload["aes_key_b64"], validate=True)
    except KeyError as exc:
        raise ProofError("ERROR: Invalid secret payload: missing aes_key_b64") from exc
    except binascii.Error as exc:
        raise ProofError(f"ERROR: Invalid secret payload: aes_key_b64 is not valid base64: {exc}") from exc

    if len(aes_key) != 32:
        raise ProofError(f"ERROR: Expected 32-byte AES-256 key, got {len(aes_key)} bytes")
    return aes_key


def decrypt_and_verify(manifest: dict[str, Any], nonce: bytes, aad: bytes, aes_key: bytes) -> None:
    section("11. Decrypting Excel locally and verifying SHA256")
    ciphertext = Path(CIPHERTEXT_FILE).read_bytes()
    try:
        plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise ProofError("ERROR: AES-GCM authentication failed; ciphertext, nonce, AAD, or AES key is wrong") from exc

    actual_plaintext_sha256 = hashlib.sha256(plaintext).hexdigest()
    expected_plaintext_sha256 = require_manifest_string(manifest, "original_sha256")

    print("Local AES-256-GCM decryption succeeded.")
    print("Expected original SHA256:", expected_plaintext_sha256)
    print("Actual decrypted SHA256:", actual_plaintext_sha256)
    print("Hash match:", actual_plaintext_sha256 == expected_plaintext_sha256)

    if actual_plaintext_sha256 != expected_plaintext_sha256:
        raise ProofError("ERROR: Decrypted Excel hash does not match original")

    write_bytes_private(Path(DECRYPTED_FILE), plaintext)
    print("Decrypted file written:", DECRYPTED_FILE)
    print("Decrypted file size bytes:", len(plaintext))


def file_evidence_check() -> None:
    section("12. File evidence check")
    path = Path(DECRYPTED_FILE)
    if not path.exists():
        raise ProofError(f"ERROR: Decrypted file was not written: {DECRYPTED_FILE}")
    first_8 = path.read_bytes()[:8].hex()
    print("Decrypted file exists:", True)
    print("Decrypted file size bytes:", path.stat().st_size)
    print("First 8 bytes hex:", first_8)


def cleanup_message() -> None:
    cleanup_secret_files()
    if KEEP_SECRET_EVIDENCE:
        print("Secret-bearing token, STS, and Secrets Manager response files retained because KEEP_SECRET_EVIDENCE=true.")
    else:
        print("Secret-bearing token, STS, and Secrets Manager response files deleted.")
        print("Set KEEP_SECRET_EVIDENCE=true before running only if you intentionally need to retain them.")


def final_summary() -> None:
    section("Secret-based final proof completed")
    print("Proof summary:")
    print("- Azure VM metadata was read through IMDS.")
    print("- Azure VM obtained managed identity token.")
    print("- Safe JWT claims were decoded without printing the full token.")
    print("- AWS STS accepted Azure OIDC token.")
    print("- Azure assumed AWS role without static AWS keys.")
    print("- Temporary AWS credentials were used only inside this Python process.")
    print("- Azure downloaded encrypted Excel and manifest from S3.")
    print("- Azure retrieved AES key from AWS Secrets Manager.")
    print("- No AES key file was stored in S3.")
    print("- Manifest did not contain AES key material.")
    print("- Manifest algorithm, secret name, nonce length, and AAD were validated.")
    print("- Ciphertext SHA256 was verified before decrypt.")
    print("- Azure decrypted Excel locally with AES-256-GCM using manifest AAD.")
    print("- SHA256 hash of decrypted Excel matched original hash.")
    print("- Proof is Azure managed-identity based OIDC federation with AWS Secrets Manager key retrieval and local AES-GCM decryption.")
    print("- Security type was reported from VM metadata; this script does not prove TEE-attested or confidential VM key release.")


def main() -> int:
    os.umask(0o077)
    print("=" * 60)
    print("Azure OIDC + Secrets Manager AES Key + Local Excel Decryption")
    print("=" * 60)

    check_prerequisites()
    read_vm_metadata()
    token = get_managed_identity_token()
    decode_jwt_claims(token)
    sts_response = assume_role_with_web_identity(token)
    aws_session = session_from_sts(sts_response)
    verify_caller_identity(aws_session)
    download_artifacts(aws_session)
    manifest, nonce, aad = load_and_validate_manifest()
    secret_response = get_secret_value(aws_session, EXPECTED_SECRET_NAME)
    aes_key = decode_aes_key(secret_response)
    try:
        decrypt_and_verify(manifest, nonce, aad, aes_key)
    finally:
        aes_key = b"\x00" * 32
    cleanup_message()
    file_evidence_check()
    final_summary()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProofError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        print("ERROR: Interrupted", file=sys.stderr)
        raise SystemExit(130)
