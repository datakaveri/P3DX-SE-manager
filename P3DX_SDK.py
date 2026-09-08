import os
import sys
import subprocess
import json
import base64
import urllib.parse
import time
import shutil
import re
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.fernet import Fernet

from lib.config import config

# Ensure Bundle directory is in path for decryption import
_script_dir = os.path.dirname(os.path.abspath(__file__))
_bundle_dir = os.path.join(_script_dir, 'Bundle')
_fetch_data_dir = os.path.join(_script_dir, 'Fetch_data')
if _bundle_dir not in sys.path:
    sys.path.insert(0, _bundle_dir)
from decryption import decrypt_bundle
from enclave.enclave_direct_upload import write_output_container

# Lazy import for fetch_data
_fetch_data_module = None

# Per-run output key unwrapped from the current bundle's payload.outputWrappedKey
# (see decrypt_bundle_tee) - held in memory only, for the lifetime of this
# process, never written to disk. None when the bundle didn't send one (older
# UI), in which case output uploads fall back to the shared Fernet key.
_output_crypto = None


def _get_output_crypto():
    return _output_crypto


def _get_fetch_data():
    """Import fetch_data once; required due to circular dependency."""
    global _fetch_data_module
    if _fetch_data_module is None:
        if _fetch_data_dir not in sys.path:
            sys.path.insert(0, _fetch_data_dir)
        import fetch_data as _fetch_data_module
    return _fetch_data_module


def load_config_file(config_path="DPconfig.json"):
    """Load configuration from JSON file."""
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")
    
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        return config
    except Exception as e:
        raise ValueError(f"Failed to load config from {config_path}: {e}")


def create_fernet_cipher(key_data):
    """Create Fernet cipher from key data, handling various key formats."""
    try:
        return Fernet(key_data)
    except Exception:
        key_str = key_data.decode('utf-8', errors='ignore').strip()
        if len(key_str) == 44:
            decoded = base64.b64decode(key_str)
            key = base64.urlsafe_b64encode(decoded)
            return Fernet(key)
        elif len(key_data) == 32:
            key = base64.urlsafe_b64encode(key_data)
            return Fernet(key)
        else:
            raise ValueError(f"Invalid key format: {len(key_data)} bytes")




def pull_compose_file(url, filename="docker-compose.yml"):
    """Download a docker-compose file from the given URL."""
    try:
        response = requests.get(url)
        response.raise_for_status()
        with open(filename, "wb") as file:
            file.write(response.content)
        print(f"Downloaded content from '{url}' and saved to '{filename}'")
    except requests.exceptions.RequestException as exc:
        print(f"Error downloading content: {exc}")


def extract_docker_image_from_compose(compose_file="docker-compose.yml"):
    """Extract the application docker image name from docker-compose.yml.

    Parses the compose file properly and skips the skald-fta service. This is
    the image that gets pulled, hashed, and extended into PCR 11, so picking
    the wrong one silently attests the wrong workload — and the previous
    first-`image:`-in-the-file regex would return skald-fta's image the moment a
    compose file declares that service ahead of skald-anonymisation.

    Falls back to the original regex only when the file isn't parseable as
    compose, so no deployment that works today stops working.
    """
    if not os.path.exists(compose_file):
        raise FileNotFoundError(f"Docker compose file not found: {compose_file}")

    fta_service = getattr(config.free_text_anonymization, 'compose_service', 'skald-fta')

    try:
        with open(compose_file, 'r') as f:
            doc = yaml.safe_load(f) or {}
        services = doc.get("services") or {}
        for name, svc in services.items():
            if name == fta_service or not isinstance(svc, dict):
                continue
            image = svc.get("image")
            if isinstance(image, str) and image.strip():
                return image.strip()
        if services:
            raise ValueError(
                f"docker-compose.yml declares no application image outside the "
                f"'{fta_service}' service: {sorted(services)}"
            )
    except (OSError, yaml.YAMLError):
        pass

    with open(compose_file, 'r') as f:
        content = f.read()

    match = re.search(r'^\s*image:\s*([^\s\n#]+)', content, re.MULTILINE)
    if match:
        return match.group(1).strip()
    else:
        raise ValueError("Could not extract docker image from docker-compose.yml")




def _expected_pcr15(code_hash):
    """PCR15's value after a single extend from a freshly-booted (zero) PCR.

    TPM PCR extension is PCR_new = SHA256(PCR_old || measurement), and PCR_old is
    32 zero bytes at boot.
    """
    return hashlib.sha256(bytes(32) + bytes.fromhex(code_hash)).hexdigest()


def _read_pcr15():
    result = subprocess.run(["sudo", "tpm2_pcrread", "sha256:15"],
                            capture_output=True, text=True, check=False, timeout=10)
    match = re.search(r"15\s*:\s*0x([a-fA-F0-9]{64})", result.stdout)
    return match.group(1).lower() if match else None


def public_key_fingerprint():
    """SHA-256 over the DER SubjectPublicKeyInfo, hex.

    The middleware uses this to decide whether a data key wrapped earlier can
    still be opened by this enclave. It is computed the same way on both sides,
    from the key bytes, so neither has to trust the other's label for it.
    """
    with open(config.get_path('public_key'), "r") as fh:
        body = "".join(line for line in fh.read().splitlines()
                       if not line.startswith("-----")).strip()
    return hashlib.sha256(base64.b64decode(body)).hexdigest()


def generate_and_save_key_pair(force=False):
    """Mint a fresh keypair for this run, and a TLS certificate for it.

    **Ephemeral again, deliberately.** For one phase these keys were long-lived
    and vTPM-sealed, because the browser had to wrap its data key for a specific
    enclave before the scheduler had chosen one. Now the browser wraps for the
    *middleware*, which re-delivers the key over RA-TLS to whichever enclave it
    attests — so nothing outside this machine ever needs to name this key in
    advance, and it can go back to living exactly one job.

    That is the stronger position. A key that exists only for one run cannot leak
    a previous user's data if it is later compromised, needs no sealing, no
    rotation endpoint, and no PCR15 policy that breaks on every code change. The
    sealing machinery moved to the middleware, where there is one machine to
    reason about instead of five.

    `force` is retained for call-site compatibility and no longer means anything:
    every call generates. The parameter is accepted rather than removed so an
    older caller does not fail with a TypeError while the fleet is mid-rollout.

    The certificate is self-signed over this same keypair, and that is the point:
    the middleware checks the TLS certificate's SPKI against the public key
    inside this enclave's attestation, so the certificate needs no CA and could
    not usefully have one.
    """
    os.makedirs(config.paths.keys_dir, exist_ok=True)
    os.chmod(config.paths.keys_dir, 0o700)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Stored as bare single-line base64 of the DER SubjectPublicKeyInfo — no PEM
    # armour, no newlines. This is the exact form the attestation client copies
    # into its payload and the browser re-armours, so the shape is load-bearing:
    # a stray marker here produces a PEM the UI cannot import.
    #
    # Encoded from DER directly rather than by slicing a PEM string. The old
    # `split("\n")[1:-1]` kept the trailing "-----END PUBLIC KEY-----" line and
    # relied on a second pass to strip markers afterwards; doing it in one step
    # removes the chance of that pass going missing.
    public_key = base64.b64encode(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).decode()
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key_path = config.get_path('public_key')
    with open(public_key_path, "w") as public_key_out:
        public_key_out.write(public_key)
    os.chmod(public_key_path, 0o644)

    private_key_path = config.get_path('private_key')
    fd = os.open(private_key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with open(fd, "wb") as private_key_out:
        private_key_out.write(private_key_bytes)

    # Clear out sealed artefacts from the long-lived-key phase. Left behind they
    # are not merely clutter: `load_enclave_private_key_pem` would still prefer
    # the sealed blob if sealing were ever re-enabled, and it holds a *different*
    # key than the certificate now being served.
    for stale in ('private_key_enc', 'kek_pub', 'kek_priv', 'key_generation'):
        try:
            path = config.get_path(stale)
        except (KeyError, AttributeError):
            continue
        if os.path.exists(path):
            os.unlink(path)

    generate_tls_certificate(private_key)
    print(f"Per-run keypair and TLS certificate ready "
          f"(fingerprint {public_key_fingerprint()[:16]}...)")


def generate_tls_certificate(private_key, days_valid=2):
    """Self-signed certificate over the per-run key, for the RA-TLS listener.

    Not a trust anchor and not trying to be. The middleware ignores the issuer,
    the subject and the chain entirely, and checks only that the certificate's
    SubjectPublicKeyInfo equals the public key inside this enclave's MAA token.
    A CA could not help here even in principle: this key is minted inside the
    enclave minutes before use and no CA has ever seen it.

    Short-dated anyway, because a certificate outliving the key it describes is
    a confusing artefact to find on a disk, and this one has no reason to live
    past the run.
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, os.getenv("TEE_ID", "p3dx-enclave")),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SPIDEr processing enclave"),
    ])

    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        # Backdated a little: the middleware and the enclave are different
        # machines, and a certificate that is not yet valid by a few seconds of
        # clock skew fails a handshake for no real reason.
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )

    cert_path = os.path.join(config.paths.keys_dir, "tls_cert.pem")
    with open(cert_path, "wb") as fh:
        fh.write(certificate.public_bytes(serialization.Encoding.PEM))
    os.chmod(cert_path, 0o644)
    return cert_path


def load_enclave_private_key_pem():
    """Return the per-run private key PEM in memory.

    Single entry point for everything that needs the private key. No longer has
    a sealed branch: the key lives one run, so there is nothing on this disk
    worth sealing against a future boot — the middleware holds the long-lived
    identity now.
    """
    with open(config.get_path('private_key'), "rb") as fh:
        return fh.read()


def reload_ratls_listener(address):
    """Ask the enclave manager to rebind its TLS listener to the new certificate.

    The deploy runs as its own process and cannot reach the manager's listener
    object, so it asks over the loopback interface — the same way it already
    reports state.

    A failure here is reported and not raised: the deploy has genuinely produced
    a valid keypair and can continue, and the manager also rebinds at startup.
    Aborting a deploy over it would turn a recoverable condition into a failed
    job.
    """
    url = urllib.parse.urljoin(address, "/enclave/ratls/reload")
    try:
        response = requests.post(url, timeout=30)
        print(f"RA-TLS listener reload: {response.status_code} {response.text.strip()}",
              flush=True)
    except requests.RequestException as e:
        print(f"WARNING: could not reload the RA-TLS listener: {e}. "
              f"This node may not be able to receive a data key.", flush=True)


def mint_attestation(nonce):
    """Mint a fresh MAA token for a nonce the middleware chose.

    This is the enclave side of the RA-TLS handshake. The nonce is
    `sha256(channel binding)` of the TLS session the middleware is asking over,
    so the resulting token is usable on that connection and no other.

    Not cached, and it must never be. A cached token is by construction bound to
    a channel that has already closed, so serving one would silently convert a
    relay-resistant exchange into a replayable one — the exact property this
    whole mechanism exists to provide.
    """
    save_nonce(nonce)
    execute_guest_attestation()
    return get_jwt_from_file()


def pull_docker_image(app_name):
    """Pull a Docker image."""
    print("Pulling docker image")
    subprocess.run(["docker", "pull", app_name])


def hash_docker_image(image):
    """Returns SHA256 digest from RepoDigest or computes from docker inspect JSON."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format={{index .RepoDigests 0}}", image],
            capture_output=True, text=True, check=True, timeout=10
        )
        match = re.search(r'sha256:([a-f0-9]{64})', result.stdout)
        if match:
            return match.group(1)
    except Exception:
        pass
    result = subprocess.run(
        ["docker", "inspect", image], capture_output=True, text=True, check=True, timeout=10
    )
    return hashlib.sha256(json.dumps(json.loads(result.stdout)[0], sort_keys=True).encode()).hexdigest()


def save_image_hash(image_hash, path=None):
    if path is None:
        path = config.get_path('image_hash')
    with open(path, "w") as f:
        f.write(image_hash)


def hash_enclave_manager_code(base_dir=None):
    """
    Deterministically hash enclave manager code directory.
    """
    if base_dir is None:
        base_dir = config.base_dir
    
    sha256_digest = hashlib.sha256()

    # Files to include in hash (deterministic order)
    files_to_hash = []
    
    for root, dirs, files in os.walk(base_dir):
        # Sort for deterministic order
        dirs.sort()
        files.sort()
        
        # Skip certain directories
        skip_dirs = {'.git', '__pycache__', '.mono', 'keys', 'node_modules', '.pytest_cache'}
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        
        for fname in files:
            # Only hash source code and config files
            if fname.endswith((".py", ".sh", ".json", ".service", ".md", ".txt", ".yaml", ".yml")):
                # Skip files in keys directory and other excluded paths
                if 'keys' in root or '.git' in root or '__pycache__' in root:
                    continue
                path = os.path.join(root, fname)
                files_to_hash.append(path)
    
    # Sort files for deterministic hashing
    files_to_hash.sort()
    
    # Hash each file's content
    for file_path in files_to_hash:
        try:
            with open(file_path, "rb") as f:
                file_content = f.read()
            # Include relative path in hash to ensure file location matters
            rel_path = os.path.relpath(file_path, base_dir)
            sha256_digest.update(rel_path.encode('utf-8'))
            sha256_digest.update(file_content)
        except Exception as e:
            print(f"Warning: Could not hash {file_path}: {e}")
    
    return sha256_digest.hexdigest()


def save_code_hash(code_hash, path=None):
    """Save enclave manager code hash to file."""
    if path is None:
        path = config.get_path('code_hash')
    with open(path, "w") as f:
        f.write(code_hash)


def _is_pcr15_extended():
    """Check if PCR 15 has already been extended."""
    try:
        result = subprocess.run(
            ["sudo", "tpm2_pcrread", "sha256:15"],
            capture_output=True, text=True, check=False, timeout=5
        )
        if result.returncode != 0:
            return False
        # Parse output: "    15 : 0x<64 hex chars>" - PCR 15 value
        match = re.search(r"15\s*:\s*0x([a-fA-F0-9]{64})", result.stdout)
        if match:
            value = match.group(1).lower()
            return value != "0" * 64
        return False
    except Exception:
        return False


def measure_enclave_manager_code_vtpm(base_dir=None):
    """
    Hash enclave manager code directory and extend to PCR 15.
    """
    if base_dir is None:
        base_dir = config.base_dir
    
    if _is_pcr15_extended():
        print("Enclave manager code already extended to PCR 15.")
    else:
        print(f"Hashing enclave manager code directory: {base_dir}")
        code_hash = hash_enclave_manager_code(base_dir)
        
        if code_hash:
            print(f"SHA256 digest for enclave manager code is: {code_hash}")
            save_code_hash(code_hash)
            
            extend_result = subprocess.run(
                ["sudo", "tpm2_pcrextend", f"15:sha256={code_hash}"],
                capture_output=True, text=True, check=False
            )
            if extend_result.returncode == 0:
                print("Enclave manager code hash extended successfully to PCR 15.")
            else:
                err = extend_result.stderr.strip() or extend_result.stdout.strip() or "Unknown error"
                print(f"Warning: Failed to extend to PCR 15: {err}")


def measureDockervTPM(link):
    """Extend image digest to PCR 11.
    """
    sha256_digest = hash_docker_image(link)
    if sha256_digest:
        print(f"SHA256 digest for image '{link}' is: {sha256_digest}")
        extend_result = subprocess.run(
            ["sudo", "tpm2_pcrextend", f"11:sha256={sha256_digest}"],
            capture_output=True, text=True, check=False
        )
        if extend_result.returncode == 0:
            print("Measurement extended successfully to PCR 11.")
        else:
            err = extend_result.stderr.strip() or extend_result.stdout.strip() or "Unknown error"
            print(f"Warning: Failed to extend to PCR 11: {err}")


def generate_nonce(size=32):
    """Generate a cryptographically secure random nonce."""
    nonce = secrets.token_bytes(size)
    return base64.urlsafe_b64encode(nonce).decode("utf-8")


def save_nonce(nonce, path=None):
    if path is None:
        path = config.get_path('deployment_nonce')
    with open(path, "w") as f:
        f.write(nonce)


def extend_nonce_to_pcr8(nonce, pcr_file_path=None):
    """Extend nonce hash into PCR 8"""
    if pcr_file_path is None:
        pcr_file_path = config.get_path('pcr_values')
    
    nonce_hash = hashlib.sha256(nonce.encode()).hexdigest()
    extend_result = subprocess.run(
        ["sudo", "tpm2_pcrextend", f"8:sha256={nonce_hash}"],
        capture_output=True, text=True, check=False
    )
    if extend_result.returncode == 0:
        print("Nonce extended successfully to PCR 8.")
    else:
        err = extend_result.stderr.strip() or extend_result.stdout.strip() or "Unknown error"
        print(f"Warning: Failed to extend nonce to PCR 8: {err}")

    pcr_values = {}
    try:
        result = subprocess.run(
            ["sudo", "tpm2_pcrread", "sha256:0,1,2,3,4,5,6,7,8,11,15"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n")[1:]:
                parts = line.split(":")
                if len(parts) == 2:
                    pcr_values[parts[0].strip()] = parts[1].strip()
            with open(pcr_file_path, "w") as f:
                f.write(json.dumps(pcr_values))
            print(f"PCR values written to {pcr_file_path} (PCRs 0-8, 11, 15)")
        else:
            err = result.stderr.strip() if result.stderr else "tpm2_pcrread not available"
            print(f"Warning: Error reading PCR values: {err}")
    except Exception as exc:
        print(f"Warning: Error writing pcr_values.json: {exc}")


def execute_guest_attestation():
    """Run guest attestation sample app to generate a JWT."""
    commands_folder = config.paths.guest_attestation
    jwt_file = config.get_path('jwt_response')
    original_cwd = os.getcwd()
    
    try:
        if not os.path.exists(commands_folder):
            raise RuntimeError(f"Guest attestation folder not found: {commands_folder}")
        
        os.chdir(commands_folder)
        result = subprocess.run(
            config.get_command('python') + ["generate-token.py"],
            capture_output=True,
            text=True,
            check=False
        )
        
        stdout_info = result.stdout.strip() if result.stdout else ""
        stderr_info = result.stderr.strip() if result.stderr else ""
        
        if result.returncode != 0:
            error_msg = stderr_info if stderr_info else stdout_info
            if not error_msg:
                error_msg = f"Process exited with code {result.returncode}"
            raise RuntimeError(f"Guest attestation failed: {error_msg}")
        
        if not os.path.exists(jwt_file):
            resolved_path = os.path.abspath("../../keys/jwt-response.txt")
            error_details = []
            if stdout_info:
                error_details.append(f"stdout: {stdout_info}")
            if stderr_info:
                error_details.append(f"stderr: {stderr_info}")
            if not error_details:
                error_details.append("No output captured")
            
            error_msg = (
                f"JWT file was not created. Expected: {jwt_file}, "
                f"Resolved from script dir: {resolved_path}. "
                f"Script output: {'; '.join(error_details)}"
            )
            
            if "Error executing command" in stdout_info or stderr_info:
                error_msg += (
                    f" The AttestationClient command failed. "
                    f"Please check if AttestationClient is executable and if the nonce file exists."
                )
            
            raise RuntimeError(error_msg)
        
    finally:
        os.chdir(original_cwd)


def call_set_state_endpoint(state, address):
    """Helper to call the enclave setstate endpoint."""
    endpoint_url = urllib.parse.urljoin(address, "/enclave/setstate")
    payload = {"state": state}
    response = requests.post(endpoint_url, json=payload)
    print(response.text)


def setState(title, description, step, maxSteps, address, job_id=""):
    """Update enclave state via the manager endpoint.

    `job_id` stamps the state with the scheduler's job, so a status poll that
    lands just after a previous job finished can be distinguished from this
    job's own status — the hazard of a singleton status endpoint.
    """
    state = {
        "title": title,
        "description": description,
        "step": step,
        "maxSteps": maxSteps,
        "job_id": job_id,
    }
    call_set_state_endpoint(state, address)


#: Root-owned fallback for the callback settings. The deploy script runs as a
#: `sudo sh -c` subprocess, and sudo scrubs the environment, so the systemd
#: Environment= lines that configure the manager do NOT reach it. Without this
#: file every queued job finishes silently and the scheduler only learns of it
#: when its stall timer fires — a successful run that looks like a dead TEE.
#:
#: A file rather than passing the values on the command line: an argv is visible
#: in `ps` to every local user, and one of these values is a shared secret.
CALLBACK_CONFIG_PATH = os.getenv("TEE_CALLBACK_CONFIG", "/etc/p3dx/callback.conf")


def _callback_config():
    """(url, secret) from the environment, falling back to the config file."""
    url = os.getenv("TEE_CALLBACK_URL", "").rstrip("/")
    secret = os.getenv("TEE_CALLBACK_SECRET", "")
    if url and secret:
        return url, secret

    try:
        with open(CALLBACK_CONFIG_PATH) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key, value = key.strip(), value.strip().strip('"').strip("'")
                if key == "TEE_CALLBACK_URL" and not url:
                    url = value.rstrip("/")
                elif key == "TEE_CALLBACK_SECRET" and not secret:
                    secret = value
    except OSError:
        pass
    return url, secret


def report_job_complete(job_id, output_url=None, error=None):
    """Tell the middleware a queued job finished.

    This callback is the scheduler's ground truth. Its stall timer exists only
    to catch an enclave that died without reporting, so a job that finishes and
    stays silent burns a full stall window before anyone notices — and a job
    that *failed* and stays silent looks identical to one still working.

    Never raises: a delivery failure must not turn a completed run into a crashed
    deployment. The scheduler's timeout covers us if this does not land.
    """
    if not job_id:
        return  # hand-run deploy, nothing is waiting on a callback

    callback_url, secret = _callback_config()
    if not callback_url or not secret:
        print("No TEE_CALLBACK_URL/SECRET configured; skipping completion callback",
              flush=True)
        return

    payload = {"error": error} if error else {"output_url": output_url}

    # Attach this run's status.json.
    #
    # It is the only structured description of what the pipeline produced —
    # application, phase, outputs.dicom/image/direct, the k-anon parameter grid —
    # and it lives ONLY on this machine, which the scheduler deallocates minutes
    # after the job finishes. Callers used to fetch it from /enclave/status, which
    # meant the result became unreachable the moment the enclave powered down and,
    # worse, answered about whichever enclave happened to reply.
    #
    # Best effort: a run that produced no readable status still has a valid
    # completion to report, and failing the callback over this would turn a
    # finished job into a stalled one.
    try:
        payload["result"] = get_app_status()
    except Exception as e:
        print(f"Could not attach status to the completion callback: {e}", flush=True)
    try:
        resp = requests.post(
            f"{callback_url}/internal/jobs/{job_id}/callback",
            json=payload,
            headers={"X-Callback-Secret": secret},
            timeout=15,
        )
        print(f"Completion callback for {job_id}: HTTP {resp.status_code}", flush=True)
    except requests.exceptions.RequestException as e:
        print(f"Completion callback for {job_id} failed: {e}", flush=True)


def ensure_tee_folders():
    """Create TEE folders if they don't exist and clean old files."""
    folders = [
        config.paths.tee_input_data,
        config.paths.tee_input_config,
        config.paths.tee_output,
        config.paths.tee_urls
    ]
    
    for folder in folders:
        if os.path.exists(folder):
            # Remove old files but keep directory
            for item in os.listdir(folder):
                item_path = os.path.join(folder, item)
                if os.path.isfile(item_path):
                    os.remove(item_path)
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)
        else:
            os.makedirs(folder, exist_ok=True)
        print(f"Ensured folder exists: {folder}")


def get_jwt_from_file():
    """Read JWT from jwt-response.txt file."""
    jwt_file = config.get_path('jwt_response')
    if not os.path.exists(jwt_file):
        raise FileNotFoundError(f"JWT file not found: {jwt_file}")
    with open(jwt_file, 'r') as f:
        return f.read().strip()


def send_jwt_to_ui(jwt, address):
    """Send JWT to UI endpoint for polling."""
    endpoint_url = urllib.parse.urljoin(address, "/enclave/jwt")
    payload = {"jwt": jwt}
    response = requests.post(endpoint_url, json=payload)
    if response.status_code == 200:
        print("JWT sent to UI successfully")
        return True
    else:
        print(f"Failed to send JWT to UI: {response.status_code} - {response.text}")
        return False


def wait_for_bundle_from_ui(address, timeout=300):
    """Poll UI endpoint for encrypted bundle."""
    endpoint_url = urllib.parse.urljoin(address, "/enclave/bundle")
    start_time = time.time()
    
    print(f"Waiting for bundle from UI (timeout: {timeout}s)...")
    while time.time() - start_time < timeout:
        try:
            response = requests.get(endpoint_url, timeout=5)
            if response.status_code == 200:
                bundle_data = response.json()
                if bundle_data.get('bundle'):
                    print("Bundle received from UI")
                    return bundle_data
            elif response.status_code == 404:
                # No bundle yet, continue polling
                time.sleep(2)
                continue
            else:
                print(f"Unexpected status: {response.status_code}")
                time.sleep(2)
        except requests.exceptions.RequestException as e:
            time.sleep(2)
            continue
    
    raise TimeoutError(f"Timeout waiting for bundle from UI after {timeout} seconds")


def save_bundle_to_file(bundle_data, bundle_path=None):
    """Save bundle data to file."""
    if bundle_path is None:
        bundle_path = config.get_path('encrypted_bundle')
    os.makedirs(os.path.dirname(bundle_path), exist_ok=True)
    with open(bundle_path, 'w') as f:
        json.dump(bundle_data, f, indent=2)
    print(f"Bundle saved to: {bundle_path}")
    return bundle_path


def decrypt_bundle_tee(bundle_path, private_key_path):
    """Decrypt bundle using decryption.py logic."""
    global _output_crypto
    print("Decrypting bundle...")
    result = decrypt_bundle(bundle_path, private_key_path)
    _output_crypto = result.get('output') if isinstance(result, dict) else None
    print("Bundle decrypted successfully")


def fetch_and_decrypt_data(config_path="DPconfig.json"):
    """Fetch encrypted data from Azure Blob Storage and decrypt using fetch_data.py logic."""
    fetch_data = _get_fetch_data()
    print("Fetching and decrypting data from Azure Blob Storage...")
    fetch_data.fetch_and_decrypt_tee()
    print("Data fetched and decrypted successfully")


# ---------------------------------------------------------------------------
# Free-text anonymisation (skald-fta) pre-stage
# ---------------------------------------------------------------------------
#
# When the client's app config sets <data_type>.free_text_anonymization.enabled
# = true, skald-fta runs BEFORE SKALD over the same three mounts, masks
# PII/NER hits inside the configured free-text columns, and writes a sanitised
# CSV to staged_input_path plus a detection audit to audit_output_path — both
# under the shared output/ mount.
#
# The handoff is the output/ mount, not the config: SKALD's own parser already
# reads free_text_anonymization.staged_input_path/enabled out of the very same
# config.json and consumes the staged CSV instead of scanning data/. So the
# enclave passes the config through byte-for-byte and only has to guarantee
# both containers see the same output directory.
#
# Two containers, not one compose project, on purpose. `docker compose up`
# starts services concurrently, so adding skald-fta as a second service would
# race it against SKALD and hand SKALD a half-written staged file. `docker
# run` gives strict ordering and a clean exit code to gate on.

_FTA_BLOCK_KEY = "free_text_anonymization"

# Reserved output/ filenames skald-fta may not be pointed at. status.json is
# the contract /enclave/status returns verbatim to the UI, and pipeline.log /
# generalized.* are SKALD's own results — letting a config redirect the staged
# CSV or the audit JSON onto any of these would either forge the status the UI
# trusts or get SKALD's real output filtered out of the upload as an
# intermediate.
_FTA_RESERVED_OUTPUT_NAMES = {
    "status.json", "pipeline.log", "manifest.json",
    "generalized.csv", "generalized.json", "generalized.xlsx", "generalized.xls",
}


def _fta_setting(name, default=None):
    """Read one key from config.yml's free_text_anonymization block."""
    return getattr(config.free_text_anonymization, name, default)


def _iter_app_configs():
    """Yield (filename, dict) for each JSON app config the bundle delivered."""
    cfg_dir = config.paths.tee_input_config
    try:
        names = sorted(os.listdir(cfg_dir))
    except OSError:
        return
    for name in names:
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(cfg_dir, name)) as f:
                data = json.load(f)
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            yield name, data


def _find_free_text_block(cfg):
    """Locate the free_text_anonymization block in one app config.

    The stage is specified as config[data_type].free_text_anonymization, but
    which key plays data_type is the client's to choose and the block is also
    seen at the top level, so three shapes are accepted, in order:
      1. cfg["free_text_anonymization"]
      2. cfg[cfg["data_type"]]["free_text_anonymization"]  (also dataType/format)
      3. cfg[<first dict-valued key that has one>]["free_text_anonymization"]

    Searching this broadly is deliberate. Failing to find a block that is
    there means the stage is skipped and unmasked free text reaches the
    requester — unrecoverable, because the output has already left. Finding
    one that the client did not mean as the gate only costs an extra container
    run that masks columns the client itself named. The asymmetry is the whole
    argument; do not narrow this to a single shape without a config contract
    pinned by the UI.

    Returns (block, dotted-path) or (None, None).
    """
    block = cfg.get(_FTA_BLOCK_KEY)
    if isinstance(block, dict):
        return block, _FTA_BLOCK_KEY

    for key_name in ("data_type", "dataType", "format"):
        named = cfg.get(key_name)
        if isinstance(named, str) and isinstance(cfg.get(named), dict):
            block = cfg[named].get(_FTA_BLOCK_KEY)
            if isinstance(block, dict):
                return block, f"{named}.{_FTA_BLOCK_KEY}"

    for key, value in cfg.items():
        if isinstance(value, dict):
            block = value.get(_FTA_BLOCK_KEY)
            if isinstance(block, dict):
                return block, f"{key}.{_FTA_BLOCK_KEY}"

    return None, None


def read_free_text_config():
    """Return (block, provenance) for this run's free_text_anonymization block.

    provenance is a "<config filename>:<dotted path>" string for the log, so a
    run that unexpectedly did or didn't anonymise free text can be traced back
    to where the gate was read from. (None, None) when no config declares one.
    """
    for name, cfg in _iter_app_configs():
        block, where = _find_free_text_block(cfg)
        if block is not None:
            return block, f"{name}:{where}"
    return None, None


def _as_bool(value):
    """Coerce a JSON-ish flag to bool, tolerating "true"/1 from hand-edited configs."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "1", "on")
    return False


def _fta_output_basename(raw, fallback, field):
    """Resolve one configured artifact path to a basename inside output/.

    staged_input_path and audit_output_path are container-relative (e.g.
    "output/sanitized_input.csv"). Both MUST land in /app/output: that mount is
    the only directory skald-fta and SKALD share, so a path anywhere else means
    SKALD will never see the staged CSV and would silently fall back to
    scanning data/ for the raw, un-masked file. Rejecting it up front turns a
    silent privacy regression into a startup error.
    """
    value = raw.strip() if isinstance(raw, str) and raw.strip() else fallback
    if not value:
        raise RuntimeError(
            f"free_text_anonymization.{field} is empty and config.yml declares "
            f"no default — cannot tell where skald-fta will write."
        )

    normalized = os.path.normpath(value)
    parts = [p for p in normalized.split(os.sep) if p not in ("", ".")]
    if os.path.isabs(normalized):
        if parts[:2] != ["app", "output"]:
            raise RuntimeError(
                f"free_text_anonymization.{field} must live under /app/output "
                f"(the only mount skald-fta and SKALD share), got {value!r}"
            )
        parts = parts[2:]
    elif parts and parts[0] == "output":
        parts = parts[1:]
    elif len(parts) > 1:
        raise RuntimeError(
            f"free_text_anonymization.{field} must live under the shared "
            f"output/ mount, got {value!r}"
        )

    if len(parts) != 1:
        raise RuntimeError(
            f"free_text_anonymization.{field} must name a file directly inside "
            f"output/ (no subdirectories, no traversal), got {value!r}"
        )

    name = parts[0]
    if name in _FTA_RESERVED_OUTPUT_NAMES:
        raise RuntimeError(
            f"free_text_anonymization.{field} may not be {name!r} — that name "
            f"is reserved for the pipeline's own status/result files"
        )
    return name


def _fta_declared_artifacts(block):
    """Basenames skald-fta is configured to write, as {field: basename}."""
    return {
        "staged_input_path": _fta_output_basename(
            block.get("staged_input_path"),
            _fta_setting("default_staged_name", "sanitized_input.csv"),
            "staged_input_path",
        ),
        "audit_output_path": _fta_output_basename(
            block.get("audit_output_path"),
            _fta_setting("default_audit_name", "free_text_audit.json"),
            "audit_output_path",
        ),
    }


def _output_snapshot():
    """Set of regular-file basenames currently in the shared output/ mount."""
    out = config.paths.tee_output
    try:
        return {n for n in os.listdir(out) if os.path.isfile(os.path.join(out, n))}
    except OSError:
        return set()


def _fta_ledger_path():
    return config.get_path('fta_artifacts')


def clear_free_text_artifacts():
    """Purge the previous run's ledger AND its leftover artifacts from output/.

    Called unconditionally before every pipeline run, ahead of the enabled gate,
    because both halves matter in opposite directions:

      * a stale LEDGER would keep excluding those basenames from the upload on a
        later run that never ran skald-fta, withholding files the requester
        should get;
      * a stale STAGED CSV is worse. deploy_enclave.py clears output/ via
        ensure_tee_folders(), but the /run/*_pipeline path does not, so a
        previous free-text run's sanitized_input.csv can still be sitting there.
        On a run with free_text_anonymization disabled, nothing would mark it as
        an intermediate and it would be encrypted and uploaded as though it were
        a result — a partially-anonymised dataset shipped as the real one.

    Purging up front also means that when the stage does run, the artifacts it
    finds afterwards are provably its own, which is what
    run_free_text_anonymization() relies on to detect a container that exited 0
    without writing anything.
    """
    try:
        os.remove(_fta_ledger_path())
    except FileNotFoundError:
        pass
    except OSError as exc:
        print(f"Warning: could not clear skald-fta artifact ledger: {exc}", flush=True)

    # Names this stage could have written: whatever the current config declares,
    # plus the config.yml defaults for a run whose config omits the fields.
    stale_names = {
        _fta_setting("default_staged_name", "sanitized_input.csv"),
        _fta_setting("default_audit_name", "free_text_audit.json"),
    }
    block, _ = read_free_text_config()
    if isinstance(block, dict):
        try:
            stale_names.update(_fta_declared_artifacts(block).values())
        except RuntimeError:
            pass  # invalid paths are reported by the stage itself

    for name in sorted(n for n in stale_names
                       if n and n not in _FTA_RESERVED_OUTPUT_NAMES):
        path = os.path.join(config.paths.tee_output, name)
        try:
            os.remove(path)
            print(f"Removed stale output/{name} left by an earlier run", flush=True)
        except FileNotFoundError:
            pass
        except OSError as exc:
            print(f"Warning: could not remove stale output/{name}: {exc}", flush=True)


def _record_free_text_artifacts(names):
    """Persist the intermediates skald-fta left in output/.

    Written under keys/, never output/, precisely because every file in
    output/ is a candidate for encryption and upload — a ledger stored there
    would list itself.
    """
    path = _fta_ledger_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(sorted(names), f, indent=2)
    except OSError as exc:
        print(f"Warning: could not write skald-fta artifact ledger: {exc}", flush=True)


def free_text_artifact_names():
    """Basenames in output/ that belong to skald-fta, not to SKALD.

    These are pipeline intermediates and MUST NOT be uploaded:

      * the staged CSV has had free text masked but has NOT been through
        SKALD's k-anonymisation, generalisation, hashing or suppression — it
        still carries every quasi-identifier the run exists to treat, so
        shipping it alongside the anonymised result defeats the entire second
        stage;
      * the audit JSON is a per-cell detection record, an internal artifact
        that was never part of the result contract.

    Union of two independent signals so a gap in either still holds the line:
    the ledger of files skald-fta actually created, and the basenames the app
    config declares (which survives a re-run in a fresh process where the
    ledger is gone).
    """
    names = set()

    try:
        with open(_fta_ledger_path()) as f:
            recorded = json.load(f)
        if isinstance(recorded, list):
            names.update(str(n) for n in recorded)
    except (OSError, ValueError):
        pass

    block, _ = read_free_text_config()
    if isinstance(block, dict) and _as_bool(block.get("enabled")):
        try:
            names.update(_fta_declared_artifacts(block).values())
        except RuntimeError:
            # An invalid path config already failed the run in
            # run_free_text_anonymization(); nothing to exclude here.
            pass

    return {n for n in names if n not in _FTA_RESERVED_OUTPUT_NAMES}


def _compose_output_mounts(compose_file, fta_service):
    """Host paths that compose binds to /app/output, per non-fta service.

    Returns {service_name: host_path_or_None}. host_path is None when the
    service mounts *something* at /app/output that isn't a host bind (a named
    volume), which cannot be the shared directory. Services with no
    /app/output mapping at all are omitted — nothing to check there.

    Handles both compose volume forms: the short "host:container[:opts]"
    string and the long {type, source, target} mapping. Relative host paths
    resolve against the compose file's own directory, as compose does.
    """
    with open(compose_file) as f:
        doc = yaml.safe_load(f) or {}

    named_volumes = set((doc.get("volumes") or {}) if isinstance(doc.get("volumes"), dict) else ())
    compose_dir = os.path.dirname(os.path.abspath(compose_file))
    found = {}

    for name, svc in (doc.get("services") or {}).items():
        if name == fta_service or not isinstance(svc, dict):
            continue
        for entry in svc.get("volumes") or []:
            source, target = None, None
            if isinstance(entry, str):
                # Split from the right so a Windows-style or option-suffixed
                # spec still yields the container path in the middle field.
                bits = entry.split(":")
                if len(bits) >= 2:
                    source, target = bits[0], bits[1]
            elif isinstance(entry, dict):
                target = entry.get("target")
                if entry.get("type", "bind") == "bind":
                    source = entry.get("source")

            if not isinstance(target, str) or os.path.normpath(target) != "/app/output":
                continue

            if not isinstance(source, str) or not source or source in named_volumes:
                found[name] = None
            elif os.path.isabs(source):
                found[name] = os.path.normpath(source)
            else:
                found[name] = os.path.normpath(os.path.join(compose_dir, source))
            break

    return found


def _verify_shared_output_mount(fta_service):
    """Fail early unless SKALD's /app/output is the directory skald-fta writes to.

    The shared output volume IS the handoff. skald-fta writes the staged CSV to
    /app/output (host: tee_output) and SKALD resolves
    free_text_anonymization.staged_input_path against its own /app/output. Give
    the two stages different host directories and SKALD hard-fails with
    "DATA_MISSING: Configured input file not found" — it does not fall back to
    the raw input, so nothing leaks, but the run dies on an error that points at
    a missing file rather than at the mount that caused it. Checking the compose
    file before starting skald-fta names the real cause instead, and costs
    nothing on a correctly wired compose.

    Only advisory when the compose file declares no /app/output mount at all:
    that shape can't be distinguished from a compose this code doesn't
    understand, and refusing to run would break deployments that work today.
    """
    compose_file = config.get_path('docker_compose')
    if not os.path.exists(compose_file):
        print(f"Warning: {compose_file} not found — cannot verify that SKALD "
              f"shares skald-fta's output directory.", flush=True)
        return

    try:
        mounts = _compose_output_mounts(compose_file, fta_service)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"Warning: could not parse {compose_file} to verify the shared "
              f"output mount: {exc}", flush=True)
        return

    if not mounts:
        print(f"Warning: no service in {os.path.basename(compose_file)} mounts "
              f"/app/output — cannot confirm SKALD will see skald-fta's staged "
              f"input. Proceeding; SKALD will report DATA_MISSING if the mount "
              f"is wrong.", flush=True)
        return

    expected = os.path.realpath(config.paths.tee_output)
    mismatched = {
        svc: host for svc, host in mounts.items()
        if host is None or os.path.realpath(host) != expected
    }
    if mismatched:
        detail = ", ".join(
            f"{svc} -> {host if host else 'named volume (not a host bind)'}"
            for svc, host in sorted(mismatched.items())
        )
        raise RuntimeError(
            f"free_text_anonymization is enabled, but {os.path.basename(compose_file)} "
            f"does not give SKALD the same host output directory skald-fta writes "
            f"to. skald-fta writes the staged CSV into {expected}; compose maps "
            f"/app/output for: {detail}. Both stages must bind the SAME host "
            f"directory at /app/output — otherwise SKALD hard-fails with "
            f"'DATA_MISSING: Configured input file not found'. Fix the compose "
            f"file's output volume and redeploy."
        )

    print(f"Shared output mount verified: {sorted(mounts)} -> {expected}", flush=True)


_FTA_CONFIG_FILENAME = "config.json"


def _prepare_fta_config_dir(source_name):
    """Stage the run's app config as the single file /app/config/config.json.

    skald-fta opens /app/config/config.json by exact name. The bundle lands the
    config under whatever metadata.fileNames.config said, defaulting to
    generated-config.json (Bundle/decryption.py), so skald-fta fails with
    "Could not read config /app/config/config.json". SKALD is handed no
    config-path argument at all — the compose file gives it only the three
    mounts — so it discovers the file itself and never noticed the name.

    Staged into a directory of its own rather than by dropping a second file
    into the shared config mount: that mount is also SKALD's, and a second
    .json alongside the real one could change which config SKALD discovers.

    Exactly one file is staged, deliberately. If skald-fta later grows the same
    scan-the-directory discovery SKALD has, a directory holding both
    generated-config.json and config.json would look ambiguous to it; one file
    named config.json satisfies the current exact-name lookup and any future
    single-config discovery. The copy is byte-for-byte, so both containers read
    an identical, unmodified config — only the filename differs.

    Returns the host dir to mount at /app/config.
    """
    src = os.path.join(config.paths.tee_input_config, source_name)
    staging = config.get_path('tee_fta_config')

    # Rebuilt every run: a config left here by a previous run must never be the
    # one skald-fta reads.
    if os.path.isdir(staging):
        shutil.rmtree(staging, ignore_errors=True)
    try:
        os.makedirs(staging, exist_ok=True)
        os.chmod(staging, 0o700)
    except OSError as exc:
        _fail_free_text(f"Could not create the skald-fta config staging dir {staging}: {exc}")

    target = os.path.join(staging, _FTA_CONFIG_FILENAME)
    try:
        shutil.copy2(src, target)
        os.chmod(target, 0o600)
    except OSError as exc:
        # The bundle writes the config 0600 and root-owned, so a read failure
        # here means the stage is running without the deploy path's privileges.
        _fail_free_text(
            f"Could not stage the app config for skald-fta: copying {src} to "
            f"{target} failed ({exc}). The bundle writes the config 0600 and "
            f"root-owned, so this stage needs the same privileges as the deploy "
            f"path."
        )

    if source_name != _FTA_CONFIG_FILENAME:
        print(f"Staged {source_name} as {_FTA_CONFIG_FILENAME} for skald-fta "
              f"(content unchanged; skald-fta opens that exact filename).",
              flush=True)
    return staging


# The extensions both containers auto-discover in data/. Anything else in that
# directory (a leftover dataset.enc, say) is not a candidate input.
_DATA_INPUT_EXTENSIONS = (".csv", ".json", ".xls", ".xlsx")


def _discover_data_input():
    """Return the single data file in data/, the way both containers find it."""
    data_dir = config.paths.tee_input_data
    try:
        names = sorted(os.listdir(data_dir))
    except OSError as exc:
        _fail_free_text(f"Could not read the data directory {data_dir}: {exc}")

    candidates = [
        n for n in names
        if os.path.isfile(os.path.join(data_dir, n))
        and n.lower().endswith(_DATA_INPUT_EXTENSIONS)
    ]
    if len(candidates) != 1:
        _fail_free_text(
            f"Expected exactly one {'/'.join(_DATA_INPUT_EXTENSIONS)} file in "
            f"{data_dir} for the free-text stage, found {len(candidates)}: "
            f"{candidates}. Both containers auto-discover a single input, so "
            f"this is ambiguous."
        )
    return os.path.join(data_dir, candidates[0])


def _swap_staged_input_into_data(staged_path):
    """Put the sanitised CSV in data/ as the only input, replacing the raw file.

    The documented handoff — SKALD reading
    free_text_anonymization.staged_input_path out of the shared output/ mount —
    is NOT implemented in the deployed skald image. Observed on a real run:
    SKALD logged the staged CSV as "file(s) from an earlier run that this run
    will not overwrite", then re-read the raw file from data/ and emitted a
    "success" whose free-text column still carried names, a street address and
    an application number. A silent leak, which is strictly worse than a crash.

    So the handoff is made structural instead of cooperative. After skald-fta
    succeeds, the raw file is REPLACED by the sanitised CSV, leaving data/ with
    exactly one input. SKALD's existing auto-discovery then reads masked data
    with no change on its side, and — the point — the unmasked text is no
    longer anywhere SKALD could read it, so no future skald version can
    reintroduce the leak by ignoring a config field.

    The staged file is left in output/ as well: it is skald-fta's declared
    artifact, it is what the audit refers to, and free_text_artifact_names()
    already withholds it from the upload.

    Note the input format necessarily becomes CSV here. That is inherent to
    skald-fta, which writes a CSV regardless of what was submitted — not a
    consequence of this swap. _upload_direct_output already labels the returned
    bytes by the actual output extension rather than the submitted one.
    """
    raw_path = _discover_data_input()
    stem = os.path.splitext(os.path.basename(raw_path))[0]
    target = os.path.join(config.paths.tee_input_data, stem + ".csv")

    try:
        shutil.copy2(staged_path, target)
        os.chmod(target, 0o600)
        # Only after the sanitised copy is in place, and only if the raw file
        # is a different filename — otherwise it has just been overwritten.
        if os.path.realpath(raw_path) != os.path.realpath(target):
            os.remove(raw_path)
    except OSError as exc:
        _fail_free_text(
            f"Could not stage the sanitised input into {config.paths.tee_input_data}: "
            f"{exc}. Refusing to start SKALD, which would otherwise read the raw, "
            f"un-masked file."
        )

    # Structural guard: prove the raw input is gone and the only thing SKALD can
    # discover is byte-identical to what skald-fta produced.
    remaining = _discover_data_input()
    if os.path.realpath(remaining) != os.path.realpath(target):
        _fail_free_text(
            f"After staging, the input SKALD would discover is "
            f"{os.path.basename(remaining)}, not the sanitised "
            f"{os.path.basename(target)}. Refusing to start SKALD."
        )
    try:
        with open(staged_path, "rb") as a, open(target, "rb") as b:
            identical = a.read() == b.read()
    except OSError as exc:
        _fail_free_text(f"Could not verify the staged input in data/: {exc}")
    if not identical:
        _fail_free_text(
            f"The input staged into data/ does not match skald-fta's "
            f"{os.path.basename(staged_path)}. Refusing to start SKALD."
        )

    print(f"Sanitised input staged as data/{os.path.basename(target)} "
          f"(raw input removed — SKALD can no longer read un-masked text).",
          flush=True)


def _resolve_fta_image():
    """Return (image_ref, provenance) for skald-fta.

    The client-supplied docker-compose.yml wins when it declares the service,
    so the forthcoming skald-fta compose entry is honoured without a code
    change; otherwise the pin in config.yml is used.
    """
    service = _fta_setting("compose_service", "skald-fta")
    compose_file = config.get_path('docker_compose')
    if service and os.path.exists(compose_file):
        try:
            with open(compose_file) as f:
                doc = yaml.safe_load(f) or {}
            svc = (doc.get("services") or {}).get(service) or {}
            image = svc.get("image")
            if isinstance(image, str) and image.strip():
                return image.strip(), f"docker-compose.yml service '{service}'"
        except (OSError, ValueError, yaml.YAMLError) as exc:
            print(f"Warning: could not read '{service}' from compose file: {exc}", flush=True)

    pinned = _fta_setting("image")
    if not isinstance(pinned, str) or not pinned.strip():
        raise RuntimeError(
            "free_text_anonymization.enabled is true but no skald-fta image is "
            "available: the compose file declares no "
            f"'{service}' service and config.yml sets no "
            "free_text_anonymization.image."
        )
    return pinned.strip(), "config.yml free_text_anonymization.image"


def _fail_free_text(message):
    """Surface a skald-fta stage failure to the UI, then raise.

    Without this the run dies at step 10 having written no status.json, and
    get_app_status() keeps answering "Application is still running" forever —
    the UI hangs on a run that is already dead. Mirrors
    _write_direct_error_status(): /enclave/status returns this file verbatim.
    """
    status_path = config.get_path('status')
    try:
        os.makedirs(os.path.dirname(status_path), exist_ok=True)
        # Same remove-then-create dance as _write_direct_error_status: a
        # previous container may have left a root-owned status.json here.
        try:
            if os.path.exists(status_path):
                os.remove(status_path)
        except OSError:
            pass
        with open(status_path, "w") as f:
            json.dump({
                "status": "error",
                "title": "Error: Free-text anonymisation",
                "description": message,
            }, f, indent=2)
        try:
            os.chmod(status_path, 0o644)
        except OSError:
            pass
    except OSError as exc:
        print(f"Warning: could not write error status for the UI: {exc}", flush=True)
    raise RuntimeError(message)


def _assert_image_available(image, source):
    """Confirm the image is actually present before trying to run it.

    `docker pull` failures are not fatal on their own here — pull_docker_image()
    doesn't check its exit code, and a cached image is fine offline. But running
    a missing image exits 125 from the docker CLI *before the container starts*,
    which the exit-code contract would otherwise report as "skald-fta failed",
    wrongly implying the stage ran and rejected the data. Registry problems get
    named as registry problems instead.
    """
    probe = subprocess.run(["docker", "image", "inspect", image],
                           capture_output=True, text=True, check=False)
    if probe.returncode == 0:
        return
    _fail_free_text(
        f"skald-fta image {image!r} (from {source}) is not available and could "
        f"not be pulled, so free-text anonymisation could not run and SKALD was "
        f"not started. Registry said: "
        f"{(probe.stderr or probe.stdout).strip().splitlines()[0] if (probe.stderr or probe.stdout).strip() else 'image not present locally'}. "
        f"If the pull was refused as 'unauthorized', the GHCR package is private "
        f"or not yet published — make it public, or give this host a GHCR pull "
        f"credential (docker login ghcr.io)."
    )


def run_free_text_anonymization():
    """Run the skald-fta stage if this run's config asks for it.

    Returns True if skald-fta ran to success, False if the stage was not
    enabled (no block, or enabled false) and the run should go straight to
    SKALD exactly as before.

    Raises RuntimeError on any stage failure, which is how every other
    pipeline-stage failure is reported here: the caller stops, never starts
    SKALD, and the error surfaces to the UI. That is the on_failure: "fail"
    contract — skald-fta exits non-zero and writes no staged file. Under
    on_failure: "continue" it exits 0 and writes the staged file with the
    failures recorded in the audit JSON, so this function returns normally and
    SKALD proceeds.

    NOTE (attestation): the skald-fta image digest is recorded to
    keys/fta_image_hash.txt but deliberately NOT extended into a PCR. PCR 11
    is measured at deploy step 4 and pcr_values.json is snapshotted at step
    4.5, both before the bundle — and therefore this gate — is known. Adding
    an extension here would move live PCR 11 away from the value already sent
    to the client and break its attestation check. Measuring skald-fta
    properly means pinning the image ref pre-attestation; see the handover
    notes.
    """
    block, provenance = read_free_text_config()
    if block is None:
        print("Free-text anonymisation: no free_text_anonymization block in the "
              "app config — running SKALD directly.", flush=True)
        return False

    if not _as_bool(block.get("enabled")):
        print(f"Free-text anonymisation: disabled at {provenance} — running "
              "SKALD directly.", flush=True)
        return False

    print("="*60, flush=True)
    print("Pipeline stage: free-text anonymisation (skald-fta)", flush=True)
    print("="*60, flush=True)
    print(f"Gate read from: {provenance}", flush=True)

    artifacts = _fta_declared_artifacts(block)
    staged_name = artifacts["staged_input_path"]
    audit_name = artifacts["audit_output_path"]
    on_failure = str(block.get("on_failure", "fail")).strip().lower() or "fail"

    columns = block.get("columns")
    print(f"  columns:            {columns if columns else '(none declared)'}", flush=True)
    print(f"  minimum_confidence: {block.get('minimum_confidence', '(default)')}", flush=True)
    print(f"  staged_input_path:  output/{staged_name}", flush=True)
    print(f"  audit_output_path:  output/{audit_name}", flush=True)
    print(f"  on_failure:         {on_failure}", flush=True)

    # The shared output/ mount is the whole handoff — check it before doing any
    # work, so a mis-wired compose fails on the mount instead of on SKALD's
    # downstream DATA_MISSING.
    _verify_shared_output_mount(_fta_setting("compose_service", "skald-fta"))

    image, image_src = _resolve_fta_image()
    print(f"skald-fta image: {image}  (from {image_src})", flush=True)

    pull_docker_image(image)
    _assert_image_available(image, image_src)

    try:
        digest = hash_docker_image(image)
        with open(config.get_path('fta_image_hash'), "w") as f:
            f.write(digest)
        print(f"skald-fta image digest: {digest}", flush=True)
    except Exception as exc:
        # Auditing aid, not a gate — the image is already pulled and the run
        # can proceed without the digest on file.
        print(f"Warning: could not record skald-fta image digest: {exc}", flush=True)

    container_name = "skald-fta"
    # A leftover container of this name (previous run killed mid-flight) would
    # fail `docker run` with a name conflict, so clear it first.
    subprocess.run(["docker", "rm", "-f", container_name],
                   capture_output=True, text=True, check=False)

    # The same three mounts SKALD gets, pointing at the same host locations.
    # output/ being the identical directory is the entire handoff mechanism.
    fta_config_dir = _prepare_fta_config_dir(provenance.split(":", 1)[0])

    cmd = [
        "docker", "run", "--rm", "--name", container_name,
        "-v", f"{fta_config_dir}:/app/config:ro",
        "-v", f"{config.paths.tee_input_data}:/app/data",
        "-v", f"{config.paths.tee_output}:/app/output",
        image,
    ]
    print(f"Running: {' '.join(cmd)}", flush=True)
    print("="*60, flush=True)
    print("skald-fta LOGS (live):", flush=True)
    print("="*60, flush=True)

    before = _output_snapshot()
    timeout = _fta_setting("timeout_seconds", 3600)
    try:
        result = subprocess.run(
            cmd, stdout=sys.stdout, stderr=sys.stderr, timeout=timeout, check=False
        )
        returncode = result.returncode
    except subprocess.TimeoutExpired:
        # subprocess kills the docker *client*; the container itself keeps
        # running and holding the output mount unless it is removed too.
        subprocess.run(["docker", "rm", "-f", container_name],
                       capture_output=True, text=True, check=False)
        _fail_free_text(
            f"Free-text anonymisation (skald-fta) exceeded its {timeout}s limit "
            f"and was terminated. SKALD was not started."
        )

    created = _output_snapshot() - before
    if created:
        _record_free_text_artifacts(created)
        print(f"\nskald-fta wrote: {sorted(created)}", flush=True)

    if returncode != 0:
        _fail_free_text(
            f"Free-text anonymisation (skald-fta) failed with exit code "
            f"{returncode} (on_failure={on_failure}). No staged input was "
            f"produced, so SKALD was not started and no output is available."
        )

    staged_path = os.path.join(config.paths.tee_output, staged_name)
    if not os.path.isfile(staged_path):
        _fail_free_text(
            f"Free-text anonymisation (skald-fta) exited 0 but wrote no staged "
            f"input at output/{staged_name}. SKALD would hard-fail on this with "
            f"'DATA_MISSING: Configured input file not found' — stopping here "
            f"instead, since the missing staged file is the actual fault."
        )

    _swap_staged_input_into_data(staged_path)

    print(f"\nFree-text anonymisation complete. SKALD will read the sanitised "
          f"input from data/.", flush=True)
    print("="*60, flush=True)
    return True


def run_docker_containers():
    """Run the anonymisation pipeline: skald-fta (conditionally), then SKALD.

    The free-text stage is gated here rather than at the call sites so that
    every entry point gets it — deploy_enclave.py's step 10 and the
    /run/*_pipeline re-run thread both land in this function, and a gate added
    to only one of them would silently skip free-text masking on the other.
    Runs that don't enable free_text_anonymization are byte-for-byte unchanged:
    the gate short-circuits and compose comes up exactly as before.
    """
    # Before the gate, not inside it: a ledger left by an earlier run must not
    # survive into a run that doesn't enable the stage (see
    # clear_free_text_artifacts).
    clear_free_text_artifacts()
    run_free_text_anonymization()

    print("Stopping existing containers...", flush=True)
    subprocess.run(config.get_docker_command("down"), capture_output=True, text=True)
    
    print("Starting containers in detached mode...", flush=True)
    start_result = subprocess.run(
        config.get_docker_command("up", "--build", "-d"),
        capture_output=True,
        text=True
    )
    if start_result.returncode != 0:
        print(f"ERROR: Docker Compose 'up' failed with exit code {start_result.returncode}", flush=True)
        print(f"Stderr: {start_result.stderr}", flush=True)
        print(f"Stdout: {start_result.stdout}", flush=True)
        raise RuntimeError(f"Application failed to start. Check logs for details.")
    
    print("Containers started. Following container logs live...", flush=True)
    print("="*60, flush=True)
    print("CONTAINER LOGS (live):", flush=True)
    print("="*60, flush=True)
    
    log_process = subprocess.Popen(
        config.get_docker_command("logs", "-f"),
        stdout=sys.stdout,
        stderr=sys.stderr,
        text=True,
        bufsize=1
    )
    
    log_process.wait()
    
    ps_result = subprocess.run(
        config.get_docker_command("ps", "-q"),
        capture_output=True,
        text=True
    )
    if ps_result.returncode == 0 and ps_result.stdout.strip():
        ps_status = subprocess.run(
            config.get_docker_command("ps"),
            capture_output=True,
            text=True
        )
        print("\n" + "="*60, flush=True)
        print("Container Status:", flush=True)
        print(ps_status.stdout, flush=True)
    
    print("\n" + "="*60, flush=True)
    print(f"Application execution complete. Output saved to {config.paths.tee_output}", flush=True)


def _read_stripped_manifest(output_dir):
    """Read the container's manifest.json and return a summary safe to expose.

    Drops the `file` and `output_dir` fields from each entry — they carry the
    original filename and an internal TEE path — keeping only the de-id summary
    (counts, per-technique breakdown, pixel_verification_status). Returns None
    if no manifest is present.
    """
    manifest_path = os.path.join(output_dir, "manifest.json")
    if not os.path.isfile(manifest_path):
        return None
    try:
        with open(manifest_path) as f:
            manifest = json.load(f)
    except (OSError, ValueError):
        return None

    _DROP = {"file", "output_dir"}
    entries = manifest.get("files")
    if isinstance(entries, list):
        manifest["files"] = [
            {k: v for k, v in entry.items() if k not in _DROP}
            if isinstance(entry, dict) else entry
            for entry in entries
        ]
    return manifest


#: Suffix under which the container's own status.json is preserved when a
#: direct-upload failure overwrites it.
PIPELINE_STATUS_SUFFIX = ".pipeline"


def _write_direct_error_status(description):
    """Surface a direct-upload failure through /enclave/status instead of
    leaving whatever the container last wrote there. The UI renders
    `description` verbatim, so this is the difference between the user seeing
    the real failure and seeing a stale unrelated "success" block."""
    status_payload = {
        "status": "error",
        "title": "Error: Direct-upload output",
        "description": description,
    }
    status_path = config.get_path('status')
    os.makedirs(os.path.dirname(status_path), exist_ok=True)

    # Keep whatever the container wrote. Overwriting it in place destroys the
    # only record of what the pipeline actually produced — which is exactly the
    # evidence needed to explain a selection failure, and precisely when it is
    # gone. Diagnosing the first workbook upload meant reconstructing the run
    # from pipeline.log because this had already replaced the real status.
    try:
        if os.path.exists(status_path):
            os.replace(status_path, status_path + PIPELINE_STATUS_SUFFIX)
    except OSError:
        try:
            os.remove(status_path)
        except OSError:
            pass
    with open(status_path, "w") as f:
        json.dump(status_payload, f, indent=2)
    try:
        os.chmod(status_path, 0o644)
    except OSError:
        pass


#: The keys by which the container names its own result file, most faithful to
#: the submission first. See _select_tabular_output for the ordering rationale.
_RESULT_PATH_KEYS = ("restored_workbook_path", "format_matched_output_path",
                     "final_output_path")


def _status_names_a_result_path(status):
    """Does the container CLAIM to have written a result file? Independent of
    whether that file exists — the gap between the two is a container bug, and
    telling them apart is what keeps it from being read as a query-only run."""
    if not isinstance(status, dict):
        return False
    sections = []
    outputs = status.get("outputs")
    if isinstance(outputs, dict):
        sections.append(outputs)
    sections.append(status)
    return any(isinstance(section.get(key), str) and section[key].strip()
               for key in _RESULT_PATH_KEYS for section in sections)


def _select_tabular_output(output_dir, status_path):
    """Pick the anonymised artifact SKALD wants returned, per status.json.

    SKALD >= v3.2 returns the result in the input's own format: `generalized.csv`
    is always written and stays canonical for every statistic in status.json,
    but json/xlsx input ALSO gets `generalized.json`/`generalized.xlsx`, and
    that format-matched file is what the requester should get back — otherwise
    someone who submitted a workbook receives a CSV.

    Preference order is restored_workbook_path, then format_matched_output_path,
    then final_output_path — most faithful to the submission first. The
    restored (per-sheet) workbook leads because it reconstructs the sheet
    structure the requester actually sent, whereas the format-matched workbook
    is the sheets merged into one worksheet. NOTE: only the latter two are
    specified; restored_workbook_path's precedence is inferred from SKALD
    letting the per-sheet workbook win the filename when both apply, and is
    worth confirming with the container's owner. It is a no-op unless SKALD
    populates that field, which needs explicit `sheet_joins` in the config.

    Returns None when status.json names none of them (pre-v3.2 SKALD), leaving
    the caller on its existing single-candidate logic.

    The paths are container-relative ("./output/generalized.xlsx"), so only the
    basename is used and the result must resolve inside output_dir — status.json
    is written by the container, so treating a path in it as authoritative would
    otherwise let a compromised image name any file on the host and have it
    encrypted and uploaded.
    """
    try:
        with open(status_path) as f:
            status = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(status, dict):
        return None

    # SKALD nests these under "outputs" alongside the run statistics; they are
    # not top-level fields. Reading only the top level meant this function
    # returned None for *every* run ever made, so the whole v3.2 selection was
    # dead and the caller always fell through to "there must be exactly one
    # file". CSV input survived that by writing exactly one file; the first
    # workbook submitted produced generalized.csv AND generalized.xlsx and
    # failed as ambiguous, having actually anonymised the data correctly.
    #
    # The top level is still searched, so a container that promotes these to
    # the root — or an older one that already did — keeps working.
    sections = []
    outputs = status.get("outputs")
    if isinstance(outputs, dict):
        sections.append(outputs)
    sections.append(status)

    output_dir_real = os.path.realpath(output_dir)
    for key in _RESULT_PATH_KEYS:
        for section in sections:
            raw = section.get(key)
            if not isinstance(raw, str) or not raw.strip():
                continue
            candidate = os.path.join(output_dir, os.path.basename(raw.strip()))
            resolved = os.path.realpath(candidate)
            if not resolved.startswith(output_dir_real + os.sep):
                continue
            if os.path.isfile(resolved):
                return resolved
    return None


#: SKALD's tabular result, before the extension. It always writes the .csv and,
#: for json/xlsx input, a format-matched sibling next to it.
_TABULAR_OUTPUT_STEM = "generalized"

#: The submitted format -> the extension SKALD writes for it. Keyed by what the
#: upload sidecar records in `format`.
_FORMAT_EXTENSIONS = {
    "excel": ".xlsx", "xlsx": ".xlsx", "xls": ".xlsx",
    "json": ".json", "csv": ".csv",
}


def tabular_output_candidates(output_dir, status_path):
    """The files in output_dir that could be a tabular run's single result,
    and the set that was excluded to get there.

    Split out from resolve_tabular_output_path because _upload_direct_output
    needs to know whether there are ZERO candidates *without* triggering that
    function's failure path — which writes an error status over whatever the
    pipeline reported. A DP query run legitimately has none.
    """
    status_name = os.path.basename(status_path)
    # free_text_artifact_names() matters twice over here: without it a free-text
    # run leaves the staged CSV and audit JSON behind, so this count is 3 rather
    # than 1 and every such run dies on the ambiguity check instead of returning
    # its result.
    #
    # status_name + PIPELINE_STATUS_SUFFIX is the container's own status
    # preserved by a previous failed attempt. The scheduler requeues onto
    # another TEE and may land back here, so without this the retry would see
    # one more "result file" than the first attempt did.
    #
    # The k-means plots are excluded because they are uploaded separately, each
    # in its own container (see write_kmeans_plot_containers) — and because
    # leaving them in makes a k-means run unreturnable either way:
    # _select_by_submitted_format refuses to guess once a non-generalized.*
    # name is present, so their mere existence turned "one result file" into an
    # ambiguity error.
    excluded = ({status_name, status_name + PIPELINE_STATUS_SUFFIX,
                 "pipeline.log"} | _KNOWN_KEY_MATERIAL
                | _KNOWN_DIAGNOSTIC_ARTIFACTS | set(_KMEANS_PLOT_FILES)
                | free_text_artifact_names())
    candidates = [
        f for f in os.listdir(output_dir)
        if os.path.isfile(os.path.join(output_dir, f)) and f not in excluded
    ]
    return candidates, excluded


def resolve_tabular_output_path(output_dir, status_path, fmt):
    """The one file a tabular direct-upload run should return.

    Three sources, in order of how much they are trusted:

      1. status.json, which names the result explicitly — SKALD >= v3.2 writes
         generalized.csv AND a format-matched sibling for json/xlsx input, so
         "the only file present" stopped being a usable answer.
      2. the single remaining candidate, for pre-v3.2 output where status.json
         names no path at all.
      3. the submitted format, when several of SKALD's own siblings remain.

    Raises RuntimeError, after recording the failure in status.json, when none
    of the three can pick a file. Refusing is right: the wrong choice here means
    uploading a file that was never anonymised.

    Public and separate from `_upload_direct_output` because the wiring is the
    part that broke. `_select_tabular_output` was correct in isolation and
    simply never returned anything, and no test could see that while the
    decision lived inline in a function that also encrypts and uploads.
    """
    output_path = _select_tabular_output(output_dir, status_path)
    if output_path is not None:
        return output_path

    candidates, excluded = tabular_output_candidates(output_dir, status_path)

    if len(candidates) == 1:
        return os.path.join(output_dir, candidates[0])

    output_path = _select_by_submitted_format(output_dir, candidates, fmt)
    if output_path is not None:
        return output_path

    message = (
        f"Direct-upload output expects exactly one result file in "
        f"{output_dir} (excluding {sorted(excluded)}), found "
        f"{len(candidates)}: {candidates}. {_describe_pipeline_status(status_path)}"
    )
    _write_direct_error_status(message)
    raise RuntimeError(message)


def _describe_pipeline_status(status_path):
    """A one-line account of what the pipeline itself reported, for the
    file-selection failure message.

    The bare "found N result files" is the finaliser's symptom, not the cause —
    diagnosing a real failure meant SSHing to a live enclave to read
    status.json, because the message named the file count and nothing about what
    the pipeline actually did. Folding the container's own status in makes the
    error self-explanatory. Best-effort: never raises, and falls back to the
    original guidance when status.json says nothing useful.
    """
    try:
        with open(status_path) as f:
            status = json.load(f)
    except (OSError, ValueError):
        return "Narrow the pipeline's output before uploading."
    if not isinstance(status, dict):
        return "Narrow the pipeline's output before uploading."

    if status.get("status") == "error":
        reason = status.get("error") or status.get("description") or "no reason given"
        return f"The pipeline reported an error: {reason}"
    if status.get("status") == "success":
        phase = status.get("phase")
        phase_note = f" phase='{phase}'" if phase else ""
        return (f"The pipeline reported status='success'{phase_note} but wrote no "
                "result file — this is not a shape the direct-upload finaliser "
                "knows how to return.")
    return "Narrow the pipeline's output before uploading."


def _select_by_submitted_format(output_dir, candidates, fmt):
    """Choose between SKALD's sibling outputs using the format that was sent.

    A last resort for when status.json names no path at all. The rule is the
    one the requester would expect and the one SKALD's own log states — "Input
    was Excel, wrote matching output" — so someone who submits a workbook gets
    a workbook back rather than a CSV.

    Returns None unless the candidates are exactly SKALD's `generalized.*`
    family, because outside that family there is no principled choice to make
    and guessing would be worse than the explicit ambiguity error.
    """
    wanted = _FORMAT_EXTENSIONS.get((fmt or "").strip().lower())
    if not wanted:
        return None

    siblings = {}
    for name in candidates:
        stem, ext = os.path.splitext(name)
        if stem != _TABULAR_OUTPUT_STEM:
            return None  # something unexpected is present; do not guess
        siblings[ext.lower()] = name

    chosen = siblings.get(wanted) or siblings.get(".csv")
    if not chosen:
        return None
    path = os.path.join(output_dir, chosen)
    return path if os.path.isfile(path) else None


def _is_query_only_run(output_dir, status_path, status):
    """True when the pipeline reported a query result and wrote no result
    file — a DP query run, whose answer is the result object itself.

    Deliberately narrow. A container that NAMES a result file in status.json
    is not this shape even when the file is missing: that is the container
    contradicting itself, and it stays the hard error it already was rather
    than being quietly reported as a query-only success.
    """
    if _app_query_result(status) is None:
        return False
    if _status_names_a_result_path(status):
        return False
    return not tabular_output_candidates(output_dir, status_path)[0]


def _upload_direct_output(output_dir, urls):
    """
    Direct-upload mode: hand the pipeline's single result file to the enclave
    manager process over its own loopback address, so it — the only process
    holding the browser's output_key in memory — can encrypt it into the
    SPIDROU1 container and upload it. This subprocess never receives that
    key, only a completion result; see lib/direct_upload.finalize_output()
    and backend-changes-direct-upload.md §2.6.

    Picks exactly one result file. For a DICOM dataset that's the same
    `after_deidentification.dcm` allow-list _upload_dicom_output uses (the
    container's output dir also holds the original PHI-bearing image, the
    re-identification keystore, and audit JSONs, none of which may leave the
    TEE). For anything else it's whatever single file remains in output_dir
    after excluding status.json/pipeline.log. Either way, ambiguity is a hard
    error — guessing wrong here would silently encrypt-and-ship the wrong, or
    sensitive, file — and the error is written to status.json (not just
    raised) so /enclave/status reports it instead of a stale prior result.

    Before any of that: the container writes status.json itself on both
    success and failure (see get_app_status()'s docstring — "the app
    controls structure"). If it already reports an error, that is the truth
    and MUST be preserved — treating whatever files happen to remain
    (pipeline.log, partial output, ...) as a valid result and overwriting
    that error with a fabricated "success" would be worse than the crash
    this replaces: it would silently misreport a failed run as succeeded.

    A DP query run is the one shape with no result file at all: its answer IS
    the JSON result object in status.json, and there is nothing anonymised to
    hand back. That still goes through finalize-output rather than returning
    early the way two-pass k-anon pass 1 does, because the k-means plots do
    need encrypting and uploading and only the enclave manager process holds
    the key for it.
    """
    status_path = config.get_path('status')
    existing_status = None
    if os.path.isfile(status_path):
        try:
            with open(status_path) as f:
                existing_status = json.load(f)
        except (OSError, ValueError):
            existing_status = None
        if isinstance(existing_status, dict) and existing_status.get("status") == "error":
            raise RuntimeError(
                "Pipeline reported an error; refusing to treat remaining output "
                f"files as a successful result: {existing_status.get('error')}"
            )

        # Two-pass k-anon, pass 1: the pipeline deliberately produced no result
        # file, only a parameter grid for the user to pick k from. That grid is
        # already in status.json and reaches the UI through the completion
        # callback's `result` (report_job_complete attaches get_app_status()).
        # There is nothing to encrypt or upload; forcing this through the
        # one-result-file check below turns a successful analysis into a failure
        # and, via _write_direct_error_status, destroys the grid. Keying on the
        # phase is precise — pass 2 writes generalized.csv and succeeds normally.
        if isinstance(existing_status, dict) and existing_status.get("phase") == "awaiting_pass2":
            print("Direct-upload: two-pass k-anon pass 1 — parameter grid only, "
                  "nothing to upload", flush=True)
            return None

    dataset_url = urls.get("blobUrl", "")
    prefix = "enclave://upload/"
    if not dataset_url.startswith(prefix):
        message = f"Direct-upload output requires an enclave upload blobUrl, got: {dataset_url}"
        _write_direct_error_status(message)
        raise RuntimeError(message)
    upload_id = dataset_url[len(prefix):]

    scratch_dir = os.environ.get("ENCLAVE_SCRATCH_DIR", "/enclave/scratch")
    meta_path = os.path.join(scratch_dir, f"{upload_id}.meta.json")
    original_name, fmt = "dataset", "csv"
    try:
        with open(meta_path) as f:
            meta = json.load(f)
        original_name = meta.get("filename", original_name)
        fmt = meta.get("format", fmt)
    except (OSError, ValueError):
        pass  # meta sidecar missing/unreadable — fall back to the defaults above
    finally:
        try:
            os.remove(meta_path)
        except FileNotFoundError:
            pass

    manifest = None
    if fmt == "dicom":
        deid_files = _find_deidentified_outputs(output_dir)
        if len(deid_files) != 1:
            message = (
                f"Direct-upload DICOM output expects exactly one "
                f"'{_DEID_OUTPUT_NAME}' under {output_dir}, found "
                f"{len(deid_files)}: {[os.path.relpath(p, output_dir) for p in deid_files]}."
            )
            _write_direct_error_status(message)
            raise RuntimeError(message)
        output_path = deid_files[0]
        manifest = _read_stripped_manifest(output_dir)
    elif fmt == "image":
        # A direct image run used to fall into the tabular branch below, which
        # looks for a `generalized.*` file and fails — the image pipeline writes
        # a single redacted image, not a table. Select it the same way the blob
        # image path does, so a direct skald_image run lands its result instead
        # of erroring on a shape it was never going to produce.
        image_files = _find_image_outputs(output_dir)
        if len(image_files) != 1:
            message = (
                f"Direct-upload image output expects exactly one redacted image "
                f"in {output_dir}, found {len(image_files)}: "
                f"{[os.path.basename(p) for p in image_files]}."
            )
            _write_direct_error_status(message)
            raise RuntimeError(message)
        output_path = image_files[0]
    elif _is_query_only_run(output_dir, status_path, existing_status):
        # The result object in status.json is the whole answer.
        # resolve_tabular_output_path would fail this with "found 0" and, via
        # _write_direct_error_status, destroy that answer — the same way pass-1
        # k-anon used to fail. The plots below still need uploading.
        output_path = None
        print("Direct-upload: DP query result, no result file to upload", flush=True)
    else:
        output_path = resolve_tabular_output_path(output_dir, status_path, fmt)
        print(f"Direct-upload result selected: {os.path.basename(output_path)}")

    stem, _ = os.path.splitext(original_name)
    # Extension and content type must describe the bytes actually being
    # uploaded, not the input's format: SKALD may fall back to generalized.csv
    # for a workbook submission (no format-matched file written), and labelling
    # those CSV bytes .xlsx would break the reader that opens them.
    #
    # Image types are folded in from the same _IMAGE_CONTENT_TYPES the blob path
    # uses, and an image result keeps its own extension (.png stays .png) rather
    # than taking the `_anonymised` tabular suffix — the redacted image is the
    # result, and a viewer opens it by extension.
    if output_path is not None:
        ext = os.path.splitext(output_path)[1]
        content_type = {
            ".csv": "text/csv",
            ".json": "application/json",
            ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ".xls": "application/vnd.ms-excel",
            ".dcm": "application/dicom",
            **_IMAGE_CONTENT_TYPES,
        }.get(ext.lower(), "application/octet-stream")
        if fmt == "image":
            filename = f"{stem or 'image'}_redacted{ext}"
        else:
            filename = f"{stem or 'dataset'}_anonymised{ext}"

    dp_config = load_config_file(config.get_path('config_file'))
    address = dp_config["enclaveManagerAddress"]
    endpoint = urllib.parse.urljoin(address, f"/internal/upload/{upload_id}/finalize-output")

    payload = {}
    if output_path is not None:
        payload.update({
            "output_path": output_path,
            "filename": filename,
            "content_type": content_type,
        })
    if manifest is not None:
        payload["manifest"] = manifest

    # Let the manager check its session's output key against the one this
    # process unwrapped from the bundle, before it encrypts anything under
    # either. The check value is not the key — see output_key_check_value, and
    # §2.6 on why the key itself never crosses this boundary. Absent when the
    # bundle carried no per-run key (older UI), in which case there is nothing
    # to compare and the session's key stands alone.
    output_crypto = _get_output_crypto()
    if output_crypto is not None:
        payload["output_key_check"] = output_key_check_value(output_crypto["key"])

    print(f"Handing off output to enclave manager for encryption: {endpoint}")
    response = requests.post(endpoint, json=payload, timeout=60)
    if response.status_code != 200:
        message = f"finalize-output failed: {response.status_code} {response.text}"
        _write_direct_error_status(message)
        raise RuntimeError(message)
    result = response.json()
    print(f"Direct-upload output finalised: {result}")
    return result.get("output_url") or result.get("blob_url")


def _write_dicom_status(output_blob_url, manifest=None):
    """Write the SKALD-DICOM status.json contract that /enclave/status returns
    verbatim to the UI/middleware. `output_blob_url` is the bare location of
    the encrypted de-identified image stored back to the output container."""
    dicom_output = {"outputBlobUrl": output_blob_url}
    if manifest is not None:
        dicom_output["manifest"] = manifest
    status_payload = {
        "status": "success",
        "application": "skald-dicom",
        "outputs": {"dicom": dicom_output},
    }
    status_path = config.get_path('status')
    os.makedirs(os.path.dirname(status_path), exist_ok=True)
    # The container runs as root inside Docker and may have already written
    # its own status.json into this bind-mounted directory. When this runs via
    # deploy_enclave.py's subprocess (also root) that's a non-issue; when it
    # runs via the in-process /run/dicom_pipeline re-run thread (this
    # process, non-root), overwriting a root-owned file in place fails even
    # though this user owns the directory and can unlink it. Remove-then-
    # create sidesteps that in both cases.
    try:
        if os.path.exists(status_path):
            os.remove(status_path)
    except OSError:
        pass
    with open(status_path, "w") as f:
        json.dump(status_payload, f, indent=2)
    try:
        os.chmod(status_path, 0o644)
    except OSError:
        pass
    print(f"DICOM status written to {status_path}: {output_blob_url}")


# The SKALD-DICOM container writes several artifacts into the shared output
# volume, and MOST of them must never leave the TEE:
#   after_deidentification.dcm  -> the de-identified image   (SAFE — we ship this)
#   before_deidentification.dcm -> the original, still PHI    (NEVER upload)
#   keystore/*                  -> FPE keys + token_vault, i.e. the material
#                                  needed to RE-IDENTIFY patients (NEVER upload)
#   phi_tags.json / *_audit.json / data.json -> extracted PHI + audit (NEVER)
# We ALLOW-LIST the single de-identified artifact by exact basename rather than
# deny-listing, so any new sensitive file the container starts emitting is
# excluded by default instead of being accidentally uploaded.
_DEID_OUTPUT_NAME = "after_deidentification.dcm"

# The tabular SKALD techniques (k-anonymisation, FPE-based chunk-anonymisation,
# ...) can write their own re-identification key material alongside the actual
# result - e.g. symmetric_keys.json / fpe_encrypt_keys.json observed from a
# live run. That material must never leave the TEE, same as DICOM's keystore/
# above. Unlike the DICOM case, we do NOT yet have a confirmed contract from
# the container for a single allow-listed result filename per technique (open
# item - needs the same SKALD-owner confirmation as the DICOM behaviour did),
# so this is a deny-list stopgap covering only the filenames observed so far.
# It does NOT generalise the way the DICOM allow-list does: a new key-material
# file this doesn't name would be uploaded by default. Extend this set (or
# replace it with a real allow-list) as soon as the container's per-technique
# output contract is confirmed.
_KNOWN_KEY_MATERIAL = {"symmetric_keys.json", "fpe_encrypt_keys.json"}

# Separate from _KNOWN_KEY_MATERIAL on purpose: these are anonymisation-run
# diagnostics (equivalence-class size histogram, OLA-2 search nodes, the
# k/suppression parameter sweep) observed alongside generalized.csv on a real
# tabular run. They carry no PII and no re-identification material — nothing
# here is dangerous to expose — they just are not the anonymised dataset
# itself, so they must not be mistaken for "the" single result file. Same
# stopgap caveat as _KNOWN_KEY_MATERIAL: a deny-list, not a confirmed
# per-technique contract, so a new diagnostic filename the container starts
# emitting would be uploaded by default until this set is extended.
_KNOWN_DIAGNOSTIC_ARTIFACTS = {
    "parameter_grid.txt", "equivalence_class_stats.json", "top_ola2_nodes.json",
}


def _find_deidentified_outputs(output_dir):
    """Recursively collect ONLY the de-identified .dcm output(s)."""
    found = []
    for root, dirs, files in os.walk(output_dir):
        # Never descend into the keystore (re-identification material).
        dirs[:] = [d for d in dirs if d.lower() != "keystore"]
        for name in sorted(files):
            if name == _DEID_OUTPUT_NAME:
                found.append(os.path.join(root, name))
    return sorted(found)


def _upload_dicom_output(fetch_data, output_dir, container_base_url, urls):
    """Encrypt and store the de-identified DICOM output(s) back to the output
    container, then write the status contract.

    Only `after_deidentification.dcm` files are uploaded — the original image,
    the keystore, and the audit JSONs stay inside the TEE (they contain PHI or
    re-identification keys).

    When the bundle carried a per-run output key (see decrypt_bundle_tee /
    _get_output_crypto), the output is encrypted into the SPIDROU1 container
    with write_output_container() so the browser can decrypt and render it
    directly, using the SAME key it generated for this run — not the shared
    Key Vault Fernet key, which never leaves this per-run key's job of
    decrypting the input. Older UIs that don't send that key fall back to the
    previous behaviour (Fernet with the shared Key Vault key). Either way the
    status reports the (bare) blob location, not a fetch URL.
    """
    output_crypto = _get_output_crypto()
    encrypt_output = bool(getattr(config.dicom, "encrypt_output", True))

    if not os.path.exists(output_dir):
        raise FileNotFoundError(f"Output directory not found: {output_dir}")

    deid_files = _find_deidentified_outputs(output_dir)
    if not deid_files:
        raise FileNotFoundError(
            f"No '{_DEID_OUTPUT_NAME}' found under {output_dir}. The container "
            "did not produce a de-identified image, or wrote it under an "
            "unexpected name."
        )

    cipher = None
    if output_crypto is None and encrypt_output:
        print("Fetching encryption key from Key Vault (encrypt_output=true)...")
        fernet_key = fetch_data.fetch_fernet_key_from_kv(urls["keyVaultUrl"])
        cipher = create_fernet_cipher(fernet_key)

    print(f"Uploading {len(deid_files)} de-identified DICOM output(s)")
    primary_blob_url = None
    for src_path in deid_files:
        # Name the blob after the per-image subdir so batch outputs don't collide.
        case_name = os.path.basename(os.path.dirname(src_path)) or "output"
        blob_base = f"{case_name}_deidentified.dcm"

        if output_crypto is not None:
            upload_name = blob_base + ".enc"
            upload_src = f"/tmp/{upload_name}"
            with open(upload_src, "wb") as f:
                write_output_container(
                    src_path, f,
                    run_id=output_crypto["run_id"],
                    output_key=output_crypto["key"],
                    output_base_iv=output_crypto["base_iv"],
                    filename=blob_base,
                    content_type="application/dicom",
                )
        elif encrypt_output:
            with open(src_path, "rb") as f:
                payload = cipher.encrypt(f.read())
            upload_name = blob_base + ".enc"
            upload_src = f"/tmp/{upload_name}"
            with open(upload_src, "wb") as f:
                f.write(payload)
        else:
            upload_name = blob_base
            upload_src = src_path

        blob_url = f"{container_base_url}/{upload_name}"
        print(f"Uploading {upload_name} to {blob_url}...")
        fetch_data.upload_blob(blob_url, upload_src)
        if output_crypto is not None or encrypt_output:
            os.remove(upload_src)

        if primary_blob_url is None:
            primary_blob_url = blob_url

    manifest = _read_stripped_manifest(output_dir)
    _write_dicom_status(primary_blob_url, manifest=manifest)
    print("DICOM output stored to blob; status written")
    return primary_blob_url


# DP k-means: two diagnostic plots the application drops alongside the main
# tabular result, in output_dir, when the run's DP config included a k-means
# query. Fixed basenames per the application's own contract, not user-chosen —
# same "allow-list a known name" rationale as _DEID_OUTPUT_NAME above. Maps
# each basename to the status.json field its uploaded URL is reported under.
_KMEANS_PLOT_FILES = {
    "item_level_kmeans_convergence.png": "plot_convergence",
    "item_level_kmeans_wcss.png": "plot_wcss",
}

#: Where the pipeline application reports a query result (a DP k-means/mean/
#: histogram answer, as opposed to an anonymised file). The UI reads a DP
#: result from these keys, so they are what has to survive a status write.
APP_RESULT_KEYS = ("result", "results")


def _app_query_result(status):
    """The query result object the application reported, or None. Takes an
    already-parsed status dict so callers that read status.json for other
    reasons don't read it twice."""
    if not isinstance(status, dict):
        return None
    for key in APP_RESULT_KEYS:
        value = status.get(key)
        if value is not None:
            return value
    return None


#: Domain-separation label for output_key_check_value(). Fixed forever: it is
#: part of the value's definition, and both processes must derive the same one.
_OUTPUT_KEY_CHECK_LABEL = b"P3DX output key check v1"


def output_key_check_value(output_key):
    """A value that proves two processes hold the same output key, without
    either of them sending the key.

    There is exactly ONE output key per job on the browser side: it is
    generated once, filed in IndexedDB under the job id, and the decrypt hook
    has no second key to fall back on. But the enclave receives it twice, by
    two routes that nothing here ties together — the bundle's
    outputWrappedKey, unwrapped in the deploy subprocess (see
    decrypt_bundle_tee), and POST /enclave/upload/init's output_wrapped_key,
    unwrapped into the UploadManager session in the enclave manager process.
    Whether those carry the same bytes depends on the middleware forwarding
    one key to both surfaces, which cannot be verified from inside the
    enclave. If they ever diverge the run still "succeeds" and the user gets
    output they can never decrypt, with no recourse — so the two are compared
    at finalize time instead of assumed equal.

    HMAC over a fixed label rather than a bare digest of the key: a key check
    value is a standard construction for exactly this, and it means the thing
    crossing the process boundary is not a hash of a secret. Truncated to 32
    hex chars — this only ever has to detect a mismatch, not resist collision
    search by someone who could already choose keys.
    """
    return hmac.new(output_key, _OUTPUT_KEY_CHECK_LABEL, hashlib.sha256).hexdigest()[:32]


def write_kmeans_plot_containers(fetch_data, output_dir, container_base_url, *,
                                 run_id, output_key, staging_dir="/tmp"):
    """Encrypt each k-means plot the DP application wrote into its OWN
    SPIDROU1 container and upload it. Returns {status.json field: bare blob
    URL} for whichever plots were present — a job with no k-means query has
    neither file, and this is a silent no-op.

    Same key, same container format (write_output_container), same upload
    target as the run's main result — see _upload_dicom_output above. The only
    differences: there are two extra files here, additional to (not replacing)
    the main result, and each gets its own fresh random base_iv.

    AES-GCM's keystream depends only on (key, nonce). Reusing the job's shared
    output_base_iv across these containers would encrypt different plaintext
    (chunk 0 of the convergence plot vs. chunk 0 of the WCSS plot vs. chunk 0
    of the main result) under an identical (key, nonce) pair, leaking their
    XOR and endangering the authentication key — so a fresh 12-byte base_iv is
    generated per container and written into that container's own header; the
    browser's reader already takes base_iv from the header rather than a
    value fixed at job creation. The per-container run_id suffix
    (":convergence" / ":wcss") is kept only as domain separation against one
    container's chunks being spliced into another's — it is NOT what makes
    reusing output_base_iv safe, and does not substitute for the fresh IV.

    Takes `run_id`/`output_key` explicitly rather than reading _output_crypto,
    because the two ingest paths hold the job's output key in different
    processes: the blob-input path in this subprocess (see _upload_kmeans_plots
    below), the direct-upload path only inside the enclave manager's
    UploadManager session (see lib/direct_upload.finalize_output, which checks
    the two agree before using either). Both call this, so one browser reader
    decrypts byte-identical containers either way.
    """
    plot_urls = {}
    for basename, field in _KMEANS_PLOT_FILES.items():
        src_path = os.path.join(output_dir, basename)
        if not os.path.isfile(src_path):
            continue

        suffix = field[len("plot_"):]  # "plot_convergence" -> "convergence"
        upload_name = basename + ".enc"
        staged = os.path.join(staging_dir, upload_name)
        container_base_iv = os.urandom(12)  # fresh per container — see docstring
        with open(staged, "wb") as f:
            write_output_container(
                src_path, f,
                run_id=f"{run_id}:{suffix}",
                output_key=output_key,
                output_base_iv=container_base_iv,
                filename=basename,
                content_type="image/png",
            )
        try:
            os.chmod(staged, 0o600)
        except OSError:
            pass

        blob_url = f"{container_base_url}/{upload_name}"
        print(f"Uploading {upload_name} to {blob_url}...", flush=True)
        try:
            fetch_data.upload_blob(blob_url, staged)
        finally:
            try:
                os.unlink(staged)
            except OSError:
                pass
        plot_urls[field] = blob_url

    return plot_urls


def _upload_kmeans_plots(fetch_data, output_dir, container_base_url):
    """The blob-input path's k-means plot upload: encrypt and upload the plots
    under this run's browser-held output key, then report their bare blob URLs
    by merging them into the `"query": "kmeans"` result object the DP
    application already wrote into status.json.

    A job whose plots exist but which has no output_crypto (no per-run browser
    key on this run) can't satisfy "same key as the main result", so it logs
    and skips rather than failing an otherwise-successful pipeline run.
    """
    output_crypto = _get_output_crypto()
    if output_crypto is None:
        if any(os.path.isfile(os.path.join(output_dir, name)) for name in _KMEANS_PLOT_FILES):
            print("k-means plot(s) present but no per-run output key on this "
                  "job; skipping plot upload", flush=True)
        return {}

    plot_urls = write_kmeans_plot_containers(
        fetch_data, output_dir, container_base_url,
        run_id=output_crypto["run_id"], output_key=output_crypto["key"],
    )
    if plot_urls:
        _patch_kmeans_status(plot_urls)
    return plot_urls


def _find_kmeans_query_result(node):
    """Depth-first search for a dict with `"query": "kmeans"` anywhere in a
    parsed status.json tree (arbitrarily nested dicts/lists) — the DP
    application owns that shape, not this module, so this doesn't assume a
    fixed path to it."""
    if isinstance(node, dict):
        if node.get("query") == "kmeans":
            return node
        for value in node.values():
            found = _find_kmeans_query_result(value)
            if found is not None:
                return found
    elif isinstance(node, list):
        for item in node:
            found = _find_kmeans_query_result(item)
            if found is not None:
                return found
    return None


def _patch_kmeans_status(plot_urls):
    """Merge plot_convergence/plot_wcss into the k-means result object already
    in status.json, without disturbing anything else the DP application wrote
    there (centroids, labels, etc. — that content is the application's, not
    ours; see _upload_kmeans_plots)."""
    status_path = config.get_path('status')
    try:
        with open(status_path) as f:
            status = json.load(f)
    except (OSError, ValueError) as e:
        print(f"Could not read status.json to attach k-means plot URLs: {e}", flush=True)
        return

    target = _find_kmeans_query_result(status)
    if target is None:
        print('No "query": "kmeans" object found in status.json; plot URLs '
              "were uploaded but not attached", flush=True)
        return
    target.update(plot_urls)

    try:
        if os.path.exists(status_path):
            os.remove(status_path)
    except OSError:
        pass
    with open(status_path, "w") as f:
        json.dump(status, f, indent=2)
    try:
        os.chmod(status_path, 0o644)
    except OSError:
        pass


# skald-image writes exactly one redacted image into /app/output (mirrors
# tee_output). Unlike the DICOM container's fixed after_deidentification.dcm
# basename, the app package's own output-filename convention is not yet
# confirmed with its owner, so this allow-lists by extension instead — same
# `ext` set the pipeline_config.json contract already exposes to the UI, not
# a filename. Ambiguity (0 or >1 image files) is a hard error rather than a
# guess, same rationale as _find_deidentified_outputs above.
_IMAGE_OUTPUT_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".webp"}

_IMAGE_CONTENT_TYPES = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".bmp": "image/bmp",
    ".tif": "image/tiff",
    ".tiff": "image/tiff",
    ".webp": "image/webp",
}


def _find_image_outputs(output_dir):
    """Collect image files directly under output_dir (non-recursive — the
    app package processes a single image per job per the current contract)."""
    found = []
    for name in sorted(os.listdir(output_dir)):
        path = os.path.join(output_dir, name)
        if os.path.isfile(path) and os.path.splitext(name)[1].lower() in _IMAGE_OUTPUT_EXTENSIONS:
            found.append(path)
    return found


def _read_image_manifest(output_dir):
    """Optional detection/redaction summary the container may drop alongside
    its output, following the same manifest.json convention the tabular
    SKALD techniques use (see _read_stripped_manifest). Not yet confirmed
    with the skald-image app owner — returns {} if absent or unreadable, so
    callers degrade to reporting only the fields they already know."""
    manifest_path = os.path.join(output_dir, "manifest.json")
    if not os.path.isfile(manifest_path):
        return {}
    try:
        with open(manifest_path) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_image_status(output_blob_url, filename, byte_count, run_config, manifest):
    """Write the skald-image status.json contract that /enclave/status returns
    verbatim to the UI. Written ONCE with outputs.image fully populated — see
    the direct-upload race this avoids: publishing status:"success" before
    outputs is filled in is what left the UI permanently stuck reporting "no
    output location" there, and it applies here identically."""
    image_output = {
        "outputBlobUrl": output_blob_url,
        "filename": filename,
        "bytes": byte_count,
    }
    # mask_mode/conf are user-settable and known from the validated request
    # config regardless of what (if anything) the container reports back.
    if run_config.get("mask_mode") is not None:
        image_output["mask_mode"] = run_config["mask_mode"]
    if run_config.get("conf") is not None:
        image_output["conf"] = run_config["conf"]
    # redacted_regions/detections are the container's own claims about what
    # it found — only include them if it actually reported something.
    if isinstance(manifest.get("redacted_regions"), int):
        image_output["redacted_regions"] = manifest["redacted_regions"]
    if isinstance(manifest.get("detections"), dict):
        image_output["detections"] = manifest["detections"]

    status_payload = {
        "status": "success",
        "application": "skald-image",
        "outputs": {"image": image_output},
    }
    status_path = config.get_path('status')
    os.makedirs(os.path.dirname(status_path), exist_ok=True)
    # Same remove-then-create dance as _write_dicom_status: the container may
    # have already written a root-owned status.json into this directory.
    try:
        if os.path.exists(status_path):
            os.remove(status_path)
    except OSError:
        pass
    with open(status_path, "w") as f:
        json.dump(status_payload, f, indent=2)
    try:
        os.chmod(status_path, 0o644)
    except OSError:
        pass
    print(f"Image status written to {status_path}: {output_blob_url}")


def _upload_image_output(fetch_data, output_dir, container_base_url, urls):
    """Encrypt the redacted image and store it back to the output container,
    then write the status contract. Only the redacted image is uploaded — a
    temp_dir misconfiguration writing the unredacted source into output_dir is
    rejected earlier, in fetch_data._validate_and_normalize_image_config(),
    not tolerated here by picking "the other file".

    When the bundle carried a per-run output key (see decrypt_bundle_tee /
    _get_output_crypto), the image is encrypted into the SPIDROU1 container
    with write_output_container() so the browser can decrypt and render it
    directly. Older UIs that don't send that key fall back to the previous
    behaviour: Fernet with the same dataset key used for input decryption.
    """
    if not os.path.exists(output_dir):
        raise FileNotFoundError(f"Output directory not found: {output_dir}")

    image_files = _find_image_outputs(output_dir)
    if len(image_files) != 1:
        raise FileNotFoundError(
            f"Expected exactly one redacted image in {output_dir}, found "
            f"{len(image_files)}: {[os.path.basename(p) for p in image_files]}."
        )
    src_path = image_files[0]
    plaintext_bytes = os.path.getsize(src_path)

    output_crypto = _get_output_crypto()
    upload_name = os.path.basename(src_path) + ".enc"
    upload_src = f"/tmp/{upload_name}"

    if output_crypto is not None:
        ext = os.path.splitext(src_path)[1].lower()
        content_type = _IMAGE_CONTENT_TYPES.get(ext, "application/octet-stream")
        with open(upload_src, "wb") as f:
            write_output_container(
                src_path, f,
                run_id=output_crypto["run_id"],
                output_key=output_crypto["key"],
                output_base_iv=output_crypto["base_iv"],
                filename=os.path.basename(src_path),
                content_type=content_type,
            )
    else:
        print("Fetching encryption key from Key Vault...")
        fernet_key = fetch_data.fetch_fernet_key_from_kv(urls["keyVaultUrl"])
        cipher = create_fernet_cipher(fernet_key)

        with open(src_path, "rb") as f:
            encrypted_data = cipher.encrypt(f.read())
        with open(upload_src, "wb") as f:
            f.write(encrypted_data)

    blob_url = f"{container_base_url}/{upload_name}"
    print(f"Uploading {upload_name} to {blob_url}...")
    fetch_data.upload_blob(blob_url, upload_src)
    os.remove(upload_src)

    run_config = {}
    try:
        with open(os.path.join(config.paths.tee_input_config, "pipeline_config.json")) as f:
            run_config = json.load(f)
    except (OSError, ValueError):
        pass

    manifest = _read_image_manifest(output_dir)
    _write_image_status(blob_url, os.path.basename(src_path), plaintext_bytes, run_config, manifest)
    print("Image output stored to blob; status written")
    return blob_url


def encrypt_and_upload_output(config_path="DPconfig.json"):
    """Encrypt all files in output folder and upload to Azure Blob Storage.

    Returns the primary output blob URL so the deploy script can hand it to the
    scheduler's completion callback — without it the user's job completes but
    their result has no address.
    """
    fetch_data = _get_fetch_data()
    output_dir = config.paths.tee_output
    urls_path = Path(config.get_path('decrypted_urls'))

    if not urls_path.exists():
        raise FileNotFoundError(
            f"decrypted_urls.json not found at {urls_path}. "
            "Cannot determine upload location without decrypted URLs."
        )

    with open(urls_path, "r") as f:
        urls = json.load(f)

    if "keyVaultUrl" not in urls:
        raise ValueError("keyVaultUrl not found in decrypted_urls.json")

    keyvault_url = urls["keyVaultUrl"]

    if "outputContainerUrl" not in urls:
        raise ValueError("outputContainerUrl not found in decrypted_urls.json")

    container_base_url = urls["outputContainerUrl"].rstrip("/")

    # Direct-upload mode short-circuits ALL format-based branching below: the
    # output must go through the browser-held output key regardless of
    # whether the underlying dataset was csv/json/excel/dicom, so this check
    # must come BEFORE the dicom-format check — a direct-mode DICOM run would
    # otherwise be wrongly routed into the SAS/plaintext DICOM path instead.
    if urls.get("outputContainerUrl", "") == "enclave://download":
        return _upload_direct_output(output_dir, urls)

    # DICOM (SKALD-DICOM) output takes a separate path: unencrypted upload +
    # SAS + status contract. The tabular flow below is unchanged.
    output_format = fetch_data.read_output_format()
    if output_format == "dicom":
        return _upload_dicom_output(fetch_data, output_dir, container_base_url, urls)

    # skald-image output: single redacted image, Fernet-encrypted with the
    # same dataset key used for input, uploaded to the output container with
    # its own status contract (outputs.image).
    if output_format == "image":
        return _upload_image_output(fetch_data, output_dir, container_base_url, urls)

    print("Fetching encryption key from Key Vault...")
    fernet_key = fetch_data.fetch_fernet_key_from_kv(keyvault_url)
    cipher = create_fernet_cipher(fernet_key)
    
    if not os.path.exists(output_dir):
        raise FileNotFoundError(f"Output directory not found: {output_dir}")
    
    # skald-fta's staged CSV and detection audit share this directory with
    # SKALD's result because that mount IS the handoff between the two stages.
    # They are intermediates: the staged CSV has had free text masked but never
    # went through k-anonymisation, so uploading it would ship every
    # quasi-identifier the run exists to treat. See free_text_artifact_names().
    # The k-means plots are uploaded separately below, each in its own
    # SPIDROU1 container under a fresh IV (see _upload_kmeans_plots) — they
    # must not also go through this loop's shared-Fernet-key path.
    excluded = _KNOWN_KEY_MATERIAL | free_text_artifact_names() | set(_KMEANS_PLOT_FILES)
    output_files = [
        os.path.join(output_dir, f)
        for f in os.listdir(output_dir)
        if os.path.isfile(os.path.join(output_dir, f)) and f not in excluded
    ]

    if not output_files:
        raise FileNotFoundError(f"No files found in output directory: {output_dir}")
    
    print(f"Found {len(output_files)} file(s) to encrypt and upload")

    # A tabular run can emit several files; the first is reported to the
    # scheduler as the job's address. The rest sit beside it in the same
    # container, which is how this flow has always worked.
    primary_blob_url = None

    # Upload each encrypted file
    for output_file in output_files:
        print(f"Encrypting {output_file}...")
        with open(output_file, 'rb') as f:
            plaintext = f.read()
        
        encrypted_data = cipher.encrypt(plaintext)
        
        encrypted_filename = os.path.basename(output_file) + '.enc'
        temp_encrypted = f"/tmp/{encrypted_filename}"
        with open(temp_encrypted, 'wb') as f:
            f.write(encrypted_data)
        
        upload_blob_url = f"{container_base_url}/{encrypted_filename}"
        print(f"Uploading to blob storage: {upload_blob_url}...")
        
        try:
            fetch_data.upload_blob(upload_blob_url, temp_encrypted)
            print(f"Successfully uploaded {encrypted_filename}")
        except Exception as e:
            print(f"Failed to upload {encrypted_filename}: {e}")
            raise

        if primary_blob_url is None:
            primary_blob_url = upload_blob_url

        os.remove(temp_encrypted)

    _upload_kmeans_plots(fetch_data, output_dir, container_base_url)

    print("Output encryption and upload complete")
    return primary_blob_url


def get_app_status():
    """Read status.json and return to UI
    
    Returns:
        dict: Status response with one of:
            - {"status": "processing", "message": "..."} if status.json doesn't exist yet
            - status.json content as-is on success/error (app controls structure)
    """
    status_file = config.get_path('status')
    
    if not os.path.exists(status_file):
        return {
            "status": "processing",
            "message": "Application is still running. Status will be available once processing completes."
        }
    
    try:
        with open(status_file, 'r', encoding='utf-8') as f:
            status_data = json.load(f)
        return status_data
    except json.JSONDecodeError as e:
        return {
            "status": "error",
            "error": {
                "code": "JSON_PARSE_ERROR",
                "message": "Failed to parse status.json",
                "details": str(e)
            }
        }
    except Exception as e:
        return {
            "status": "error",
            "error": {
                "code": "UNEXPECTED_ERROR",
                "message": "Unexpected error reading status",
                "details": str(e)
            }
        }


def restart_enclave_manager():
    """Gracefully reload the enclave manager systemd service.

    Uses `systemctl reload` (gunicorn SIGHUP) instead of `restart` so the
    listening socket stays bound while the worker respawns with fresh state -
    a plain restart briefly drops the socket and nginx returns 502 to any
    client polling status during that window.
    """
    print("Reloading enclavemanager service...", flush=True)
    result = subprocess.run(
        ["sudo", "systemctl", "reload", config.service.name],
        capture_output=True,
        text=True
    )
    if result.returncode == 0:
        print("enclavemanager service reloaded successfully", flush=True)
        # Give the new worker a moment to finish booting
        time.sleep(2)
    else:
        print(f"Warning: Failed to reload enclavemanager service: {result.stderr}", flush=True)
