from flask import Flask, jsonify, Response, request, send_file
from flask_cors import CORS
from werkzeug.exceptions import HTTPException
import subprocess
import os
import json
import re
import shlex
import time
import logging
import traceback
from urllib.parse import urlparse
import P3DX_SDK
from lib.config import config


app = Flask(__name__)

# Enable CORS for all routes with configuration from config.yml
CORS(app, 
     resources={
         r"/*": {
             "origins": config.cors.origins,
             "methods": config.cors.methods,
             "allow_headers": config.cors.allow_headers,
             "expose_headers": config.cors.expose_headers,
             "supports_credentials": config.cors.supports_credentials,
             "max_age": config.cors.max_age
         }
     },
     supports_credentials=True)


# Default state when application is not running
state = {
    "step": 0,
    "maxSteps": 11,
    "title": "Inactive",
    "description": "Inactive",
}


# Flag to track if application is running
is_app_running = False



# Removed after_request handler - flask-cors already handles CORS headers
# Adding duplicate headers causes "multiple values" error



# DEPLOY: Deploys the TEE enclave
@app.route("/enclave/deploy", methods=["POST"])
def deploy_enclave():
    jwt_file_path = config.get_path('jwt_response')
    subprocess.run(["sudo", "rm", "-rf", jwt_file_path], check=False, capture_output=True)
    
    print("STARTING deploy")
    global is_app_running, stored_bundle
    
    if is_app_running:
        print("Previous deployment detected. Restarting service to reset state...")
        try:
            P3DX_SDK.restart_enclave_manager()

            time.sleep(3)
            is_app_running = False
            stored_bundle = None
        except Exception as e:
            print(f"Warning: Failed to restart service: {str(e)}")
            response = {
                "title": "Error",
                "description": f"Previous deployment detected but failed to restart service: {str(e)}"
            }
            return jsonify(response), 500
    
    stored_bundle = None

    global state
    state = {
        "step": 1,
        "maxSteps": 11,
        "title": "Spawning Trusted Execution Environment (TEE)",
        "description": "Step 1"
    }
    
    content = request.json if request.json else {}
    compose_url = content.get("compose_url")

    if not compose_url:
        return jsonify({
            "title": "Error",
            "description": "compose_url is required in request payload"
        }), 400

    try:
        cmd = f"python3 -u deploy_enclave.py {repr(compose_url)} 2>&1 | systemd-cat -t tee-deployment"
        subprocess.Popen(
            ["sudo", "sh", "-c", cmd],
            cwd=config.base_dir
        )
        
        is_app_running = True
        response = {
            "title": "Success",
            "description": "Application execution has started."
        }
        return jsonify(response), 200
        
    except Exception as e:
        response = {
            "title": "Error",
            "description": f"Failed to start application: {str(e)}"
        }
        return jsonify(response), 500



def _is_safe_blob_url(url):
    """Accept only absolute https URLs.

    The dataset and Key Vault URLs arrive over HTTP and are handed to the
    fetcher, which signs requests with this VM's managed identity. Requiring
    https keeps the identity's token off plaintext connections and rejects
    scheme tricks (file://, http://169.254.169.254/... aimed at IMDS itself).
    """
    try:
        u = urlparse(url)
    except ValueError:
        return False
    return u.scheme == "https" and bool(u.netloc)


# RUN: minimal anonymisation path — fetch data + key, decrypt, run SKALD.
# Unlike /enclave/deploy this needs no bundle from the UI and performs no
# attestation handshake; see run_anonymisation.py for the trade-off.
@app.route("/enclave/run", methods=["POST"])
def run_anonymisation():
    global is_app_running, state

    print("STARTING anonymisation run")

    if is_app_running:
        print("Previous run detected. Restarting service to reset state...")
        try:
            P3DX_SDK.restart_enclave_manager()
            time.sleep(3)
            is_app_running = False
        except Exception as e:
            return jsonify({
                "title": "Error",
                "description": f"Previous run detected but failed to restart service: {str(e)}"
            }), 500

    content = request.json if request.json else {}
    contract_id = content.get("contract_id", "")
    tee_id = content.get("tee_id", "")
    # Dataset location comes from the contract (datasetDetails.resourceUrl),
    # relayed by the governance layer. Falls back to config.demo when absent.
    dataset_url = content.get("dataset_url", "")
    keyvault_url = content.get("keyvault_url", "")

    if dataset_url and not _is_safe_blob_url(dataset_url):
        return jsonify({
            "title": "Error",
            "description": "dataset_url must be an https:// URL"
        }), 400
    if keyvault_url and not _is_safe_blob_url(keyvault_url):
        return jsonify({
            "title": "Error",
            "description": "keyvault_url must be an https:// URL"
        }), 400

    state = {
        "step": 1,
        "maxSteps": 6,
        "title": "Preparing TEE folders",
        "description": "Step 1"
    }

    try:
        # Logs stream to journalctl -t tee-anon, matching the deploy path's
        # systemd-cat convention. The run parameters originate in a request
        # body, so every one is shell-quoted before landing in `sh -c`.
        argv = ["python3", "-u", "run_anonymisation.py"]
        for flag, value in (("--dataset-url", dataset_url),
                            ("--keyvault-url", keyvault_url),
                            ("--contract-id", contract_id),
                            ("--tee-id", tee_id)):
            if value:
                argv += [flag, value]
        cmd = f"{shlex.join(argv)} 2>&1 | systemd-cat -t tee-anon"
        subprocess.Popen(["sudo", "sh", "-c", cmd], cwd=config.base_dir)

        is_app_running = True
        print(f"Anonymisation started (contract_id={contract_id!r} tee_id={tee_id!r})")
        return jsonify({
            "title": "Success",
            "description": "Anonymisation run has started.",
            "contract_id": contract_id,
            "tee_id": tee_id,
            "maxSteps": 6
        }), 200

    except Exception as e:
        return jsonify({
            "title": "Error",
            "description": f"Failed to start anonymisation: {str(e)}"
        }), 500


# Cap on how much file content is inlined into the JSON manifest. Larger files
# are listed with their size only and must be fetched individually via ?file=.
MAX_INLINE_OUTPUT_BYTES = 5 * 1024 * 1024

INLINE_OUTPUT_SUFFIXES = (".csv", ".json", ".txt", ".log", ".tsv", ".yaml", ".yml")

# SKALD writes the keys for its own encrypt/FPE operations into the output
# directory (symmetric_keys.json, fpe_encrypt_keys.json). Serving those next to
# the anonymised data would hand the consumer the means to reverse the very
# columns the config asked to be encrypted, so they are withheld here — both
# from the manifest and from ?file=. Suffix-matched rather than hardcoded so a
# future key file is withheld by default rather than leaking until noticed.
KEY_MATERIAL_SUFFIXES = ("_keys.json",)


def _is_key_material(name):
    """True if name looks like key material that must not leave the enclave."""
    return name.lower().endswith(KEY_MATERIAL_SUFFIXES)


def _readable_output_path(filename):
    """Resolve a filename inside the output dir, relaxing docker's root-owned perms.

    Returns the absolute path, or None if the name escapes the output directory.
    """
    output_dir = os.path.abspath(config.paths.tee_output)
    candidate = os.path.abspath(os.path.join(output_dir, filename))

    # Reject traversal: the resolved path must stay inside the output dir.
    if candidate != output_dir and not candidate.startswith(output_dir + os.sep):
        return None

    if os.path.exists(candidate):
        # SKALD writes as root inside the container; make it readable like
        # /enclave/inference already does for status.json.
        subprocess.run(["sudo", "chmod", "644", candidate], check=False, capture_output=True)

    return candidate


# OUTPUT: Returns the anonymised output produced by the run.
# Default: a JSON manifest with small text files inlined.
# ?file=<name>: that single file as a download.
@app.route("/enclave/output", methods=["GET"])
def get_output():
    output_dir = config.paths.tee_output
    print(f"Fetching anonymisation output from {output_dir}...")

    if not os.path.isdir(output_dir):
        return jsonify({
            "title": "Error: No output",
            "description": f"Output directory does not exist: {output_dir}"
        }), 404

    requested = request.args.get("file")
    if requested:
        if _is_key_material(os.path.basename(requested)):
            return jsonify({
                "title": "Error: Forbidden",
                "description": "Encryption key material is not served from the enclave."
            }), 403
        path = _readable_output_path(requested)
        if path is None:
            return jsonify({
                "title": "Error: Invalid file",
                "description": "file must name a file inside the output directory"
            }), 400
        if not os.path.isfile(path):
            return jsonify({
                "title": "Error: Not found",
                "description": f"No such output file: {requested}"
            }), 404
        return send_file(path, as_attachment=True,
                         download_name=os.path.basename(path))

    files = []
    withheld = []
    for name in sorted(os.listdir(output_dir)):
        if _is_key_material(name):
            withheld.append(name)
            continue
        path = _readable_output_path(name)
        if path is None or not os.path.isfile(path):
            continue

        size = os.path.getsize(path)
        entry = {"name": name, "size_bytes": size}

        inlineable = (name.lower().endswith(INLINE_OUTPUT_SUFFIXES)
                      and size <= MAX_INLINE_OUTPUT_BYTES)
        if inlineable:
            try:
                with open(path, "r", errors="replace") as f:
                    entry["content"] = f.read()
            except OSError as e:
                entry["error"] = f"could not read: {e}"
        else:
            entry["note"] = "fetch individually via ?file=" + name

        files.append(entry)

    if not files:
        return jsonify({
            "title": "Error: No output",
            "description": f"No output files found in {output_dir}. Has the run finished?",
            "step": state.get("step", 0),
            "maxSteps": state.get("maxSteps", 6)
        }), 404

    return jsonify({
        "title": "Success",
        "output_dir": output_dir,
        "file_count": len(files),
        "files": files,
        # Named but not served, so the caller knows they exist and are withheld
        # rather than silently missing.
        "withheld": withheld
    }), 200


stored_bundle = None

@app.route("/enclave/jwt", methods=["POST"])
def receive_jwt():
    try:
        content = request.json
        if not content or 'jwt' not in content:
            return jsonify({"error": "Missing jwt in request"}), 400
        return jsonify({"status": "success", "message": "JWT stored"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/enclave/jwt", methods=["GET"])
def get_jwt():
    print("Fetching JWT token...")
    jwt_file_path = config.get_path('jwt_response')
    
    if not os.path.exists(jwt_file_path):
        response = {
            "title": "Error: JWT not found",
            "description": "JWT token not available yet. Deployment in progress..."
        }
        return jsonify(response), 404
    
    try:
        result = subprocess.run(
            ['sudo', 'chmod', '644', jwt_file_path],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        with open(jwt_file_path, "r") as f:
            jwt_token = f.read().strip()
        
        if not jwt_token:
            response = {
                "title": "Error: Empty JWT",
                "description": "JWT token file is empty."
            }
            return jsonify(response), 404
        
        print(f"JWT token retrieved successfully (length: {len(jwt_token)})")
        
        response = {
            "title": "Success",
            "jwt": jwt_token
        }
        return jsonify(response), 200
        
    except subprocess.CalledProcessError as e:
        response = {
            "title": "Error: Permission denied",
            "description": f"Failed to set file permissions: {e.stderr.decode() if e.stderr else str(e)}"
        }
        return jsonify(response), 500
        
    except Exception as e:
        response = {
            "title": "Error reading JWT",
            "description": f"Failed to read JWT token: {str(e)}"
        }
        return jsonify(response), 500



# ATTEST: Produce an MAA attestation token bound to a caller-supplied nonce.
#
# Differs from GET /enclave/jwt/fresh, which mints its own nonce: here the
# governance layer supplies the challenge, so the token it gets back cannot be a
# replay of an earlier genuine attestation. The nonce reaches the hardware via
# AttestationClient -n and comes back as a signed claim.
@app.route("/enclave/attest", methods=["POST"])
def attest():
    content = request.json if request.json else {}
    nonce = str(content.get("nonce", "")).strip()

    if not nonce:
        return jsonify({
            "title": "Error",
            "description": "nonce is required"
        }), 400
    # AttestationClient takes the nonce as a CLI argument; keep it to an
    # unambiguous base64 alphabet so it can never be read as another flag.
    if len(nonce) > 128 or not re.fullmatch(r"[A-Za-z0-9+/=_-]+", nonce):
        return jsonify({
            "title": "Error",
            "description": "nonce must be <=128 chars of base64 ([A-Za-z0-9+/=_-])"
        }), 400

    print(f"Attesting with caller-supplied nonce (len={len(nonce)})...")

    jwt_file_path = config.get_path('jwt_response')
    keys_dir = config.paths.keys_dir
    original_cwd = os.getcwd()

    try:
        os.chdir(config.base_dir)
        os.makedirs(keys_dir, exist_ok=True)
        subprocess.run(["sudo", "chown", "-R", f"{config.user}:{config.user}", keys_dir],
                       check=False, capture_output=True)
        subprocess.run(["sudo", "chmod", "-R", "755", keys_dir],
                       check=False, capture_output=True)

        # A stale token must not be mistaken for a fresh one if attestation fails.
        if os.path.exists(jwt_file_path):
            subprocess.run(["sudo", "rm", "-f", jwt_file_path], check=False, capture_output=True)

        P3DX_SDK.save_nonce(nonce)
        try:
            P3DX_SDK.extend_nonce_to_pcr8(nonce)
        except Exception as e:
            # PCR 8 is not in MAA's attested PCR set (it reports 0-7), so the
            # nonce binding does not depend on this. Log and carry on.
            print(f"Note: PCR8 extension failed, not fatal for token binding: {e}")

        P3DX_SDK.execute_guest_attestation()

        subprocess.run(["sudo", "chown", f"{config.user}:{config.user}", jwt_file_path],
                       check=False, capture_output=True)
        subprocess.run(["sudo", "chmod", "644", jwt_file_path],
                       check=False, capture_output=True)

        with open(jwt_file_path, "r") as f:
            token = f.read().strip()

        if not token:
            return jsonify({
                "title": "Error",
                "description": "Attestation produced an empty token"
            }), 500

        print(f"Attestation token generated (length: {len(token)})")
        return jsonify({"title": "Success", "jwt": token, "nonce": nonce}), 200

    except RuntimeError as e:
        return jsonify({"title": "Error", "description": str(e)}), 500
    except Exception as e:
        print(f"Unexpected error during attestation: {e}")
        return jsonify({
            "title": "Error",
            "description": f"Attestation failed: {e}"
        }), 500
    finally:
        os.chdir(original_cwd)


# GET FRESH JWT: Returns a fresh JWT token
@app.route("/enclave/jwt/fresh", methods=["GET"])
def get_fresh_jwt():
    """Generate a fresh JWT token by deleting old JWT and executing guest attestation.
    
    Returns:
        JSON response with newly generated JWT token or error details.
    """
    print("Generating fresh JWT token...")
    
    jwt_file_path = config.get_path('jwt_response')
    private_key_path = config.get_path('private_key')
    public_key_path = config.get_path('public_key')
    keys_dir = config.paths.keys_dir
    
    original_cwd = os.getcwd()
    
    try:
        os.chdir(config.base_dir)
        os.makedirs(keys_dir, exist_ok=True)
        
        subprocess.run(
            ["sudo", "chown", "-R", f"{config.user}:{config.user}", keys_dir],
            check=False,
            capture_output=True
        )
        subprocess.run(
            ["sudo", "chmod", "-R", "755", keys_dir],
            check=False,
            capture_output=True
        )
        
        if os.path.exists(jwt_file_path):
            subprocess.run(
                ["sudo", "rm", "-rf", jwt_file_path],
                check=False,
                capture_output=True
            )
            print("Old JWT file deleted")
        
        if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
            print("Keys not found. Generating new key pair...")
            P3DX_SDK.generate_and_save_key_pair()
            print("Key pair generated successfully")

        try:
            # Measure enclave manager code 
            P3DX_SDK.measure_enclave_manager_code_vtpm()
            print("Enclave manager code hash measured successfully")
            
            # Measure Docker image
            # link = P3DX_SDK.extract_docker_image_from_compose()
            # P3DX_SDK.measureDockervTPM(link)
            # print("Application image hash measured successfully")
        except Exception as e:
            print(f"Warning: Failed to measure code/image: {str(e)}")
        
        # new nonce generated every time a fresh endpoint is hit
        print("Generating fresh deployment nonce...")
        nonce = P3DX_SDK.generate_nonce()                  
        P3DX_SDK.save_nonce(nonce)
        P3DX_SDK.extend_nonce_to_pcr8(nonce)
        print(f"Generated deployment nonce: {nonce}")

        print("Executing guest attestation to generate new JWT...")
        P3DX_SDK.execute_guest_attestation()
        
        subprocess.run(
            ["sudo", "chown", f"{config.user}:{config.user}", jwt_file_path],
            check=False,
            capture_output=True
        )
        subprocess.run(
            ['sudo', 'chmod', '644', jwt_file_path],
            check=False,
            capture_output=True
        )
        
        with open(jwt_file_path, "r") as f:
            jwt_token = f.read().strip()
        
        if not jwt_token:
            response = {
                "title": "Error: Empty JWT",
                "description": "JWT token file is empty after generation."
            }
            return jsonify(response), 500
        
        print(f"Fresh JWT token generated successfully (length: {len(jwt_token)})")
        
        response = {
            "title": "Success",
            "jwt": jwt_token
        }
        return jsonify(response), 200
        
    except RuntimeError as e:
        response = {
            "title": "Error: JWT generation failed",
            "description": str(e)
        }
        return jsonify(response), 500
        
    except Exception as e:
        print(f"Unexpected error generating JWT: {str(e)}")
        response = {
            "title": "Error: JWT generation failed",
            "description": f"Failed to generate JWT token: {str(e)}"
        }
        return jsonify(response), 500
        
    finally:
        os.chdir(original_cwd)

# GET BUNDLE: Returns the encrypted bundle for polling
@app.route("/enclave/bundle", methods=["GET"])
def get_bundle():
    global stored_bundle
    
    bundle_file = config.get_path('encrypted_bundle')
    if os.path.exists(bundle_file):
        try:
            with open(bundle_file, 'r') as f:
                stored_bundle = json.load(f)
        except Exception:
            pass
    
    if stored_bundle:
        return jsonify({"bundle": stored_bundle}), 200
    else:
        return jsonify({"error": "Bundle not found"}), 404


@app.route("/enclave/bundle/upload", methods=["POST"])
def upload_encrypted_bundle():
    print("Receiving encrypted bundle...")
    
    try:
        content = request.json
        
        if not content:
            response = {
                "title": "Error",
                "description": "No data received"
            }
            return jsonify(response), 400
        
        bundle_dir = config.paths.bundle_dir
        os.makedirs(bundle_dir, exist_ok=True)
        
        global stored_bundle
        stored_bundle = content
        
        output_file = config.get_path('encrypted_bundle')
        
        with open(output_file, 'w') as f:
            json.dump(content, f, indent=2)
        
        os.chmod(output_file, 0o644)
        
        print(f"Encrypted bundle saved to {output_file}")
        print(f"File size: {os.path.getsize(output_file)} bytes")
        
        response = {
            "title": "Success",
            "description": f"Encrypted bundle saved successfully",
            "file_path": output_file,
            "file_size": os.path.getsize(output_file)
        }
        return jsonify(response), 200
        
    except Exception as e:
        print(f"Error saving encrypted bundle: {str(e)}")
        response = {
            "title": "Error",
            "description": f"Failed to save encrypted bundle: {str(e)}"
        }
        return jsonify(response), 500



# INFERENCE: Returns the inference as a JSON object
@app.route("/enclave/inference", methods=["GET"])
def get_inference():
    print("Fetching inference...")
    logger = logging.getLogger()
    logging.debug('STARTING INFERENCE')
    
    global state
    
    if state["step"] != 5:
        response = {
            "title": "Error: App execution incomplete",
            "description": "No inference output found. Current step: " + str(state["step"])
        }
        return jsonify(response), 403


    output_file = config.get_path('status')
    
    if os.path.exists(output_file):
        try:
            result = subprocess.run(
                ['sudo', 'chmod', '644', output_file], 
                check=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE
            )
            
            if result.returncode == 0:
                print(f"Successfully set permissions on file: {output_file}")
            else:
                print(f"Failed to set permissions. Error: {result.stderr.decode()}")
                
        except subprocess.CalledProcessError as e:
            print(f"Error executing sudo chmod: {e.stderr.decode()}")
    else:
        print(f"File not found: {output_file}")


    if os.path.isfile(output_file):
        with open(output_file, "r") as f:
            content = f.read()
        
        print(f"Inference file read successfully (size: {len(content)} bytes)")
        
        response = app.response_class(
            response=content,
            mimetype="application/json"
        )
        return response
    else:
        response = {
            "title": "Error: No Inference Output",
            "description": "Inference file does not exist at " + output_file
        }
        return jsonify(response), 403



# SETSTATE: Sets the state of the enclave
@app.route("/enclave/setstate", methods=["POST"])
def setState():
    global state
    global is_app_running
    print("In /enclave/setstate...")
    
    content = request.json
    if not content or "state" not in content:
        return jsonify({"status": "error", "message": "Missing 'state' in request body"}), 400
    
    state = content["state"]
    
    print(f"State updated - Step {state['step']}/{state['maxSteps']}: {state['title']}")
    
    # Compare against the run's own maxSteps rather than a literal 11: the
    # minimal anonymisation path (run_anonymisation.py) finishes at step 6.
    if state["step"] >= state.get("maxSteps", 11):
        is_app_running = False
        print("Run completed, resetting is_app_running flag")
    
    response = app.response_class(
        response='{"status": "ok"}', 
        status=200, 
        mimetype="application/json"
    )
    return response



# STATE: Returns the current state of the enclave
@app.route("/enclave/state", methods=["GET"])
def get_state():
    global state
    response = {
        "step": state.get("step", 0),
        "maxSteps": state.get("maxSteps", 11),
        "title": state.get("title", "Inactive"),
        "description": state.get("description", "Inactive"),
    }
    print(f"State requested - Step {response['step']}/{response['maxSteps']}")
    return jsonify(response)


# STATUS: Returns application status
@app.route("/enclave/status", methods=["GET"])
def get_app_status_endpoint():
    """Poll endpoint for application status.
    
    Returns status.json content
    """
    print("Fetching application status...")
    
    try:
        status_response = P3DX_SDK.get_app_status()
        return jsonify(status_response), 200
            
    except Exception as e:
        print(f"Error fetching status: {str(e)}")
        return jsonify({
            "status": "error",
            "error": {
                "code": "ENDPOINT_ERROR",
                "message": "Failed to fetch status",
                "details": str(e)
            }
        }), 500


# Error handler for critical errors that require service restart
@app.errorhandler(Exception)
def handle_critical_error(e):
    """Handle critical errors by restarting the service.
    
    Excludes:
    - HTTP exceptions (404, 400, etc.) - normal routing errors
    - PermissionError - file permission issues, should be handled in routes
    - OSError/IOError - file system errors, usually recoverable
    
    Only actual application crashes and unhandled exceptions trigger service restart.
    """
    # Skip HTTP exceptions - these are normal routing errors, not critical failures
    if isinstance(e, HTTPException):
        # Return proper JSON response with CORS headers for HTTP errors
        response = jsonify({
            "title": "Error",
            "description": f"{e.code} {e.name}: {e.description}"
        })
        response.status_code = e.code
        return response
    
    # Skip file permission and I/O errors - these are recoverable and should be handled in routes
    if isinstance(e, (PermissionError, OSError, IOError)):
        print(f"File system error (non-critical): {str(e)}")
        traceback.print_exc()
        response = jsonify({
            "title": "Error",
            "description": f"File system error: {str(e)}. Please check file permissions and try again."
        })
        response.status_code = 500
        return response
    
    # Only handle actual critical errors (unhandled exceptions, crashes, etc.)
    print(f"Critical error in manager: {str(e)}")
    traceback.print_exc()
    
    # Restart service on critical errors only
    # Use a flag to prevent infinite restart loops
    restart_attempted = False
    try:
        P3DX_SDK.restart_enclave_manager()
        restart_attempted = True
        print("Service restart initiated successfully")
    except Exception as restart_error:
        error_msg = str(restart_error) if restart_error else "Unknown error"
        print(f"Failed to restart service: {error_msg}")
    
    response = jsonify({
        "title": "Error",
        "description": f"Critical error occurred. {'Service restarting' if restart_attempted else 'Service restart failed'}: {str(e)}"
    })
    response.status_code = 500
    return response


if __name__ == "__main__":
    print("=" * 60)
    print("Starting Enclave Manager")
    print(f"Port: {config.service.port}")
    print("Endpoints available:")
    print("  - POST /enclave/deploy")
    print("  - POST /enclave/run")
    print("  - POST /enclave/attest")
    print("  - GET  /enclave/output")
    print("  - GET  /enclave/jwt")
    print("  - GET  /enclave/state")
    print("  - POST /enclave/setstate")
    print("  - GET  /enclave/inference")
    print("  - GET  /enclave/status")
    print("=" * 60)
    app.run(host=config.service.host, port=config.service.port, debug=True)
