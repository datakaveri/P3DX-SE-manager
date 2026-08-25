from flask import Flask, jsonify, Response, request
from flask_cors import CORS
from werkzeug.exceptions import HTTPException
import subprocess
import os
import json
import time
import logging
import traceback
import threading
import P3DX_SDK
from lib.config import config
from lib import immudb_client
from lib import direct_upload
from enclave.enclave_direct_upload import UploadError, MAX_CHUNK_BYTES


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

        # Direct-upload ownership check. This is the ONLY point in the whole
        # deploy flow where the bundle-uploader's X-User-Sub (available on
        # this request) and the UploadManager singleton (which holds the
        # /init session's user_sub, in this process's memory only) are both
        # available at once. deploy_enclave.py, which later decrypts and
        # actually uses this bundle, runs as a separate subprocess with no
        # access to that in-memory state — if the check does not happen here,
        # it can never happen at all, and a forged dataset_ref would go
        # unchecked all the way to step 9.
        try:
            dataset_ref = _peek_bundle_blob_url(content)
        except Exception as e:
            return jsonify({
                "title": "Error",
                "description": f"Could not read bundle payload: {e}"
            }), 400

        if dataset_ref and dataset_ref.startswith("enclave://upload/"):
            sub = _caller_user_sub()
            if not sub:
                return jsonify({
                    "title": "Error",
                    "description": "Missing authenticated caller identity"
                }), 401
            try:
                direct_upload.stage_for_pipeline(sub, dataset_ref)
            except UploadError as e:
                return jsonify({"title": "Error", "description": e.description}), e.status

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
    
    if state["step"] == 11:
        is_app_running = False
        print("Deployment completed, resetting is_app_running flag")
    
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


# ---------------------------------------------------------------------------
# Direct dataset upload (chunked, browser-encrypted; see
# backend-changes-direct-upload.md and enclave/enclave_direct_upload.py)
# ---------------------------------------------------------------------------

def _caller_user_sub():
    """The caller's JWT `sub`, decoded by the middleware and forwarded as
    X-User-Sub. Trusted as-is, with no independent verification here — that is
    a deliberate, narrow trust boundary, not an oversight:

    - The middleware ALWAYS overwrites any client-supplied X-User-Sub with the
      value it decoded from the caller's verified Bearer JWT; a client cannot
      set or spoof it.
    - This host is network-restricted to only accept traffic from the
      middleware, so an arbitrary caller cannot reach this endpoint directly
      to forge the header in the first place.
    - Missing/unauthenticated requests get a 401 at the middleware, before
      anything is forwarded — so a genuinely missing header here indicates the
      network restriction has failed or is being tested around, not a normal
      client error. Treat it as unauthenticated rather than falling back to a
      shared "anonymous" identity, which would silently break the per-user
      session isolation (MAX_CONCURRENT_SESSIONS_PER_USER) this whole feature
      depends on.

    If the network-restriction assumption ever changes, the fix is mTLS with
    identity derived from the client certificate, not a header — see
    backend-changes-direct-upload.md.
    """
    return request.headers.get("X-User-Sub", "")


def _upload_error_response(exc):
    return jsonify({"title": "Error", "description": exc.description}), exc.status


def _require_user_sub():
    sub = _caller_user_sub()
    if not sub:
        raise UploadError(401, "Missing authenticated caller identity")
    return sub


@app.route("/enclave/upload/init", methods=["POST"])
def upload_init():
    try:
        sub = _require_user_sub()
        manager = direct_upload.get_manager()
        body = request.get_json(silent=True)
        if body is None:
            raise UploadError(400, "Request body must be JSON")
        result = manager.init(sub, body)
        return jsonify(result), 201
    except UploadError as e:
        return _upload_error_response(e)
    except (KeyError, ValueError, TypeError) as e:
        return jsonify({"title": "Error", "description": f"Malformed request: {e}"}), 400


def _expected_chunk_ciphertext_bytes(manager, sub, upload_id, index):
    """
    Look up how many ciphertext bytes this chunk SHOULD be, from the session
    the caller already established at /init — chunk_size for every chunk
    but the last, (total_bytes - index*chunk_size) for the last, plus the
    16-byte GCM tag. Knowing this lets the streaming read path preallocate
    exactly, like the Content-Length path does, instead of growing a
    bytearray to EOF.

    Returns None if the session is unknown, owned by someone else, already
    completed, or the index is out of range — in every one of those cases
    _read_chunk_body() falls back to its bounded-growth path, and
    manager.put_chunk() below still performs the real ownership/validity
    check and raises the correct (identical, non-oracle) error. This lookup
    must never become a way to learn something about a session before that
    real check runs.
    """
    session = manager._sessions.get(upload_id)  # noqa: SLF001 -- see stage_for_pipeline() for why
    if session is None or session.user_sub != sub or session.completed:
        return None
    if not 0 <= index < session.total_chunks:
        return None
    plaintext_len = (
        session.chunk_size if index < session.total_chunks - 1
        else session.total_bytes - index * session.chunk_size
    )
    return plaintext_len + 16  # AES-GCM tag


def _read_chunk_body(expected_bytes=None):
    """
    Read the chunk PUT body, handling both wire encodings a real client can
    use — and real chunked-uploader traffic here is ALWAYS the second one:

    - Content-Length present (e.g. a client that buffers and computes the
      length up front): preallocate a single exact-size buffer and read
      into it directly.
    - Content-Length absent, Transfer-Encoding: chunked: the length is
      genuinely unknown from the HTTP layer alone — that is what chunked
      encoding means, not a missing header to reject. But the session
      already knows how big this specific chunk should be (see
      _expected_chunk_ciphertext_bytes), so we preallocate against THAT
      instead of growing a bytearray to EOF. This matters because
      AESGCM.decrypt already holds ciphertext + plaintext simultaneously —
      ~128 MiB at a 64 MiB chunk, the documented AEAD floor. A doubling
      bytearray on top of that would add a further transient 1.5-2x of the
      ciphertext: the one place this handler could exceed the design doc's
      memory budget without it being obvious.
    - Only when the expected size genuinely can't be determined (unknown or
      foreign upload_id) does this fall back to growing a bounded buffer to
      EOF — manager.put_chunk() still performs the real ownership check
      immediately afterward and raises the correct error either way.

    In every case the total is bounded by MAX_CHUNK_BYTES.
    """
    stream = request.stream
    content_length = request.content_length

    if content_length:
        if content_length > MAX_CHUNK_BYTES:
            raise UploadError(413, "Chunk exceeds the negotiated chunk size")
        buf = bytearray(content_length)
        view = memoryview(buf)
        read_total = 0
        while read_total < content_length:
            piece = stream.read(min(65536, content_length - read_total))
            if not piece:
                break
            n = len(piece)
            view[read_total:read_total + n] = piece
            read_total += n
        if read_total != content_length:
            raise UploadError(400, "Chunk body shorter than declared Content-Length")
        return bytes(buf)

    if expected_bytes is not None and 0 < expected_bytes <= MAX_CHUNK_BYTES:
        buf = bytearray(expected_bytes)
        view = memoryview(buf)
        read_total = 0
        while read_total < expected_bytes:
            piece = stream.read(min(65536, expected_bytes - read_total))
            if not piece:
                break
            n = len(piece)
            view[read_total:read_total + n] = piece
            read_total += n
        if read_total != expected_bytes:
            raise UploadError(400, "Chunk body shorter than expected for this session")
        # Confirm nothing more is still arriving — a single extra byte read
        # means the sender is putting more than this chunk should contain.
        if stream.read(1):
            raise UploadError(413, "Chunk exceeds the negotiated chunk size")
        return bytes(buf)

    buf = bytearray()
    while True:
        piece = stream.read(65536)
        if not piece:
            break
        buf.extend(piece)
        if len(buf) > MAX_CHUNK_BYTES:
            raise UploadError(413, "Chunk exceeds the negotiated chunk size")
    if not buf:
        raise UploadError(400, "Empty chunk body")
    return bytes(buf)


@app.route("/enclave/upload/<upload_id>/chunk/<int:index>", methods=["PUT"])
def upload_chunk(upload_id, index):
    try:
        sub = _require_user_sub()
        manager = direct_upload.get_manager()

        expected_bytes = _expected_chunk_ciphertext_bytes(manager, sub, upload_id, index)
        body = _read_chunk_body(expected_bytes)
        digest = request.headers.get("X-Chunk-SHA256", "")
        result = manager.put_chunk(sub, upload_id, index, body, digest)
        return jsonify(result), 200
    except UploadError as e:
        return _upload_error_response(e)
    except (KeyError, ValueError, TypeError) as e:
        return jsonify({"title": "Error", "description": f"Malformed request: {e}"}), 400


@app.route("/enclave/upload/<upload_id>/status", methods=["GET"])
def upload_status(upload_id):
    try:
        sub = _require_user_sub()
        manager = direct_upload.get_manager()
        return jsonify(manager.status(sub, upload_id)), 200
    except UploadError as e:
        return _upload_error_response(e)


@app.route("/enclave/upload/<upload_id>/complete", methods=["POST"])
def upload_complete(upload_id):
    try:
        sub = _require_user_sub()
        manager = direct_upload.get_manager()
        body = request.get_json(silent=True)
        if body is None:
            raise UploadError(400, "Request body must be JSON")
        result = manager.complete(sub, upload_id, str(body.get("plaintext_sha256", "")))
        return jsonify(result), 200
    except UploadError as e:
        return _upload_error_response(e)
    except (KeyError, ValueError, TypeError) as e:
        return jsonify({"title": "Error", "description": f"Malformed request: {e}"}), 400


@app.route("/enclave/upload/<upload_id>", methods=["DELETE"])
def upload_delete(upload_id):
    try:
        sub = _require_user_sub()
        manager = direct_upload.get_manager()
        manager.delete(sub, upload_id)
        return jsonify({"title": "ok", "description": "deleted"}), 200
    except UploadError as e:
        return _upload_error_response(e)


def _peek_bundle_blob_url(content):
    """
    Decrypt just the blobUrl field of an uploaded bundle, without touching
    encryptedFiles/config and without writing anything to disk. Used only to
    detect the enclave://upload/ sentinel early enough to run the ownership
    check in upload_encrypted_bundle() before the bundle is even saved.

    Reuses the same decrypt_rsa_wrapped_key / decrypt_fernet_token functions
    Bundle/decryption.py already uses for the full bundle decrypt later — in
    particular the same (deliberately spec-swapped) Fernet key-half ordering,
    so this agrees with the real decrypt rather than risking a second,
    subtly-different implementation of the same non-standard scheme.

    Returns None if the bundle has no encryptedUrls.blobUrl to peek at.
    """
    bundle = content.get('bundle', content) if isinstance(content, dict) else {}
    payload = bundle.get('payload', {}) if isinstance(bundle, dict) else {}
    wrapped_key = payload.get('wrappedKey')
    blob_token = payload.get('encryptedUrls', {}).get('blobUrl')
    if not wrapped_key or not blob_token:
        return None
    from decryption import decrypt_rsa_wrapped_key, decrypt_fernet_token
    private_key_path = config.get_path('private_key')
    fernet_key = decrypt_rsa_wrapped_key(wrapped_key, private_key_path)
    return decrypt_fernet_token(blob_token, fernet_key).decode('utf-8')


def _require_loopback():
    """
    Restrict a route to callers on this same host. Used only for the
    finalize-output handoff from the deploy_enclave.py subprocess below — it
    is not part of the public API surface middleware proxies, and the caller
    has no X-User-Sub to check (the subprocess has no per-request user
    identity, same as the existing /enclave/setstate and /enclave/bundle GET
    routes it calls today).

    This assumes requests to this port either originate on this host or
    arrive through a local reverse proxy that preserves the real client
    address — if that assumption doesn't hold on the actual deployment
    topology, this check alone is not sufficient. The path-containment check
    in direct_upload.finalize_output() is the load-bearing defense regardless
    of how this route is reached.
    """
    if request.remote_addr not in ("127.0.0.1", "::1"):
        raise UploadError(403, "This endpoint is host-internal only")


@app.route("/internal/upload/<upload_id>/finalize-output", methods=["POST"])
def upload_finalize_output(upload_id):
    """
    Called by deploy_enclave.py (or the /run/*_pipeline background thread)
    once the pipeline has produced its result, so THIS process — the only one
    holding the browser's output_key in memory — can encrypt it into the
    SPIDROU1 container and upload it. The caller never receives the key
    itself, only this completion signal; see backend-changes-direct-upload.md
    §2.6 on why the key must never cross the process boundary.
    """
    try:
        _require_loopback()
        body = request.get_json(silent=True) or {}
        result = direct_upload.finalize_output(
            upload_id,
            output_path=str(body.get("output_path", "")),
            filename=str(body.get("filename", "output")),
            content_type=str(body.get("content_type", "application/octet-stream")),
            manifest=body.get("manifest"),
        )
        return jsonify(result), 200
    except UploadError as e:
        return _upload_error_response(e)
    except (KeyError, ValueError, TypeError, OSError) as e:
        return jsonify({"title": "Error", "description": f"finalize-output failed: {e}"}), 400


# ---------------------------------------------------------------------------
# Pipeline helpers
# ---------------------------------------------------------------------------

def _run_pipeline_background(job_id: str, username: str, blob_url: str,
                              technique: str, run_config: dict,
                              session_id: str, started_at: str):
    """
    Background thread: execute the anonymisation pipeline, then write the
    completed/failed row to immuDB.

    Execution steps mirror deploy_enclave.py steps 9-11:
      1. Fetch & decrypt data from blob_url
      2. Write run_config as SKALD config, run Docker containers
      3. Encrypt & upload output
    """
    t0 = time.time()
    try:
        config_file_path = config.get_path('config_file')
        with open(config_file_path, 'r') as f:
            dp_config = json.load(f)

        # Merge caller-supplied run_config into the on-disk config so SKALD
        # picks up technique-specific parameters (k, epsilon, chunk_size, …)
        dp_config.update(run_config or {})
        dp_config["technique"] = technique
        # DICOM re-runs ignore SKALD technique fields; mark the format/operation
        # so the fetch/upload path uses the .dcm + SAS flow.
        if technique == "dicom_deidentify":
            dp_config["format"] = "dicom"
            dp_config.setdefault("operations", ["dicom_deidentify"])
        with open(config_file_path, 'w') as f:
            json.dump(dp_config, f, indent=2)

        P3DX_SDK.fetch_and_decrypt_data(config_file_path)
        P3DX_SDK.run_docker_containers()
        P3DX_SDK.encrypt_and_upload_output(config_file_path)

        # Derive output blob URL from the decrypted URLs written during fetch
        import pathlib
        urls_path = pathlib.Path(config.get_path('decrypted_urls'))
        output_blob_url = ""
        if urls_path.exists():
            with open(urls_path) as f:
                urls = json.load(f)
            container = urls.get("outputContainerUrl", "").rstrip("/")
            output_blob_url = f"{container}/pipeline.log.enc" if container else ""

        duration_ms = int((time.time() - t0) * 1000)
        immudb_client.write_run_complete(
            job_id=job_id,
            username=username,
            blob_url=blob_url,
            technique=technique,
            run_config=run_config,
            session_id=session_id,
            started_at=started_at,
            output_blob_url=output_blob_url,
            duration_ms=duration_ms,
        )
        print(f"Pipeline {technique} job {job_id} completed in {duration_ms}ms")

    except Exception as exc:
        duration_ms = int((time.time() - t0) * 1000)
        print(f"Pipeline {technique} job {job_id} failed after {duration_ms}ms: {exc}")
        traceback.print_exc()
        immudb_client.write_run_fail(
            job_id=job_id,
            username=username,
            blob_url=blob_url,
            technique=technique,
            run_config=run_config,
            session_id=session_id,
            started_at=started_at,
            error_message=str(exc),
        )


def _start_pipeline(technique: str):
    """
    Common handler for all three pipeline endpoints.
    Validates the request, writes the 'running' immuDB row, spawns the
    background thread, and returns {run_id, status} immediately.
    """
    content = request.get_json(silent=True) or {}

    blob_url   = content.get("blob_url")
    username   = content.get("username", "")
    run_config = content.get("run_config", {})
    session_id = content.get("session_id", "")

    if not blob_url:
        return jsonify({"title": "Error", "description": "blob_url is required"}), 400

    from datetime import datetime, timezone
    started_at = datetime.now(timezone.utc).isoformat()

    job_id = immudb_client.write_run_start(
        username=username,
        blob_url=blob_url,
        technique=technique,
        run_config=run_config,
        session_id=session_id,
    )

    thread = threading.Thread(
        target=_run_pipeline_background,
        args=(job_id, username, blob_url, technique, run_config,
              session_id, started_at),
        daemon=True,
    )
    thread.start()

    return jsonify({
        "title":   "Started",
        "run_id":  job_id,
        "status":  "running",
        "technique": technique,
    }), 202


# ---------------------------------------------------------------------------
# Pipeline endpoints
# ---------------------------------------------------------------------------

@app.route("/run/k_anon_pipeline", methods=["POST"])
def run_k_anon_pipeline():
    return _start_pipeline("k_anonymisation")


@app.route("/run/dp_pipeline", methods=["POST"])
def run_dp_pipeline():
    return _start_pipeline("differential_privacy")


@app.route("/run/chunkanon_pipeline", methods=["POST"])
def run_chunkanon_pipeline():
    return _start_pipeline("chunk_anonymisation")


@app.route("/run/dicom_pipeline", methods=["POST"])
def run_dicom_pipeline():
    return _start_pipeline("dicom_deidentify")


# ---------------------------------------------------------------------------
# Run status endpoint (called by LLM VM to build chat context)
# ---------------------------------------------------------------------------

@app.route("/run/status", methods=["GET"])
def get_run_status():
    """
    GET /run/status?blob_url=<url>&username=<user>

    Queries run_history for the latest row matching blob_url (and optionally
    username) and returns it so the LLM VM can join session context.
    """
    blob_url = request.args.get("blob_url")
    username = request.args.get("username")

    if not blob_url:
        return jsonify({"title": "Error", "description": "blob_url query param required"}), 400

    record = immudb_client.get_latest_run(blob_url=blob_url, username=username or None)
    if record is None:
        return jsonify({"title": "Not Found", "description": "No run found for given blob_url"}), 404

    return jsonify(record), 200


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
    print("  - GET  /enclave/jwt")
    print("  - GET  /enclave/state")
    print("  - POST /enclave/setstate")
    print("  - GET  /enclave/inference")
    print("  - GET  /enclave/status")
    print("  - POST /enclave/upload/init")
    print("  - PUT  /enclave/upload/<id>/chunk/<index>")
    print("  - GET  /enclave/upload/<id>/status")
    print("  - POST /enclave/upload/<id>/complete")
    print("  - DELETE /enclave/upload/<id>")
    print("  - POST /internal/upload/<id>/finalize-output (host-internal only)")
    print("  - POST /run/k_anon_pipeline")
    print("  - POST /run/dp_pipeline")
    print("  - POST /run/chunkanon_pipeline")
    print("  - POST /run/dicom_pipeline")
    print("  - GET  /run/status")
    print("=" * 60)
    app.run(host=config.service.host, port=config.service.port, debug=True)
