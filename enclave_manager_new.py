from flask import Flask, jsonify, Response, request
from flask_cors import CORS
from werkzeug.exceptions import HTTPException
import subprocess
import os
import json
import time
import logging
import PPDX_SKALD


app = Flask(__name__)

# Enable CORS for all routes with proper configuration
# Remove trailing slashes from origins - CORS matching is strict
CORS(app, 
     resources={
         r"/*": {
             "origins": [
                 "http://localhost:5173",
                 "http://localhost:3000", 
                 "https://spider.p3dx.iudx.org.in"
             ],
             "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
             "allow_headers": ["Content-Type", "Authorization", "X-Requested-With"],
             "expose_headers": ["Content-Type", "Authorization"],
             "supports_credentials": True,
             "max_age": 3600
         }
     },
     supports_credentials=True)


# Default state when application is not running
state = {
    "step": 0,
    "maxSteps": 5,
    "title": "Inactive",
    "description": "Inactive",
}


# Flag to track if application is running
is_app_running = False



# Removed after_request handler - flask-cors already handles CORS headers
# Adding duplicate headers causes "multiple values" error



# DEPLOY: Deploys the SKALD enclave (ACTUAL IMPLEMENTATION)
@app.route("/enclave/deploy", methods=["POST"])
def deploy_enclave():
    jwt_file_path = "/home/kanonTEE/P3DX-SE-manager/keys/jwt-response.txt"
    subprocess.run(["sudo", "rm", "-rf", jwt_file_path], check=False, capture_output=True)
    
    print("STARTING deploy")
    global is_app_running, stored_bundle
    
    if is_app_running:
        print("Previous deployment detected. Restarting service to reset state...")
        try:
            PPDX_SKALD.restart_enclave_manager()

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
        "maxSteps": 5,
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
        cmd = f"python3 -u deploy_enclaveSKALD.py {repr(compose_url)} 2>&1 | systemd-cat -t skald-deployment"
        subprocess.Popen(
            ["sudo", "sh", "-c", cmd],
            cwd="/home/kanonTEE/P3DX-SE-manager"
        )
        
        is_app_running = True
        response = {
            "title": "Success",
            "description": "SKALD application execution has started."
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
    base_dir = "/home/kanonTEE/P3DX-SE-manager"
    jwt_file_path = os.path.join(base_dir, "keys", "jwt-response.txt")
    
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
    
    base_dir = "/home/kanonTEE/P3DX-SE-manager"
    keys_dir = os.path.join(base_dir, "keys")
    jwt_file_path = os.path.join(keys_dir, "jwt-response.txt")
    private_key_path = os.path.join(keys_dir, "private_key.pem")
    public_key_path = os.path.join(keys_dir, "public_key.pem")
    
    original_cwd = os.getcwd()
    
    try:
        os.chdir(base_dir)
        os.makedirs(keys_dir, exist_ok=True)
        
        subprocess.run(
            ["sudo", "chown", "-R", f"{os.getenv('USER', 'kanonTEE')}:{os.getenv('USER', 'kanonTEE')}", keys_dir],
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
            PPDX_SKALD.generate_and_save_key_pair()
            print("Key pair generated successfully")

        try:
            # Measure enclave manager code
            PPDX_SKALD.measure_enclave_manager_code_vtpm()
            print("Enclave manager code hash measured successfully")
            
            # Measure Docker image
            link = PPDX_SKALD.extract_docker_image_from_compose()
            PPDX_SKALD.measureDockervTPM(link)        
            print("Application image hash measured successfully")
        except Exception as e:
            print(f"Warning: Failed to measure code/image: {str(e)}")
        
        # new nonce generated every time a fresh endpoint is hit
        print("Generating fresh deployment nonce...")
        nonce = PPDX_SKALD.generate_nonce()                  
        PPDX_SKALD.save_nonce(nonce)                         
        print(f"Generated deployment nonce: {nonce}")

        print("Executing guest attestation to generate new JWT...")
        PPDX_SKALD.execute_guest_attestation()
        
        subprocess.run(
            ["sudo", "chown", f"{os.getenv('USER', 'kanonTEE')}:{os.getenv('USER', 'kanonTEE')}", jwt_file_path],
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
    
    bundle_file = "/home/kanonTEE/P3DX-SE-manager/Bundle/encrypted.json"
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
        
        bundle_dir = "/home/kanonTEE/P3DX-SE-manager/Bundle"
        os.makedirs(bundle_dir, exist_ok=True)
        
        global stored_bundle
        stored_bundle = content
        
        output_file = os.path.join(bundle_dir, "encrypted.json")
        
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


    output_file = "/tmp/tee_output/status.json"
    
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
    state = content["state"]
    
    print(f"State updated - Step {state['step']}/{state['maxSteps']}: {state['title']}")
    
    if state["step"] == 5:
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
    print(f"State requested - Step {state['step']}/{state['maxSteps']}")
    return jsonify(state)


# STATUS: Returns application status
@app.route("/enclave/status", methods=["GET"])
def get_app_status_endpoint():
    """Poll endpoint for application status.
    
    Returns status.json content
    """
    print("Fetching application status...")
    
    try:
        status_response = PPDX_SKALD.get_app_status()
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
        PPDX_SKALD.restart_enclave_manager()
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
    print("Port: 4000")
    print("Endpoints available:")
    print("  - POST /enclave/deploy")
    print("  - GET  /enclave/jwt")
    print("  - GET  /enclave/state")
    print("  - POST /enclave/setstate")
    print("  - GET  /enclave/inference")
    print("  - GET  /enclave/status")
    print("=" * 60)
    app.run(host="0.0.0.0", port=4000, debug=True)
