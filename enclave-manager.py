# Enclave Manager Flask API
from flask import Flask, jsonify, Response, request
from flask_cors import CORS
import subprocess
import os
import json
import logging
import threading

# Import log capture module
from log_capture import clear_logs, get_all_logs, stream_and_capture_box_logs


app = Flask(__name__)
CORS(app)
app_name = ""

# Default /state response (when application is not running)
state = {
    "step": 0,
    "maxSteps": 5,
    "title": "Inactive",
    "description": "Inactive",
}

# Setting the flag as false when the application is not running
is_app_running = False


@app.before_request
def before_request():
    return


#DEPLOY: Deploys the enclave, builds & runs the application & saves the output in a file
@app.route("/enclave/deploy", methods=["POST"])
def deploy_enclave():
    print("STARTING deploy")
    global is_app_running
    global app_name
    
    # Check if the application is already running, if yes, return response saying so
    if is_app_running:
        response = {
            "title": "Error",
            "description": "Application is already running." 
        }
        return jsonify(response), 400

    global state
    state = {
        "step": 1,
        "maxSteps": 5,
        "title": "Spawning Trusted Execution Environment (TEE)",
        "description": "Step 1"
    }
    
    content = request.json
    print("Content:", content)
    
    app_name = content["repo"]
    docker_compose_url = content["url"]
    context = content.get("context", {})
    json_context = json.dumps(context)
    print(json_context)

    try:
        if context:
            subprocess.Popen(["sudo", "python3", "deploy_enclave.py", docker_compose_url, json_context])
        else:
            if app_name == "anon_pipeline_AMD":
                dataset_name = content["dataset_name"]
                rs_url = content["rs_url"]
                subprocess.Popen(["sudo", "python3", "deploy_enclaveDP.py", dataset_name, rs_url, docker_compose_url])
            elif app_name == "K-anonymisation-AMD":
                dataset_name = content["dataset_name"]
                rs_url = content["rs_url"]
                subprocess.Popen(["sudo", "python3", "deploy_enclaveKAnon.py", dataset_name, rs_url, docker_compose_url])
            else:
                subprocess.Popen(["sudo", "python3", "deploy_enclave_FL-Client.py", docker_compose_url])
        
        is_app_running = True
        response = {
            "title": "Success",
            "description": "Application execution has started."
        }
        return jsonify(response), 200
    except Exception as e:
        response = Response(
            response=f"Error: {str(e)}",
            status=500,
            mimetype="application/json"
        )
    
    print("RUNNING FLAG:", is_app_running)
    return response


#INFERENCE: Returns the inference as a JSON object, containing runOutput & labels
@app.route("/enclave/inference", methods=["GET"])
def get_inference():
    logger = logging.getLogger()
    logging.debug('STARTING INFERENCE')
    if logger.handlers:
        logger.handlers[0].flush()
    
    global state
    global app_name
    
    if state["step"] != 5:
        response = {
            "title": "Error: No Inference Output/File does not exist",
            "description": "No inference output found."
        }
        return jsonify(response), 403

    if app_name == "anon_pipeline_AMD":
        output_file = "/tmp/DPoutput/inference.json"
    elif app_name == "K-anonymisation-AMD":
        output_file = "/tmp/arx_output/inference.json"
    elif app_name == "Smart Credit App":
        output_file = "/tmp/FCoutput/output.json"
    elif app_name in ["AMD_SEV_PNEUMONIA_APP", "AMD_SEV_YOLO_APP"]:
        output_file = "/tmp/output/results.json"
    else:
        response = {
            "title": "Error: Incorrect app",
            "description": "No inference output found."
        }
        return jsonify(response), 403
    
    if os.path.exists(output_file):
        try:
            # Use subprocess to run chmod with sudo
            result = subprocess.run(['sudo', 'chmod', '755', output_file], 
                                    check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            if result.returncode == 0:
                print(f"Successfully set a+x permissions on file: {output_file}")
            else:
                print(f"Failed to set permissions. Error: {result.stderr.decode()}")
        except subprocess.CalledProcessError as e:
            print(f"Error executing sudo chmod: {e.stderr.decode()}")
    else:
        print(f"File not found: {output_file}")

    if os.path.isfile(output_file):
        with open(output_file, "r") as f:
            content = f.read()
        response = app.response_class(
            response=content,
            mimetype="application/json"
        )
        return response
    else:
        response = {
            "title": "Error: No Inference Output/File does not exist",
            "description": "No inference output found."
        }
        return jsonify(response), 403


#SETSTATE: Sets the state of the enclave as a JSON object
@app.route("/enclave/setstate", methods=["POST"])
def setState():
    global state
    global is_app_running
    print("In /enclave/setstate...")
    content = request.json
    state = content["state"]
    
    if state["step"] == 5:
        # Resetting deploy flag as false
        is_app_running = False
    
    response = app.response_class(
        response="{ok}", status=200, mimetype="application/json"
    )
    return response


#STATE: Returns the current state of the enclave as a JSON object
@app.route("/enclave/state", methods=["GET"])
def get_state():
    global state
    return jsonify(state)


#START: Starts the enclave
@app.route("/enclave/start", methods=["POST"])
def start_enclave():
    start_enclave_script = "/home/ubuntu/start_enclave.sh"
    
    if not os.path.exists(start_enclave_script):
        return jsonify({
            "title": "Error: start script not found",
            "description": f"Missing: {start_enclave_script}"
        }), 500
    
    try:
        # Clear prior logs when a new run starts
        clear_logs()
        
        # Execute the shell script with stdout capture to get box_out logs
        proc = subprocess.Popen(
            ["sudo", "bash", start_enclave_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            text=True,
        )
        threading.Thread(target=stream_and_capture_box_logs, args=(proc,), daemon=True).start()
        
        response = app.response_class(
            response="{ok}", status=200, mimetype="application/json"
        )
        return response
    except Exception as e:
        response = {
            "title": "Error: Failed to start enclave",
            "description": str(e)
        }
        return jsonify(response), 500


#LOGS: Returns captured box_out logs as simple messages
@app.route("/enclave/logs", methods=["GET"])
def get_enclave_logs():
    """
    Returns only the message content from box_out logs.
    Response: {"logs": ["message1", "message2", ...], "count": N}
    """
    try:
        logs = get_all_logs()
        return jsonify({
            "logs": logs,
            "count": len(logs)
        }), 200
    except Exception as e:
        return jsonify({
            "title": "Error: Failed to fetch logs",
            "description": str(e)
        }), 500


#STATUS: Returns enclave status
@app.route("/enclave/status", methods=["GET"])
def get_status():
    status_script = "/home/ubuntu/status_enclave.sh"
    try:
        subprocess.Popen(["sudo", "bash", status_script])
        response = app.response_class(
            response="{ok}", status=200, mimetype="application/json"
        )
        return response
    except Exception as e:
        response = {
            "title": "Error: Failed to get enclave status",
            "description": str(e)
        }
        return jsonify(response), 500
