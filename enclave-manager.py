#mport requests
from flask import Flask, jsonify, Response
from flask import request
import subprocess
import os
import json
import stat
import logging

app = Flask(__name__)

app_name = ""

#default /state response (when application is not running)
state = {
    "step": 0,
    "maxSteps": 5,
    "title": "Inactive",
    "description": "Inactive",
}

#setting the flag as false when the application is not running
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
    #check if the application is already running, if yes, return response saying so
    if is_app_running:
        response={
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
    # take as parameters the docker-compose.yml file and the json co
    content = request.json
    docker_compose_url = content["url"]
    context = content.get("context", {})
    # context = {
    #     "PPB_no": "T01050090085",
    #     "crop" : "Coriander",
    #     "crop_area" : 0.05,
    #     "season" : "Rabi", 
    #     "land_type" :"Irr"
    # }
    json_context = json.dumps(context)
    print(json_context)
    try:
        if context:
            subprocess.Popen(["sudo", "python3" , "deploy_enclave.py", docker_compose_url, json_context])
            app_name = "farmer_credit"

        else:
            subprocess.Popen(["sudo", "python3" , "deploy_enclave_pneumonia.py", docker_compose_url])
            app_name = "pneumonia"

        is_app_running = True
        response={
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
    print("RUNNING FLAG: ",is_app_running)
    return response


#INFERENCE: Returns the inference as a JSON object, containing runOutput & labels
@app.route("/enclave/inference", methods=["GET"])
def get_inference():
    # print("STARTING inference")
    logger = logging.getLogger()
    logging.debug('STARTING INFERNCE')
    logger.handlers[0].flush()
    global state
    global app_name
    if(state["step"]!=5):
        response={
                "title": "Error: No Inference Output/File does not exist",
                "description": "No inference output found."
            }
        return jsonify(response), 403

    if(app_name == "farmer_credit"):    
        output_file = "/tmp/FCoutput/output.json"
    elif(app_name == "pneumonia"):
        output_file = "/tmp/output/results.json"
    else:
        response={
                "title": "Error: Incorrect app",
                "description": "No inference output found."
            }
        return jsonify(response), 403
    
    if os.path.exists(output_file):
        try:
            # Use subprocess to run chmod with sudo
            result = subprocess.run(['sudo', 'chmod', '755', output_file], 
                                    check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Check result
            if result.returncode == 0:
                print(f"Successfully set a+x permissions on file: {output_file}")
            else:
                print(f"Failed to set permissions. Error: {result.stderr.decode()}")

        except subprocess.CalledProcessError as e:
            print(f"Error executing sudo chmod: {e.stderr.decode()}")
    else:
        print(f"File not found: {output_file}")


    if os.path.isfile(output_file):
        f=open(output_file, "r")
        content = f.read()
        response = app.response_class(
            response=content,
            mimetype="application/json"
        )
        return response
    else:
        response={
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
    if(state["step"]==5):
        #Resetting deploy flag as false
        is_app_running = False
    response = app.response_class(
        response="{ok}", status=200, mimetype="application/json"
    )
    return response


#STATE: Returns the current state of the enclave as a JSON object
@app.route("/enclave/state", methods=["GET"])
def get_state():
    global state # = {"step":3, "maxSteps":10, "title": "Building enclave,", "description":"The enclave is being compiled,"}
    return jsonify(state) 
