#mport requests
from flask import Flask, jsonify, Response
from flask import request
import subprocess
import os

app = Flask(__name__)

#default /state response (when application is not running)
state = {
    "step": 0,
    "maxSteps": 9,
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

    global state
    state = {
        "step": 0,
        "maxSteps": 10,
        "title": "Inactive",
        "description": "Inactive",
    }
    #check if the application is already running, if yes, return response saying so
    if is_app_running:
        response={
            "title": "Error",
            "description": "Application is already running." 
        }
        return jsonify(response), 400

    # take as parameters the docker-compose.yml file and the json co
    content = request.json
    docker_compose_url = content["url"]
    #json_config = content.get("config", {})
    json_context = {
        "PPB_no": "T01050090085",
        "crop" : "Bajra",
        "crop_area" : "0.5",
        "season" : "Kharif"
    }
    
    try:
        subprocess.Popen(["sudo", "python3" , "deploy_enclave.py", docker_compose_url, json_context])
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
    print("STARTING inference")
    global state
    if(state["step"]!=10):
        response={
                "title": "Error: No Inference Output/File does not exist",
                "description": "No inference output found."
            }
        return jsonify(response), 403
    output_file = "/tmp/output/results.json"
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
    if(state["step"]==10):
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
