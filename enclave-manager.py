#mport requests
from flask import Flask, jsonify, Response
from flask import request
import subprocess
import os
from urllib.parse import urljoin

app = Flask(__name__)

#default /state response (when application is not running)
state = {
    "step": 0,
    "maxSteps": 10,
    "title": "Inactive",
    "description": "Inactive",
}

#setting the flag as false when the application is not running
is_app_running = False

@app.before_request
def before_request():
    return


#INFERENCE: Returns the inference as a JSON object, containing runOutput & labels
@app.route("/enclave/inference", methods=["GET"])
def get_inference():
    fileName = "~/pulledcode/sgx-yolo-app/yolov5/labels.json"

    if (os.path.isfile(fileName)==False):
        inferenceString = "NO INFERENCE"
        return inferenceString, 403

    f=open("~/pulledcode/sgx-yolo-app/yolov5/labels.json", "r")
    content = f.read()
    #response = "Here is a temporary response for now.."
    response = app.response_class(
        response=content,
        mimetype="application/json"
    )
    return response



#SETSTATE: Sets the state of the enclave as a JSON object
@app.route("/enclave/setstate", methods=["POST"])
def setState():
    global state
    global is_app_running
    print("In /enclave/setstate...")
    content = request.json
    state = content["state"]
    if(state["step"]==10):
        #print("Resetting deploy flag as false")
        is_app_running = False
    response = app.response_class(
        #response="{}", status=200, mimetype="application/json"
        response="{ok}", status=200, mimetype="application/json"
    )
    return response



#STATE: Returns the current state of the enclave as a JSON object
@app.route("/enclave/state", methods=["GET"])
def get_state():
    global state # = {"step":3, "maxSteps":10, "title": "Building enclave,", "description":"The enclave is being compiled,"}
    return jsonify(state) 

'''
@app.route("/enclave/pcrs", methods=["GET"])
def get_pcrs():
    # the file should contain a JSON object with a key called 'pcrs'
    # get any other data if required and merge it with the object
    with open("./pcrs.json", "r") as f:
        pcrs = json.load(f)
        print ("PCRs loaded =", pcrs)
        return pcrs
'''


#DEPLOY: Deploys the enclave, builds & runs the application & saves the output in a file
@app.route("/enclave/deploy", methods=["POST"])
def deploy_enclave():
    global is_app_running

    # check if the application is already running, if yes, return response saying so
    if is_app_running:
        return Response(
            response="Application is already being executed.",
            status=400,
            mimetype="application/json"
        )

    print("In /enclave/deploy...")
    content = request.json
    id = content["id"]
    repo = content["repo"]
    branch = content["branch"]
    url = content["url"]
    name = content["name"]

    try:
        subprocess.Popen(["./deploy_enclave.sh", url, repo, branch, id, name])

        # set the flag to true to indicate that the application is running
        is_app_running = True

        response = Response(
            response="Application started successfully.",
            status=200,
            mimetype="application/json"
        )
    except Exception as e:
        response = Response(
            response=f"Error: {str(e)}",
            status=500,
            mimetype="application/json"
        )

    return response