#mport requests
#import urllib2
from flask import Flask, jsonify, Response
from flask import request
import subprocess
#from subprocess import Popen
import json
import os
#import PPDX_SDK as sdk
#import requests

app = Flask(__name__)

state = {
    "step": 0,
    "maxSteps": 10,
    "title": "Inactive",
    "description": "Inactive",
}

stateString="CC_NOTRUNNING"

@app.before_request
def before_request():
    # TODO do the token validation for the auth admin token before handling the request
    return


# TODO get enclave name or ID as query parameter if multiple enclaves are managed
# only returning the content in pcrs.json

@app.route("/enclave/inference", methods=["GET"])
def get_inference():
    #api_url="http://127.0.0.1:4500/enclavecc/displayinference"
    #sponse = requests.get(api_url)
    #response = subprocess.call(["curl", api_url]
    fileName = "/home/iudx/pulledcode/sgx-yolo-app/yolov5/labels.json"

    if (os.path.isfile(fileName)==False):
        inferenceString = "NO INFERENCE"
        return inferenceString, 403

    f=open("/home/iudx/pulledcode/sgx-yolo-app/yolov5/labels.json", "r")
    content = f.read()
    #response = "Here is a temporary response for now.."
    response = app.response_class(
        response=content,
        mimetype="application/json"
    )
    return response


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

@app.route("/enclave/state", methods=["GET"])
def get_state():
    global state # = {"step":3, "maxSteps":10, "title": "Building enclave,", "description":"The enclave is being compiled,"}
    #stateReturned = json.dumps(state, indent=4)
    return jsonify(state) 

'''
@app.route("/enclave/state", methods=["GET"])
def get_state():
        #load state.json, if it exists
        fName = "/home/iudx/yoloHelper/state.json"
        if (os.path.isfile(fName)==False):
            stateString = "No output log."
        else:
            with open(fName,"r") as f:
                stateString=json.load(f)
        return stateString
'''

@app.route("/enclave/pcrs", methods=["GET"])
def get_pcrs():
    # the file should contain a JSON object with a key called 'pcrs'
    # get any other data if required and merge it with the object
    with open("./pcrs.json", "r") as f:
        pcrs = json.load(f)
        print ("PCRs loaded =", pcrs)
        return pcrs


is_app_running = False

@app.route("/enclave/deploy", methods=["POST"])
def deploy_enclave():
    global is_app_running

    if is_app_running:
        return Response(
            response="Application is already running",
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
        # Calling the actual shell script. Don't wait for it to return and just send 200 OK
        # Send url, id, and name as arguments
        subprocess.Popen(["./deploy_enclave.sh", url, repo, branch, id, name])
        is_app_running = True

        response = Response(
            response="{running}",
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