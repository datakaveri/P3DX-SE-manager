#mport requests
#import urllib2
from flask import Flask
from flask import request
from subprocess import Popen
import json
import os
#import requests

app = Flask(__name__)


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
    response = f.read()
    #response = "Here is a temporary response for now.."
    print (response)
    inferenceString=response
    return inferenceString


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

@app.route("/enclave/pcrs", methods=["GET"])
def get_pcrs():
    # the file should contain a JSON object with a key called 'pcrs'
    # get any other data if required and merge it with the object
    with open("./pcrs.json", "r") as f:
        pcrs = json.load(f)
        print ("PCRs loaded =", pcrs)
        return pcrs


@app.route("/enclave/deploy", methods=["POST"])
def deploy_enclave():
    print("In /enclave/deploy...")
    content = request.json
    # TODO check if all values are valid
    id = content["id"]
    repo = content["repo"]
    branch = content["branch"]
    url = content["url"]
    name = content["name"]

    # calling the actual shell script. Don't wait for it to return and just send 200 OK
    # send url, id and name as arguments
    pid = Popen(["./deploy_enclave.sh", url, repo, branch, id, name]).pid
    stateString="CC_DEPLOYED"
    response = app.response_class(
        response="{}", status=200, mimetype="application/json"
    )
    return response
