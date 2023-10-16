#mport requests
from flask import Flask, jsonify, Response
from flask import request
import subprocess
import os
import shutil
#from urllib.parse import urljoin

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
    global state
    if(state["step"]!=10):
        response={
            "title": "Error: No Inference Output",
            "description": "Start execution of the application or wait for it to finish."
        }
        return jsonify(response), 403
    else:
        fileName = "/home/iudx/pulledcode/sgx-yolo-app/yolov5/labels.json"
        fileName2 = "/home/iudx/pulledcode/sgx-healthcare-inferencing/diseaseDetection/output.json"

        if(os.path.isfile(fileName)):
            f=open(fileName, "r")
            content = f.read()
            response = app.response_class(
                response=content,
                mimetype="application/json"
            )
            return response
        elif(os.path.isfile(fileName2)):
            f=open(fileName2, "r")
            content = f.read()
            response = app.response_class(
                response=content,
                mimetype="application/json"
            )
            return response
        else:
            response={
                "title": "Error: No Inference Output",
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
    global state
    state = {
        "step": 0,
        "maxSteps": 10,
        "title": "Inactive",
        "description": "Inactive",
    }
    # check if the application is already running, if yes, return response saying so
    if is_app_running:
        response={
            "title": "Error",
            "description": "Application is already running." 
        }
        return jsonify(response), 400

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

        response={
            "title": "Success",
            "description": "Application execution has started."
        }
        return jsonify(response), 200
    except Exception as e:
        is_app_running = False
        state = {
            "step": 0,
            "maxSteps": 10,
            "title": "Inactive",
            "description": "Inactive",
        }
        pulledcode_path = "/home/iudx/pulledcode"
        shutil.rmtree(pulledcode_path)
        response = Response(
            response=f"Error: {str(e)}",
            status=500,
            mimetype="application/json"
        )

    return response


@app.route("/enclave/profiling", methods=["GET"])
def get_profiling():
    print("In /enclave/profiling...")

    profilingFileEM = "./profiling.json"
    profilingFileApp = "/home/iudx/pulledcode/sgx-yolo-app/profiling.json"

    if not os.path.isfile(profilingFileApp):
        file=profilingFileEM
    else:
        file=profilingFileApp
    
    f=open(file, "r")
    content = f.read()
    response = app.response_class(
        response=content,
        mimetype="application/json"
    )
    return response