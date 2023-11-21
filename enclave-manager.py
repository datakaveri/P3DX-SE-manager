#mport requests
from flask import Flask, jsonify, Response
from flask import request
import subprocess
import os
import shutil
import threading

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
        pulledcodepath="/home/iudx/pulledcode/"
        fileNameYOLO=pulledcodepath+"sgx-yolo-app/yolov5/labels.json"
        fileNameHI=pulledcodepath+"sgx-healthcare-inferencing/output.json"
        fileNameHT=pulledcodepath+"sgx-healthcare-training/output.json"
        fileNameDP=pulledcodepath+"sgx-diff-privacy/scripts/output.json"
        file = ""
        done=False
        for file in [fileNameYOLO, fileNameHI, fileNameHT, fileNameDP]:
            if os.path.isfile(file):
                f=open(file, "r")
                content = f.read()
                response = app.response_class(
                    response=content,
                    mimetype="application/json"
                )
                done=True
                return response
        if not done:
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
        process=subprocess.Popen(["./deploy_enclave.sh", url, repo, branch, id, name])
        is_app_running = True

        monitor_thread = threading.Thread(target=monitor_subprocess, args=(process,))
        monitor_thread.start()
        
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


@app.route("/enclave/profiling", methods=["GET"])
def get_profiling():
    print("In /enclave/profiling...")
    global state
    if(state["step"]==0):
        response={
            "title": "Error: No Profiling Output",
            "description": "Start execution of the application."
        }
        return jsonify(response), 403
    
    profilingFileEM = "./profiling.json"
    applications = ["yolo-app", "healthcare-training", "healthcare-inferencing"]
    file = ""
    for application in applications:
        profilingFile = "/home/iudx/pulledcode/sgx-"+application+"/profiling.json"
        if os.path.isfile(profilingFile):
            file=profilingFile
            break
    if file=="":
        if os.path.isfile(profilingFileEM):
            file=profilingFileEM
        else:
            response={
            "title": "Error: No Profiling Output",
            "description": "No profiling output found."
            }
            return jsonify(response), 403
        
    f=open(file, "r")
    content = f.read()
    response = app.response_class(
        response=content,
        mimetype="application/json"
    )
    return response

def monitor_subprocess(process):
    print("Inside monitor subprocess")
    global is_app_running
    global state
    process.wait()  # Wait for the subprocess to finish
    exit_code = process.returncode
    print("Exit code:",exit_code)
    if exit_code != 0:
        # Subprocess had an error
        print("Error: Subprocess exited with code:", exit_code)
        is_app_running = False
        print("setting flag and state")
        state = {
            "step": 0,
            "maxSteps": 10,
            "title": "Inactive",
            "description": "Inactive",
        }