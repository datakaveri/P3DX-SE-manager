from flask import Flask, jsonify, request
from flask_cors import CORS
import subprocess
import threading

app = Flask(__name__)
CORS(app)  # ✅ This enables CORS for all routes

def run_script():
    subprocess.run("bash /home/ubuntu/start_enclave.sh", shell=True)

@app.route("/start", methods=["POST"])
def start():
    threading.Thread(target=run_script).start()
    return jsonify({"status": "started"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5005)
