# from flask import Flask, request, jsonify, Response
# import requests
# import logging

# app = Flask(__name__)
# logging.basicConfig(level=logging.WARNING)

# enclave_base = "http://20.40.47.131:4000"


# def forward_request(method, path):
#     url = f"{enclave_base}{path}"

#     payload = request.get_json(silent=True)
#     if payload is None:
#         payload = {}

#     logging.warning(f"BROKER HIT: {method} {path}")
#     logging.warning(f"Payload: {payload}")

#     try:
#         # all requests to enclave have a timeout of 30 seconds
#         if method == "GET":
#             resp = requests.get(url, params=request.args, timeout=30)

#         elif method == "POST":
#             resp = requests.post(
#                 url,
#                 json=payload,
#                 headers={"Content-Type": "application/json"},
#                 timeout=30
#             )

#         else:
#             return jsonify({"error": "Method not supported"}), 405

#         return Response(
#             response=resp.content,
#             status=resp.status_code,
#             content_type=resp.headers.get("Content-Type", "application/json")
#         )

#     except requests.exceptions.RequestException as e:
#         logging.error(f"Forwarding failed: {e}")
#         return jsonify({
#             "title": "Broker Error",
#             "description": str(e)
#         }), 502

# @app.route("/enclave/forward", methods=["POST"])
# def proxy_forward():
#     return forward_request("POST", "/enclave/deploy")


# @app.route("/enclave/jwt", methods=["GET"])
# def proxy_jwt():
#     return forward_request("GET", "/enclave/jwt")


# @app.route("/enclave/bundle/upload", methods=["POST"])
# def proxy_bundle_upload():
#     return forward_request("POST", "/enclave/bundle/upload")


# @app.route("/enclave/status", methods=["GET"])
# def proxy_status():
#     return forward_request("GET", "/enclave/status")


# @app.route("/enclave/jwt/fresh", methods=["GET"])
# def proxy_jwt_fresh():
#     return forward_request("GET", "/enclave/jwt/fresh")

# @app.route("/health", methods=["GET"])
# def health():
#     return jsonify({"status": "broker-ok"}), 200

from flask import Flask, request, jsonify, Response
import requests
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.WARNING)

ENCLAVE_131_BASE = "http://20.40.47.131:4000"

state = {
    "step": 0,
    "maxSteps": 5,
    "title": "Inactive",
    "description": "Inactive"
}

is_app_running = False

def forward_request(method, path):
    url = f"{ENCLAVE_131_BASE}{path}"

    payload = request.get_json(silent=True)
    if payload is None:
        payload = {}

    logging.warning(f"FORWARD → {method} {path}")
    logging.warning(f"Payload: {payload}")

    try:
        if method == "GET":
            resp = requests.get(url, params=request.args, timeout=30)

        elif method == "POST":
            resp = requests.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=30
            )
        else:
            return jsonify({"error": "Method not supported"}), 405

        return Response(
            response=resp.content,
            status=resp.status_code,
            content_type=resp.headers.get("Content-Type", "application/json")
        )

    except requests.exceptions.RequestException as e:
        logging.error(f"Forwarding failed: {e}")
        return jsonify({
            "title": "Broker Error",
            "description": str(e)
        }), 502


@app.route("/enclave/deploy", methods=["POST"])
def deploy_enclave():
    global is_app_running, state

    logging.warning("DEPLOY requested on 153")

    if is_app_running:
        return jsonify({
            "title": "Error",
            "description": "Deployment already in progress"
        }), 409

    # UI-visible state
    state = {
        "step": 1,
        "maxSteps": 5,
        "title": "Spawning Trusted Execution Environment (TEE)",
        "description": "Step 1"
    }

    # Commands that MUST be executed on 131
    payload = {
        "commands": [
            "sudo rm -rf /home/kanonTEE/P3DX-SE-manager/keys/image_hash.txt"
        ]
    }


    try:
        resp = requests.post(
            f"{ENCLAVE_131_BASE}/enclave/deploy",
            json=payload,
            timeout=10
        )

        if resp.status_code != 200:
            raise RuntimeError(resp.text)

        is_app_running = True

        return jsonify({
            "title": "Success",
            "description": "SKALD application execution has started."
        }), 200

    except Exception as e:
        is_app_running = False
        logging.error(f"Failed to start SKALD: {e}")

        return jsonify({
            "title": "Error",
            "description": str(e)
        }), 500

# bunch of endpoints from 153

@app.route("/enclave/jwt", methods=["GET"])
def proxy_jwt():
    return forward_request("GET", "/enclave/jwt")


@app.route("/enclave/jwt/fresh", methods=["GET"])
def proxy_jwt_fresh():
    return forward_request("GET", "/enclave/jwt/fresh")


@app.route("/enclave/bundle", methods=["GET"])
def proxy_bundle():
    return forward_request("GET", "/enclave/bundle")


@app.route("/enclave/bundle/upload", methods=["POST"])
def proxy_bundle_upload():
    return forward_request("POST", "/enclave/bundle/upload")


@app.route("/enclave/status", methods=["GET"])
def proxy_status():
    return forward_request("GET", "/enclave/status")


@app.route("/enclave/inference", methods=["GET"])
def proxy_inference():
    return forward_request("GET", "/enclave/inference")


@app.route("/enclave/state", methods=["GET"])
def proxy_state():
    return forward_request("GET", "/enclave/state")


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "broker-ok"}), 200


if __name__ == "__main__":
    print("=" * 60)
    print("Enclave Manager (BROKER)")
    print("VM: 153")
    print("Port: 4000")
    print("Owns:")
    print("  POST /enclave/deploy")
    print("Proxies everything else to 131")
    print("=" * 60)
    app.run(host="0.0.0.0", port=4000)
