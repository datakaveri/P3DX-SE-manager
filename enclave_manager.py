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
import os
import json
import logging
import time

app = Flask(__name__)
logging.basicConfig(level=logging.WARNING)

jwt_wait_time = 180


def load_stuff():
    config_path = os.path.join(os.path.dirname(__file__), "DPconfig.json")

    with open(config_path, "r") as f:
        config = json.load(f)

    try:
        return config["remote_enclave_manager"]["base_url"], config["maa_url"]
    except KeyError as e:
        raise RuntimeError(f"Missing required config field: {e}")


ENCLAVE_131_BASE, MAA_URL = load_stuff()

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

    payload = {
        "commands": []
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


def poll_for_jwt(path, timeout_seconds, interval_seconds):
    deadline = time.time() + timeout_seconds

    while time.time() <= deadline:
        try:
            resp = requests.get(
                f"{ENCLAVE_131_BASE}{path}",
                timeout=10
            )

            if resp.status_code == 200:
                return Response(
                    response=resp.content,
                    status=200,
                    content_type=resp.headers.get("Content-Type", "application/json")
                )

            if resp.status_code == 404:
                time.sleep(interval_seconds)
                continue

            return Response(
                response=resp.content,
                status=resp.status_code,
                content_type=resp.headers.get("Content-Type", "application/json")
            )

        except requests.exceptions.RequestException as e:
            logging.error(f"JWT polling failed: {e}")
            time.sleep(interval_seconds)

    maa_status = {
        "status": "unknown",
        "endpoint": MAA_URL
    }

    try:
        start = time.time()
        maa_resp = requests.get(MAA_URL, timeout=5)
        latency_ms = int((time.time() - start) * 1000)

        maa_status.update({
            "status": "up",
            "http_status": maa_resp.status_code,
            "latency_ms": latency_ms
        })

        reason = (
            "Timeout Error. MAA is working but failed to get JWT."
        )

    except requests.exceptions.Timeout:
        maa_status["status"] = "timeout"
        reason = (
            "Timeout Error. MAA is working but couldn't get JWT."
        )

    except requests.exceptions.RequestException as e:
        maa_status.update({
            "status": "down",
            "error": str(e)
        })
        reason = (
            "Timeout Error. MAA is down. "
        )

    return jsonify({
        "Error: ": reason
    }), 504


@app.route("/enclave/jwt", methods=["GET"])
def proxy_jwt():
    return poll_for_jwt("/enclave/jwt", 180, 3)


@app.route("/enclave/jwt/fresh", methods=["GET"])
def proxy_jwt_fresh():
    return poll_for_jwt("/enclave/jwt/fresh", 180, 3)


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