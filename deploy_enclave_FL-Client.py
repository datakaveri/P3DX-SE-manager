import subprocess
import os
import PPDX_SDK
import sys
import json
import shutil
import time
import logging
from datetime import datetime
import docker
import asyncio
import websockets

# WebSocket server address
WS_URI = "wss://nickname-few-vc-casa.trycloudflare.com"

import re
import asyncio
import json
import docker
import websockets
from datetime import datetime

PING_INTERVAL = 20  # seconds

async def send_log(message, container="host"):
    """Send a log message to the WebSocket server."""
    try:
        async with websockets.connect(WS_URI) as ws:
            await ws.send(json.dumps({
                "role": "client",  # or "server" depending on context
                "container": container,
                "log": message,
                "timestamp": datetime.utcnow().isoformat()
            }))
    except Exception as e:
        print("WebSocket error (send_log):", e)


import asyncio
import json
import re
import docker
import websockets
from datetime import datetime

# Config
PING_INTERVAL = 20  # seconds

async def send_ping(ws):
    """Send periodic ping messages to keep the WebSocket alive."""
    try:
        while True:
            await ws.send(json.dumps({
                "event": "ping",
                "timestamp": datetime.utcnow().isoformat()
            }))
            await asyncio.sleep(PING_INTERVAL)
    except Exception as e:
        print("❌ Ping error:", e)

        
async def stream_client_logs(container, ws):
    """Stream logs from client container and send over WebSocket."""
    try:
        for line in container.logs(stream=True, follow=True):
            try:
                log_msg = line.decode().strip()
                if not log_msg:
                    continue

                print(log_msg)

                # ✅ Detect "Run ... epoch of ... round"
                round_match = re.search(r"Run \d+ epoch of (\d+) round", log_msg)
                if round_match:
                    round_num = int(round_match.group(1))
                    await ws.send(json.dumps({
                        "role": "client",
                        "event": "round_complete",
                        "round": round_num,
                        "log": log_msg,
                        "timestamp": datetime.utcnow().isoformat()
                    }))
                else:
                    # Regular log forwarding
                    await ws.send(json.dumps({
                        "role": "client",
                        "event": "log",
                        "log": log_msg,
                        "timestamp": datetime.utcnow().isoformat()
                    }))

            except Exception as e:
                print("⚠️ Log send error:", e)
    except Exception as e:
        print("❌ Log stream error:", e)

async def stream_logs(container_name):
    """Main function to handle WebSocket + Docker log streaming."""
    try:
        client = docker.from_env()
        container = client.containers.get(container_name)

        async with websockets.connect(WS_URI, ping_interval=None) as ws:
            # Run both ping and log stream concurrently
            ping_task = asyncio.create_task(send_ping(ws))
            log_task = asyncio.create_task(stream_client_logs(container, ws))

            done, pending = await asyncio.wait(
                [ping_task, log_task],
                return_when=asyncio.FIRST_EXCEPTION
            )

            # Cancel the other task if one fails
            for task in pending:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

    except Exception as e:
        print("🚨 WebSocket error (stream_logs):", e)




def load_config(filename):
    try:
        with open(filename, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        raise FileNotFoundError(f"Configuration file '{filename}' not found.")
    except json.JSONDecodeError:
        raise ValueError(f"Invalid JSON format in configuration file '{filename}'.")


def box_out(message):
    lines = message.splitlines()
    max_width = max(len(line) for line in lines)
    print("+" + "-" * (max_width + 2) + "+")
    for line in lines:
        print("| " + line.ljust(max_width) + " |")
    print("+" + "-" * (max_width + 2) + "+")


def remove_files():
    paths = [
        ('./docker-compose.yml', os.remove),
        ('./keys', shutil.rmtree),
        ('/tmp/inputdata', shutil.rmtree),
        ('/tmp/output', shutil.rmtree),
    ]

    for path, remover in paths:
        if os.path.exists(path):
            remover(path)
            print(f"Removed: {path}")
        else:
            print(f"Not found: {path}")

    for folder in ['/tmp/inputdata', '/tmp/output']:
        os.makedirs(folder, exist_ok=True)
        os.chmod(folder, 0o755)
        print(f"Recreated with a+x permissions: {folder}")


# ------------------ Main Execution ------------------ #

if __name__ == "__main__":
    config_file = "config_file_pneumonia.json"
    config = load_config(config_file)
    address = config["enclaveManagerAddress"]

    remove_files()

    if len(sys.argv) < 2:
        print("Error: Missing GitHub raw link argument.")
        sys.exit(1)

    github_raw_link = sys.argv[1]
    if not github_raw_link.startswith("https://raw.githubusercontent.com/"):
        print("Error: Invalid GitHub raw link format.")
        sys.exit(1)

    async def run_all():
        # Step 1 - Pull Docker Compose & extract image
        box_out("Pulling Docker Compose from GitHub...")
        await send_log("Pulling Docker Compose from GitHub...")
        PPDX_SDK.pull_compose_file(github_raw_link)
        print('Extracting docker link...')
        link = subprocess.check_output(["sudo", "docker", "compose", "config", "--images"]).decode().strip()
        print("Image information:", link)
        await send_log(f"Docker Image: {link}")

        # Step 2 - Pull Docker Image
        box_out("Pulling docker image...")
        await send_log("Pulling docker image...")
        PPDX_SDK.pull_docker_image(link)
        print("Pulled docker image")

        # Step 3 - Key Generation
        box_out("Generating and saving key pair...")
        await send_log("Generating and saving key pair...")
        PPDX_SDK.setState("TEE Attestation & Authorisation", "Step 2", 2, 5, address)
        PPDX_SDK.generate_and_save_key_pair()

        # Step 4 - Measure image
        box_out("Measuring Docker image into vTPM...")
        await send_log("Measuring Docker image into vTPM...")
        PPDX_SDK.measureDockervTPM(link)
        print("Measured and stored in vTPM")

        # Step 5 - Attestation with MAA
        box_out("Guest Attestation Executing...")
        await send_log("Guest Attestation Executing...")
        PPDX_SDK.execute_guest_attestation()
        print("JWT received from MAA")

        # Step 6 - Send to APD
        box_out("Sending JWT to APD for verification...")
        await send_log("Sending JWT to APD for verification...")
        token = PPDX_SDK.getAttestationToken(config)
        print("Access token received from APD")

        # Step 7 - Get Files
        box_out("Getting files from RS...")
        await send_log("Getting files from Resource Server...")
        PPDX_SDK.setState("Getting data into Secure enclave", "Step 3", 3, 5, address)
        PPDX_SDK.getFileFromResourceServer(token)

        # Step 8 - Decrypt Files
        box_out("Decrypting & storing files...")
        await send_log("Decrypting & storing files...")
        PPDX_SDK.decryptFile()
        print("Files decrypted and stored in /tmp/inputdata")

        # Step 9 - Run Container
        box_out("Running the Application...")
        await send_log("Running the Application...")
        PPDX_SDK.setState("Running pneumonia detection application", "Step 4", 4, 5, address)
        subprocess.run(["sudo", "docker", "compose", "down"])
        subprocess.run(["sudo", "docker", "compose", "up", "-d"])

        # Step 10 - Stream container logs
        # time.sleep(3)  # Ensure container is ready
        await stream_logs("p3dx-se-manager-col1-1")

        # Step 11 - Completion
        PPDX_SDK.setState("Secure Execution Complete", "Step 5", 5, 5, address)
        await send_log("Secure execution complete.")
        print("DONE\nOutput saved to /tmp/output")

    asyncio.run(run_all())
