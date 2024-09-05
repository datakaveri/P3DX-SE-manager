import subprocess
import os
import PPDX_SDK
import sys
import json
import shutil

# Simulate sourcing external scripts -  
# You'd integrate the necessary functions from setState.sh and profilingStep.sh here 


def load_config(filename):
    """Loads configuration data from a JSON file."""
    try:
        with open(filename, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        raise FileNotFoundError(f"Configuration file '{filename}' not found.")
    except json.JSONDecodeError:
        raise ValueError(f"Invalid JSON format in configuration file '{filename}'.")

def box_out(message):
    """Prints a box around a message using text characters."""

    lines = message.splitlines()  # Split message into lines
    max_width = max(len(line) for line in lines)  # Find longest line

    # Top border
    print("+" + "-" * (max_width + 2) + "+")

    # Content with padding
    for line in lines:
        print("| " + line.ljust(max_width) + " |")

    # Bottom border
    print("+" + "-" * (max_width + 2) + "+")


def remove_profiling_file():
    if os.path.exists("profiling.json"):
        os.remove("profiling.json")

def remove_files():
    file_path = os.path.join('.','docker-compose.yml')
    if os.path.exists(file_path):
        os.remove(file_path)
        print(f"Removed file: {file_path}")
    else:
        print(f"File not found: {file_path}")
    
    folder_path = os.path.join('/tmp', 'FCoutput')
    if os.path.exists(folder_path):
        shutil.rmtree(folder_path)
        print(f"Removed folder and contents: {folder_path}")
    else:
        print(f"Folder not found: {folder_path}")
    
    # make FCoutput folder
    os.makedirs('/tmp/FCoutput', exist_ok=True)

    folder_path = os.path.join('/tmp', 'FCcontext')
    if os.path.exists(folder_path):
        shutil.rmtree(folder_path)
        print(f"Removed folder and contents: {folder_path}")
    else:
        print(f"Folder not found: {folder_path}")

    # make contextFolder folder if it does not exist
    os.makedirs('/tmp/FCcontext', exist_ok=True)

# Start the main process
if __name__ == "__main__":
    config_file = "config.json"
    config = load_config(config_file)
    address = config["address"]

    remove_files()

    if len(sys.argv) < 2:
        print("Error: Missing GitHub raw link argument.")
        print("Usage: sudo python3 deploy_enclave.py <github_raw_link>")
        sys.exit(1)  # Exit with an error code

    github_raw_link = sys.argv[1]
    json_context = sys.argv[2]
    if not github_raw_link.startswith("https://raw.githubusercontent.com/"):
        print("Error: Invalid GitHub raw link format.")
        sys.exit(1)

    # Step 1 - Pulling docker compose & extracting docker image link
    box_out("Pulling Docker Compose from GitHub...")
    PPDX_SDK.pull_compose_file(github_raw_link)
    print('Extracting docker link...')
    link = subprocess.check_output(["sudo", "docker", "compose", "config", "--images"]).decode().strip()
    print("Image information:", link)

    # Step 2 - Docker image pulling
    box_out("Pulling docker image...")
    sha_digest = PPDX_SDK.pull_docker_image(link)
    print("Pulled docker & got sha digest")


    # Step 3 - Spawning container
    print("\nStep 3") 
    box_out("Spawning Container..")
    PPDX_SDK.spawn_container(sha_digest, json_context)
    print("Application running..")