import subprocess
import os
import shutil
import sys
import traceback
import PPDX_SKALD as PPDX_SKALD

# Force unbuffered output for live logging
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)


DOCKER_COMPOSE_URL = "https://raw.githubusercontent.com/prathmeshj1729/Docker-Compose/refs/heads/main/docker-compose-skald.yaml"






def box_out(message):
    """Prints a box around a message using text characters."""
    lines = message.splitlines()
    max_width = max(len(line) for line in lines) if lines else 0
    
    print("+" + "-" * (max_width + 2) + "+", flush=True)
    for line in lines:
        print("| " + line.ljust(max_width) + " |", flush=True)
    print("+" + "-" * (max_width + 2) + "+", flush=True)


def cleanup_and_prepare_folders():
    """Clean up old files and prepare SKALD folders."""
    print("Cleaning up and preparing folders...", flush=True)
    
    docker_compose_file = os.path.join('.', 'docker-compose.yml')
    if os.path.exists(docker_compose_file):
        os.remove(docker_compose_file)
        print(f"Removed: {docker_compose_file}", flush=True)
    
    keys_folder = os.path.join('.', 'keys')
    if os.path.exists(keys_folder):
        shutil.rmtree(keys_folder)
        print(f"Removed: {keys_folder} (keys and JWT token)", flush=True)
    
    bundle_file = os.path.join('.', 'Bundle', 'encrypted.json')
    if os.path.exists(bundle_file):
        os.remove(bundle_file)
        print(f"Removed: {bundle_file}", flush=True)
    
    PPDX_SKALD.ensure_skald_folders()


def main():
    """Main deployment workflow."""
    print("="*60, flush=True)
    print("SKALD Enclave Deployment", flush=True)
    print("="*60, flush=True)
    
    config_file = "DPconfig.json"
    config = PPDX_SKALD.load_config_file(config_file)
    address = config["enclaveManagerAddress"]
    
    cleanup_and_prepare_folders()
    
    # Step 1 - Pulling docker compose & extracting docker image link
    print("\n" + "="*60, flush=True)
    print("Step 1: Pulling Docker Compose from GitHub", flush=True)
    print("="*60, flush=True)
    box_out("Pulling Docker Compose from GitHub...")
    PPDX_SKALD.pull_compose_file(DOCKER_COMPOSE_URL)
    print('Extracting docker image link...', flush=True)
    
    link = PPDX_SKALD.extract_docker_image_from_compose()
    print(f"Docker image: {link}", flush=True)
    
    # Step 2 - Key generation
    print("\n" + "="*60, flush=True)
    print("Step 2: Generating Key Pair", flush=True)
    print("="*60, flush=True)
    box_out("Generating and saving key pair...")
    PPDX_SKALD.setState("TEE Attestation & Authorisation", "Step 2", 2, 11, address)
    PPDX_SKALD.generate_and_save_key_pair()
    print("Key pair generated", flush=True)
    
    # Step 3 - Docker image pulling
    print("\n" + "="*60, flush=True)
    print("Step 3: Pulling Docker Image", flush=True)
    print("="*60, flush=True)
    box_out("Pulling docker image...")
    PPDX_SKALD.pull_docker_image(link)
    print("Docker image pulled", flush=True)
    image_hash = PPDX_SKALD.hash_docker_image(link)
    PPDX_SKALD.save_image_hash(image_hash)

    # Step 4 - Measuring enclave manager code and Docker image into vTPM
    print("\n" + "="*60, flush=True)
    print("Step 4: Measuring Code and Docker Image into vTPM", flush=True)
    print("="*60, flush=True)
    box_out("Measuring enclave manager code")
    PPDX_SKALD.measure_enclave_manager_code_vtpm()
    print("Enclave manager code measured and stored", flush=True)
    
    box_out("Measuring Docker image...")
    PPDX_SKALD.measureDockervTPM(link)
    print("Docker image measured and stored", flush=True)

    # Step 4.5 - Generate deployment nonce
    nonce = PPDX_SKALD.generate_nonce()
    PPDX_SKALD.save_nonce(nonce)
    print(f"Generated deployment nonce: {nonce}", flush=True)

    # Step 5 - Send VTPM & public key to MAA & get attestation token
    print("\n" + "="*60, flush=True)
    print("Step 5: Guest Attestation", flush=True)
    print("="*60, flush=True)
    box_out("Guest Attestation Executing...")
    PPDX_SKALD.execute_guest_attestation()
    print("Guest Attestation complete. JWT received from MAA", flush=True)
    
    # Step 6 - Send the JWT to UI
    print("\n" + "="*60, flush=True)
    print("Step 6: Sending JWT to UI", flush=True)
    print("="*60, flush=True)
    box_out("Sending JWT to UI for polling...")
    jwt = PPDX_SKALD.get_jwt_from_file()
    PPDX_SKALD.send_jwt_to_ui(jwt, address)
    print("JWT sent to UI. Waiting for bundle...", flush=True)
    
    # Step 7 - Receive encrypted bundle from UI
    print("\n" + "="*60, flush=True)
    print("Step 7: Receiving Encrypted Bundle from UI", flush=True)
    print("="*60, flush=True)
    box_out("Waiting for encrypted bundle from UI...")
    PPDX_SKALD.setState("Receiving encrypted bundle", "Step 7", 7, 11, address)
    bundle_data = PPDX_SKALD.wait_for_bundle_from_ui(address, timeout=300)
    bundle_path = PPDX_SKALD.save_bundle_to_file(bundle_data)
    print("Bundle received and saved", flush=True)
    
    # Step 8 - Decrypt bundle
    print("\n" + "="*60, flush=True)
    print("Step 8: Decrypting Bundle", flush=True)
    print("="*60, flush=True)
    box_out("Decrypting bundle...")
    PPDX_SKALD.setState("Decrypting bundle", "Step 8", 8, 11, address)
    private_key_path = "keys/private_key.pem"
    PPDX_SKALD.decrypt_bundle_skald(bundle_path, private_key_path)
    print("Bundle decrypted. Config and URLs saved", flush=True)
    
    # Step 9 - Fetch and decrypt data
    print("\n" + "="*60, flush=True)
    print("Step 9: Fetching and Decrypting Data", flush=True)
    print("="*60, flush=True)
    box_out("Fetching encrypted data from Azure Blob Storage...")
    PPDX_SKALD.setState("Fetching and decrypting data", "Step 9", 9, 11, address)
    PPDX_SKALD.fetch_and_decrypt_data(config_file)
    print("Data fetched, decrypted, and saved", flush=True)
    
    # Step 10 - Running the application in docker
    print("\n" + "="*60, flush=True)
    print("Step 10: Running SKALD Application", flush=True)
    print("="*60, flush=True)
    box_out("Running the Application in Docker...")
    PPDX_SKALD.setState("Performing secure de-identification in TEE", "Step 10", 10, 11, address)
    PPDX_SKALD.run_docker_containers()
    
    # Step 11 - Encrypt inference and upload
    print("\n" + "="*60, flush=True)
    print("Step 11: Encrypting and Uploading Inference", flush=True)
    print("="*60, flush=True)
    box_out("Encrypting inference output...")
    PPDX_SKALD.setState("Encrypting and uploading inference", "Step 11", 11, 11, address)
    PPDX_SKALD.encrypt_inference_skald(config_file)
    print("Inference encrypted and uploaded to Azure Blob Storage", flush=True)
    
    
    # Final state
    print("\n" + "="*60, flush=True)
    print("DEPLOYMENT COMPLETE", flush=True)
    print("="*60, flush=True)
    PPDX_SKALD.setState("Secure Computation Complete", "Step 11", 11, 11, address)
    print("All steps completed successfully!", flush=True)
    PPDX_SKALD.restart_enclave_manager()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nDeployment interrupted by user", flush=True)
        PPDX_SKALD.restart_enclave_manager()
        exit(1)
    except Exception as e:
        print(f"\n\nERROR: {e}", flush=True)
        traceback.print_exc()
        PPDX_SKALD.restart_enclave_manager()
        exit(1)
