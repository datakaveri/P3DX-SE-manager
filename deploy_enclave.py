import subprocess
import os
import shutil
import sys
import traceback
import P3DX_SDK

# Force unbuffered output for live logging
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)


def get_compose_url():
    """Get Docker Compose URL from command line argument."""
    if len(sys.argv) < 2:
        raise ValueError("compose_url is required. Usage: python deploy_enclave.py <compose_url>")
    return sys.argv[1]






def box_out(message):
    """Prints a box around a message using text characters."""
    lines = message.splitlines()
    max_width = max(len(line) for line in lines) if lines else 0
    
    print("+" + "-" * (max_width + 2) + "+", flush=True)
    for line in lines:
        print("| " + line.ljust(max_width) + " |", flush=True)
    print("+" + "-" * (max_width + 2) + "+", flush=True)


def cleanup_and_prepare_folders():
    """Clean up old files and prepare TEE folders."""
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
    
    P3DX_SDK.ensure_tee_folders()


def main():
    """Main deployment workflow."""
    compose_url = get_compose_url()
    
    print("="*60, flush=True)
    print("TEE Enclave Deployment", flush=True)
    print("="*60, flush=True)
    
    config_file = "DPconfig.json"
    config = P3DX_SDK.load_config_file(config_file)
    address = config["enclaveManagerAddress"]
    
    cleanup_and_prepare_folders()
    
    # Step 1 - Pulling docker compose & extracting docker image link
    print("\n" + "="*60, flush=True)
    print("Step 1: Pulling Docker Compose from GitHub", flush=True)
    print("="*60, flush=True)
    box_out("Pulling Docker Compose from GitHub...")
    P3DX_SDK.pull_compose_file(compose_url)
    print('Extracting docker image link...', flush=True)
    
    link = P3DX_SDK.extract_docker_image_from_compose()
    print(f"Docker image: {link}", flush=True)
    
    # Step 2 - Key generation
    print("\n" + "="*60, flush=True)
    print("Step 2: Generating Key Pair", flush=True)
    print("="*60, flush=True)
    box_out("Generating and saving key pair...")
    P3DX_SDK.setState("TEE Attestation & Authorisation", "Step 2", 2, 11, address)
    P3DX_SDK.generate_and_save_key_pair()
    print("Key pair generated", flush=True)
    
    # Step 3 - Docker image pulling
    print("\n" + "="*60, flush=True)
    print("Step 3: Pulling Docker Image", flush=True)
    print("="*60, flush=True)
    box_out("Pulling docker image...")
    P3DX_SDK.pull_docker_image(link)
    print("Docker image pulled", flush=True)
    image_hash = P3DX_SDK.hash_docker_image(link)
    P3DX_SDK.save_image_hash(image_hash)

    # Step 4 - Measuring enclave manager code into PCR 15 
    print("\n" + "="*60, flush=True)
    print("Step 4: Measuring Enclave Manager Code ", flush=True)
    print("="*60, flush=True)
    box_out("Measuring enclave manager code")
    P3DX_SDK.measure_enclave_manager_code_vtpm()
    print("Enclave manager code measured and stored", flush=True)
    
    # # Measure Docker image
    box_out("Measuring Docker image...")
    P3DX_SDK.measureDockervTPM(link)
    print("Docker image measured and stored", flush=True)

    # Step 4.5 - Generate deployment nonce
    nonce = P3DX_SDK.generate_nonce()
    P3DX_SDK.save_nonce(nonce)
    P3DX_SDK.extend_nonce_to_pcr8(nonce)
    print(f"Generated deployment nonce: {nonce}", flush=True)

    # Step 5 - Send VTPM & public key to MAA & get attestation token
    print("\n" + "="*60, flush=True)
    print("Step 5: Guest Attestation", flush=True)
    print("="*60, flush=True)
    box_out("Guest Attestation Executing...")
    P3DX_SDK.execute_guest_attestation()
    print("Guest Attestation complete. JWT received from MAA", flush=True)
    
    # Step 6 - Send the JWT to UI
    print("\n" + "="*60, flush=True)
    print("Step 6: Sending JWT to UI", flush=True)
    print("="*60, flush=True)
    box_out("Sending JWT to UI for polling...")
    jwt = P3DX_SDK.get_jwt_from_file()
    P3DX_SDK.send_jwt_to_ui(jwt, address)
    print("JWT sent to UI. Waiting for bundle...", flush=True)
    
    # Step 7 - Receive encrypted bundle from UI
    print("\n" + "="*60, flush=True)
    print("Step 7: Receiving Encrypted Bundle from UI", flush=True)
    print("="*60, flush=True)
    box_out("Waiting for encrypted bundle from UI...")
    P3DX_SDK.setState("Receiving encrypted bundle", "Step 7", 7, 11, address)
    bundle_data = P3DX_SDK.wait_for_bundle_from_ui(address, timeout=300)
    bundle_path = P3DX_SDK.save_bundle_to_file(bundle_data)
    print("Bundle received and saved", flush=True)
    
    # Step 8 - Decrypt bundle
    print("\n" + "="*60, flush=True)
    print("Step 8: Decrypting Bundle", flush=True)
    print("="*60, flush=True)
    box_out("Decrypting bundle...")
    P3DX_SDK.setState("Decrypting bundle", "Step 8", 8, 11, address)
    private_key_path = "keys/private_key.pem"
    P3DX_SDK.decrypt_bundle_tee(bundle_path, private_key_path)
    print("Bundle decrypted. Config and URLs saved", flush=True)
    
    # Step 9 - Fetch and decrypt data
    print("\n" + "="*60, flush=True)
    print("Step 9: Fetching and Decrypting Data", flush=True)
    print("="*60, flush=True)
    box_out("Fetching encrypted data from Azure Blob Storage...")
    P3DX_SDK.setState("Fetching and decrypting data", "Step 9", 9, 11, address)
    P3DX_SDK.fetch_and_decrypt_data(config_file)
    print("Data fetched, decrypted, and saved", flush=True)
    
    # Step 10 - Running the application in docker
    print("\n" + "="*60, flush=True)
    print("Step 10: Running Application", flush=True)
    print("="*60, flush=True)
    box_out("Running the Application in Docker...")
    P3DX_SDK.setState("Running application in TEE", "Step 10", 10, 11, address)
    P3DX_SDK.run_docker_containers()
    
    # Step 11 - Encrypt inference and upload
    print("\n" + "="*60, flush=True)
    print("Step 11: Encrypting and Uploading Inference", flush=True)
    print("="*60, flush=True)
    box_out("Encrypting inference output...")
    P3DX_SDK.setState("Encrypting and uploading inference", "Step 11", 11, 11, address)
    P3DX_SDK.encrypt_and_upload_output(config_file)
    print("Inference encrypted and uploaded to Azure Blob Storage", flush=True)
    
    
    # Final state
    print("\n" + "="*60, flush=True)
    print("DEPLOYMENT COMPLETE", flush=True)
    print("="*60, flush=True)
    P3DX_SDK.setState("Secure Computation Complete", "Step 11", 11, 11, address)
    print("All steps completed successfully!", flush=True)
    P3DX_SDK.restart_enclave_manager()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nDeployment interrupted by user", flush=True)
        P3DX_SDK.restart_enclave_manager()
        exit(1)
    except Exception as e:
        print(f"\n\nERROR: {e}", flush=True)
        traceback.print_exc()
        P3DX_SDK.restart_enclave_manager()
        exit(1)
