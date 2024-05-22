# Import the execute_guest_attestation function from the guest_attestation package
from guest_attestation import execute_guest_attestation
from token_verification import verify_and_decode_jwt
from vm_pcr_verification import vm_pcr_verification


def main():
    # Provide the Docker image link as an argument
    docker_image_link = "kaushalkirpekar/yolo_docker3"
    
    execute_guest_attestation(docker_image_link)
    verify_and_decode_jwt()
    vm_pcr_verification()

if __name__ == "__main__":
    main()
