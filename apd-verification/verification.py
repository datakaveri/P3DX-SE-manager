import json
import os
import base64
import subprocess

def decode_json_to_bin(folder_path):
    # Path to the binary_files.json
    json_file_path = 'binary_files.json'

    if not os.path.exists(json_file_path):
        print(f"Error: JSON file '{json_file_path}' not found.")
        return

    try:
        # Read the JSON data from the file
        with open(json_file_path, "r") as json_file:
            binary_data = json.load(json_file)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON file: {e}")
        return

    # Create output directory for the binary files
    output_dir = folder_path
    os.makedirs(output_dir, exist_ok=True)

    # Decode base64 content and write to binary files
    for file_name, encoded_content in binary_data.items():
        binary_content = base64.b64decode(encoded_content)
        output_file_path = os.path.join(output_dir, file_name)
        try:
            with open(output_file_path, "wb") as output_file:
                output_file.write(binary_content)
            print(f"Binary file '{file_name}' successfully decoded and saved.")
        except Exception as e:
            print(f"Error saving binary file '{file_name}': {e}")

def verify_guest_report():
    try:
        result = subprocess.run(['./snpguest', 'verify', 'attestation', '.', 'vm-verification/guest_report.bin'], capture_output=True, text=True, check=True)
        # Print the output
        print("Verification command output:")
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        # Handle errors
        print("Error executing verification command:")
        print(e.stderr)
    except FileNotFoundError:
        print(f"Error: Binary file not found.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def verify_tpm_quote():
    script_dir = os.path.dirname(__file__)
    os.chdir('vm-verification')
    try:
        # Construct the full command
        command = ["sudo", "tpm2_checkquote", "-u", '../outputfile.pem', "-m", 'message_output_file.msg', "-s", 'signature_output_file.sig', "-f", 'PCR_output_file.pcrs', "-g", "sha256"]
        
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        print(result.stdout)

        # Execute the command and redirect output to a file
        with open('../tpm_checkquote_output.txt', "w") as f:
            f.write(result.stdout)
            f.write(result.stderr)
        
        # Print the output file path
        print(f"Output written to tpm_checkquote_output.txt")
        os.chdir(script_dir)
        
    except subprocess.CalledProcessError as e:
        # Handle errors
        print("Error executing tpm2_checkquote command:")
        print(e.stderr)
        os.chdir(script_dir)
    except FileNotFoundError:
        print("Error: tpm2_checkquote command not found.")
        os.chdir(script_dir)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        os.chdir(script_dir)
    


if __name__ == "__main__":
    folder_path = 'vm-verification'

    decode_json_to_bin(folder_path)
    verify_guest_report()
    verify_tpm_quote()