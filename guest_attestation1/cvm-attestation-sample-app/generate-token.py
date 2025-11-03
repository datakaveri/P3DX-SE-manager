import subprocess
import os

def run_command_and_save_output(command, output_file):
    # Run the command using subprocess with shell=True to catch full stderr
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    # Always print outputs for debugging
    print("Return code:", process.returncode)
    print("STDOUT:\n", stdout.decode())
    print("STDERR:\n", stderr.decode())

    if process.returncode == 0:
        with open(output_file, "wb") as file:
            file.write(stdout)
        print("Token generated successfully. Output saved to", output_file)
    else:
        print("Error: Command failed.")

def main():
    command = "sudo ./AttestationClient -o token"
    output_file = os.path.abspath("../../keys/jwt-response.txt")
    run_command_and_save_output(command, output_file)

if __name__ == "__main__":
    main()
