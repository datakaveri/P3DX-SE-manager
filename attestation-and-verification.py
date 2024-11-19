import subprocess
import os
import time

def execute_python_file(folder_path, file_name, args=None):
    file_path = os.path.join(folder_path, file_name)
    try:
        if args:
            os.chdir(folder_path)
            subprocess.run(['python3', file_name, *args], check=True)
            os.chdir('..')
        else:
            subprocess.run(['python3', file_name], check=True, cwd=folder_path)
    except subprocess.CalledProcessError as e:
        print(f"Error executing {file_name}: {e}")

# Define the folder paths and file names
folders_and_files = [
    ('guest-attestation', 'guest-attestation.py', ['kaushalkirpekar/yolo_docker3']),
    ('token-verification', 'jwt_verification.py', None),
    ('pcr-verification', 'pcr_verification.py', None)
]

# Execute each Python file
for folder, file, args in folders_and_files:
    execute_python_file(folder, file, args)
    time.sleep(5)
