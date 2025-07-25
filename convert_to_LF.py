import os
import subprocess
import sys

def check_dos2unix():
    """Verify if dos2unix is installed"""
    if subprocess.call(["which", "dos2unix"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
        print("Error: dos2unix not installed.  Install it with 'sudo apt update && sudo apt install dos2unix'")
        sys.exit(1)

def convert_files_to_lf(start_dir=".."):
    """Search for all .sh files into the folder and convert them using dos2unix."""
    for root, dirs, files in os.walk(start_dir):
        for file in files:
            if file.endswith(".sh"):
                filepath = os.path.join(root, file)
                subprocess.run(["dos2unix", filepath], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print(f"Convertited: {file}")
    print("\033[92mConversion complete! Every .sh file is in the LF format.\033[0m")

if __name__ == "__main__":
    check_dos2unix()
    convert_files_to_lf()
