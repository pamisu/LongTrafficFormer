import os
import subprocess
import shutil

def split_pcap_file(input_dir):
    """
    Split a pcap file into flows using SplitCap.
    """
    original_dir = os.getcwd()
    os.chdir(input_dir)

    output_dir = "flow"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    else:
        os.system(f'rmdir /S /Q {output_dir}')
        os.makedirs(output_dir, exist_ok=True)

    for filename in os.listdir('.'):
        if filename.endswith('.pcap'):
            print(f"Processing {filename}...")
            output_dir = os.path.join("flow", os.path.splitext(filename)[0])
            command = [
                "SplitCap", "-r", filename, "-o", output_dir, "-s", "session"
            ]
            subprocess.run(command, check=True)
    
    os.chdir(original_dir)

if __name__ == "__main__":
    split_pcap_file("data/test/")
    # split_pcap_file("data/ustc-tfc/")