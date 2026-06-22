import subprocess
import sys
import shutil
from datetime import datetime

def run_nmap_vuln_scan(target_ip):
    if not shutil.which("nmap"):
        print("[!] Error: Nmap installation not detected on system PATH.")
        print("[*] Please install Nmap manually before executing this automation tool.")
        sys.exit(1)

    output_file = f"vuln_scan_report_{target_ip.replace('.', '_')}.txt"
    
    print("-" * 60)
    print(f"[*] Initializing Automated Nmap Vulnerability Scan on: {target_ip}")
    print(f"[*] Utilizing Nmap Scripting Engine (NSE) default vulnerability scripts...")
    print(f"[*] Target Report Destination: {output_file}")
    print("-" * 60)

    nmap_command = ["nmap", "-sV", "--script", "vuln", "-oN", output_file, target_ip]

    try:
        process = subprocess.Popen(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                print(output.strip())

        rc = process.poll()
        if rc == 0:
            print("\n[+] Scan completed successfully.")
            print(f"[+] Security vulnerabilities mapped to detailed log file: {output_file}")
        else:
            stderr_output = process.stderr.read()
            print(f"\n[!] Nmap error encountered: {stderr_output}")

    except KeyboardInterrupt:
        print("\n[!] Execution terminated early by user request.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Unexpected execution failure: {str(e)}")

if __name__ == "__main__":
    print("WARNING: Only run vulnerability scans against assets you own or have written permission to test.")
    target = input("Enter target IP or Domain (e.g., 127.0.0.1): ").strip()
    
    if target:
        run_nmap_vuln_scan(target)
    else:
        print("[!] Execution halted: Target IP parameter missing.")
