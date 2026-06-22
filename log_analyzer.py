import os
import re
from collections import Counter

# Regular expression pattern to parse standard Apache/Nginx combined log format
LOG_PATTERN = r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?"\w+ (?P<request>.*?) HTTP/.*?" (?P<status>\d{3})'

def analyze_log(file_path):
    if not os.path.exists(file_path):
        print(f"[!] Error: File '{file_path}' not found.")
        return

    ip_list = []
    status_list = []
    failed_login_ips = []

    print(f"[*] Analyzing log file: {file_path}...\n")

    with open(file_path, "r") as file:
        for line in file:
            match = re.search(LOG_PATTERN, line)
            if match:
                ip = match.group("ip")
                status = match.group("status")
                request = match.group("request")

                ip_list.append(ip)
                status_list.append(status)

                # Flag potential suspicious activity (401/403 errors on login endpoints)
                if status in ["401", "403"] and ("login" in request.lower() or "admin" in request.lower()):
                    failed_login_ips.append(ip)

    ip_counts = Counter(ip_list)
    status_counts = Counter(status_list)
    suspicious_counts = Counter(failed_login_ips)

    print("=" * 60)
    print("                      SECURITY LOG REPORT                      ")
    print("=" * 60)
    
    print("\n[+] Top 5 Most Frequent IP Addresses:")
    for ip, count in ip_counts.most_common(5):
        print(f"    - {ip}: {count} requests")

    print("\n[+] HTTP Status Code Breakdown:")
    for status, count in status_counts.items():
        print(f"    - Status {status}: {count} occurrences")

    print("\n[!] Security Alerts (Potential Brute-Force / Unauthorized Probing):")
    if suspicious_counts:
        for ip, count in suspicious_counts.items():
            if count >= 3:
                print(f"    - ALERT: IP {ip} failed authentication {count} times.")
    else:
        print("    - No suspicious repetitive authentication failures detected.")
    print("=" * 60)

if __name__ == "__main__":
    test_log = "access.log"
    if not os.path.exists(test_log):
        with open(test_log, "w") as f:
            f.write('192.168.1.50 - - [22/Jun/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 4523\n')
            f.write('192.168.1.105 - - [22/Jun/2026:10:01:00 +0000] "POST /wp-login.php HTTP/1.1" 401 230\n')
            f.write('192.168.1.105 - - [22/Jun/2026:10:01:05 +0000] "POST /wp-login.php HTTP/1.1" 401 230\n')
            f.write('192.168.1.105 - - [22/Jun/2026:10:01:10 +0000] "POST /wp-login.php HTTP/1.1" 401 230\n')
            f.write('10.0.0.5 - - [22/Jun/2026:10:02:00 +0000] "GET /admin HTTP/1.1" 403 152\n')
    
    analyze_log(test_log)
