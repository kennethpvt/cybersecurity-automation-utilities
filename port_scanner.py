import socket
import sys
import threading
from datetime import datetime
from queue import Queue

# Thread-safe print lock
print_lock = threading.Lock()

# Define target and ports
TARGET = "127.0.0.1"
START_PORT = 1
END_PORT = 1024
THREAD_COUNT = 100

print("-" * 50)
print(f"Scanning Target: {TARGET}")
print(f"Time Started: {str(datetime.now())}")
print("-" * 50)

queue = Queue()
open_ports = []

def port_scan(port):
    """Attempts to connect to a specific port on the target IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        result = s.connect_ex((TARGET, port))
        if result == 0:
            with print_lock:
                print(f"[+] Port {port} is OPEN")
            open_ports.append(port)
        s.close()
    except socket.gaierror:
        with print_lock:
            print("\n[!] Hostname could not be resolved.")
        sys.exit()
    except socket.error:
        with print_lock:
            print("\n[!] Could not connect to server.")
        sys.exit()

def threader():
    """Worker thread to pull ports from the queue and scan them."""
    while True:
        worker = queue.get()
        port_scan(worker)
        queue.task_done()

def main():
    for _ in range(THREAD_COUNT):
        t = threading.Thread(target=threader)
        t.daemon = True
        t.start()

    for port in range(START_PORT, END_PORT + 1):
        queue.put(port)

    queue.join()
    
    print("-" * 50)
    print(f"Scan complete. Open ports found: {sorted(open_ports)}")
    print("-" * 50)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Exiting script via user interruption.")
        sys.exit()
