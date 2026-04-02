import subprocess
import time
import socket
import shutil


class MetasploitManager:

    def __init__(self):

        self.host = "127.0.0.1"
        self.port = 55553
        self.password = "password123"

    # Check if RPC already running
    def is_running(self):

        try:

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            sock.settimeout(1)

            result = sock.connect_ex((self.host, self.port))

            sock.close()

            return result == 0

        except Exception:

            return False

    # Start RPC automatically
    def start_rpc(self):

        if self.is_running():

            print("[+] Metasploit RPC already running")

            return True

        print("[*] Starting Metasploit RPC automatically...")
        if not shutil.which("msfrpcd"):
            print("[!] msfrpcd command not found. Install Metasploit RPC daemon first.")
            return False

        try:

            subprocess.Popen(
                [
                    "msfrpcd",
                    "-P", self.password,
                    "-S",
                    "-a", self.host,
                    "-p", str(self.port)
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            time.sleep(5)

            if self.is_running():

                print("[+] Metasploit RPC started successfully")

                return True

            else:

                print("[!] Failed to start Metasploit RPC")

                return False

        except Exception as e:

            print(f"[!] RPC start error: {e}")

            return False
