import subprocess
import os
import time


class FTPAnonymousModule:

    NAME = "ftp_anonymous_login"

    def discover(self, state):

        if state.phase != "INITIAL_ACCESS":
            return []

        services = state.network.get("services", {})

        if "21" in services:
            return [{
                "name": self.NAME,
                "type": "initial_access"
            }]

        return []

    def execute(self, state):

        target_ip = state.target["ip"]

        print(f"[*] Attempting FTP anonymous login on {target_ip}")

        # Build FTP script
        ftp_script = f"""
open {target_ip}
user anonymous anonymous
quit
"""

        try:

            proc = subprocess.run(
                ["ftp", "-n"],
                input=ftp_script.encode(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10
            )

            # Convert bytes → string safely
            output = proc.stdout.decode("utf-8", errors="ignore")

            # Check login success
            if "230" in output or "logged in" in output.lower():

                print("[+] Anonymous FTP login successful")

                state.access["ftp_anonymous"] = True

                return True

            else:

                print("[!] Anonymous FTP login failed")

                return False

        except subprocess.TimeoutExpired:

            print("[!] FTP command timed out")

            return False

        except FileNotFoundError:

            print("[!] FTP client not found")

            return False

        except Exception as e:

            print(f"[!] FTP error: {e}")

            return False

        finally:

            # Safe cleanup placeholder (if temp files added later)
            time.sleep(0.2)
