import requests
import os


class DirectoryBruteforceModule:

    NAME = "directory_bruteforce"

    DEFAULT_WORDLIST = [
        "admin",
        "login",
        "dashboard",
        "config",
        "backup",
        "uploads",
        "test",
        "dev",
        "api",
        "robots.txt",
        "secret",
        "panel",
    ]

    def discover(self, state):

        if state.phase != "RECON":
            return []

        if "http" in state.network:
            return [{
                "name": self.NAME,
                "type": "recon"
            }]

        return []

    def execute(self, state):

        target_ip = state.target["ip"]

        http_info = state.network.get("http")

        if not http_info:
            return False

        protocol = http_info.get("protocol", "http")

        base_url = f"{protocol}://{target_ip}"

        print(f"[*] Running directory brute-force on {base_url}")

        discovered = []

        for word in self.DEFAULT_WORDLIST:

            url = f"{base_url}/{word}"

            try:

                response = requests.get(url, timeout=3, verify=False)

                if response.status_code in [200, 301, 302, 403]:

                    print(f"[+] Found: /{word} (Status: {response.status_code})")

                    discovered.append({
                        "path": f"/{word}",
                        "status": response.status_code
                    })

            except requests.exceptions.RequestException:
                pass

        if discovered:

            state.network["directories"] = discovered

            print(f"[+] Found {len(discovered)} directories")

        else:

            print("[!] No directories found")

        return True
