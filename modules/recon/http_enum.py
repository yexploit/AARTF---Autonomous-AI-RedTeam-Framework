import socket
import requests


class HTTPEnumerationModule:

    NAME = "http_enumeration"

    COMMON_PATHS = [
        "/",
        "/robots.txt",
        "/admin",
        "/login",
        "/dashboard",
        "/config",
        "/backup",
        "/test",
    ]

    def discover(self, state):

        if state.phase != "RECON":
            return []

        services = state.network.get("services", {})

        # check if HTTP port exists
        if "80" in services or "443" in services:
            return [{
                "name": self.NAME,
                "type": "recon"
            }]

        return []

    def execute(self, state):

        target_ip = state.target["ip"]

        print(f"[*] Running HTTP enumeration on {target_ip}")

        http_info = {}

        protocols = ["http", "https"]

        for proto in protocols:

            url = f"{proto}://{target_ip}"

            try:

                response = requests.get(url, timeout=5, verify=False)

                http_info["protocol"] = proto
                http_info["status_code"] = response.status_code

                # Server header
                server = response.headers.get("Server")
                if server:
                    http_info["server"] = server

                # interesting paths
                discovered_paths = []

                for path in self.COMMON_PATHS:

                    full_url = f"{url}{path}"

                    try:

                        r = requests.get(full_url, timeout=3, verify=False)

                        if r.status_code < 400:
                            discovered_paths.append(path)

                    except:
                        pass

                http_info["discovered_paths"] = discovered_paths

                break

            except requests.exceptions.RequestException:
                continue

        if http_info:

            state.network["http"] = http_info

            print("[+] HTTP service detected")
            print(f"[+] Server: {http_info.get('server', 'unknown')}")

            if http_info.get("discovered_paths"):
                print("[+] Interesting paths found:")
                for p in http_info["discovered_paths"]:
                    print(f"    {p}")

            return True

        else:

            print("[!] No HTTP service detected")

            return False
