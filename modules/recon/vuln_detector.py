class VulnerabilityDetectionModule:

    NAME = "vulnerability_detection"

    def discover(self, state):

        if state.phase != "RECON":
            return []

        if "http" in state.network or "directories" in state.network:
            return [{
                "name": self.NAME,
                "type": "recon"
            }]

        return []

    def execute(self, state):

        print("[*] Running vulnerability detection")

        vulnerabilities = []

        http_info = state.network.get("http", {})
        directories = state.network.get("directories", [])
        services = state.network.get("services", {})

        # Detect exposed admin panels
        sensitive_paths = [
            "/admin",
            "/login",
            "/dashboard",
            "/panel",
            "/config",
            "/backup"
        ]

        for d in directories:

            path = d.get("path")

            if path in sensitive_paths:

                vulnerabilities.append({
                    "type": "exposed_admin_interface",
                    "path": path,
                    "severity": "HIGH",
                    "description": f"Sensitive admin interface exposed at {path}"
                })

        # Detect outdated server versions
        server = http_info.get("server", "")

        if server:

            outdated_keywords = [
                "apache/2.2",
                "apache/2.4.1",
                "nginx/1.10",
                "iis/7"
            ]

            for keyword in outdated_keywords:

                if keyword.lower() in server.lower():

                    vulnerabilities.append({
                        "type": "outdated_server",
                        "server": server,
                        "severity": "MEDIUM",
                        "description": f"Outdated server version detected: {server}"
                    })

        # Detect FTP exposure
        if "21" in services:

            vulnerabilities.append({
                "type": "ftp_exposed",
                "port": 21,
                "severity": "MEDIUM",
                "description": "FTP service exposed, may allow brute force or anonymous login"
            })

        # Store vulnerabilities
        if vulnerabilities:

            state.network["vulnerabilities"] = vulnerabilities

            print(f"[+] Found {len(vulnerabilities)} potential vulnerabilities")

            for v in vulnerabilities:

                print(f"    [{v['severity']}] {v['description']}")

        else:

            print("[!] No obvious vulnerabilities detected")

        return True
