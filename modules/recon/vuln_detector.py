class VulnerabilityDetectionModule:

    NAME = "vulnerability_detection"

    def discover(self, state):
        if state.phase != "VULNERABILITY_CORRELATION":
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
        http_info_map = state.network.get("http", {})
        directories = state.network.get("directories", [])
        services = state.services_detail

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
                    "title": f"Sensitive path exposed: {path}",
                    "type": "exposed_admin_interface",
                    "path": path,
                    "severity": "HIGH",
                    "confidence": 80,
                    "description": f"Sensitive admin interface exposed at {path}",
                    "evidence": [f"{d.get('url', path)} -> HTTP {d.get('status')}"],
                    "affected_service": "http",
                    "affected_port": d.get("port"),
                    "kill_chain_stage": "Vulnerability Correlation",
                    "attack_opportunities": [
                        "Review authentication handling and role exposure.",
                        "Inspect whether default credentials are expected in the lab.",
                    ],
                    "verification_steps": [
                        f"Open {d.get('url', path)} manually and inspect the workflow.",
                        "Document redirects, error messages, and login prompts.",
                    ],
                    "remediation": [
                        "Restrict access to administrative interfaces.",
                        "Apply strong authentication and segmentation.",
                    ],
                    "source": self.NAME,
                })

        # Detect outdated server versions
        outdated_keywords = [
            "apache/2.2",
            "apache/2.4.1",
            "nginx/1.10",
            "iis/7",
            "tomcat/5",
            "tomcat/6",
        ]

        for port, http_info in http_info_map.items():
            server = http_info.get("server", "")
            if not server:
                continue
            for keyword in outdated_keywords:
                if keyword.lower() in server.lower():
                    vulnerabilities.append({
                        "title": f"Outdated web stack reported on port {port}",
                        "type": "outdated_server",
                        "server": server,
                        "severity": "MEDIUM",
                        "confidence": 75,
                        "description": f"Outdated server version detected: {server}",
                        "evidence": [f"Server header: {server}", f"Base URL: {http_info.get('base_url')}"],
                        "affected_service": "http",
                        "affected_port": port,
                        "kill_chain_stage": "Vulnerability Correlation",
                        "attack_opportunities": [
                            "Compare the exact version with known legacy weaknesses.",
                            "Inspect default content and management pages.",
                        ],
                        "verification_steps": [
                            "Validate the version using page headers and nmap service detection.",
                            "Check whether the version is intentionally vulnerable in the lab image.",
                        ],
                        "remediation": [
                            "Upgrade the web server to a supported release.",
                            "Remove unnecessary default content and modules.",
                        ],
                        "source": self.NAME,
                    })

        # Detect FTP exposure
        if "21" in services:
            vulnerabilities.append({
                "title": "FTP exposed to unaudited network clients",
                "type": "ftp_exposed",
                "port": 21,
                "severity": "MEDIUM",
                "confidence": 70,
                "description": "FTP service exposed, may allow weak authentication or anonymous access",
                "evidence": [f"FTP service banner: {services['21'].get('banner') or services['21'].get('service')}"],
                "affected_service": services["21"].get("service"),
                "affected_port": "21",
                "kill_chain_stage": "Vulnerability Correlation",
                "attack_opportunities": [
                    "Review anonymous login and writable directory exposure.",
                    "Correlate with any exposed web upload paths.",
                ],
                "verification_steps": [
                    "Confirm whether anonymous access is enabled in the lab.",
                    "Inspect whether directory listings expose credentials or backups.",
                ],
                "remediation": [
                    "Disable anonymous FTP access.",
                    "Restrict reachable FTP services to required clients only.",
                ],
                "source": self.NAME,
            })

        if "445" in services or "139" in services:
            vulnerabilities.append({
                "title": "SMB/NetBIOS exposure suggests file-share attack surface",
                "type": "smb_exposure",
                "severity": "HIGH",
                "confidence": 79,
                "description": "Windows file-sharing services are reachable and may expose shares, guest access, or legacy lab vulnerabilities.",
                "evidence": [f"Open SMB-related ports: {[port for port in ('139', '445') if port in services]}"],
                "affected_service": "smb",
                "affected_port": "445" if "445" in services else "139",
                "kill_chain_stage": "Vulnerability Correlation",
                "attack_opportunities": [
                    "Enumerate shares and guest/anonymous access.",
                    "Review Samba version and training-lab relevance.",
                ],
                "verification_steps": [
                    "List accessible shares and permissions.",
                    "Identify whether guest access or null sessions are allowed.",
                ],
                "remediation": [
                    "Restrict SMB exposure.",
                    "Disable guest access and patch legacy Samba versions.",
                ],
                "source": self.NAME,
            })

        # Store vulnerabilities
        if vulnerabilities:
            print(f"[+] Found {len(vulnerabilities)} potential vulnerabilities")
            for v in vulnerabilities:
                state.add_finding(v)
                print(f"    [{v['severity']}] {v['description']}")
        else:
            print("[!] No obvious vulnerabilities detected")
        return {
            "success": True,
            "summary": f"Detected {len(vulnerabilities)} heuristic findings",
        }
