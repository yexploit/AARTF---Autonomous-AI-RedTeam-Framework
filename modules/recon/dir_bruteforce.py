import requests


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
        if state.phase != "ENUMERATION":
            return []

        if "http" in state.network:
            return [{
                "name": self.NAME,
                "type": "recon"
            }]

        return []

    def execute(self, state):
        target_ip = state.target["ip"]
        discovered = []
        http_info_map = state.network.get("http", {})

        if not http_info_map:
            return {"success": False, "summary": "HTTP enumeration data unavailable"}

        for port, http_info in http_info_map.items():
            protocol = http_info.get("protocol", "http")
            base_url = http_info.get("base_url") or f"{protocol}://{target_ip}"
            print(f"[*] Running directory brute-force on {base_url}")

            for word in self.DEFAULT_WORDLIST:
                url = f"{base_url}/{word}"
                try:
                    response = requests.get(url, timeout=3, verify=False)
                except requests.exceptions.RequestException:
                    continue

                if response.status_code in [200, 301, 302, 403]:
                    print(f"[+] Found: /{word} (Status: {response.status_code})")
                    discovered.append({
                        "path": f"/{word}",
                        "status": response.status_code,
                        "url": url,
                        "port": port,
                    })

        if discovered:
            state.network["directories"] = discovered
            print(f"[+] Found {len(discovered)} directories")
            admin_hits = [item for item in discovered if item["path"] in {"/admin", "/login", "/dashboard", "/panel", "/config", "/backup"}]
            for hit in admin_hits:
                state.add_finding(
                    {
                        "title": f"Sensitive web path exposed at {hit['path']}",
                        "type": "sensitive_web_path",
                        "severity": "MEDIUM",
                        "confidence": 72,
                        "description": f"The path {hit['path']} was reachable on {hit['url']}.",
                        "evidence": [f"{hit['url']} -> HTTP {hit['status']}"],
                        "affected_service": "http",
                        "affected_port": hit["port"],
                        "kill_chain_stage": "Enumeration",
                        "attack_opportunities": [
                            "Review for default content, backups, or exposed workflows.",
                            "Inspect whether authentication is enforced consistently.",
                        ],
                        "verification_steps": [
                            f"Browse to {hit['url']} manually.",
                            "Check whether the content discloses credentials, configs, or application metadata.",
                        ],
                        "remediation": [
                            "Remove unnecessary exposed content.",
                            "Restrict access to non-public application paths.",
                        ],
                        "source": self.NAME,
                    }
                )
            return {
                "success": True,
                "summary": f"Found {len(discovered)} interesting web paths",
            }

        print("[!] No directories found")
        return {"success": True, "summary": "No common web paths discovered"}
