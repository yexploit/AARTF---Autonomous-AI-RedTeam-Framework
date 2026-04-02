class AttackPathPlanner:

    def __init__(self, state):

        self.state = state

    def plan(self):

        print("[*] AI Attack Planner analyzing attack paths")

        vulnerabilities = self.state.network.get("vulnerabilities", [])
        privesc_candidates = self.state.post_exploit.get("privesc_candidates", [])
        directories = self.state.network.get("directories", [])
        services = self.state.network.get("services", {})

        plans = []

        # Plan based on admin interfaces
        for vuln in vulnerabilities:

            if vuln["type"] == "exposed_admin_interface":

                plans.append({
                    "path": f"Exploit admin interface at {vuln['path']}",
                    "score": 90,
                    "reason": "Admin interface exposed"
                })

            elif vuln["type"] == "outdated_server":

                plans.append({
                    "path": f"Exploit outdated server: {vuln['server']}",
                    "score": 80,
                    "reason": "Outdated server version"
                })

            elif vuln["type"] == "ftp_exposed":

                plans.append({
                    "path": "Attempt FTP credential attack",
                    "score": 60,
                    "reason": "FTP service exposed"
                })

        # PrivEsc plans
        for candidate in privesc_candidates:

            if candidate["severity"] == "CRITICAL":

                plans.append({
                    "path": f"Privilege escalation via {candidate['type']}",
                    "score": 95,
                    "reason": "Critical privilege escalation vector"
                })

            elif candidate["severity"] == "HIGH":

                plans.append({
                    "path": f"Privilege escalation via {candidate['type']}",
                    "score": 85,
                    "reason": "High severity privilege escalation"
                })

        # Sort plans
        plans.sort(key=lambda x: x["score"], reverse=True)

        if plans:

            best = plans[0]

            self.state.attack_plan = {
                "best_path": best["path"],
                "confidence": best["score"],
                "reason": best["reason"],
                "all_paths": plans
            }

            print("[+] Best attack path selected:")
            print(f"    Path: {best['path']}")
            print(f"    Confidence: {best['score']}")
            print(f"    Reason: {best['reason']}")

        else:

            self.state.attack_plan = {
                "best_path": None,
                "confidence": 0,
                "reason": "No viable attack paths found",
                "all_paths": []
            }

            print("[!] No viable attack paths found")

        return True
