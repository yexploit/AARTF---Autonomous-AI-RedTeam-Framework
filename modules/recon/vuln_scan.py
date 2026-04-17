from core.cve_database import CVEDatabase


class VulnerabilityScanModule:

    NAME = "vulnerability_scan"

    def discover(self, state):
        if state.phase == "VULNERABILITY_CORRELATION":
            return [{
                "name": self.NAME
            }]
        return []

    def execute(self, state):
        print("[*] Scanning for vulnerabilities...")
        db = CVEDatabase()
        findings = db.correlate(state)
        if findings:
            print("[+] Vulnerabilities found:")
            for finding in findings:
                state.add_finding(finding)
                print(f"   {finding['title']} ({finding['severity']})")
        else:
            print("[!] No vulnerabilities found")
        return {
            "success": True,
            "summary": f"Correlated {len(findings)} service-driven risks",
        }
