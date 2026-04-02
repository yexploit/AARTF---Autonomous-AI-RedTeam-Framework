from core.cve_database import CVEDatabase


class VulnerabilityScanModule:

    NAME = "vulnerability_scan"

    def discover(self, state):

        if state.phase == "RECON":

            return [{
                "name": self.NAME
            }]

        return []

    def execute(self, state):

        print("[*] Scanning for vulnerabilities...")

        services = state.network.get("services", {})

        db = CVEDatabase()

        vulns = db.find_cves(services)

        state.network["vulnerabilities"] = vulns

        if vulns:

            print("[+] Vulnerabilities found:")

            for v in vulns:

                print(f"   {v['cve']} ({v['severity']})")

        else:

            print("[!] No vulnerabilities found")

        return True
