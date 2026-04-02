class CVEDatabase:

    def __init__(self):

        # Local CVE mapping (expandable)
        self.cve_map = {

            "openssh": [
                {
                    "cve": "CVE-2018-15473",
                    "severity": "HIGH",
                    "exploit": "ssh_user_enum"
                }
            ],

            "vsftpd": [
                {
                    "cve": "CVE-2011-2523",
                    "severity": "CRITICAL",
                    "exploit": "vsftpd_backdoor"
                }
            ],

            "apache": [
                {
                    "cve": "CVE-2021-41773",
                    "severity": "CRITICAL",
                    "exploit": "apache_path_traversal"
                }
            ],

            "http": [
                {
                    "cve": "CVE-2021-42013",
                    "severity": "HIGH",
                    "exploit": "apache_rce"
                }
            ]
        }

    def find_cves(self, services):

        vulnerabilities = []

        for port, service in services.items():

            service_lower = service.lower()

            for keyword in self.cve_map:

                if keyword in service_lower:

                    vulnerabilities.extend(
                        self.cve_map[keyword]
                    )

        return vulnerabilities
