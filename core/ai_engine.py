import json


class AIEngine:

    def __init__(self, state):

        self.state = state

    def analyze(self):

        print("[*] AI Engine analyzing attack data")

        vulnerabilities = self.state.network.get("vulnerabilities", [])
        privesc = self.state.post_exploit.get("privesc_candidates", [])
        directories = self.state.network.get("directories", [])
        services = self.state.network.get("services", {})

        summary = {

            "target": self.state.target,

            "services": list(services.keys()),

            "vulnerabilities": vulnerabilities,

            "directories": directories,

            "privilege_escalation": privesc

        }

        reasoning = self.generate_reasoning(summary)

        self.state.ai_analysis = reasoning

        print("[+] AI Analysis complete")

        print("    Recommendation:", reasoning["recommendation"])

        return True

    def generate_reasoning(self, data):

        # Rule-based AI reasoning (safe fallback)

        if data["privilege_escalation"]:

            return {
                "recommendation": "Attempt privilege escalation first",
                "confidence": 90,
                "reason": "Privilege escalation vectors detected"
            }

        if data["vulnerabilities"]:

            vuln = data["vulnerabilities"][0]

            return {
                "recommendation": f"Exploit vulnerability: {vuln['type']}",
                "confidence": 80,
                "reason": vuln["description"]
            }

        if data["directories"]:

            return {
                "recommendation": "Investigate discovered web directories",
                "confidence": 60,
                "reason": "Interesting web paths discovered"
            }

        return {
            "recommendation": "Continue reconnaissance",
            "confidence": 30,
            "reason": "No obvious attack vectors yet"
        }
