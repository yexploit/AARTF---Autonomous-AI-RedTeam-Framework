import os
import datetime


class ReportGenerator:

    def __init__(self, state):

        self.state = state

        # Handle target safely
        if isinstance(state.target, dict):
            self.target = state.target.get("ip", "unknown")
        else:
            self.target = str(state.target)

        self.report_dir = "reports"

        # Create reports directory if not exists
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)

    # =============================
    # MAIN GENERATE FUNCTION
    # =============================

    def generate(self):

        safe_target = self.target.replace(".", "_").replace("/", "_")

        filename = f"{self.report_dir}/attack_report_{safe_target}.txt"

        report_content = self.build_report()

        with open(filename, "w", encoding="utf-8") as f:

            f.write(report_content)

        print(f"[+] Report generated: {filename}")

    # =============================
    # BUILD FULL REPORT CONTENT
    # =============================

    def build_report(self):

        report = ""

        # Header
        report += "=====================================\n"
        report += " AUTONOMOUS AI RED TEAM REPORT\n"
        report += "=====================================\n"

        report += f"\nGenerated: {datetime.datetime.now()}\n"

        report += f"Target: {self.target}\n"

        report += f"Final Phase: {self.state.phase}\n"

        # =============================
        # Open Ports
        # =============================

        report += "\n-------------------------------------\n"
        report += "OPEN PORTS\n"
        report += "-------------------------------------\n"

        open_ports = self.state.network.get("open_ports", {})

        if open_ports:
            for port, service in open_ports.items():
                report += f"Port {port}: {service}\n"
        else:
            report += "No open ports detected\n"

        # =============================
        # Services
        # =============================

        report += "\n-------------------------------------\n"
        report += "SERVICES\n"
        report += "-------------------------------------\n"

        services = self.state.network.get("services", {})

        if services:
            for port, service in services.items():
                report += f"{port}: {service}\n"
        else:
            report += "No services identified\n"

        # =============================
        # Vulnerabilities
        # =============================

        report += "\n-------------------------------------\n"
        report += "VULNERABILITIES\n"
        report += "-------------------------------------\n"

        vulnerabilities = self.state.network.get("vulnerabilities", [])

        if vulnerabilities:

            for vuln in vulnerabilities:

                cve = vuln.get("cve", "Unknown CVE")
                severity = vuln.get("severity", "Unknown")

                report += f"{cve} ({severity})\n"

        else:

            report += "No vulnerabilities detected\n"

        # =============================
        # Actions Taken
        # =============================

        report += "\n-------------------------------------\n"
        report += "ATTACK ACTIONS EXECUTED\n"
        report += "-------------------------------------\n"

        if hasattr(self.state, "actions_taken") and self.state.actions_taken:

            for action in self.state.actions_taken:

                report += f"{action}\n"

        else:

            report += "No actions recorded\n"

        # =============================
        # Session Data (POST EXPLOITATION)
        # =============================

        report += "\n-------------------------------------\n"
        report += "POST-EXPLOITATION SESSION DATA\n"
        report += "-------------------------------------\n"

        if hasattr(self.state, "session_data") and self.state.session_data:

            for cmd, output in self.state.session_data.items():

                report += f"\nCommand: {cmd}\n"

                report += "Output:\n"

                report += f"{output}\n"

        else:

            report += "No session interaction data available\n"

        # =============================
        # Compromise Status
        # =============================

        report += "\n-------------------------------------\n"
        report += "COMPROMISE STATUS\n"
        report += "-------------------------------------\n"

        report += f"Compromised: {self.state.compromised}\n"

        report += f"Privilege Escalated: {self.state.escalated}\n"

        report += "\n=====================================\n"
        report += " END OF REPORT\n"
        report += "=====================================\n"

        return report
