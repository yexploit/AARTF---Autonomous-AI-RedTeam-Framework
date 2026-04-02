from core.attack_controller import AttackController
from core.attack_graph import AttackGraph
from core.attack_timeline import AttackTimeline
from core.pdf_report import PDFReportGenerator
from core.report_generator import ReportGenerator
from modules.exploitation.http_bruteforce import HTTPBruteforceModule
from modules.exploitation.metasploit_exploit import MetasploitExploitModule
from modules.exploitation.reverse_shell import ReverseShellModule
from modules.exploitation.ssh_bruteforce import SSHBruteforceModule
from modules.exploitation.ssh_credential_reuse import SSHCredentialReuseModule
from modules.post_exploitation.credential_harvester import CredentialHarvesterModule
from modules.post_exploitation.lateral_movement import LateralMovementModule
from modules.post_exploitation.persistence import PersistenceModule
from modules.post_exploitation.privilege_escalation import PrivilegeEscalationModule
from modules.recon.nmap_scan import NmapScanModule
from modules.recon.vuln_scan import VulnerabilityScanModule


class AttackEngine:
    MAX_RETRIES = 2
    MAX_ITERATIONS = 20

    def __init__(self, state):
        self.state = state
        print("[+] Engine initialized")

        self.recon_modules = [VulnerabilityScanModule(), NmapScanModule()]
        self.exploit_modules = [
            MetasploitExploitModule(),
            SSHBruteforceModule(),
            HTTPBruteforceModule(),
            ReverseShellModule(),
            SSHCredentialReuseModule(),
        ]
        self.post_exploit_modules = [
            PrivilegeEscalationModule(),
            LateralMovementModule(),
            CredentialHarvesterModule(),
            PersistenceModule(),
        ]

        # O(1) module lookup by action name instead of scanning all modules.
        all_modules = self.recon_modules + self.exploit_modules + self.post_exploit_modules
        self.module_by_name = {module.NAME: module for module in all_modules}
        self.controller = AttackController(state)

    def run(self):
        print("[*] Starting autonomous attack chain")

        for iteration in range(1, self.MAX_ITERATIONS + 1):
            if self.state.phase == "COMPLETE":
                break

            print(f"[DEBUG] Current Phase: {self.state.phase}")
            actions = self.discover_actions()

            if not actions:
                print("[!] No actions available.")
                break

            action = actions[0]
            self.execute_action(action)
            self.controller.update_phase()
        else:
            print("[!] Max iterations reached. Stopping.")

        print("[+] Attack chain finished")

    def generate_reports(self):
        print("[*] Generating reports...")
        ReportGenerator(self.state).generate()
        PDFReportGenerator(self.state).generate()
        AttackGraph(self.state).save_png()
        AttackTimeline(self.state).export_video()
        print("[+] All reports generated")

    def discover_actions(self):
        actions = []

        if self.state.phase == "RECON":
            modules = self.recon_modules
        elif self.state.phase in ("INITIAL_ACCESS", "EXPLOITATION"):
            modules = self.exploit_modules
        elif self.state.phase in ("POST_ACCESS", "PRIVILEGE_ESCALATION"):
            modules = self.post_exploit_modules
        else:
            modules = []

        for module in modules:
            actions.extend(module.discover(self.state))

        # Deterministic order keeps behavior stable for testing.
        actions.sort(key=lambda item: item.get("name", ""))
        return actions

    def execute_action(self, action):
        action_name = action["name"]
        print(f"[*] Executing: {action_name}")

        attempts = self.state.action_attempts.get(action_name, 0) + 1
        self.state.action_attempts[action_name] = attempts

        if attempts > self.MAX_RETRIES:
            print(f"[!] Max retries reached for {action_name}")
            return False

        module = self.module_by_name.get(action_name)
        if module is None:
            print(f"[!] No module implementation found for {action_name}")
            return False

        success = module.execute(self.state)
        if success:
            print(f"[+] {action_name} succeeded")
        else:
            print(f"[!] {action_name} failed")
        return success


