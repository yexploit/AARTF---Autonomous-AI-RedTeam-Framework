from core.attack_graph import AttackGraph
from core.ai_prioritizer import AIAttackPlanner
from core.attack_timeline import AttackTimeline
from core.pdf_report import PDFReportGenerator
from core.report_generator import ReportGenerator
from modules.recon.dir_bruteforce import DirectoryBruteforceModule
from modules.recon.http_enum import HTTPEnumerationModule
from modules.recon.host_pattern_analyzer import HostPatternAnalyzerModule
from modules.recon.mail_analyzer import MailAnalyzerModule
from modules.recon.nmap_scan import NmapScanModule
from modules.recon.protocol_probe import ProtocolProbeModule
from modules.recon.service_advisor import ServiceAdvisoryModule
from modules.recon.share_enum import ShareEnumerationModule
from modules.recon.vuln_detector import VulnerabilityDetectionModule
from modules.recon.vuln_scan import VulnerabilityScanModule


class AttackEngine:
    def __init__(self, state):
        self.state = state
        print("[+] Engine initialized")
        self.phase_modules = {
            "RECONNAISSANCE": [NmapScanModule()],
            "ENUMERATION": [HTTPEnumerationModule(), DirectoryBruteforceModule(), ProtocolProbeModule(), ShareEnumerationModule(), ServiceAdvisoryModule()],
            "VULNERABILITY_CORRELATION": [VulnerabilityScanModule(), VulnerabilityDetectionModule(), HostPatternAnalyzerModule(), MailAnalyzerModule()],
        }
        self.planner = AIAttackPlanner()

    def run(self):
        print("[*] Starting advisory assessment workflow")
        phase_sequence = [
            "RECONNAISSANCE",
            "ENUMERATION",
            "VULNERABILITY_CORRELATION",
            "ATTACK_PATH_PLANNING",
            "VALIDATION_GUIDANCE",
            "POST_COMPROMISE_OPPORTUNITIES",
            "REPORTING",
        ]

        for phase in phase_sequence:
            self.state.update_phase(phase)
            print(f"[*] Phase: {phase}")
            if phase in self.phase_modules:
                self._run_modules_for_phase(phase)
            elif phase == "ATTACK_PATH_PLANNING":
                self.plan_attack_paths()
            elif phase == "VALIDATION_GUIDANCE":
                self.generate_validation_guidance()
            elif phase == "POST_COMPROMISE_OPPORTUNITIES":
                self.generate_post_compromise_notes()
            elif phase == "REPORTING":
                self.summarize_assessment()

        self.state.update_phase("COMPLETE")
        self.state.status = "COMPLETED"
        print("[+] Advisory assessment finished")

    def generate_reports(self):
        print("[*] Generating reports...")
        ReportGenerator(self.state).generate()
        PDFReportGenerator(self.state).generate()
        AttackGraph(self.state).save_png()
        AttackTimeline(self.state).export_video()
        print("[+] All reports generated")

    def _run_modules_for_phase(self, phase):
        modules = self.phase_modules.get(phase, [])
        for module in modules:
            action_name = getattr(module, "NAME", module.__class__.__name__)
            self.state.action_attempts[action_name] = self.state.action_attempts.get(action_name, 0) + 1
            print(f"[*] Executing: {action_name}")
            try:
                result = module.execute(self.state)
                success = self._is_success(result)
                details = self._extract_details(result)
            except Exception as exc:
                success = False
                details = str(exc)
                print(f"[!] {action_name} failed: {exc}")

            status = "success" if success else "partial"
            self.state.log_action(action_name, phase, status, details)
            if success:
                print(f"[+] {action_name} completed")
            else:
                print(f"[!] {action_name} returned limited results")

    def _is_success(self, result):
        if isinstance(result, dict):
            return bool(result.get("success", True))
        return bool(result)

    def _extract_details(self, result):
        if isinstance(result, dict):
            return result.get("summary") or result.get("details") or ""
        return ""

    def plan_attack_paths(self):
        print("[*] Planning likely attack paths")
        self.planner.analyze(self.state)
        self.state.log_action(
            "ai_attack_path_planner",
            self.state.phase,
            "success",
            f"{len(self.state.attack_paths)} attack paths generated",
        )

    def generate_validation_guidance(self):
        print("[*] Building validation guidance")
        if not self.state.attack_paths:
            self.state.add_learning_note(
                "Validation Guidance",
                "No high-confidence attack paths were found. Review banner data, service versions, and web content manually.",
            )
            return

        for attack_path in self.state.attack_paths[:3]:
            title = f"Validate {attack_path['title']}"
            detail = " -> ".join(attack_path["steps"]) if attack_path["steps"] else attack_path["summary"]
            self.state.add_learning_note(title, detail)

    def generate_post_compromise_notes(self):
        print("[*] Compiling post-compromise opportunities")
        if not self.state.network.get("services"):
            return

        if "445" in self.state.network["services"] or "139" in self.state.network["services"]:
            self.state.add_learning_note(
                "Post-Compromise Windows Follow-up",
                "If valid credentials are obtained later, review share permissions, local admin reuse, and lateral movement opportunities across SMB-exposed hosts.",
            )
        if "22" in self.state.network["services"]:
            self.state.add_learning_note(
                "Post-Compromise SSH Follow-up",
                "If shell access is achieved in a lab, inspect sudo rights, writable cron locations, SSH keys, and service credentials for privilege-escalation learning.",
            )

    def summarize_assessment(self):
        self.state.finalize_assessment()
        top_path = self.state.attack_paths[0]["title"] if self.state.attack_paths else "No prioritized attack path identified"
        self.state.executive_summary = (
            f"Assessment of {self.state.target_ip} found {len(self.state.services_detail)} exposed services and "
            f"{len(self.state.findings)} learner-relevant findings. Overall risk is "
            f"{self.state.assessment['risk_rating']} with top path: {top_path}."
        )


