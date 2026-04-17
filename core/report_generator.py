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
        self.state.finalize_assessment()
        lines = []
        lines.append("=====================================")
        lines.append(" AARTF ADVISORY ASSESSMENT REPORT")
        lines.append("=====================================")
        lines.append(f"Generated: {datetime.datetime.now()}")
        lines.append(f"Target: {self.target}")
        lines.append(f"Final Phase: {self.state.phase}")
        lines.append(f"AI Mode: {self.state.ai_status.get('mode')} ({self.state.ai_status.get('detail')})")
        lines.append("")
        lines.append("EXECUTIVE SUMMARY")
        lines.append("-------------------------------------")
        lines.append(self.state.executive_summary or "Assessment completed.")
        lines.append(f"Overall Risk: {self.state.assessment['risk_rating']} ({self.state.assessment['risk_score']}/100)")
        lines.append(f"Average Confidence: {self.state.assessment['confidence']}")
        lines.append("")
        lines.append("TARGET PROFILE")
        lines.append("-------------------------------------")
        lines.append(f"Host: {self.target}")
        lines.append(f"OS Hint: {self.state.target.get('os', 'unknown')}")
        coverage = ", ".join(self.state.assessment.get("kill_chain_coverage", [])) or "None"
        lines.append(f"Kill-Chain Coverage: {coverage}")
        lines.append("")
        lines.append("SERVICE INVENTORY")
        lines.append("-------------------------------------")
        if self.state.services_detail:
            for port, service in sorted(self.state.services_detail.items(), key=lambda item: int(item[0])):
                details = ", ".join(
                    part for part in [service.get("service"), service.get("product"), service.get("version"), service.get("extrainfo")] if part
                )
                lines.append(f"Port {port}: {details or 'unknown'}")
        else:
            lines.append("No services identified")

        protocol_observations = self.state.attack_surface.get("protocol_observations", {})
        lines.append("")
        lines.append("PROTOCOL OBSERVATIONS")
        lines.append("-------------------------------------")
        if protocol_observations:
            for port, observation in sorted(protocol_observations.items(), key=lambda item: int(item[0])):
                lines.append(f"Port {port} [{observation.get('label', 'unknown')}]: {observation.get('summary', '')}")
        else:
            lines.append("No protocol-specific observations captured")

        lines.append("")
        lines.append("NORMALIZED FINDINGS")
        lines.append("-------------------------------------")
        if self.state.findings:
            for finding in self.state.findings:
                lines.append(f"[{finding['severity']}] {finding['title']} (confidence {finding['confidence']})")
                if finding.get("summary"):
                    lines.append(f"  Summary: {finding['summary']}")
                if finding.get("evidence"):
                    lines.append(f"  Evidence: {' | '.join(finding['evidence'][:3])}")
                if finding.get("attack_opportunities"):
                    lines.append(f"  Path Ideas: {' | '.join(finding['attack_opportunities'][:2])}")
                if finding.get("remediation"):
                    lines.append(f"  Remediation: {' | '.join(finding['remediation'][:2])}")
        else:
            lines.append("No findings detected")

        lines.append("")
        lines.append("PRIORITIZED ATTACK PATHS")
        lines.append("-------------------------------------")
        if self.state.attack_paths:
            for bucket in ("primary", "alternate", "supporting"):
                bucket_paths = [path for path in self.state.attack_paths if path.get("path_kind", "supporting") == bucket]
                if not bucket_paths:
                    continue
                lines.append(f"{bucket.upper()} PATHS")
                for path in bucket_paths[:5]:
                    lines.append(f"{path['title']} [{path['severity']}] score={path['score']} confidence={path['confidence']}")
                    if path.get("summary"):
                        lines.append(f"  Why: {path['summary']}")
                    if path.get("steps"):
                        lines.append(f"  Steps: {' -> '.join(path['steps'][:4])}")
                    if path.get("blockers"):
                        lines.append(f"  Blockers: {' | '.join(path['blockers'][:2])}")
                    if path.get("next_action"):
                        lines.append(f"  Best Next Action: {path['next_action']}")
        else:
            lines.append("No prioritized attack paths were generated")

        lines.append("")
        lines.append("LEARNER WALKTHROUGH")
        lines.append("-------------------------------------")
        walkthrough = self.state.walkthrough or []
        if walkthrough:
            for idx, step in enumerate(walkthrough, start=1):
                lines.append(f"{idx}. {step}")
        else:
            lines.append("No walkthrough available")

        lines.append("")
        lines.append("LEARNER NOTES")
        lines.append("-------------------------------------")
        if self.state.learning_notes:
            for note in self.state.learning_notes:
                lines.append(f"{note['title']}: {note['details']}")
        else:
            lines.append("No learner notes recorded")

        lines.append("")
        lines.append("RECOMMENDATIONS")
        lines.append("-------------------------------------")
        if self.state.recommendations:
            for rec in self.state.recommendations:
                lines.append(f"[{rec['priority']}] {rec['title']}: {rec['details']}")
        else:
            lines.append("No recommendations recorded")

        lines.append("")
        lines.append("ACTION LOG")
        lines.append("-------------------------------------")
        if self.state.action_log:
            for entry in self.state.action_log:
                lines.append(f"{entry['timestamp']} | {entry['phase']} | {entry['action']} | {entry['status']} | {entry['details']}")
        else:
            lines.append("No actions recorded")

        lines.append("")
        lines.append("END OF REPORT")
        lines.append("=====================================")
        return "\n".join(lines) + "\n"
