class MailAnalyzerModule:
    NAME = "mail_analyzer"

    def discover(self, state):
        if state.phase != "VULNERABILITY_CORRELATION":
            return []
        observations = state.attack_surface.get("protocol_observations", {})
        if not any(port in observations for port in ("25", "110", "143", "587", "993", "995")):
            return []
        return [{"name": self.NAME, "type": "analysis"}]

    def execute(self, state):
        observations = state.attack_surface.get("protocol_observations", {})
        findings_added = 0

        smtp_ports = [port for port in ("25", "587") if port in observations]
        if smtp_ports:
            combined = " ".join(observations[port].get("raw", "") for port in smtp_ports).lower()
            if "auth" in combined:
                state.add_finding(
                    {
                        "title": "Mail service exposes authentication capability details",
                        "type": "mail_auth_capabilities",
                        "severity": "LOW",
                        "confidence": 63,
                        "description": "Mail capability responses disclose authentication support, which can help refine identity and credential-oriented learner paths.",
                        "summary": "Mail auth capabilities can strengthen username and auth-surface analysis.",
                        "evidence": [observations[port].get("summary", "") for port in smtp_ports],
                        "affected_service": "mail",
                        "affected_port": smtp_ports[0],
                        "kill_chain_stage": "Vulnerability Correlation",
                        "attack_opportunities": [
                            "Correlate auth mechanisms with other login-capable services.",
                            "Use mail presence to enrich username discovery and credential pathways.",
                        ],
                        "verification_steps": [
                            "Review the exact mail capability lines returned by the server.",
                            "Compare authentication support with the rest of the exposed identity surface.",
                        ],
                        "remediation": [
                            "Reduce unnecessary mail exposure and information leakage.",
                        ],
                        "source": self.NAME,
                    }
                )
                findings_added += 1

        pop_imap_ports = [port for port in ("110", "143", "993", "995") if port in observations]
        if pop_imap_ports:
            state.add_learning_note(
                "Mail identity surface",
                "POP/IMAP exposure can complement SMTP by revealing authentication style and strengthening username-focused learner paths.",
            )

        return {
            "success": True,
            "summary": f"Added {findings_added} mail-capability findings",
        }
