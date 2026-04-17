class HostPatternAnalyzerModule:
    NAME = "host_pattern_analyzer"

    def discover(self, state):
        if state.phase != "VULNERABILITY_CORRELATION":
            return []
        if not state.services_detail:
            return []
        return [{"name": self.NAME, "type": "analysis"}]

    def execute(self, state):
        findings_added = 0
        service_ports = set(state.services_detail.keys())
        service_text = " ".join(
            " ".join(
                filter(
                    None,
                    [
                        details.get("service"),
                        details.get("product"),
                        details.get("version"),
                        details.get("banner"),
                        details.get("extrainfo"),
                    ],
                )
            ).lower()
            for details in state.services_detail.values()
        )

        if {"139", "445"} & service_ports and ("microsoft-ds" in service_text or "samba" in service_text or "netbios" in service_text):
            state.add_finding(
                {
                    "title": "Composite Windows/SMB host profile identified",
                    "type": "composite_windows_file_surface",
                    "severity": "HIGH",
                    "confidence": 81,
                    "description": "The target exposes a Windows-style file-sharing surface with SMB/NetBIOS indicators, suggesting shares, identity clues, and trust relationships as likely learning paths.",
                    "summary": "Service grouping suggests a Windows or Samba-oriented file-sharing host profile.",
                    "evidence": ["Ports 139/445 exposed with SMB/NetBIOS-related service indicators."],
                    "affected_service": "smb",
                    "affected_port": "445" if "445" in service_ports else "139",
                    "kill_chain_stage": "Vulnerability Correlation",
                    "attack_opportunities": [
                        "Prioritize share enumeration and guest/null-session style checks where appropriate.",
                        "Use file-sharing exposure to gather usernames, files, and lateral movement clues.",
                    ],
                    "verification_steps": [
                        "Correlate SMB exposure with RPC/high-port evidence and host identity clues.",
                        "Inspect whether shares or guest access are implied by the broader service mix.",
                    ],
                    "remediation": [
                        "Reduce SMB exposure and guest access.",
                        "Restrict administrative services to trusted networks.",
                    ],
                    "source": self.NAME,
                }
            )
            findings_added += 1

        if any(port in service_ports for port in ("80", "443", "8080", "8180")) and any(port in service_ports for port in ("3306", "5432")):
            state.add_finding(
                {
                    "title": "Composite web application and database stack identified",
                    "type": "composite_web_database_stack",
                    "severity": "HIGH",
                    "confidence": 78,
                    "description": "The host exposes both a web surface and a database listener, which often indicates a strong app-to-data learning pathway and potential credential/configuration overlap.",
                    "summary": "Web and database service exposure together suggest a multi-step application path rather than an isolated service issue.",
                    "evidence": ["HTTP-like and database-like services are both externally reachable."],
                    "affected_service": "http",
                    "affected_port": "80" if "80" in service_ports else ("443" if "443" in service_ports else "8080"),
                    "kill_chain_stage": "Vulnerability Correlation",
                    "attack_opportunities": [
                        "Prioritize app configuration, backups, and secret exposure.",
                        "Correlate web findings with database credentials or legacy versions.",
                    ],
                    "verification_steps": [
                        "Inspect whether the web stack leaks config or credential material.",
                        "Determine whether the database should be externally reachable at all.",
                    ],
                    "remediation": [
                        "Segment databases away from public access.",
                        "Protect application secrets and remove unnecessary exposure.",
                    ],
                    "source": self.NAME,
                }
            )
            findings_added += 1

        if any(port in service_ports for port in ("21", "80", "443", "8080")):
            state.add_finding(
                {
                    "title": "Composite file-transfer to web-content path possible",
                    "type": "composite_upload_to_web_path",
                    "severity": "MEDIUM",
                    "confidence": 67,
                    "description": "When both file-transfer and web services are present, the target may support an upload-to-web validation path or shared-content exposure path.",
                    "summary": "FTP plus web exposure is a common learning pattern for content placement, backup disclosure, or shared web roots.",
                    "evidence": ["File-transfer and web services are both present on the target."],
                    "affected_service": "ftp",
                    "affected_port": "21",
                    "kill_chain_stage": "Vulnerability Correlation",
                    "attack_opportunities": [
                        "Compare FTP exposure with discovered web paths and uploads directories.",
                        "Inspect whether shared content roots are implied by the service mix.",
                    ],
                    "verification_steps": [
                        "Review whether writable or browsable content is exposed through both protocols.",
                        "Inspect web paths for uploads, backups, and file references.",
                    ],
                    "remediation": [
                        "Isolate file-transfer content from public web roots.",
                        "Disable unnecessary writable exposure.",
                    ],
                    "source": self.NAME,
                }
            )
            findings_added += 1

        if any(port in service_ports for port in ("25", "110", "143", "993", "995")) and any(port in service_ports for port in ("22", "21", "80", "443")):
            state.add_learning_note(
                "Composite identity surface",
                "Mail plus login-capable or web-facing services often increases the chance of discovering usernames, auth patterns, or credential reuse clues across the target.",
            )

        if any(port in service_ports for port in ("23", "512", "513", "514")) and any(port in service_ports for port in ("111", "2049", "21", "22")):
            state.add_finding(
                {
                    "title": "Composite legacy administration stack exposed",
                    "type": "composite_legacy_admin_stack",
                    "severity": "HIGH",
                    "confidence": 83,
                    "description": "The host exposes multiple legacy or trust-oriented services, which is a strong sign that it should be prioritized for learner analysis.",
                    "summary": "A cluster of legacy administrative services suggests weak trust boundaries and multiple plausible validation paths.",
                    "evidence": ["Legacy remote administration services are exposed alongside other management/file services."],
                    "affected_service": "legacy_admin",
                    "affected_port": "23" if "23" in service_ports else "512",
                    "kill_chain_stage": "Vulnerability Correlation",
                    "attack_opportunities": [
                        "Prioritize legacy plaintext or trust-based services above lower-signal modern services.",
                        "Use adjacent management services to support host-role and trust analysis.",
                    ],
                    "verification_steps": [
                        "Map which legacy services appear most direct or most weakly hardened.",
                        "Correlate service banners with likely host purpose and training-lab intent.",
                    ],
                    "remediation": [
                        "Remove deprecated administration protocols.",
                        "Modernize access control and service exposure.",
                    ],
                    "source": self.NAME,
                }
            )
            findings_added += 1

        return {
            "success": True,
            "summary": f"Added {findings_added} composite host-pattern findings",
        }
