import uuid
from collections import Counter
from datetime import datetime


class SessionState:
    PHASES = [
        "RECONNAISSANCE",
        "ENUMERATION",
        "VULNERABILITY_CORRELATION",
        "ATTACK_PATH_PLANNING",
        "VALIDATION_GUIDANCE",
        "POST_COMPROMISE_OPPORTUNITIES",
        "REPORTING",
        "COMPLETE",
    ]

    def __init__(self, target_ip):
        self.session_id = str(uuid.uuid4())
        self.action_attempts = {}

        self.target = {
            "ip": target_ip,
            "hostname": None,
            "os": "unknown",
        }
        self.phase = "RECONNAISSANCE"
        self.status = "RUNNING"

        self.network = {
            "open_ports": {},
            "services": {},
        }
        self.access = {
            "credentials": [],
            "shells": {
                "low_priv": False,
                "high_priv": False,
                "user": None,
            },
        }
        self.privesc = {
            "kernel": None,
            "suid_bins": [],
            "cron_jobs": [],
            "writable_paths": [],
        }
        self.constraints = {
            "stealth": True,
            "no_bruteforce": True,
            "web_only": False,
        }

        self.created_at = datetime.utcnow().isoformat()
        self.last_updated = self.created_at
        self.failed_actions = set()
        self.last_action = None
        self.actions_taken = []
        self.action_log = []
        self.attack_surface = {}
        self.credentials = []
        self.compromised = False
        self.escalated = False
        self.internal_networks = []
        self.pivot_targets = []
        self.session_data = {}
        self.findings = []
        self.attack_paths = []
        self.recommendations = []
        self.learning_notes = []
        self.executive_summary = ""
        self.walkthrough = []
        self.report_sections = {}
        self.ai_analysis = {}
        self.ai_enabled = False
        self.ai_status = {
            "available": False,
            "mode": "rules",
            "provider": "rule_based",
            "detail": "OpenAI API key not configured.",
        }
        self.assessment = {
            "risk_score": 0,
            "risk_rating": "INFO",
            "confidence": 0,
            "kill_chain_coverage": [],
            "top_findings": [],
        }
        self.assets = [
            {
                "type": "host",
                "value": target_ip,
                "label": target_ip,
            }
        ]
        self.services_detail = {}

        self.access["ftp"] = {
            "listing": [],
            "cwd": "/",
            "writable_dirs": [],
            "uploaded_files": [],
        }
        self.access["web"] = {
            "accessible_files": [],
            "web_root": None,
            "php_execution": False,
            "php_probe_url": None,
        }
        self.user_consent = {
            "reverse_shell": False,
            "timestamp": None,
        }
        self.post_exploit = {
            "enumeration": {},
            "privesc_candidates": [],
            "ranked_privesc": [],
            "best_privesc": None,
            "user": None,
            "privilege": "unknown",
        }

        # Persistence control modes:
        # "AUTO" -> automatic persistence
        # "MANUAL" -> ask before installing
        # "OFF" -> disabled
        self.persistence_mode = "MANUAL"
        self.persistence_installed = False

    @property
    def target_ip(self):
        return self.target.get("ip")

    def update_phase(self, new_phase):
        self.phase = new_phase
        self.last_updated = datetime.utcnow().isoformat()

    def summary(self):
        return {
            "session_id": self.session_id,
            "target": self.target,
            "phase": self.phase,
            "status": self.status,
            "open_ports": self.network["open_ports"],
            "services": self.network["services"],
            "actions_taken": self.actions_taken,
            "findings": self.findings,
            "attack_paths": self.attack_paths,
            "ai_status": self.ai_status,
            "last_updated": self.last_updated,
        }

    def should_move_to_initial_access(self):
        return len(self.network["open_ports"]) > 0

    def has_initial_access(self):
        return len(self.access["credentials"]) > 0

    def mark_action_failed(self, action_name):
        self.failed_actions.add(action_name)

    def is_action_failed(self, action_name):
        return action_name in self.failed_actions

    def store_ftp_listing(self, files):
        self.access["ftp"]["listing"] = files

    def has_ftp_listing(self):
        return len(self.access["ftp"]["listing"]) > 0

    def add_writable_dir(self, path):
        if path not in self.access["ftp"]["writable_dirs"]:
            self.access["ftp"]["writable_dirs"].append(path)

    def add_uploaded_file(self, path):
        if path not in self.access["ftp"]["uploaded_files"]:
            self.access["ftp"]["uploaded_files"].append(path)

    def has_uploaded_files(self):
        return len(self.access["ftp"]["uploaded_files"]) > 0

    def add_web_accessible_file(self, url):
        if url not in self.access["web"]["accessible_files"]:
            self.access["web"]["accessible_files"].append(url)

    def has_web_access(self):
        return len(self.access["web"]["accessible_files"]) > 0

    def mark_php_execution(self, url):
        self.access["web"]["php_execution"] = True
        self.access["web"]["php_probe_url"] = url

    def has_php_execution(self):
        return self.access["web"]["php_execution"] is True

    def grant_reverse_shell_consent(self):
        self.user_consent["reverse_shell"] = True
        self.user_consent["timestamp"] = datetime.utcnow().isoformat()

    def has_reverse_shell_consent(self):
        return self.user_consent["reverse_shell"] is True

    def move_to_post_exploit(self):
        self.phase = "POST_EXPLOIT"
        self.last_updated = datetime.utcnow().isoformat()

    def record_post_enum(self, key, value):
        self.post_exploit["enumeration"][key] = value

    def add_service(self, port, service_name, details=None):
        port_str = str(port)
        details = details or {}
        normalized = {
            "port": port_str,
            "service": service_name or "unknown",
            "product": details.get("product"),
            "version": details.get("version"),
            "protocol": details.get("protocol", "tcp"),
            "banner": details.get("banner"),
            "extrainfo": details.get("extrainfo"),
            "source": details.get("source", "unknown"),
            "state": details.get("state", "open"),
        }
        self.network["services"][port_str] = normalized["service"]
        self.network["open_ports"][port_str] = normalized["service"]
        self.services_detail[port_str] = normalized

    def add_finding(self, finding):
        finding_id = finding.get("id") or f"F-{len(self.findings) + 1:03d}"
        normalized = {
            "id": finding_id,
            "title": finding.get("title") or finding.get("type") or "Unclassified finding",
            "type": finding.get("type") or "general_risk",
            "severity": str(finding.get("severity", "INFO")).upper(),
            "confidence": int(finding.get("confidence", 50)),
            "summary": finding.get("summary") or finding.get("description") or "",
            "description": finding.get("description") or finding.get("summary") or "",
            "evidence": finding.get("evidence") or [],
            "affected_service": finding.get("affected_service"),
            "affected_port": str(finding["affected_port"]) if finding.get("affected_port") is not None else None,
            "kill_chain_stage": finding.get("kill_chain_stage", "Enumeration"),
            "attack_opportunities": finding.get("attack_opportunities") or [],
            "verification_steps": finding.get("verification_steps") or [],
            "remediation": finding.get("remediation") or [],
            "references": finding.get("references") or [],
            "source": finding.get("source", "module"),
        }
        existing = next((item for item in self.findings if item["id"] == finding_id), None)
        if existing is None:
            self.findings.append(normalized)
        else:
            existing.update(normalized)
        self.network["vulnerabilities"] = self.findings
        self.assessment["kill_chain_coverage"] = sorted(
            {item.get("kill_chain_stage", "Enumeration") for item in self.findings}
        )

    def add_attack_path(self, attack_path):
        path_id = attack_path.get("id") or f"AP-{len(self.attack_paths) + 1:03d}"
        normalized = {
            "id": path_id,
            "title": attack_path.get("title") or "Untitled path",
            "summary": attack_path.get("summary") or "",
            "score": int(attack_path.get("score", 0)),
            "confidence": int(attack_path.get("confidence", attack_path.get("score", 0))),
            "severity": str(attack_path.get("severity", "INFO")).upper(),
            "path_kind": attack_path.get("path_kind", "supporting"),
            "prerequisites": attack_path.get("prerequisites") or [],
            "steps": attack_path.get("steps") or [],
            "blockers": attack_path.get("blockers") or [],
            "evidence": attack_path.get("evidence") or [],
            "affected_services": attack_path.get("affected_services") or [],
            "source_findings": attack_path.get("source_findings") or [],
            "next_action": attack_path.get("next_action") or "",
            "kill_chain_focus": attack_path.get("kill_chain_focus", "Attack Path Planning"),
        }
        existing = next((item for item in self.attack_paths if item["id"] == path_id), None)
        if existing is None:
            self.attack_paths.append(normalized)
        else:
            existing.update(normalized)
        self.attack_paths.sort(key=lambda item: item["score"], reverse=True)

    def add_recommendation(self, title, details, priority="MEDIUM", category="general"):
        recommendation = {
            "title": title,
            "details": details,
            "priority": str(priority).upper(),
            "category": category,
        }
        if recommendation not in self.recommendations:
            self.recommendations.append(recommendation)

    def add_learning_note(self, title, details):
        note = {"title": title, "details": details}
        if note not in self.learning_notes:
            self.learning_notes.append(note)

    def log_action(self, action_name, phase, status, details=None):
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "phase": phase,
            "action": action_name,
            "status": status,
            "details": details or "",
        }
        self.last_action = action_name
        self.actions_taken.append(f"{phase}: {action_name} [{status}]")
        self.action_log.append(entry)

    def set_ai_status(self, available, mode, provider, detail):
        self.ai_enabled = bool(available)
        self.ai_status = {
            "available": bool(available),
            "mode": mode,
            "provider": provider,
            "detail": detail,
        }

    def finalize_assessment(self):
        severity_weights = {
            "CRITICAL": 40,
            "HIGH": 25,
            "MEDIUM": 15,
            "LOW": 7,
            "INFO": 3,
        }
        counts = Counter(item.get("severity", "INFO") for item in self.findings)
        risk_score = sum(severity_weights.get(severity, 0) * count for severity, count in counts.items())
        if counts.get("CRITICAL"):
            risk_rating = "CRITICAL"
        elif counts.get("HIGH"):
            risk_rating = "HIGH"
        elif counts.get("MEDIUM"):
            risk_rating = "MEDIUM"
        elif counts.get("LOW"):
            risk_rating = "LOW"
        else:
            risk_rating = "INFO"
        confidence_values = [item.get("confidence", 0) for item in self.findings]
        self.assessment["risk_score"] = min(risk_score, 100)
        self.assessment["risk_rating"] = risk_rating
        self.assessment["confidence"] = int(sum(confidence_values) / len(confidence_values)) if confidence_values else 0
        self.assessment["top_findings"] = [
            {
                "id": item["id"],
                "title": item["title"],
                "severity": item["severity"],
            }
            for item in sorted(
                self.findings,
                key=lambda finding: (severity_weights.get(finding["severity"], 0), finding.get("confidence", 0)),
                reverse=True,
            )[:5]
        ]
