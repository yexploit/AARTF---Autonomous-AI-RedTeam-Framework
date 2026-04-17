import json
import os

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()


class AIAttackPlanner:
    def __init__(self):
        api_key = os.getenv("OPENAI_API_KEY")
        self.client = OpenAI(api_key=api_key) if api_key else None

    def analyze(self, state):
        fallback_paths = self._build_rule_based_paths(state)
        if not self.client:
            state.set_ai_status(False, "rules", "rule_based", "OpenAI API key not configured; using local planner.")
            self._apply_paths(state, fallback_paths, rule_based_summary=True)
            return

        try:
            prompt = self._build_prompt(state, fallback_paths)
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are an educational security assessment planner. "
                            "Return concise JSON only. Do not provide exploit payloads or harmful instructions."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
            )
            content = response.choices[0].message.content.strip()
            payload = self._parse_json(content)
            ai_paths = payload.get("paths") or []
            if not ai_paths:
                raise ValueError("AI response did not contain paths.")

            state.set_ai_status(True, "ai_enriched", "openai", "OpenAI attack-path planner enabled.")
            self._apply_paths(state, ai_paths, summary=payload.get("executive_summary"))
            self._apply_recommendations(state, payload.get("recommendations") or [])
        except Exception as exc:
            print(f"[AI Error] {exc}")
            state.set_ai_status(False, "rules", "rule_based", f"AI planner unavailable; fallback active ({exc}).")
            self._apply_paths(state, fallback_paths, rule_based_summary=True)

    def score_host(self, services, vulnerabilities):
        severity_weights = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 15, "LOW": 7, "INFO": 3}
        score = min(100, len(services) * 5 + sum(severity_weights.get(v.get("severity", "INFO"), 0) for v in vulnerabilities))
        return score

    def _build_rule_based_paths(self, state):
        paths = []
        findings = sorted(
            state.findings,
            key=lambda item: (self._severity_weight(item.get("severity", "INFO")), item.get("confidence", 0)),
            reverse=True,
        )
        for finding in findings[:6]:
            title = finding["title"]
            service_label = finding.get("affected_service") or "service"
            port_label = finding.get("affected_port") or "unknown port"
            steps = finding.get("verification_steps") or [
                f"Validate the service banner and version on {port_label}/{service_label}.",
                f"Review why {title} matters using the evidence collected in the findings panel.",
                "Use a lab-safe manual verification workflow before attempting any active validation.",
            ]
            paths.append(
                {
                    "title": f"Investigate {title}",
                    "summary": finding.get("summary", ""),
                    "score": min(100, self._severity_weight(finding["severity"]) + finding.get("confidence", 0) // 2),
                    "confidence": finding.get("confidence", 0),
                    "severity": finding.get("severity", "INFO"),
                    "path_kind": "supporting",
                    "prerequisites": [
                        f"Reachability to {state.target_ip}",
                        f"Confirm port {port_label} remains exposed",
                    ],
                    "steps": steps,
                    "blockers": ["Evidence may be incomplete if service fingerprinting was partial."],
                    "evidence": finding.get("evidence", []),
                    "affected_services": [service_label],
                    "source_findings": [finding["id"]],
                    "next_action": steps[0] if steps else "",
                }
            )
        service_names = {str(details.get("service", "")).lower(): port for port, details in state.services_detail.items()}
        if any(name in service_names for name in ("http", "ssl/http", "ajp13")) and any("tomcat" in str(details.get("product", "")).lower() or "tomcat" in str(details.get("banner", "")).lower() for details in state.services_detail.values()):
            paths.append(
                {
                    "title": "Investigate Java web application path",
                    "summary": "Tomcat or related Java web middleware is present, making web management interfaces and deployed applications a strong learner path.",
                    "score": 82,
                    "confidence": 75,
                    "severity": "HIGH",
                    "path_kind": "alternate",
                    "prerequisites": [
                        f"Reachability to {state.target_ip}",
                        "Identify the relevant HTTP/Tomcat endpoint and management surface.",
                    ],
                    "steps": [
                        "Profile the web stack, titles, headers, and management endpoints.",
                        "Inspect Tomcat-related paths such as manager surfaces or default apps.",
                        "Correlate exposed applications with credentials, backups, or Java middleware findings.",
                    ],
                    "blockers": [
                        "Manager interfaces may be filtered or require valid credentials.",
                    ],
                    "evidence": [
                        "Tomcat or Java middleware indicators were detected in service enumeration.",
                    ],
                    "affected_services": ["http", "tomcat", "ajp13"],
                    "source_findings": [finding["id"] for finding in findings if finding.get("affected_service") in {"http", "ajp13"}][:3],
                    "next_action": "Inspect the Java web surface and management endpoints manually.",
                }
            )
        if any(name in service_names for name in ("ftp", "ssh", "telnet")):
            paths.append(
                {
                    "title": "Investigate credential-oriented access path",
                    "summary": "Multiple remote administration or file-transfer services are exposed, which increases the chance that banner leaks, usernames, or reused credentials will shape the intended learner path.",
                    "score": 74,
                    "confidence": 68,
                    "severity": "MEDIUM",
                    "path_kind": "alternate",
                    "prerequisites": [
                        "Collect usernames, banners, and service versions from exposed login services.",
                    ],
                    "steps": [
                        "Cross-reference usernames and identity clues from mail, web, and service banners.",
                        "Review whether any service appears legacy or weakly hardened.",
                        "Prioritize the most unusual or outdated login-oriented service first.",
                    ],
                    "blockers": [
                        "No direct credential evidence may be available yet.",
                    ],
                    "evidence": [
                        "At least one of FTP, SSH, or Telnet is exposed.",
                    ],
                    "affected_services": [name for name in ("ftp", "ssh", "telnet") if name in service_names],
                    "source_findings": [finding["id"] for finding in findings if finding.get("affected_service") in {"ftp", "ssh", "telnet"}][:3],
                    "next_action": "Review login-capable services for the strongest identity or version clues.",
                }
            )
        if any(port in state.services_detail for port in ("139", "445", "111", "2049")):
            paths.append(
                {
                    "title": "Investigate network share and trust path",
                    "summary": "SMB, RPC, or NFS exposure often provides a rich learner path through shares, exports, and trust assumptions.",
                    "score": 80,
                    "confidence": 73,
                    "severity": "HIGH",
                    "path_kind": "alternate",
                    "prerequisites": [
                        "Enumerate exposed shares or exports safely.",
                    ],
                    "steps": [
                        "Identify readable or writable shares and exported paths.",
                        "Look for credentials, backups, configs, or application data in exposed content.",
                        "Use discovered data to refine later service-specific validation.",
                    ],
                    "blockers": [
                        "Share enumeration may require additional tooling or credentials.",
                    ],
                    "evidence": [
                        "Share-oriented services such as SMB, RPC, or NFS are exposed.",
                    ],
                    "affected_services": ["smb", "rpcbind", "nfs"],
                    "source_findings": [finding["id"] for finding in findings if finding.get("type") in {"smb_exposure", "rpc_nfs_exposure", "windows_rpc_exposure"}][:3],
                    "next_action": "Enumerate shares or exports and correlate the results with other findings.",
                }
            )
        if any(finding.get("type") in {"smb_share_listing", "nfs_export_listing"} for finding in findings):
            paths.append(
                {
                    "title": "Investigate exposed share content path",
                    "summary": "Share enumeration returned concrete SMB or NFS content locations, making file-based discovery one of the strongest target-specific learner paths.",
                    "score": 88,
                    "confidence": 82,
                    "severity": "HIGH",
                    "path_kind": "alternate",
                    "prerequisites": [
                        "Review the enumerated share or export names.",
                    ],
                    "steps": [
                        "Prioritize readable shares or exports that appear application-related or user-facing.",
                        "Look for configs, backups, credentials, web roots, or home-directory material.",
                        "Use discovered artifacts to refine follow-on service validation.",
                    ],
                    "blockers": [
                        "Actual share content review may depend on local tooling availability.",
                    ],
                    "evidence": [
                        "Share enumeration returned concrete SMB/NFS metadata.",
                    ],
                    "affected_services": ["smb", "nfs"],
                    "source_findings": [finding["id"] for finding in findings if finding.get("type") in {"smb_share_listing", "nfs_export_listing"}][:3],
                    "next_action": "Inspect the enumerated shares or exports first.",
                }
            )
        if any(finding.get("type") in {"composite_web_database_stack", "web_content_hint"} for finding in findings):
            paths.append(
                {
                    "title": "Investigate application-to-data path",
                    "summary": "The target shows both web-app behavior and backend data exposure signals, suggesting a chained application path rather than an isolated service issue.",
                    "score": 84,
                    "confidence": 77,
                    "severity": "HIGH",
                    "path_kind": "alternate",
                    "prerequisites": [
                        "Identify the main application entry point and any exposed data service.",
                    ],
                    "steps": [
                        "Inspect authentication, upload, and admin workflows in the web app.",
                        "Correlate any content hints, discovered paths, and backend database exposure.",
                        "Use app behavior to explain why the database or data layer matters.",
                    ],
                    "blockers": [
                        "Application logic may require manual interaction or hidden routes.",
                    ],
                    "evidence": [
                        "Web and data-service signals were both observed on the target.",
                    ],
                    "affected_services": ["http", "database"],
                    "source_findings": [finding["id"] for finding in findings if finding.get("type") in {"composite_web_database_stack", "web_content_hint"}][:3],
                    "next_action": "Start with the web application and map how it might touch the exposed data layer.",
                }
            )
        paths.sort(key=lambda item: (item["score"], item["confidence"]), reverse=True)
        return paths

    def _build_prompt(self, state, fallback_paths):
        return (
            "Analyze this lab target for learner-friendly attack-path planning.\n"
            f"Target: {state.target_ip}\n"
            f"Services: {json.dumps(list(state.services_detail.values()), indent=2)}\n"
            f"Findings: {json.dumps(state.findings, indent=2)}\n"
            f"FallbackPaths: {json.dumps(fallback_paths[:5], indent=2)}\n"
            "Return JSON in this schema:\n"
            "{\n"
            '  "executive_summary": "short summary",\n'
            '  "paths": [\n'
            "    {\n"
            '      "title": "path title",\n'
            '      "summary": "why this path matters",\n'
            '      "score": 0,\n'
            '      "confidence": 0,\n'
            '      "severity": "LOW|MEDIUM|HIGH|CRITICAL|INFO",\n'
            '      "prerequisites": ["..."],\n'
            '      "steps": ["high-level learner validation steps only"],\n'
            '      "blockers": ["..."],\n'
            '      "evidence": ["..."],\n'
            '      "affected_services": ["..."],\n'
            '      "source_findings": ["F-001"],\n'
            '      "next_action": "best next learning step"\n'
            "    }\n"
            "  ],\n"
            '  "recommendations": [\n'
            '    {"title": "recommendation", "details": "why", "priority": "HIGH", "category": "hardening"}\n'
            "  ]\n"
            "}\n"
            "Keep the answer advisory-first and safe for learning labs."
        )

    def _apply_paths(self, state, paths, summary=None, rule_based_summary=False):
        state.attack_paths = []
        for path in paths:
            state.add_attack_path(path)
        if summary:
            state.ai_analysis = {
                "recommendation": state.attack_paths[0]["next_action"] if state.attack_paths else "Review findings manually.",
                "confidence": state.attack_paths[0]["confidence"] if state.attack_paths else 0,
                "reason": summary,
            }
        elif rule_based_summary:
            state.ai_analysis = self._fallback_summary(state)
        if state.attack_paths:
            state.attack_paths[0]["path_kind"] = "primary"
        if state.attack_paths and not state.walkthrough:
            state.walkthrough = state.attack_paths[0]["steps"]

    def _apply_recommendations(self, state, recommendations):
        for recommendation in recommendations:
            state.add_recommendation(
                recommendation.get("title", "General hardening"),
                recommendation.get("details", ""),
                priority=recommendation.get("priority", "MEDIUM"),
                category=recommendation.get("category", "general"),
            )

    def _fallback_summary(self, state):
        if state.attack_paths:
            top_path = state.attack_paths[0]
            return {
                "recommendation": top_path.get("next_action") or top_path["title"],
                "confidence": top_path.get("confidence", 0),
                "reason": top_path.get("summary", "Rule-based prioritization selected the top learning path."),
            }
        return {
            "recommendation": "Continue enumeration and inspect the findings manually.",
            "confidence": 25,
            "reason": "No high-confidence attack path was produced from the collected evidence.",
        }

    def _parse_json(self, content):
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            start = content.find("{")
            end = content.rfind("}")
            if start != -1 and end != -1 and end > start:
                return json.loads(content[start:end + 1])
            raise

    def _severity_weight(self, severity):
        mapping = {"CRITICAL": 95, "HIGH": 80, "MEDIUM": 60, "LOW": 35, "INFO": 20}
        return mapping.get(str(severity).upper(), 20)


class AIPrioritizer(AIAttackPlanner):
    pass
