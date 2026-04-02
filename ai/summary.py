class ExecutiveSummaryGenerator:
    def __init__(self, llm_client=None):
        self.llm = llm_client  # optional

    def generate(self, state):
        """
        Returns a short executive summary string.
        Uses LLM if available, otherwise fallback.
        """
        if self.llm:
            return self._llm_summary(state)
        return self._fallback_summary(state)

    def _llm_summary(self, state):
        # ⚠️ Sanitized, non-technical prompt
        prompt = f"""
You are a cybersecurity consultant writing an executive summary.

Target IP: {state.target['ip']}

Findings:
- Open ports: {state.network['open_ports']}
- Anonymous FTP access: {bool(state.access['credentials'])}
- File upload via FTP: {bool(state.access.get('ftp', {}).get('uploaded_files'))}
- Web-accessible files: {bool(state.access.get('web', {}).get('accessible_files'))}
- PHP execution confirmed: {state.access.get('web', {}).get('php_execution')}

Write a concise executive summary (3–5 sentences) explaining:
- What was found
- Why it matters
- The overall risk level
Avoid technical commands or exploit details.
"""

        return self.llm.complete(prompt).strip()

    def _fallback_summary(self, state):
        # Deterministic, always works
        findings = []

        if state.network["open_ports"]:
            findings.append("multiple network services were exposed")

        if state.access["credentials"]:
            findings.append("anonymous FTP access was enabled")

        if state.access.get("ftp", {}).get("uploaded_files"):
            findings.append("file upload was possible via FTP")

        if state.access.get("web", {}).get("php_execution"):
            findings.append("server-side PHP code execution was confirmed")

        if not findings:
            return (
                "The assessment did not identify exploitable services during the "
                "reconnaissance phase. No immediate attack surface was confirmed."
            )

        summary = (
            "The security assessment identified that "
            + ", ".join(findings)
            + ". These issues indicate insecure service configurations that could "
              "allow an attacker to gain deeper access to the system. "
              "Overall, the risk level is assessed as HIGH due to the potential for "
              "full system compromise if these weaknesses are exploited."
        )

        return summary
