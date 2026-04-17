import socket


class ProtocolProbeModule:
    NAME = "protocol_probe"

    SOCKET_TIMEOUT = 3

    def discover(self, state):
        if state.phase != "ENUMERATION":
            return []
        if not state.services_detail:
            return []
        return [{"name": self.NAME, "type": "recon"}]

    def execute(self, state):
        probed = 0
        findings_added = 0
        observations = {}

        for port, details in sorted(state.services_detail.items(), key=lambda item: int(item[0])):
            probe = self._probe_service(state.target_ip, port, details)
            if not probe:
                continue

            probed += 1
            observations[port] = probe
            attack_surface = state.attack_surface.setdefault("protocol_observations", {})
            attack_surface[port] = probe

            note_title = f"Protocol probe {port}"
            note_detail = f"{probe['label']}: {probe['summary']}"
            state.add_learning_note(note_title, note_detail)

            for finding in probe.get("findings", []):
                state.add_finding(finding)
                findings_added += 1

        return {
            "success": True,
            "summary": f"Captured {probed} protocol observations and {findings_added} probe-derived findings",
        }

    def _probe_service(self, host, port, details):
        port_int = int(port)
        service_name = str(details.get("service") or "").lower()
        banner = details.get("banner") or ""
        label = details.get("service") or "unknown"

        if port_int in {21} or "ftp" in service_name:
            response = self._read_banner(host, port_int)
            if response:
                summary = f"FTP banner: {response.strip()[:180]}"
                findings = []
                if "anonymous" in response.lower():
                    findings.append(
                        self._build_finding(
                            port,
                            details,
                            "FTP banner suggests anonymous access language",
                            "ftp_banner_hint",
                            "MEDIUM",
                            62,
                            "The FTP greeting mentions anonymous access, which is worth validating in a lab-safe way.",
                            [response.strip()[:220]],
                        )
                    )
                return {"label": label, "summary": summary, "raw": response.strip(), "findings": findings}

        if port_int in {22} or "ssh" in service_name:
            response = self._read_banner(host, port_int)
            if response:
                return {
                    "label": label,
                    "summary": f"SSH banner: {response.strip()[:180]}",
                    "raw": response.strip(),
                    "findings": [],
                }

        if port_int in {23} or "telnet" in service_name:
            response = self._read_banner(host, port_int)
            if response:
                return {
                    "label": label,
                    "summary": f"Telnet greeting observed: {response.strip()[:180]}",
                    "raw": response.strip(),
                    "findings": [],
                }

        if port_int in {25, 587} or "smtp" in service_name:
            response = self._smtp_probe(host, port_int)
            if response:
                findings = []
                if "auth" in response.lower():
                    findings.append(
                        self._build_finding(
                            port,
                            details,
                            "SMTP service advertises authentication mechanisms",
                            "smtp_auth_surface",
                            "LOW",
                            58,
                            "SMTP capabilities include AUTH, which can help profile identity and authentication exposure in the target environment.",
                            [response.strip()[:220]],
                        )
                    )
                return {"label": label, "summary": f"SMTP capabilities: {response.strip()[:180]}", "raw": response.strip(), "findings": findings}

        if port_int in {110} or "pop3" in service_name:
            response = self._simple_command_probe(host, port_int, b"CAPA\r\n")
            if response:
                return {"label": label, "summary": f"POP3 response: {response.strip()[:180]}", "raw": response.strip(), "findings": []}

        if port_int in {143} or "imap" in service_name:
            response = self._simple_command_probe(host, port_int, b"a001 CAPABILITY\r\n")
            if response:
                return {"label": label, "summary": f"IMAP capability response: {response.strip()[:180]}", "raw": response.strip(), "findings": []}

        if port_int in {6667, 6697} or "irc" in service_name:
            response = self._read_banner(host, port_int)
            if response:
                return {"label": label, "summary": f"IRC banner: {response.strip()[:180]}", "raw": response.strip(), "findings": []}

        if port_int in {5900, 5901, 5902} or "vnc" in service_name:
            response = self._read_banner(host, port_int)
            if response:
                findings = []
                if "rfb" in response.lower():
                    findings.append(
                        self._build_finding(
                            port,
                            details,
                            "VNC protocol handshake exposed",
                            "vnc_protocol_exposure",
                            "MEDIUM",
                            65,
                            "The VNC handshake is directly reachable, confirming an interactive remote desktop surface.",
                            [response.strip()[:220]],
                        )
                    )
                return {"label": label, "summary": f"VNC handshake: {response.strip()[:180]}", "raw": response.strip(), "findings": findings}

        if port_int in {3306, 5432} or any(token in banner.lower() for token in ("mysql", "postgres")):
            response = self._read_banner(host, port_int, recv_size=256)
            if response:
                return {"label": label, "summary": f"Database handshake observed: {response.strip()[:180]}", "raw": response.strip(), "findings": []}

        return None

    def _read_banner(self, host, port, recv_size=512):
        try:
            with socket.create_connection((host, port), timeout=self.SOCKET_TIMEOUT) as sock:
                sock.settimeout(self.SOCKET_TIMEOUT)
                data = sock.recv(recv_size)
                return data.decode("utf-8", errors="ignore")
        except Exception:
            return None

    def _simple_command_probe(self, host, port, payload):
        try:
            with socket.create_connection((host, port), timeout=self.SOCKET_TIMEOUT) as sock:
                sock.settimeout(self.SOCKET_TIMEOUT)
                initial = sock.recv(512)
                sock.sendall(payload)
                response = sock.recv(1024)
                joined = initial + b"\n" + response
                return joined.decode("utf-8", errors="ignore")
        except Exception:
            return None

    def _smtp_probe(self, host, port):
        try:
            with socket.create_connection((host, port), timeout=self.SOCKET_TIMEOUT) as sock:
                sock.settimeout(self.SOCKET_TIMEOUT)
                banner = sock.recv(512)
                sock.sendall(b"EHLO aartf.local\r\n")
                response = sock.recv(1024)
                joined = banner + b"\n" + response
                return joined.decode("utf-8", errors="ignore")
        except Exception:
            return None

    def _build_finding(self, port, details, title, finding_type, severity, confidence, description, evidence):
        return {
            "title": title,
            "type": finding_type,
            "severity": severity,
            "confidence": confidence,
            "description": description,
            "summary": description,
            "evidence": evidence,
            "affected_service": details.get("service"),
            "affected_port": port,
            "kill_chain_stage": "Enumeration",
            "attack_opportunities": [
                "Use the observed protocol banner/capabilities to refine the likely learner path.",
                "Correlate these protocol details with version, identity, and authentication clues elsewhere.",
            ],
            "verification_steps": [
                "Review the captured handshake or capability response manually.",
                "Decide whether the service behavior suggests a higher-priority path than other exposed services.",
            ],
            "remediation": [
                "Reduce unnecessary exposure of interactive or identity-bearing services.",
            ],
            "source": self.NAME,
        }
