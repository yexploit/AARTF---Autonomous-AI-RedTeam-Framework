class ServiceAdvisoryModule:
    NAME = "service_advisory"

    def discover(self, state):
        if state.phase != "ENUMERATION":
            return []
        if not state.services_detail:
            return []
        return [{"name": self.NAME, "type": "recon"}]

    def execute(self, state):
        findings_added = 0
        notes_added = 0
        for port, details in state.services_detail.items():
            service_name = (details.get("service") or "").lower()
            banner = details.get("banner") or ""
            descriptor = " ".join(filter(None, [service_name, details.get("product"), details.get("version"), banner]))
            descriptor_lower = descriptor.lower()

            if port == "21" or "ftp" in service_name:
                state.add_learning_note(
                    f"FTP review on {port}",
                    "Review anonymous access, writable directories, and whether the banner reflects a known training-lab service version.",
                )
                notes_added += 1
            if port == "22" or "ssh" in service_name:
                state.add_learning_note(
                    f"SSH review on {port}",
                    "Check whether the service version is legacy, whether password auth is likely enabled, and whether other exposed services could leak usernames.",
                )
                notes_added += 1
            if port in {"139", "445"} or "smb" in descriptor.lower() or "netbios" in descriptor.lower():
                state.add_learning_note(
                    f"SMB review on {port}",
                    "Enumerate shares, guest access, and legacy Samba behavior. This is often a strong learner pathway on lab targets.",
                )
                notes_added += 1
            if port == "53" or any(token in descriptor_lower for token in ("domain", "bind", "dns")):
                state.add_learning_note(
                    f"DNS review on {port}",
                    "Look for hostnames, zone-transfer clues, recursion, and naming patterns that can enrich the rest of the assessment.",
                )
                notes_added += 1
            if port in {"25", "110", "143", "465", "587", "993", "995"} or any(token in descriptor_lower for token in ("smtp", "pop3", "imap")):
                state.add_learning_note(
                    f"Mail review on {port}",
                    "Inspect the mail stack for banner leakage, username discovery, auth mechanisms, and whether it can strengthen credential-based paths elsewhere.",
                )
                notes_added += 1
            if port in {"111", "2049"} or any(token in descriptor_lower for token in ("rpcbind", "nfs")):
                state.add_learning_note(
                    f"RPC/NFS review on {port}",
                    "Prioritize exported shares, permission boundaries, and whether exposed file services can reveal application or credential material.",
                )
                notes_added += 1
            if port == "23" or "telnet" in service_name:
                state.add_finding(
                    {
                        "title": "Telnet service exposes plaintext administration surface",
                        "type": "telnet_exposure",
                        "severity": "HIGH",
                        "confidence": 85,
                        "description": "Telnet was detected and should be treated as a high-priority learner pathway because it typically lacks transport security.",
                        "summary": "A plaintext remote administration protocol is reachable.",
                        "evidence": [f"Port {port} banner: {banner or service_name}"],
                        "affected_service": details.get("service"),
                        "affected_port": port,
                        "kill_chain_stage": "Enumeration",
                        "attack_opportunities": [
                            "Review whether login prompts or banners disclose usernames or lab hints.",
                            "Prioritize it ahead of lower-signal services.",
                        ],
                        "verification_steps": [
                            "Validate that the service is Telnet and note whether credentials would traverse in plaintext.",
                            "Correlate with any usernames discovered elsewhere.",
                        ],
                        "remediation": [
                            "Disable Telnet and replace it with SSH.",
                        ],
                        "source": self.NAME,
                    }
                )
                findings_added += 1
            if port in {"3306", "5432"}:
                state.add_learning_note(
                    f"Database review on {port}",
                    "Check for externally exposed database services, weak/default credentials in the lab, and version clues that explain the intended pathway.",
                )
                notes_added += 1
            if port in {"5900", "5901", "5902"} or "vnc" in descriptor_lower:
                state.add_learning_note(
                    f"VNC review on {port}",
                    "Check whether remote desktop access is authenticated properly and whether it represents a direct learner pathway on this host.",
                )
                notes_added += 1
            if port in {"6000", "6001"} or "x11" in descriptor_lower:
                state.add_learning_note(
                    f"X11 review on {port}",
                    "Treat network-exposed X11 as weak service isolation and correlate it with other interactive access surfaces.",
                )
                notes_added += 1
            if "tomcat" in descriptor.lower() or port == "8180":
                state.add_learning_note(
                    f"Tomcat review on {port}",
                    "Inspect application roots, manager consoles, and default content. Tomcat is commonly used in training machines to guide learners toward web-to-shell pathways.",
                )
                notes_added += 1
            if "java-rmi" in descriptor.lower() or "ajp13" in descriptor.lower():
                state.add_finding(
                    {
                        "title": "Java middleware service exposed",
                        "type": "java_middleware_exposure",
                        "severity": "MEDIUM",
                        "confidence": 69,
                        "description": "Java middleware services such as RMI or AJP can broaden the attack surface and deserve targeted enumeration.",
                        "summary": "A Java middleware port is exposed and should be correlated with Tomcat or application-server findings.",
                        "evidence": [f"Port {port}: {descriptor}"],
                        "affected_service": details.get("service"),
                        "affected_port": port,
                        "kill_chain_stage": "Enumeration",
                        "attack_opportunities": [
                            "Correlate with Tomcat or application-server endpoints.",
                            "Look for management interfaces or insecure connector configurations.",
                        ],
                        "verification_steps": [
                            "Identify the application server using the port and banner.",
                            "Inspect related web or management endpoints for default content.",
                        ],
                        "remediation": [
                            "Restrict middleware ports to trusted networks.",
                            "Disable unused connectors.",
                        ],
                        "source": self.NAME,
                    }
                )
                findings_added += 1
            if "irc" in descriptor_lower:
                state.add_learning_note(
                    f"IRC review on {port}",
                    "Legacy IRC daemons are uncommon and high-signal; inspect the exact product/version and compare its value against other exposed services.",
                )
                notes_added += 1
            if "distccd" in descriptor_lower:
                state.add_finding(
                    {
                        "title": "Build-distribution service exposed",
                        "type": "distccd_exposure",
                        "severity": "HIGH",
                        "confidence": 82,
                        "description": "A distccd-like service is exposed and should be treated as a strong learner candidate because it is rarely intended for broad network access.",
                        "summary": "An exposed build-distribution service often signals weak isolation.",
                        "evidence": [f"Port {port}: {descriptor}"],
                        "affected_service": details.get("service"),
                        "affected_port": port,
                        "kill_chain_stage": "Enumeration",
                        "attack_opportunities": [
                            "Prioritize the service because it is uncommon and high-signal.",
                            "Correlate it with the host role and other direct-service pathways.",
                        ],
                        "verification_steps": [
                            "Confirm the service family and whether it is intended to be externally reachable.",
                            "Document how it relates to the system's apparent role.",
                        ],
                        "remediation": [
                            "Restrict build-service exposure to trusted hosts.",
                            "Disable the service if not required.",
                        ],
                        "source": self.NAME,
                    }
                )
                findings_added += 1
            if service_name == "unknown" and port.isdigit() and int(port) >= 49152:
                state.add_learning_note(
                    f"High-port review on {port}",
                    "Treat unidentified high ports as context clues. They may reflect Windows RPC, app servers, or additional management surfaces rather than noise.",
                )
                notes_added += 1

        return {
            "success": True,
            "summary": f"Added {notes_added} service notes and {findings_added} direct findings",
        }
