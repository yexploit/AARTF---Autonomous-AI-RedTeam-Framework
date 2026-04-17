class CVEDatabase:
    def __init__(self):
        self.signatures = [
            {
                "match": ["vsftpd", "2.3.4"],
                "title": "Outdated vsftpd version associated with historic backdoor risk",
                "severity": "CRITICAL",
                "confidence": 92,
                "summary": "The detected FTP version is commonly used in training labs to represent a critical service compromise scenario.",
                "why": "Historically vulnerable FTP services can expose anonymous access or direct footholds in lab targets.",
                "verification": [
                    "Confirm the exact vsftpd version from the banner.",
                    "Review whether anonymous access or unusual FTP responses are present.",
                    "Correlate with the lab objective before attempting any validation.",
                ],
                "routes": [
                    "Assess anonymous FTP exposure and write permissions.",
                    "Review known lab walkthrough techniques for this exact version.",
                ],
                "remediation": [
                    "Upgrade or replace the service.",
                    "Disable anonymous FTP if not required.",
                ],
                "references": ["CVE-2011-2523"],
            },
            {
                "match": ["openssh", "4."],
                "title": "Legacy OpenSSH version detected",
                "severity": "HIGH",
                "confidence": 76,
                "summary": "An older OpenSSH release may indicate weak hardening or lab-relevant username enumeration and authentication weaknesses.",
                "why": "Old SSH deployments often appear in training targets and can lead to credential or configuration-focused attack paths.",
                "verification": [
                    "Confirm the OpenSSH version and operating system generation.",
                    "Review whether password authentication is enabled.",
                    "Prioritize credential hygiene and reuse checks rather than brute force.",
                ],
                "routes": [
                    "Review likely credential-based pathways.",
                    "Cross-reference usernames from other exposed services.",
                ],
                "remediation": [
                    "Upgrade OpenSSH to a supported release.",
                    "Enforce strong authentication controls.",
                ],
                "references": ["CVE-2018-15473"],
            },
            {
                "match": ["apache", "2.2"],
                "title": "Legacy Apache HTTPD release detected",
                "severity": "HIGH",
                "confidence": 84,
                "summary": "Apache 2.2-era deployments are end-of-life and frequently paired with misconfigurations or known weakness chains in labs.",
                "why": "Outdated web servers expand the likely attack surface for traversal, disclosure, and weak content exposure.",
                "verification": [
                    "Validate the full Apache version from the banner.",
                    "Inspect exposed paths, DAV, or default pages for excessive disclosure.",
                    "Review whether dangerous modules or aliases are enabled.",
                ],
                "routes": [
                    "Inspect exposed web content and application entry points.",
                    "Review path-handling and default-content weaknesses.",
                ],
                "remediation": [
                    "Upgrade Apache to a supported branch.",
                    "Remove legacy modules and lock down default content.",
                ],
                "references": ["CVE-2021-41773", "CVE-2021-42013"],
            },
            {
                "match": ["samba", "3."],
                "title": "Legacy Samba service detected",
                "severity": "HIGH",
                "confidence": 82,
                "summary": "Older Samba builds can expose weak share controls, anonymous enumeration, and learner-relevant remote compromise pathways.",
                "why": "SMB services often provide rich follow-on opportunities for enumeration and credential-based movement.",
                "verification": [
                    "Confirm Samba version and whether null sessions or guest access are enabled.",
                    "Identify readable or writable shares.",
                    "Check whether the service appears intentionally vulnerable for lab training.",
                ],
                "routes": [
                    "Enumerate shares and guest access.",
                    "Review SMB-authenticated pathways and file disclosure.",
                ],
                "remediation": [
                    "Upgrade Samba and disable guest or anonymous access.",
                    "Restrict share permissions.",
                ],
                "references": ["CVE-2007-2447"],
            },
            {
                "match": ["tomcat"],
                "title": "Tomcat administrative or application surface exposed",
                "severity": "HIGH",
                "confidence": 74,
                "summary": "Tomcat endpoints frequently expose default pages, manager consoles, or deployable application workflows in training labs.",
                "why": "Tomcat can provide a strong learner pathway when credentials or default content are weak.",
                "verification": [
                    "Inspect `/manager/html` and application roots manually.",
                    "Review authentication prompts and default content.",
                    "Correlate with any exposed credentials or backups.",
                ],
                "routes": [
                    "Evaluate administrative interfaces.",
                    "Inspect deployed applications for configuration disclosure.",
                ],
                "remediation": [
                    "Restrict manager applications.",
                    "Remove default apps and enforce strong credentials.",
                ],
                "references": [],
            },
            {
                "match": ["proftpd", "1.3"],
                "title": "Legacy ProFTPD version detected",
                "severity": "HIGH",
                "confidence": 80,
                "summary": "An older ProFTPD service can indicate a high-value learner path around weak hardening, writable directories, or training-lab vulnerabilities.",
                "why": "Older FTP daemons frequently appear on lab targets as a pivot into file disclosure or service-level compromise.",
                "verification": [
                    "Confirm the ProFTPD version from the banner.",
                    "Review whether anonymous access or upload permissions are enabled.",
                    "Correlate the FTP service with any web-served upload paths.",
                ],
                "routes": [
                    "Inspect anonymous FTP exposure and writable content paths.",
                    "Cross-reference with web content to identify upload-to-web pathways.",
                ],
                "remediation": [
                    "Upgrade ProFTPD to a supported release.",
                    "Disable anonymous access and reduce writable exposure.",
                ],
                "references": ["CVE-2010-3867"],
            },
            {
                "match": ["postgresql", "8."],
                "title": "Legacy PostgreSQL release detected",
                "severity": "MEDIUM",
                "confidence": 72,
                "summary": "An older PostgreSQL build suggests outdated patching and a potentially learner-relevant path through database exposure or weak credentials.",
                "why": "Legacy databases can expose version-specific weaknesses and often coincide with overly broad network access.",
                "verification": [
                    "Confirm the PostgreSQL major version and authentication behavior.",
                    "Determine whether the database is intended to be externally reachable.",
                ],
                "routes": [
                    "Inspect authentication exposure and default credential pathways in the lab.",
                    "Review whether database access could reveal application secrets or credentials.",
                ],
                "remediation": [
                    "Upgrade PostgreSQL to a supported branch.",
                    "Restrict network access to trusted systems only.",
                ],
                "references": [],
            },
            {
                "match": ["mysql", "5.0"],
                "title": "Legacy MySQL release detected",
                "severity": "MEDIUM",
                "confidence": 72,
                "summary": "MySQL 5.0-era systems are long out of support and may expose weak defaults, outdated authentication behavior, or sensitive data paths.",
                "why": "Database exposure can create high-value learning opportunities through credential reuse, schema disclosure, or application secrets.",
                "verification": [
                    "Validate the MySQL version and network reachability.",
                    "Inspect whether default accounts or lab credentials are in scope.",
                ],
                "routes": [
                    "Review database-authentication pathways.",
                    "Correlate database exposure with web application secrets and config files.",
                ],
                "remediation": [
                    "Upgrade MySQL to a supported release.",
                    "Restrict network access and review accounts.",
                ],
                "references": [],
            },
            {
                "match": ["unrealircd"],
                "title": "Legacy IRC daemon exposure detected",
                "severity": "HIGH",
                "confidence": 85,
                "summary": "A legacy IRC daemon on an exposed host is often an intentionally learner-relevant attack surface in lab environments.",
                "why": "Historically vulnerable IRC services have been used in training targets to demonstrate direct service compromise paths.",
                "verification": [
                    "Confirm the daemon family and version from the banner.",
                    "Determine whether the service is the intended learner pathway for the host.",
                ],
                "routes": [
                    "Review the service banner and version carefully.",
                    "Compare with other stronger or weaker exposed pathways before prioritizing.",
                ],
                "remediation": [
                    "Upgrade or replace the IRC daemon.",
                    "Remove unnecessary external exposure.",
                ],
                "references": ["CVE-2010-2075"],
            },
            {
                "match": ["distccd"],
                "title": "distccd service exposed",
                "severity": "HIGH",
                "confidence": 84,
                "summary": "An exposed distccd service can represent a direct learner pathway because it is rarely intended for broad network access.",
                "why": "Build-distribution daemons are high-signal services when found externally and often indicate weak service isolation.",
                "verification": [
                    "Confirm the distccd banner or port fingerprint.",
                    "Check whether the service is intended to be accessible beyond trusted build hosts.",
                ],
                "routes": [
                    "Prioritize the service for validation guidance.",
                    "Correlate with host role and whether a direct service pathway is expected in the lab.",
                ],
                "remediation": [
                    "Restrict distccd to trusted hosts only.",
                    "Disable the service if not required.",
                ],
                "references": ["CVE-2004-2687"],
            },
        ]

    def correlate(self, state):
        findings = []
        for port, details in state.services_detail.items():
            service_text = " ".join(
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

            findings.extend(self._service_risks(port, details, service_text))

            for signature in self.signatures:
                if all(token in service_text for token in signature["match"]):
                    findings.append(
                        {
                            "title": signature["title"],
                            "type": "service_version_risk",
                            "severity": signature["severity"],
                            "confidence": signature["confidence"],
                            "description": f"{signature['summary']} {signature['why']}",
                            "summary": signature["summary"],
                            "evidence": [
                                f"Port {port}/{details.get('service')} banner: {details.get('banner') or 'not available'}"
                            ],
                            "affected_service": details.get("service"),
                            "affected_port": port,
                            "kill_chain_stage": "Vulnerability Correlation",
                            "attack_opportunities": signature["routes"],
                            "verification_steps": signature["verification"],
                            "remediation": signature["remediation"],
                            "references": signature["references"],
                            "source": "rule_based_correlation",
                        }
                    )
        return findings

    def find_cves(self, services):
        vulnerabilities = []
        for port, service in services.items():
            service_lower = service.lower()
            if "openssh" in service_lower or "ssh" in service_lower:
                vulnerabilities.append({"cve": "CVE-2018-15473", "severity": "HIGH", "port": port})
            if "apache" in service_lower or "http" in service_lower:
                vulnerabilities.append({"cve": "CVE-2021-42013", "severity": "HIGH", "port": port})
        return vulnerabilities

    def _service_risks(self, port, details, service_text):
        risks = []
        service_name = details.get("service", "unknown")
        product = (details.get("product") or "").lower()
        version = (details.get("version") or "").lower()
        if port == "21" or "ftp" in service_text:
            risks.append(
                {
                    "title": "FTP service exposed to the network",
                    "type": "ftp_exposure",
                    "severity": "MEDIUM",
                    "confidence": 68,
                    "description": "FTP frequently appears in training labs as a path to anonymous access, weak credentials, or writable content exposure.",
                    "summary": "Network-facing FTP should be reviewed for anonymous login and file disclosure.",
                    "evidence": [f"FTP-like service detected on port {port}: {details.get('banner') or service_name}"],
                    "affected_service": service_name,
                    "affected_port": port,
                    "kill_chain_stage": "Vulnerability Correlation",
                    "attack_opportunities": [
                        "Check whether anonymous access is allowed.",
                        "Inspect whether readable or writable directories are exposed.",
                    ],
                    "verification_steps": [
                        "Confirm whether the service permits anonymous login in the lab.",
                        "Review banners and directory listing behavior before any validation attempt.",
                    ],
                    "remediation": [
                        "Disable unused FTP access.",
                        "Restrict anonymous and writable permissions.",
                    ],
                    "references": [],
                    "source": "rule_based_correlation",
                }
            )
        if port == "22" or "ssh" in service_text:
            risks.append(
                {
                    "title": "SSH administration surface exposed",
                    "type": "ssh_exposure",
                    "severity": "MEDIUM",
                    "confidence": 70,
                    "description": "SSH is a common administrative entry point and should be correlated with usernames, credentials, and exposed services that may leak access material.",
                    "summary": "Reachable SSH expands the value of any credential or configuration disclosure elsewhere on the host.",
                    "evidence": [f"SSH-like service detected on port {port}: {details.get('banner') or service_name}"],
                    "affected_service": service_name,
                    "affected_port": port,
                    "kill_chain_stage": "Vulnerability Correlation",
                    "attack_opportunities": [
                        "Cross-reference usernames, keys, and credentials exposed by other services.",
                        "Prioritize legacy SSH versions higher than modern hardened builds.",
                    ],
                    "verification_steps": [
                        "Validate the SSH version and whether password authentication appears likely.",
                        "Review related services for leaked usernames or reusable credentials.",
                    ],
                    "remediation": [
                        "Limit SSH exposure to trusted users and networks.",
                        "Harden authentication and upgrade legacy versions.",
                    ],
                    "references": [],
                    "source": "rule_based_correlation",
                }
            )
        if port in {"23", "512", "513", "514"} or any(token in service_text for token in ("telnet", "rsh", "rexec", "rlogin")):
            risks.append(
                {
                    "title": "Legacy remote administration service exposed",
                    "type": "legacy_remote_service",
                    "severity": "HIGH",
                    "confidence": 82,
                    "description": "Legacy remote administration protocols often rely on weak trust models and plaintext authentication.",
                    "summary": "Deprecated administrative protocols remain reachable from the network.",
                    "evidence": [f"Legacy service {service_name} detected on port {port}"],
                    "affected_service": service_name,
                    "affected_port": port,
                    "kill_chain_stage": "Vulnerability Correlation",
                    "attack_opportunities": [
                        "Review trust relationships and plaintext credential exposure in the lab.",
                        "Prioritize this service highly for learner analysis.",
                    ],
                    "verification_steps": [
                        "Validate whether the service uses plaintext or host-based trust.",
                        "Compare it with other exposed login surfaces on the target.",
                    ],
                    "remediation": [
                        "Remove deprecated remote administration protocols.",
                        "Replace with SSH or modern access controls.",
                    ],
                    "references": [],
                    "source": "rule_based_correlation",
                }
            )
        if port in {"25", "110", "143", "465", "587", "993", "995"} or any(token in service_text for token in ("smtp", "pop3", "imap")):
            risks.append(
                {
                    "title": "Mail service exposure may disclose usernames or relay risk",
                    "type": "mail_service_exposure",
                    "severity": "MEDIUM",
                    "confidence": 67,
                    "description": "Reachable mail services can provide usernames, banner clues, legacy auth mechanisms, or insecure relay/misconfiguration signals.",
                    "summary": "Externally reachable mail infrastructure expands the target's identity and authentication attack surface.",
                    "evidence": [f"Mail-related service {service_name} detected on port {port}"],
                    "affected_service": service_name,
                    "affected_port": port,
                    "kill_chain_stage": "Vulnerability Correlation",
                    "attack_opportunities": [
                        "Review banners and supported auth mechanisms for weak or legacy behavior.",
                        "Extract likely usernames for cross-service analysis.",
                    ],
                    "verification_steps": [
                        "Identify the mail daemon family and supported authentication methods.",
                        "Check whether enumeration or misconfiguration is evident from server responses.",
                    ],
                    "remediation": [
                        "Restrict unnecessary mail exposure.",
                        "Harden relay, authentication, and TLS configuration.",
                    ],
                    "references": [],
                    "source": "rule_based_correlation",
                }
            )
        if port in {"53"} or any(token in service_text for token in ("domain", "bind", "dns")):
            risks.append(
                {
                    "title": "DNS service exposed for enumeration",
                    "type": "dns_exposure",
                    "severity": "MEDIUM",
                    "confidence": 66,
                    "description": "An exposed DNS service can provide zone data, hostnames, and infrastructure clues that strengthen later attack-path planning.",
                    "summary": "Reachable DNS often increases reconnaissance depth and may reveal internal structure.",
                    "evidence": [f"DNS-like service detected on port {port}: {details.get('banner') or service_name}"],
                    "affected_service": service_name,
                    "affected_port": port,
                    "kill_chain_stage": "Vulnerability Correlation",
                    "attack_opportunities": [
                        "Check whether the server exposes unnecessary metadata or zone information.",
                        "Use discovered hostnames to enrich later validation paths.",
                    ],
                    "verification_steps": [
                        "Confirm whether the server allows recursion or broad metadata disclosure.",
                        "Record discovered domain and host information for later correlation.",
                    ],
                    "remediation": [
                        "Restrict recursion and unnecessary disclosure.",
                        "Limit DNS service exposure to intended clients.",
                    ],
                    "references": [],
                    "source": "rule_based_correlation",
                }
            )
        if port in {"111", "2049"} or any(token in service_text for token in ("rpcbind", "nfs")):
            risks.append(
                {
                    "title": "RPC/NFS exposure may enable share discovery or trust abuse",
                    "type": "rpc_nfs_exposure",
                    "severity": "HIGH",
                    "confidence": 78,
                    "description": "RPC and NFS services are high-signal because they can expose share metadata, trust assumptions, or sensitive file access paths.",
                    "summary": "Network file services should be prioritized for learner analysis when exposed.",
                    "evidence": [f"RPC/NFS-like service {service_name} detected on port {port}"],
                    "affected_service": service_name,
                    "affected_port": port,
                    "kill_chain_stage": "Vulnerability Correlation",
                    "attack_opportunities": [
                        "Enumerate exported shares and permissions.",
                        "Review whether mounted or exported data could expose credentials or application content.",
                    ],
                    "verification_steps": [
                        "Identify exported directories and access controls.",
                        "Inspect whether export settings are broader than intended.",
                    ],
                    "remediation": [
                        "Restrict exported file services.",
                        "Limit mount permissions and trusted client scope.",
                    ],
                    "references": [],
                    "source": "rule_based_correlation",
                }
            )
        if port in {"3306", "5432"} or any(token in service_text for token in ("mysql", "postgresql")):
            risks.append(
                {
                    "title": "Database service exposed externally",
                    "type": "database_exposure",
                    "severity": "HIGH",
                    "confidence": 74,
                    "description": "Externally reachable databases can disclose versioning, authentication behavior, and schema access opportunities.",
                    "summary": "A database listener is exposed to the network and should be reviewed for weak credentials and overexposure.",
                    "evidence": [f"Database service {service_name} reachable on port {port}"],
                    "affected_service": service_name,
                    "affected_port": port,
                    "kill_chain_stage": "Vulnerability Correlation",
                    "attack_opportunities": [
                        "Inspect default or weak credential scenarios in the lab.",
                        "Review whether the service should be externally reachable at all.",
                    ],
                    "verification_steps": [
                        "Confirm the exact database version.",
                        "Check whether the listener exposes banners or unauthenticated responses.",
                    ],
                    "remediation": [
                        "Restrict database exposure to trusted hosts.",
                        "Enforce strong authentication and patching.",
                    ],
                    "references": [],
                    "source": "rule_based_correlation",
                }
            )
        if port in {"5900", "5901", "5902"} or "vnc" in service_text:
            risks.append(
                {
                    "title": "Remote desktop service exposed via VNC",
                    "type": "vnc_exposure",
                    "severity": "HIGH",
                    "confidence": 76,
                    "description": "VNC services are commonly weakly protected in labs and can become a direct operator pathway if authentication is weak.",
                    "summary": "Exposed VNC should be prioritized because it may provide direct interactive access.",
                    "evidence": [f"VNC-like service detected on port {port}: {details.get('banner') or service_name}"],
                    "affected_service": service_name,
                    "affected_port": port,
                    "kill_chain_stage": "Vulnerability Correlation",
                    "attack_opportunities": [
                        "Review whether authentication is enforced and modernized.",
                        "Correlate with other credential exposure on the host.",
                    ],
                    "verification_steps": [
                        "Confirm the VNC version and whether the service requests authentication.",
                        "Assess whether the service is intentionally exposed for lab learning.",
                    ],
                    "remediation": [
                        "Restrict VNC to trusted networks.",
                        "Enforce strong authentication or remove unnecessary exposure.",
                    ],
                    "references": [],
                    "source": "rule_based_correlation",
                }
            )
        if port in {"6000", "6001"} or "x11" in service_text:
            risks.append(
                {
                    "title": "X11 display service exposed",
                    "type": "x11_exposure",
                    "severity": "MEDIUM",
                    "confidence": 65,
                    "description": "Exposed X11 is a sign of weak service isolation and can leak interactive or session-level opportunities in lab systems.",
                    "summary": "Reachable X11 should be treated as unnecessary exposure unless explicitly intended.",
                    "evidence": [f"X11-like service detected on port {port}"],
                    "affected_service": service_name,
                    "affected_port": port,
                    "kill_chain_stage": "Vulnerability Correlation",
                    "attack_opportunities": [
                        "Review whether display access controls are disabled or weak.",
                        "Use the presence of X11 as a signal of weak host hardening.",
                    ],
                    "verification_steps": [
                        "Identify whether access control is enforced.",
                        "Correlate with local interactive service exposure such as VNC or desktop managers.",
                    ],
                    "remediation": [
                        "Disable or firewall X11 network exposure.",
                        "Use local-only display access and secure forwarding.",
                    ],
                    "references": [],
                    "source": "rule_based_correlation",
                }
            )
        if "irc" in service_text:
            risks.append(
                {
                    "title": "IRC service exposure increases legacy attack surface",
                    "type": "irc_exposure",
                    "severity": "MEDIUM",
                    "confidence": 73,
                    "description": "Legacy IRC daemons are unusual in modern deployments and deserve high learner attention when reachable on a target.",
                    "summary": "Externally reachable IRC indicates a potentially high-signal legacy service.",
                    "evidence": [f"IRC-like service detected on port {port}: {details.get('banner') or service_name}"],
                    "affected_service": service_name,
                    "affected_port": port,
                    "kill_chain_stage": "Vulnerability Correlation",
                    "attack_opportunities": [
                        "Review the daemon family and version carefully.",
                        "Prioritize IRC higher when banners indicate legacy builds.",
                    ],
                    "verification_steps": [
                        "Confirm the daemon name and version from the banner.",
                        "Check whether the service matches common training-lab patterns.",
                    ],
                    "remediation": [
                        "Upgrade or remove the IRC daemon.",
                        "Limit external exposure.",
                    ],
                    "references": [],
                    "source": "rule_based_correlation",
                }
            )
        if port in {"8009"} or "ajp" in service_text:
            risks.append(
                {
                    "title": "AJP connector exposed",
                    "type": "ajp_exposure",
                    "severity": "HIGH",
                    "confidence": 79,
                    "description": "An exposed AJP connector suggests unnecessary application-server surface and should be correlated with Tomcat or Java middleware findings.",
                    "summary": "AJP should rarely be broadly exposed and often indicates misconfiguration.",
                    "evidence": [f"AJP-like service detected on port {port}: {details.get('banner') or service_name}"],
                    "affected_service": service_name,
                    "affected_port": port,
                    "kill_chain_stage": "Vulnerability Correlation",
                    "attack_opportunities": [
                        "Correlate with web application stacks and manager consoles.",
                        "Treat the connector as a high-signal misconfiguration.",
                    ],
                    "verification_steps": [
                        "Identify the backing Java application server.",
                        "Determine whether the connector is intended to be internet reachable.",
                    ],
                    "remediation": [
                        "Bind AJP to trusted interfaces only.",
                        "Disable unused connectors.",
                    ],
                    "references": [],
                    "source": "rule_based_correlation",
                }
            )
        if port in {"135"} or "msrpc" in service_text:
            risks.append(
                {
                    "title": "Windows RPC exposure identified",
                    "type": "windows_rpc_exposure",
                    "severity": "MEDIUM",
                    "confidence": 64,
                    "description": "MSRPC exposure helps classify the target as Windows-oriented and can indicate a broader SMB/administrative surface.",
                    "summary": "Windows RPC should be correlated with SMB and high-port services for host-role analysis.",
                    "evidence": [f"MSRPC-like service detected on port {port}"],
                    "affected_service": service_name,
                    "affected_port": port,
                    "kill_chain_stage": "Vulnerability Correlation",
                    "attack_opportunities": [
                        "Pair with SMB, NetBIOS, and high-port service evidence to profile Windows exposure.",
                        "Inspect whether the host is exposing unnecessary administrative services.",
                    ],
                    "verification_steps": [
                        "Confirm whether SMB and NetBIOS are exposed as well.",
                        "Classify the target as a Windows host for later learner guidance.",
                    ],
                    "remediation": [
                        "Restrict Windows administrative exposure.",
                        "Limit access to trusted management networks.",
                    ],
                    "references": [],
                    "source": "rule_based_correlation",
                }
            )
        if service_name == "unknown" and port.isdigit() and int(port) >= 49152:
            risks.append(
                {
                    "title": "Multiple high ephemeral ports exposed",
                    "type": "high_port_exposure",
                    "severity": "LOW",
                    "confidence": 52,
                    "description": "Unidentified high ports may represent dynamic Windows RPC services or application endpoints that merit host-role correlation.",
                    "summary": "Unknown high ports should be interpreted in context rather than ignored.",
                    "evidence": [f"High port {port} was open but not confidently identified"],
                    "affected_service": service_name,
                    "affected_port": port,
                    "kill_chain_stage": "Vulnerability Correlation",
                    "attack_opportunities": [
                        "Correlate these ports with RPC, SMB, or application-server exposure.",
                        "Use them as supporting evidence for host fingerprinting.",
                    ],
                    "verification_steps": [
                        "Review whether Nmap or alternate banner checks can improve identification.",
                    ],
                    "remediation": [
                        "Reduce unnecessary exposed services.",
                    ],
                    "references": [],
                    "source": "rule_based_correlation",
                }
            )
        return risks
