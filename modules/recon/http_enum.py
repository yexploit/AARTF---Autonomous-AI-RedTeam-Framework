import socket
from html.parser import HTMLParser

import requests


class _TitleParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_title = False
        self.title = ""

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "title":
            self.in_title = True

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title += data


class HTTPEnumerationModule:

    NAME = "http_enumeration"

    COMMON_PATHS = [
        "/",
        "/robots.txt",
        "/admin",
        "/login",
        "/dashboard",
        "/config",
        "/backup",
        "/test",
        "/phpinfo.php",
        "/server-status",
        "/manager/html",
    ]

    def discover(self, state):
        if state.phase != "ENUMERATION":
            return []

        services = state.services_detail

        # check if HTTP port exists
        if any(port in services for port in ("80", "443", "8080", "8000", "8180", "8443")):
            return [{
                "name": self.NAME,
                "type": "recon"
            }]

        return []

    def execute(self, state):
        target_ip = state.target["ip"]
        print(f"[*] Running HTTP enumeration on {target_ip}")
        ports = ["80", "443", "8080", "8000", "8180", "8443"]
        web_services = [state.services_detail[port] for port in ports if port in state.services_detail]
        findings = []
        summaries = []
        http_assets = []

        for service in web_services:
            port = service["port"]
            schemes = ["https", "http"] if port in {"443", "8443"} else ["http", "https"]
            for proto in schemes:
                url = f"{proto}://{target_ip}:{port}" if port not in {"80", "443"} else f"{proto}://{target_ip}"
                try:
                    response = requests.get(url, timeout=5, verify=False)
                except requests.exceptions.RequestException:
                    continue

                parser = _TitleParser()
                parser.feed(response.text[:4000])
                title = parser.title.strip() or "Untitled"
                server = response.headers.get("Server", service.get("banner") or "unknown")
                headers = dict(response.headers)
                discovered_paths = []

                for path in self.COMMON_PATHS:
                    full_url = f"{url}{path}"
                    try:
                        sub_response = requests.get(full_url, timeout=3, verify=False)
                    except requests.exceptions.RequestException:
                        continue
                    if sub_response.status_code < 400 or sub_response.status_code in (401, 403):
                        discovered_paths.append(
                            {
                                "path": path,
                                "status": sub_response.status_code,
                                "url": full_url,
                            }
                        )

                http_info = {
                    "protocol": proto,
                    "base_url": url,
                    "status_code": response.status_code,
                    "server": server,
                    "title": title,
                    "headers": headers,
                    "discovered_paths": discovered_paths,
                    "cookies": list(response.cookies.keys()),
                    "content_hints": self._extract_content_hints(response.text[:8000]),
                }
                state.network.setdefault("http", {})[port] = http_info
                http_assets.append(http_info)
                summaries.append(f"{url} -> {server} ({title})")

                state.add_learning_note(
                    f"HTTP profile {port}",
                    f"{url} responded with {response.status_code}, title '{title}', and server header '{server}'.",
                )

                if any(item["path"] in {"/admin", "/login", "/dashboard", "/manager/html"} for item in discovered_paths):
                    findings.append(
                        {
                            "title": f"Exposed web management surface on port {port}",
                            "type": "exposed_admin_interface",
                            "severity": "HIGH",
                            "confidence": 78,
                            "description": f"Administrative or authentication-oriented web paths were reachable on {url}.",
                            "evidence": [f"{item['url']} returned {item['status']}" for item in discovered_paths if item["path"] in {"/admin", "/login", "/dashboard", "/manager/html"}],
                            "affected_service": "http",
                            "affected_port": port,
                            "kill_chain_stage": "Enumeration",
                            "attack_opportunities": [
                                "Inspect login workflows for weak authentication patterns.",
                                "Review administrative surfaces for default credentials in labs.",
                            ],
                            "verification_steps": [
                                f"Open {url} and inspect the login or admin surface manually.",
                                "Capture authentication prompts, redirects, and exposed technology hints.",
                                "Review whether the path is expected or unintentionally exposed.",
                            ],
                            "remediation": [
                                "Restrict access to administrative paths.",
                                "Require strong authentication and MFA where applicable.",
                            ],
                            "source": self.NAME,
                        }
                    )

                if "Apache" in server or "nginx" in server or "Tomcat" in server:
                    state.add_learning_note(
                        f"Web stack identified on {port}",
                        f"Detected '{server}'. Compare the reported version against known lab-relevant weaknesses and default content exposure.",
                    )
                if http_info["content_hints"]:
                    state.add_learning_note(
                        f"Web content hints on {port}",
                        f"{url} exposed content hints: {', '.join(http_info['content_hints'][:5])}.",
                    )
                if any(token in response.text.lower() for token in ("password", "username", "login", "admin panel", "upload")):
                    findings.append(
                        {
                            "title": f"Web page content hints suggest authentication or upload workflow on port {port}",
                            "type": "web_content_hint",
                            "severity": "MEDIUM",
                            "confidence": 66,
                            "description": f"The landing page or discovered content on {url} includes strings commonly associated with authentication or upload workflows.",
                            "evidence": [f"title={title}", f"server={server}"] + [f"hint={hint}" for hint in http_info["content_hints"][:3]],
                            "affected_service": "http",
                            "affected_port": port,
                            "kill_chain_stage": "Enumeration",
                            "attack_opportunities": [
                                "Inspect forms, uploads, and authentication flows manually.",
                                "Correlate page behavior with discovered paths and backend services.",
                            ],
                            "verification_steps": [
                                f"Browse {url} and note any forms, file uploads, or login workflows.",
                                "Review whether the page discloses framework, environment, or credential-reset behavior.",
                            ],
                            "remediation": [
                                "Reduce information leakage from public pages.",
                                "Protect upload and authentication workflows appropriately.",
                            ],
                            "source": self.NAME,
                        }
                    )
                break

        for finding in findings:
            state.add_finding(finding)

        if http_assets:
            print("[+] HTTP services enumerated")
            return {
                "success": True,
                "summary": "; ".join(summaries[:3]),
            }

        print("[!] No HTTP service detected")
        return {"success": False, "summary": "no reachable HTTP services"}

    def _extract_content_hints(self, html):
        lowered = html.lower()
        hints = []
        patterns = [
            ("upload", "upload"),
            ("login", "login"),
            ("password", "password"),
            ("admin", "admin"),
            ("wordpress", "wordpress"),
            ("drupal", "drupal"),
            ("joomla", "joomla"),
            ("phpmyadmin", "phpmyadmin"),
            ("tomcat", "tomcat"),
        ]
        for needle, label in patterns:
            if needle in lowered and label not in hints:
                hints.append(label)
        return hints
