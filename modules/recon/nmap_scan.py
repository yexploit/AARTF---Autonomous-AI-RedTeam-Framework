import subprocess
import shutil
from functools import lru_cache
import re


class NmapScanModule:

    NAME = "nmap_scan"

    def discover(self, state):
        if state.phase == "RECONNAISSANCE":
            return [{
                "name": self.NAME,
                "type": "recon"
            }]
        return []

    def execute(self, state):
        target = state.target.get("ip") if isinstance(state.target, dict) else state.target

        print(f"[*] Running Nmap scan against {target}")
        if not shutil.which("nmap"):
            print("[!] nmap command not found. Skipping nmap scan.")
            state.network["nmap_output"] = ""
            state.network.setdefault("services", {})
            state.network.setdefault("open_ports", {})
            state.add_learning_note(
                "Nmap Unavailable",
                "Install Nmap and ensure it is on PATH to unlock version detection and richer correlation.",
            )
            return {"success": False, "summary": "nmap not installed"}

        try:
            output = self._run_nmap(target)

            print("[+] Nmap scan completed")
            state.network["nmap_output"] = output

            parsed = self._parse_services(output)
            for service in parsed["services"]:
                state.add_service(
                    service["port"],
                    service["service"],
                    {
                        "product": service.get("product"),
                        "version": service.get("version"),
                        "banner": service.get("banner"),
                        "extrainfo": service.get("extrainfo"),
                        "protocol": service.get("protocol", "tcp"),
                        "source": "nmap",
                    },
                )

            if parsed["os_hints"]:
                state.target["os"] = parsed["os_hints"][0]
            state.attack_surface["os_hints"] = parsed["os_hints"]
            state.attack_surface["script_highlights"] = parsed["script_highlights"]

            return {
                "success": True,
                "summary": f"Identified {len(parsed['services'])} exposed services",
            }

        except Exception as e:

            print(f"[!] Nmap scan failed: {e}")

            return {"success": False, "summary": str(e)}

    @lru_cache(maxsize=128)
    def _run_nmap(self, target):
        cmd = [
            "nmap",
            "-Pn",
            "-n",
            "-T4",
            "-sV",
            "-O",
            "--version-light",
            "--max-retries", "1",
            "--host-timeout", "45s",
            "--top-ports", "1000",
            target,
        ]
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
            check=False,
        )
        return proc.stdout.decode("utf-8", errors="ignore")

    def _parse_services(self, output):
        services = []
        os_hints = []
        script_highlights = []
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("|") or stripped.startswith("Service Info:"):
                script_highlights.append(stripped)
            if "OS details:" in stripped or "Running:" in stripped:
                os_hints.append(stripped.split(":", 1)[-1].strip())
            if "/tcp" not in stripped or " open " not in stripped:
                continue

            match = re.match(
                r"(?P<port>\d+)/(?P<protocol>\w+)\s+open\s+(?P<service>\S+)(?:\s+(?P<rest>.*))?$",
                stripped,
            )
            if not match:
                continue

            rest = (match.group("rest") or "").strip()
            product, version, extrainfo = self._split_banner(rest)
            services.append(
                {
                    "port": match.group("port"),
                    "protocol": match.group("protocol"),
                    "service": match.group("service"),
                    "product": product,
                    "version": version,
                    "banner": rest,
                    "extrainfo": extrainfo,
                }
            )
        return {
            "services": services,
            "os_hints": os_hints,
            "script_highlights": script_highlights,
        }

    def _split_banner(self, rest):
        if not rest:
            return None, None, None
        tokens = rest.split()
        product = tokens[0] if tokens else None
        version = None
        extrainfo = None
        if len(tokens) > 1 and any(ch.isdigit() for ch in tokens[1]):
            version = tokens[1]
            extrainfo = " ".join(tokens[2:]) or None
        else:
            extrainfo = " ".join(tokens[1:]) or None
        return product, version, extrainfo
