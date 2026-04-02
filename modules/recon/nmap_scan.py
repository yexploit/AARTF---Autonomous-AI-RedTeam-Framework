import subprocess
import shutil
from functools import lru_cache


class NmapScanModule:

    NAME = "nmap_scan"

    def discover(self, state):

        if state.phase == "RECON":

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
            return False

        try:
            output = self._run_nmap(target)

            print("[+] Nmap scan completed")
            state.network["nmap_output"] = output

            services = self._parse_services(output)

            state.network["services"] = services
            state.network["open_ports"] = services

            return True

        except Exception as e:

            print(f"[!] Nmap scan failed: {e}")

            return False

    @lru_cache(maxsize=128)
    def _run_nmap(self, target):
        cmd = [
            "nmap",
            "-Pn",
            "-n",
            "-T4",
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
        services = {}
        for line in output.splitlines():
            if "/tcp" not in line or "open" not in line:
                continue
            parts = line.split()
            if not parts:
                continue
            port = parts[0].split("/")[0]
            service = parts[2] if len(parts) > 2 else "unknown"
            services[port] = service
        return services
