import ipaddress
import subprocess
import platform


class SubnetScanner:

    def __init__(self, subnet):

        self.subnet = subnet

    def discover_hosts(self):

        print(f"[*] Scanning subnet: {self.subnet}")

        hosts = []

        try:

            network = ipaddress.ip_network(self.subnet, strict=False)

            for ip in network.hosts():

                ip_str = str(ip)

                if self.is_host_alive(ip_str):

                    print(f"[+] Host alive: {ip_str}")

                    hosts.append(ip_str)

        except Exception as e:

            print(f"[!] Subnet scan error: {e}")

        return hosts

    def is_host_alive(self, ip):

        try:
            if platform.system().lower().startswith("win"):
                cmd = ["ping", "-n", "1", "-w", "500", ip]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", ip]

            result = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            return result.returncode == 0

        except Exception:

            return False
