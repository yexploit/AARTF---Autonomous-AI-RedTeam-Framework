import threading
from queue import Queue, Empty

from core.state import SessionState
from core.engine import AttackEngine
from core.subnet_scanner import SubnetScanner
from core.attack_prioritizer import AttackPrioritizer

class MultiTargetController:

    def __init__(self, target, max_threads=5):

        self.target = target

        self.max_threads = max_threads

        self.queue = Queue()

        self.threads = []

    # ---------------- MAIN ---------------- #

    def run(self):

        hosts = self.get_targets()
        hosts = self.prioritize_targets(hosts)

        print(f"[+] Total targets found: {len(hosts)}")

        for host in hosts:

            self.queue.put(host)

        self.start_threads()

        self.queue.join()

        print("[+] Distributed attack completed")

    # ---------------- TARGET DISCOVERY ---------------- #

    def get_targets(self):

        if "/" in self.target:

            scanner = SubnetScanner(self.target)

            return scanner.discover_hosts()

        else:

            return [self.target]

    # ---------------- THREAD MANAGEMENT ---------------- #

    def start_threads(self):

        for i in range(self.max_threads):

            thread = threading.Thread(
                target=self.worker,
                daemon=True
            )

            thread.start()

            self.threads.append(thread)

    # ---------------- WORKER ---------------- #

    def worker(self):
        while True:
            try:
                host = self.queue.get_nowait()
            except Empty:
                return

            try:

                self.attack_host(host)

            except Exception as e:

                print(f"[!] Error attacking {host}: {e}")

            finally:

                self.queue.task_done()

    # ---------------- ATTACK EXECUTION ---------------- #

    def attack_host(self, host):

        print("\n========================")
        print(f"[*] Attacking {host}")
        print("========================")

        state = SessionState(host)

        engine = AttackEngine(state)

        engine.run()

        print(f"[+] Completed attack on {host}")

        # Autonomous pivot attack
        if hasattr(state, "pivot_targets") and state.pivot_targets:

            print("[*] Launching pivot attacks")

            for pivot_ip in state.pivot_targets:

                print(f"[*] Pivot attacking {pivot_ip}")

                pivot_state = SessionState(pivot_ip)

                pivot_engine = AttackEngine(pivot_state)

                pivot_engine.run()

    
    def prioritize_targets(self, hosts):

        prioritizer = AttackPrioritizer()

        states = []

        for host in hosts:

            state = SessionState(host)

            states.append(state)

        prioritized_states = prioritizer.prioritize(states)

        prioritized_hosts = [state.target["ip"] for state in prioritized_states]

        print("[+] Target priority order:")

        for host in prioritized_hosts:

            print(f"   → {host}")

        return prioritized_hosts

