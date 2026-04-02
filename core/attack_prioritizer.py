from core.ai_prioritizer import AIPrioritizer


class AttackPrioritizer:

    def __init__(self):

        self.ai = AIPrioritizer()

    def prioritize(self, states):

        scored = []

        print("[*] AI scoring targets...")

        for state in states:

            services = state.network.get("services", {})

            vulns = state.network.get("vulnerabilities", [])

            score = self.ai.score_host(services, vulns)

            print(f"[AI Score] {state.target['ip']} → {score}")

            scored.append((score, state))

        scored.sort(key=lambda x: x[0], reverse=True)

        return [state for score, state in scored]
