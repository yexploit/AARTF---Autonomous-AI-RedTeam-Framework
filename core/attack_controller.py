from core.exploit_selector import ExploitSelector

class AttackController:

    def __init__(self, state):

        self.state = state

    def update_phase(self):

        phase = self.state.phase

        # If compromised → move forward
        if self.state.compromised:

            if phase == "INITIAL_ACCESS":
                self.state.phase = "POST_ACCESS"
                return

        # Skip phase if all actions failed
        failed_actions = self.state.action_attempts

        if phase == "INITIAL_ACCESS":

            if all(attempts >= 2 for attempts in failed_actions.values()):

                print("[!] No initial access possible. Moving to next phase.")

                self.state.phase = "COMPLETE"

        elif phase == "RECON":

            vulns = self.state.network.get("vulnerabilities", [])

            if vulns:

                print("[+] Exploitable vulnerabilities detected")

                self.state.phase = "EXPLOITATION"

            else:

                self.state.phase = "INITIAL_ACCESS"

        # ⭐ ADD THIS BLOCK RIGHT HERE ⭐
        elif phase == "POST_ACCESS":

            if hasattr(self.state, "internal_networks") and self.state.internal_networks:

                print("[+] Internal network detected → Starting lateral movement")

                # Stay in POST_ACCESS so lateral module executes
                return

            else:

                print("[*] No internal networks found → Moving to privilege escalation")

                self.state.phase = "PRIVILEGE_ESCALATION"

        # PRIVILEGE_ESCALATION logic
        elif phase == "PRIVILEGE_ESCALATION":

            if self.state.escalated:

                print("[+] Privilege escalation successful")

                self.state.phase = "COMPLETE"


    # ---------------- CONDITIONS ---------------- #

    def has_services(self):

        services = self.state.network.get("services", {})

        return len(services) > 0

    def has_credentials(self):

        return len(self.state.credentials) > 0
