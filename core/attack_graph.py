import networkx as nx
import matplotlib.pyplot as plt
import os


class AttackGraph:

    COLORS = {
        "TARGET": "#ff4d4d",
        "RECON": "#4da6ff",
        "SERVICE": "#ffd24d",
        "VULN": "#ff944d",
        "ATTACK": "#66ff66",
        "REPORT": "#cc66ff",
    }

    def __init__(self, state):

        self.state = state

        self.graph = nx.DiGraph()

        self.positions = {}

        self.node_colors = []

    def build(self):

        self.graph.clear()
        self.positions.clear()
        self.node_colors.clear()

        y = 0

        target = self.state.target

        if isinstance(target, dict):
            target = target.get("ip")

        self.add_node(target, "TARGET", 0, y)

        y -= 1

        self.add_node("Reconnaissance", "RECON", 1, y)

        self.graph.add_edge(target, "Reconnaissance")

        services = self.state.network.get("open_ports", {})

        y_services = y - 1

        for port, service in services.items():

            label = f"{service.upper()} ({port})"

            self.add_node(label, "SERVICE", 2, y_services)

            self.graph.add_edge("Reconnaissance", label)

            y_services -= 1

        vulns = self.state.network.get("vulnerabilities", [])

        y_vuln = y_services - 1

        for vuln in vulns:

            label = vuln.get("type")

            self.add_node(label, "VULN", 3, y_vuln)

            self.graph.add_edge("Reconnaissance", label)

            y_vuln -= 1

        attack_plan = getattr(self.state, "attack_plan", {})

        if attack_plan and attack_plan.get("best_path"):

            label = attack_plan.get("best_path")

            self.add_node(label, "ATTACK", 4, y_vuln)

            self.graph.add_edge("Reconnaissance", label)

            y_vuln -= 1

        self.add_node("Report Generated", "REPORT", 5, y_vuln)

    def add_node(self, label, node_type, x, y):

        self.graph.add_node(label)

        self.positions[label] = (x, y)

        self.node_colors.append(self.COLORS[node_type])

    def show(self):

        self.build()

        plt.figure(figsize=(14, 8))

        nx.draw(
            self.graph,
            self.positions,
            with_labels=True,
            node_color=self.node_colors,
            node_size=3000,
            font_size=10,
            font_weight="bold",
            edge_color="#aaaaaa"
        )

        plt.title("AARTF Attack Graph")

        plt.axis("off")

        plt.show()

    # THIS IS THE IMPORTANT NEW FUNCTION
    def save_png(self):

        self.build()

        os.makedirs("reports", exist_ok=True)

        target = self.state.target

        if isinstance(target, dict):
            target = target.get("ip")

        filename = f"reports/attack_graph_{target}.png"

        plt.figure(figsize=(14, 8))

        nx.draw(
            self.graph,
            self.positions,
            with_labels=True,
            node_color=self.node_colors,
            node_size=3000,
            font_size=10,
            font_weight="bold",
            edge_color="#aaaaaa"
        )

        plt.title("AARTF Attack Graph")

        plt.axis("off")

        plt.savefig(filename, dpi=300, bbox_inches="tight")

        plt.close()

        print(f"[+] Attack graph saved: {filename}")
