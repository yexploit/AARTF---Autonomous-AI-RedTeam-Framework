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
        "GUIDE": "#7bdcb5",
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

        services = self.state.services_detail

        y_services = y - 1

        for port, service in sorted(services.items(), key=lambda item: int(item[0])):
            label = f"{service.get('service', 'unknown').upper()} ({port})"

            self.add_node(label, "SERVICE", 2, y_services)

            self.graph.add_edge("Reconnaissance", label)

            y_services -= 1

        vulns = self.state.findings

        y_vuln = y_services - 1

        for vuln in vulns[:8]:
            label = vuln.get("title") or vuln.get("type")

            self.add_node(label, "VULN", 3, y_vuln)

            service_port = vuln.get("affected_port")
            if service_port and service_port in services:
                self.graph.add_edge(f"{services[service_port].get('service', 'unknown').upper()} ({service_port})", label)
            else:
                self.graph.add_edge("Reconnaissance", label)

            y_vuln -= 1

        for attack_path in self.state.attack_paths[:5]:
            label = attack_path.get("title")
            self.add_node(label, "ATTACK", 4, y_vuln)
            for source in attack_path.get("source_findings", [])[:2]:
                finding = next((item for item in self.state.findings if item["id"] == source), None)
                if finding:
                    self.graph.add_edge(finding.get("title"), label)
            if not attack_path.get("source_findings"):
                self.graph.add_edge("Reconnaissance", label)
            y_vuln -= 1

        if self.state.walkthrough:
            guide_label = "Learner Walkthrough"
            self.add_node(guide_label, "GUIDE", 5, y_vuln)
            if self.state.attack_paths:
                self.graph.add_edge(self.state.attack_paths[0]["title"], guide_label)
            y_vuln -= 1

        self.add_node("Report Generated", "REPORT", 6, y_vuln)

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

        safe_target = str(target).replace(".", "_").replace("/", "_")
        filename = f"reports/attack_graph_{safe_target}.png"

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
