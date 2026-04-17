import os

import matplotlib.pyplot as plt
import networkx as nx
from matplotlib.animation import FuncAnimation
from matplotlib.animation import writers as animation_writers


class AttackTimeline:
    COLORS = {
        "inactive": "#444444",
        "active": "#00ffcc",
        "completed": "#66ff66",
    }

    def __init__(self, state):
        self.state = state
        self.graph = nx.DiGraph()
        self.steps = []
        self.positions = {}
        self.build_steps()

    def build_steps(self):
        target = self.state.target
        if isinstance(target, dict):
            target = target.get("ip")

        self.steps = [target, "Reconnaissance", "Enumeration", "Correlation"]

        services = self.state.services_detail
        for port, service in sorted(services.items(), key=lambda item: int(item[0])):
            self.steps.append(f"{service.get('service', 'unknown')}:{port}")

        for vuln in self.state.findings[:6]:
            label = vuln.get("title") or vuln.get("type") or "UnknownFinding"
            self.steps.append(label)

        if self.state.attack_paths:
            self.steps.append(self.state.attack_paths[0]["title"])
        if self.state.walkthrough:
            self.steps.append("LearnerWalkthrough")

        self.steps.append("Report")
        self.positions = {step: (idx, 0) for idx, step in enumerate(self.steps)}

    def export_video(self):
        os.makedirs("reports", exist_ok=True)
        target = self.state.target
        if isinstance(target, dict):
            target = target.get("ip", "unknown")
        safe_target = str(target).replace("/", "_")
        mp4_filename = f"reports/attack_timeline_{safe_target}.mp4"
        gif_filename = f"reports/attack_timeline_{safe_target}.gif"

        fig, ax = plt.subplots(figsize=(14, 5))
        colors = {}

        def update(frame):
            ax.clear()
            current = self.steps[frame]
            self.graph.add_node(current)
            if frame > 0:
                self.graph.add_edge(self.steps[frame - 1], current)

            for step in self.steps:
                if step == current:
                    colors[step] = self.COLORS["active"]
                elif step in self.graph.nodes:
                    colors[step] = self.COLORS["completed"]
                else:
                    colors[step] = self.COLORS["inactive"]

            node_colors = [colors.get(node, self.COLORS["inactive"]) for node in self.graph.nodes]
            nx.draw(
                self.graph,
                self.positions,
                with_labels=True,
                node_color=node_colors,
                node_size=3000,
                font_size=10,
                font_weight="bold",
                edge_color="white",
                ax=ax,
            )
            ax.set_title("AARTF Attack Timeline")
            ax.axis("off")

        anim = FuncAnimation(fig, update, frames=len(self.steps), interval=1000)
        try:
            if animation_writers.is_available("ffmpeg"):
                anim.save(mp4_filename, writer="ffmpeg", fps=1, dpi=180)
                print(f"[+] Attack timeline video saved: {mp4_filename}")
            elif animation_writers.is_available("pillow"):
                anim.save(gif_filename, writer="pillow", fps=1, dpi=180)
                print(f"[+] Attack timeline animation saved: {gif_filename}")
            else:
                raise RuntimeError("No animation writer available (ffmpeg/pillow).")
        except Exception as exc:
            fallback = f"reports/attack_timeline_{safe_target}.png"
            update(len(self.steps) - 1)
            fig.savefig(fallback, dpi=220, bbox_inches="tight")
            print(f"[!] Timeline video export failed: {exc}")
            print(f"[+] Fallback timeline image saved: {fallback}")
        finally:
            plt.close(fig)
