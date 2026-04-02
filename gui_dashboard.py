import io
import ipaddress
import os
import platform
import subprocess
import threading
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
from queue import Empty, Queue

import tkinter as tk
from tkinter import messagebox, ttk

from core.attack_graph import AttackGraph
from core.engine import AttackEngine
from core.state import SessionState


class QueueWriter(io.TextIOBase):
    def __init__(self, callback):
        super().__init__()
        self.callback = callback

    def write(self, s):
        text = str(s)
        if text.strip():
            self.callback(text.rstrip("\n"))
        return len(text)

    def flush(self):
        return None


class AARTF_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AARTF - Autonomous Security Workflow")
        self.root.geometry("1180x760")
        self.root.minsize(1050, 700)
        self.root.configure(bg="#0f172a")

        self.running = False
        self.current_state = None
        self.scan_thread = None
        self.log_queue = Queue()

        self.persistence_var = tk.StringVar(value="MANUAL")
        self.report_after_run_var = tk.BooleanVar(value=True)
        self.target_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready")
        self.last_run_var = tk.StringVar(value="Last run: never")
        self.phase_var = tk.StringVar(value="Phase: -")
        self.target_info_var = tk.StringVar(value="Target: -")
        self.ports_var = tk.StringVar(value="Open ports: 0")
        self.vulns_var = tk.StringVar(value="Vulnerabilities: 0")
        self.actions_var = tk.StringVar(value="Actions: 0")

        self._configure_style()
        self._build_layout()
        self.root.after(100, self._drain_log_queue)

    def _configure_style(self):
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure("Card.TFrame", background="#111827")
        style.configure("Top.TFrame", background="#0b1220")
        style.configure("Muted.TLabel", background="#111827", foreground="#94a3b8", font=("Segoe UI", 9))
        style.configure("Title.TLabel", background="#111827", foreground="#e2e8f0", font=("Segoe UI", 12, "bold"))
        style.configure("Value.TLabel", background="#111827", foreground="#f8fafc", font=("Segoe UI", 15, "bold"))
        style.configure("HeaderTitle.TLabel", background="#0b1220", foreground="#f8fafc", font=("Segoe UI", 17, "bold"))
        style.configure("HeaderSub.TLabel", background="#0b1220", foreground="#94a3b8", font=("Segoe UI", 10))
        style.configure("Status.TLabel", background="#0b1220", foreground="#93c5fd", font=("Segoe UI", 10, "bold"))
        style.configure("TNotebook", background="#0f172a", borderwidth=0)
        style.configure("TNotebook.Tab", padding=(14, 8), font=("Segoe UI", 10))
        style.map("TNotebook.Tab", background=[("selected", "#1d4ed8")], foreground=[("selected", "white")])

    def _build_layout(self):
        header = ttk.Frame(self.root, style="Top.TFrame", padding=(16, 12))
        header.pack(fill="x")

        ttk.Label(header, text="AARTF Dashboard", style="HeaderTitle.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="Autonomous workflow orchestration with live execution telemetry",
            style="HeaderSub.TLabel",
        ).pack(anchor="w")

        toolbar = ttk.Frame(self.root, style="Top.TFrame", padding=(16, 8))
        toolbar.pack(fill="x")

        ttk.Label(toolbar, text="Target IP / CIDR", style="HeaderSub.TLabel").pack(side="left")
        target_entry = ttk.Entry(toolbar, textvariable=self.target_var, width=38)
        target_entry.pack(side="left", padx=(8, 12))
        target_entry.focus_set()

        ttk.Label(toolbar, text="Persistence", style="HeaderSub.TLabel").pack(side="left")
        ttk.Combobox(
            toolbar,
            textvariable=self.persistence_var,
            values=["AUTO", "MANUAL", "OFF"],
            width=10,
            state="readonly",
        ).pack(side="left", padx=(8, 12))

        ttk.Checkbutton(toolbar, text="Generate reports after run", variable=self.report_after_run_var).pack(side="left")

        self.start_button = ttk.Button(toolbar, text="Start", command=self.start_scan)
        self.start_button.pack(side="right", padx=(8, 0))
        ttk.Button(toolbar, text="Refresh Snapshot", command=self.refresh_results).pack(side="right", padx=(8, 0))
        ttk.Button(toolbar, text="Open Reports", command=self.open_reports_folder).pack(side="right", padx=(8, 0))
        ttk.Button(toolbar, text="Open Report", command=self.open_report).pack(side="right", padx=(8, 0))
        ttk.Button(toolbar, text="Show Graph", command=self.show_graph).pack(side="right")

        self.progress = ttk.Progressbar(self.root, mode="indeterminate")
        self.progress.pack(fill="x", padx=16, pady=(2, 10))

        body = ttk.Panedwindow(self.root, orient="horizontal")
        body.pack(fill="both", expand=True, padx=16, pady=(0, 12))

        left = ttk.Frame(body, style="Card.TFrame", padding=12)
        right = ttk.Frame(body, style="Card.TFrame", padding=8)
        body.add(left, weight=2)
        body.add(right, weight=5)

        self._build_left_panel(left)
        self._build_right_panel(right)

        status = ttk.Frame(self.root, style="Top.TFrame", padding=(16, 8))
        status.pack(fill="x")
        ttk.Label(status, textvariable=self.status_var, style="Status.TLabel").pack(side="left")
        ttk.Label(status, textvariable=self.phase_var, style="HeaderSub.TLabel").pack(side="left", padx=(14, 0))
        ttk.Label(status, textvariable=self.last_run_var, style="HeaderSub.TLabel").pack(side="right")

    def _build_left_panel(self, parent):
        ttk.Label(parent, text="Session Overview", style="Title.TLabel").pack(anchor="w", pady=(0, 6))
        ttk.Label(parent, textvariable=self.target_info_var, style="Muted.TLabel").pack(anchor="w", pady=(0, 12))

        for value_var, caption in (
            (self.ports_var, "Open Services"),
            (self.vulns_var, "Detected Issues"),
            (self.actions_var, "Actions Executed"),
        ):
            card = ttk.Frame(parent, style="Card.TFrame", padding=(10, 10))
            card.pack(fill="x", pady=6)
            ttk.Label(card, textvariable=value_var, style="Value.TLabel").pack(anchor="w")
            ttk.Label(card, text=caption, style="Muted.TLabel").pack(anchor="w")

        tips = ttk.Frame(parent, style="Card.TFrame", padding=(10, 10))
        tips.pack(fill="both", expand=True, pady=(14, 0))
        ttk.Label(tips, text="Run Guidance", style="Title.TLabel").pack(anchor="w", pady=(0, 8))
        ttk.Label(
            tips,
            style="Muted.TLabel",
            justify="left",
            text=(
                "- Use a valid single IP or CIDR block.\n"
                "- Keep one active run at a time.\n"
                "- Use Refresh Snapshot to reload tables.\n"
                "- Reports are written under reports/."
            ),
        ).pack(anchor="w")

    def _build_right_panel(self, parent):
        notebook = ttk.Notebook(parent)
        notebook.pack(fill="both", expand=True)

        live_tab = ttk.Frame(notebook, style="Card.TFrame")
        results_tab = ttk.Frame(notebook, style="Card.TFrame")
        activity_tab = ttk.Frame(notebook, style="Card.TFrame")
        notebook.add(live_tab, text="Live Console")
        notebook.add(results_tab, text="Results")
        notebook.add(activity_tab, text="Activity")

        self.console = tk.Text(
            live_tab,
            bg="#0b1020",
            fg="#22d3ee",
            insertbackground="#f8fafc",
            wrap="word",
            font=("Consolas", 10),
            relief="flat",
            padx=10,
            pady=10,
        )
        self.console.pack(fill="both", expand=True, padx=6, pady=6)

        tables = ttk.Panedwindow(results_tab, orient="vertical")
        tables.pack(fill="both", expand=True, padx=6, pady=6)

        service_frame = ttk.Frame(tables, style="Card.TFrame")
        vuln_frame = ttk.Frame(tables, style="Card.TFrame")
        tables.add(service_frame, weight=1)
        tables.add(vuln_frame, weight=1)

        ttk.Label(service_frame, text="Open Services", style="Title.TLabel").pack(anchor="w", padx=8, pady=(6, 2))
        self.services_tree = ttk.Treeview(service_frame, columns=("port", "service"), show="headings", height=8)
        self.services_tree.heading("port", text="Port")
        self.services_tree.heading("service", text="Service")
        self.services_tree.column("port", width=120, anchor="center")
        self.services_tree.column("service", width=320, anchor="w")
        self.services_tree.pack(fill="both", expand=True, padx=8, pady=(2, 8))

        ttk.Label(vuln_frame, text="Vulnerabilities", style="Title.TLabel").pack(anchor="w", padx=8, pady=(6, 2))
        self.vuln_tree = ttk.Treeview(vuln_frame, columns=("cve", "severity"), show="headings", height=8)
        self.vuln_tree.heading("cve", text="CVE / Type")
        self.vuln_tree.heading("severity", text="Severity")
        self.vuln_tree.column("cve", width=360, anchor="w")
        self.vuln_tree.column("severity", width=120, anchor="center")
        self.vuln_tree.pack(fill="both", expand=True, padx=8, pady=(2, 8))

        ttk.Label(activity_tab, text="Action Timeline", style="Title.TLabel").pack(anchor="w", padx=8, pady=(8, 2))
        self.action_tree = ttk.Treeview(activity_tab, columns=("time", "action"), show="headings")
        self.action_tree.heading("time", text="Time")
        self.action_tree.heading("action", text="Action")
        self.action_tree.column("time", width=150, anchor="center")
        self.action_tree.column("action", width=650, anchor="w")
        self.action_tree.pack(fill="both", expand=True, padx=8, pady=(2, 8))

    def _validate_target(self, value):
        candidate = (value or "").strip()
        if not candidate:
            return False
        try:
            if "/" in candidate:
                ipaddress.ip_network(candidate, strict=False)
            else:
                ipaddress.ip_address(candidate)
            return True
        except ValueError:
            return False

    def start_scan(self):
        if self.running:
            messagebox.showinfo("Running", "A run is already in progress.")
            return

        target = self.target_var.get().strip()
        if not self._validate_target(target):
            messagebox.showerror("Invalid Target", "Enter a valid IPv4/IPv6 address or CIDR.")
            return

        self._clear_tables()
        self.console.delete("1.0", "end")
        self.current_state = None
        self.running = True
        self.status_var.set("Running")
        self.phase_var.set("Phase: initializing")
        self.target_info_var.set(f"Target: {target}")
        self.start_button.config(state="disabled")
        self.progress.start(10)

        self.scan_thread = threading.Thread(target=self._run_attack, args=(target,), daemon=True)
        self.scan_thread.start()

    def _run_attack(self, target):
        writer = QueueWriter(self.log)
        try:
            with redirect_stdout(writer), redirect_stderr(writer):
                self.log(f"[+] Session started at {datetime.now().strftime('%H:%M:%S')}")
                state = SessionState(target)
                state.persistence_mode = self.persistence_var.get()
                self.current_state = state
                engine = AttackEngine(state)
                engine.run()
                if self.report_after_run_var.get():
                    engine.generate_reports()
                self.log("[+] Run completed successfully")
        except Exception as exc:
            self.log(f"[ERROR] {exc}")
        finally:
            self.root.after(0, self._on_run_completed)

    def _on_run_completed(self):
        self.running = False
        self.start_button.config(state="normal")
        self.progress.stop()
        self.status_var.set("Idle")
        self.last_run_var.set(f"Last run: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.refresh_results()

    def refresh_results(self):
        state = self.current_state
        if not state:
            return

        self.phase_var.set(f"Phase: {state.phase}")
        self.target_info_var.set(f"Target: {state.target.get('ip', '-')}")

        services = state.network.get("services", {}) or {}
        vulns = state.network.get("vulnerabilities", []) or []
        actions = getattr(state, "actions_taken", []) or []

        self.ports_var.set(f"Open ports: {len(services)}")
        self.vulns_var.set(f"Vulnerabilities: {len(vulns)}")
        self.actions_var.set(f"Actions: {len(actions)}")

        self._replace_tree_rows(self.services_tree, [(str(p), str(s)) for p, s in services.items()])

        vuln_rows = []
        for vuln in vulns:
            label = vuln.get("cve") or vuln.get("type") or "Unknown"
            severity = vuln.get("severity", "Unknown")
            vuln_rows.append((str(label), str(severity)))
        self._replace_tree_rows(self.vuln_tree, vuln_rows)

        now = datetime.now().strftime("%H:%M:%S")
        action_rows = [(now, str(a)) for a in actions]
        self._replace_tree_rows(self.action_tree, action_rows)

    def _replace_tree_rows(self, tree, rows):
        for item in tree.get_children():
            tree.delete(item)
        for row in rows:
            tree.insert("", "end", values=row)

    def _clear_tables(self):
        self._replace_tree_rows(self.services_tree, [])
        self._replace_tree_rows(self.vuln_tree, [])
        self._replace_tree_rows(self.action_tree, [])
        self.ports_var.set("Open ports: 0")
        self.vulns_var.set("Vulnerabilities: 0")
        self.actions_var.set("Actions: 0")

    def open_report(self):
        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("Missing Target", "Enter target before opening report.")
            return

        safe_target = target.replace(".", "_").replace("/", "_")
        filename = os.path.join("reports", f"attack_report_{safe_target}.txt")
        if not os.path.exists(filename):
            messagebox.showerror("Not Found", "Report file not found for current target.")
            return

        self._open_path(filename)

    def open_reports_folder(self):
        os.makedirs("reports", exist_ok=True)
        self._open_path("reports")

    def _open_path(self, path):
        abs_path = os.path.abspath(path)
        try:
            if platform.system() == "Windows":
                os.startfile(abs_path)
            elif platform.system() == "Darwin":
                subprocess.run(["open", abs_path], check=False)
            else:
                subprocess.run(["xdg-open", abs_path], check=False)
        except Exception as exc:
            messagebox.showerror("Open Error", f"Cannot open path:\n{exc}")

    def show_graph(self):
        state = self.current_state
        if not state:
            messagebox.showerror("No Data", "Run a session first to generate graph data.")
            return
        try:
            AttackGraph(state).show()
        except Exception as exc:
            messagebox.showerror("Graph Error", str(exc))

    def log(self, message):
        self.log_queue.put(str(message))

    def _drain_log_queue(self):
        try:
            while True:
                message = self.log_queue.get_nowait()
                self.console.insert("end", message + "\n")
                self.console.see("end")
        except Empty:
            pass
        finally:
            if self.current_state:
                self.phase_var.set(f"Phase: {self.current_state.phase}")
            self.root.after(100, self._drain_log_queue)


if __name__ == "__main__":
    root = tk.Tk()
    app = AARTF_GUI(root)
    root.mainloop()
