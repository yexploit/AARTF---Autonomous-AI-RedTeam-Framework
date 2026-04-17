import io
import ipaddress
import os
import platform
import subprocess
import threading
from collections import Counter
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
        self.root.title("AARTF Security Center")
        self.root.geometry("1360x820")
        self.root.minsize(1220, 760)
        self.root.configure(bg="#070d1a")

        self.running = False
        self.current_state = None
        self.scan_thread = None
        self.log_queue = Queue()
        self.finding_records = {}
        self.path_records = {}
        self._tab_fx_rect = None
        self._tab_fx_anim = None

        self.persistence_var = tk.StringVar(value="MANUAL")
        self.report_after_run_var = tk.BooleanVar(value=True)
        self.target_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready")
        self.last_run_var = tk.StringVar(value="Last run: never")
        self.phase_var = tk.StringVar(value="Phase: -")
        self.target_info_var = tk.StringVar(value="-")
        self.ai_status_var = tk.StringVar(value="AI: rules")
        self.risk_var = tk.StringVar(value="Risk: INFO")
        self.assets_var = tk.StringVar(value="0")
        self.ports_var = tk.StringVar(value="0")
        self.vulns_var = tk.StringVar(value="0")
        self.actions_var = tk.StringVar(value="0")
        self.critical_var = tk.StringVar(value="0")
        self.high_var = tk.StringVar(value="0")
        self.medium_var = tk.StringVar(value="0")
        self.low_var = tk.StringVar(value="0")
        self.info_var = tk.StringVar(value="0")

        self._configure_style()
        self._build_layout()
        self.root.after(120, self._drain_log_queue)

    def _configure_style(self):
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        bg_app = "#050813"
        bg_sidebar = "#070f1f"
        bg_panel = "#0d1730"
        bg_card = "#121f3b"
        text_primary = "#dff8ff"
        text_muted = "#7da6c9"
        accent = "#00d4ff"
        accent_secondary = "#1aff8f"

        style.configure("App.TFrame", background=bg_app)
        style.configure("Sidebar.TFrame", background=bg_sidebar)
        style.configure("Header.TFrame", background=bg_panel)
        style.configure("Panel.TFrame", background=bg_panel)
        style.configure("Card.TFrame", background=bg_card)

        style.configure("Brand.TLabel", background=bg_sidebar, foreground=text_primary, font=("Segoe UI", 18, "bold"))
        style.configure("BrandSub.TLabel", background=bg_sidebar, foreground=text_muted, font=("Segoe UI", 9))

        style.configure("Section.TLabel", background=bg_panel, foreground=text_primary, font=("Segoe UI", 11, "bold"))
        style.configure("HeaderTitle.TLabel", background=bg_panel, foreground=text_primary, font=("Segoe UI", 16, "bold"))
        style.configure("HeaderSub.TLabel", background=bg_panel, foreground=text_muted, font=("Segoe UI", 10))
        style.configure("Caption.TLabel", background=bg_card, foreground=text_muted, font=("Segoe UI", 9))
        style.configure("KPI.TLabel", background=bg_card, foreground=text_primary, font=("Segoe UI", 20, "bold"))
        style.configure("SeverityLabel.TLabel", background=bg_card, foreground=text_muted, font=("Segoe UI", 10))
        style.configure("Status.TLabel", background=bg_panel, foreground="#68e8ff", font=("Segoe UI", 10, "bold"))

        style.configure("TButton", padding=(10, 7), font=("Segoe UI", 9, "bold"))
        style.configure("Primary.TButton", padding=(12, 8), font=("Segoe UI", 9, "bold"))
        style.map("Primary.TButton", background=[("!disabled", accent)], foreground=[("!disabled", "#00101f")])
        style.configure("Nav.TButton", background=bg_sidebar, foreground=text_muted, relief="flat", padding=(10, 8))
        style.map(
            "Nav.TButton",
            background=[("active", "#102341"), ("pressed", "#14305a")],
            foreground=[("active", accent_secondary), ("pressed", "#ffffff")],
        )

        style.configure("TEntry", fieldbackground="#0f1729", foreground=text_primary, insertcolor=text_primary, bordercolor="#243a60")
        style.configure("TCombobox", fieldbackground="#0f1729", foreground=text_primary, arrowcolor=text_primary, bordercolor="#243a60")

        style.configure("TNotebook", background=bg_panel, borderwidth=0)
        style.configure("TNotebook.Tab", font=("Segoe UI", 10, "bold"), padding=(14, 8))
        style.map("TNotebook.Tab", background=[("selected", "#103366")], foreground=[("selected", "#a8fff2")])

        style.configure(
            "Treeview",
            background="#0f1729",
            foreground="#dbe8ff",
            fieldbackground="#0f1729",
            borderwidth=0,
            rowheight=26,
            font=("Segoe UI", 9),
        )
        style.configure("Treeview.Heading", background="#13294d", foreground="#b8f7ff", font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", "#184a7f")], foreground=[("selected", "#e8ffff")])

    def _build_layout(self):
        self.root.columnconfigure(1, weight=1)
        self.root.rowconfigure(0, weight=1)

        sidebar = ttk.Frame(self.root, style="Sidebar.TFrame", width=240, padding=(18, 18))
        sidebar.grid(row=0, column=0, sticky="ns")
        sidebar.grid_propagate(False)
        self._build_sidebar(sidebar)

        workspace = ttk.Frame(self.root, style="App.TFrame", padding=(14, 14))
        workspace.grid(row=0, column=1, sticky="nsew")
        workspace.columnconfigure(0, weight=1)
        workspace.rowconfigure(2, weight=1)

        self._build_toolbar(workspace)
        self._build_kpi_row(workspace)
        self._build_body(workspace)
        self._build_status_bar(workspace)

    def _build_sidebar(self, parent):
        parent.rowconfigure(8, weight=1)

        ttk.Label(parent, text="AARTF", style="Brand.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(parent, text="Security Operations Console", style="BrandSub.TLabel").grid(row=1, column=0, sticky="w", pady=(0, 24))

        ttk.Button(parent, text="Dashboard", style="Nav.TButton", command=lambda: self._switch_to_tab(0)).grid(
            row=2, column=0, sticky="ew", pady=3
        )
        ttk.Button(parent, text="Services", style="Nav.TButton", command=lambda: self._switch_to_tab(1)).grid(
            row=3, column=0, sticky="ew", pady=3
        )
        ttk.Button(parent, text="Activity", style="Nav.TButton", command=lambda: self._switch_to_tab(2)).grid(
            row=4, column=0, sticky="ew", pady=3
        )
        ttk.Button(parent, text="Attack Paths", style="Nav.TButton", command=lambda: self._switch_to_tab(3)).grid(
            row=5, column=0, sticky="ew", pady=3
        )
        ttk.Button(parent, text="Live Console", style="Nav.TButton", command=lambda: self._switch_to_tab(4)).grid(
            row=6, column=0, sticky="ew", pady=3
        )
        ttk.Button(parent, text="Attack Graph", style="Nav.TButton", command=self.show_graph).grid(row=7, column=0, sticky="ew", pady=3)

        footer = ttk.Frame(parent, style="Sidebar.TFrame")
        footer.grid(row=9, column=0, sticky="sew")
        ttk.Label(footer, text="Design language: cyber SOC", style="BrandSub.TLabel").pack(anchor="w")
        ttk.Label(footer, text="Animated UX, lightweight runtime", style="BrandSub.TLabel").pack(anchor="w", pady=(2, 0))

    def _build_toolbar(self, parent):
        header = ttk.Frame(parent, style="Header.TFrame", padding=(16, 12))
        header.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        header.columnconfigure(1, weight=1)

        title_block = ttk.Frame(header, style="Header.TFrame")
        title_block.grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Label(title_block, text="Unified Threat Dashboard", style="HeaderTitle.TLabel").pack(anchor="w")
        ttk.Label(
            title_block,
            text="AI-guided learner workflow for lab target analysis and attack-path planning.",
            style="HeaderSub.TLabel",
        ).pack(anchor="w", pady=(2, 8))

        controls = ttk.Frame(header, style="Header.TFrame")
        controls.grid(row=1, column=0, sticky="ew")

        ttk.Label(controls, text="Target", style="HeaderSub.TLabel").grid(row=0, column=0, sticky="w")
        target_entry = ttk.Entry(controls, textvariable=self.target_var, width=36)
        target_entry.grid(row=0, column=1, padx=(8, 12), sticky="w")
        target_entry.focus_set()

        ttk.Label(controls, text="Persistence", style="HeaderSub.TLabel").grid(row=0, column=2, sticky="w")
        ttk.Combobox(
            controls,
            textvariable=self.persistence_var,
            values=["AUTO", "MANUAL", "OFF"],
            width=10,
            state="readonly",
        ).grid(row=0, column=3, padx=(8, 12), sticky="w")

        ttk.Checkbutton(controls, text="Generate reports after run", variable=self.report_after_run_var).grid(
            row=0, column=4, padx=(8, 0), sticky="w"
        )

        action_bar = ttk.Frame(header, style="Header.TFrame")
        action_bar.grid(row=1, column=1, sticky="e")
        self.start_button = ttk.Button(action_bar, text="Start Scan", style="Primary.TButton", command=self.start_scan)
        self.start_button.pack(side="left", padx=(0, 8))
        ttk.Button(action_bar, text="Refresh", command=self.refresh_results).pack(side="left", padx=4)
        ttk.Button(action_bar, text="Open Report", command=self.open_report).pack(side="left", padx=4)
        ttk.Button(action_bar, text="Reports Folder", command=self.open_reports_folder).pack(side="left", padx=4)
        ttk.Label(action_bar, textvariable=self.ai_status_var, style="HeaderSub.TLabel").pack(side="left", padx=(12, 0))

        self.progress = ttk.Progressbar(parent, mode="indeterminate")
        self.progress.grid(row=1, column=0, sticky="ew", padx=2, pady=(2, 12))

    def _build_kpi_row(self, parent):
        cards = ttk.Frame(parent, style="App.TFrame")
        cards.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        for i in range(4):
            cards.columnconfigure(i, weight=1)

        self._create_kpi_card(cards, 0, "Assets In Scope", self.assets_var)
        self._create_kpi_card(cards, 1, "Open Services", self.ports_var)
        self._create_kpi_card(cards, 2, "Findings", self.vulns_var)
        self._create_kpi_card(cards, 3, "Actions Executed", self.actions_var)

    def _create_kpi_card(self, parent, column, title, value_var):
        card = ttk.Frame(parent, style="Card.TFrame", padding=(12, 10))
        card.grid(row=0, column=column, sticky="nsew", padx=4)
        ttk.Label(card, textvariable=value_var, style="KPI.TLabel").pack(anchor="w")
        ttk.Label(card, text=title, style="Caption.TLabel").pack(anchor="w", pady=(2, 0))

    def _build_body(self, parent):
        body = ttk.Panedwindow(parent, orient="horizontal")
        body.grid(row=3, column=0, sticky="nsew")

        left_panel = ttk.Frame(body, style="Panel.TFrame", padding=(10, 10))
        right_panel = ttk.Frame(body, style="Panel.TFrame", padding=(10, 10))
        body.add(left_panel, weight=4)
        body.add(right_panel, weight=2)

        left_panel.columnconfigure(0, weight=1)
        left_panel.rowconfigure(1, weight=1)

        self.tab_fx = tk.Canvas(
            left_panel,
            height=4,
            bg="#0d1730",
            bd=0,
            highlightthickness=0,
            relief="flat",
        )
        self.tab_fx.grid(row=0, column=0, sticky="ew", pady=(0, 2))

        self.main_notebook = ttk.Notebook(left_panel)
        self.main_notebook.grid(row=1, column=0, sticky="nsew")

        findings_tab = ttk.Frame(self.main_notebook, style="Panel.TFrame", padding=(8, 8))
        services_tab = ttk.Frame(self.main_notebook, style="Panel.TFrame", padding=(8, 8))
        activity_tab = ttk.Frame(self.main_notebook, style="Panel.TFrame", padding=(8, 8))
        paths_tab = ttk.Frame(self.main_notebook, style="Panel.TFrame", padding=(8, 8))
        console_tab = ttk.Frame(self.main_notebook, style="Panel.TFrame", padding=(8, 8))

        self.main_notebook.add(findings_tab, text="Findings")
        self.main_notebook.add(services_tab, text="Services")
        self.main_notebook.add(activity_tab, text="Activity")
        self.main_notebook.add(paths_tab, text="Attack Paths")
        self.main_notebook.add(console_tab, text="Live Console")

        self._build_findings_table(findings_tab)
        self._build_services_table(services_tab)
        self._build_activity_table(activity_tab)
        self._build_paths_table(paths_tab)
        self._build_console(console_tab)
        self._build_right_panel(right_panel)
        self.main_notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)
        self.root.after(60, self._init_tab_fx)

    def _build_findings_table(self, parent):
        ttk.Label(parent, text="Vulnerability Findings", style="Section.TLabel").pack(anchor="w", pady=(0, 6))

        columns = ("id", "severity", "title", "evidence")
        self.findings_tree = ttk.Treeview(parent, columns=columns, show="headings")
        self.findings_tree.heading("id", text="ID")
        self.findings_tree.heading("severity", text="Severity")
        self.findings_tree.heading("title", text="Title")
        self.findings_tree.heading("evidence", text="Evidence")

        self.findings_tree.column("id", width=90, anchor="center")
        self.findings_tree.column("severity", width=100, anchor="center")
        self.findings_tree.column("title", width=340, anchor="w")
        self.findings_tree.column("evidence", width=380, anchor="w")
        self.findings_tree.pack(fill="both", expand=True)
        self.findings_tree.bind("<<TreeviewSelect>>", self._on_finding_selected)

        self.findings_tree.tag_configure("critical", foreground="#fca5a5")
        self.findings_tree.tag_configure("high", foreground="#fbbf24")
        self.findings_tree.tag_configure("medium", foreground="#fde68a")
        self.findings_tree.tag_configure("low", foreground="#86efac")
        self.findings_tree.tag_configure("info", foreground="#93c5fd")

    def _build_services_table(self, parent):
        ttk.Label(parent, text="Service Inventory", style="Section.TLabel").pack(anchor="w", pady=(0, 6))
        self.services_tree = ttk.Treeview(parent, columns=("port", "service"), show="headings")
        self.services_tree.heading("port", text="Port")
        self.services_tree.heading("service", text="Service")
        self.services_tree.column("port", width=120, anchor="center")
        self.services_tree.column("service", width=740, anchor="w")
        self.services_tree.pack(fill="both", expand=True)
        self.services_tree.bind("<<TreeviewSelect>>", self._on_service_selected)

    def _build_activity_table(self, parent):
        ttk.Label(parent, text="Execution Timeline", style="Section.TLabel").pack(anchor="w", pady=(0, 6))
        self.action_tree = ttk.Treeview(parent, columns=("time", "action"), show="headings")
        self.action_tree.heading("time", text="Timestamp")
        self.action_tree.heading("action", text="Action")
        self.action_tree.column("time", width=160, anchor="center")
        self.action_tree.column("action", width=700, anchor="w")
        self.action_tree.pack(fill="both", expand=True)
        self.action_tree.bind("<<TreeviewSelect>>", self._on_action_selected)

    def _build_paths_table(self, parent):
        ttk.Label(parent, text="AI-Prioritized Attack Paths", style="Section.TLabel").pack(anchor="w", pady=(0, 6))
        self.paths_tree = ttk.Treeview(parent, columns=("id", "kind", "severity", "score", "title"), show="headings")
        self.paths_tree.heading("id", text="ID")
        self.paths_tree.heading("kind", text="Kind")
        self.paths_tree.heading("severity", text="Severity")
        self.paths_tree.heading("score", text="Score")
        self.paths_tree.heading("title", text="Path")
        self.paths_tree.column("id", width=90, anchor="center")
        self.paths_tree.column("kind", width=110, anchor="center")
        self.paths_tree.column("severity", width=100, anchor="center")
        self.paths_tree.column("score", width=80, anchor="center")
        self.paths_tree.column("title", width=550, anchor="w")
        self.paths_tree.pack(fill="both", expand=True)
        self.paths_tree.bind("<<TreeviewSelect>>", self._on_path_selected)

    def _build_console(self, parent):
        ttk.Label(parent, text="Live Operator Console", style="Section.TLabel").pack(anchor="w", pady=(0, 6))
        self.console = tk.Text(
            parent,
            bg="#0a1222",
            fg="#7dd3fc",
            insertbackground="#f8fafc",
            wrap="word",
            relief="flat",
            font=("Consolas", 10),
            padx=10,
            pady=10,
        )
        self.console.pack(fill="both", expand=True)

    def _build_right_panel(self, parent):
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)

        severity_card = ttk.Frame(parent, style="Card.TFrame", padding=(12, 10))
        severity_card.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ttk.Label(severity_card, text="Risk Breakdown", style="Section.TLabel").pack(anchor="w", pady=(0, 8))

        self._create_severity_row(severity_card, "Critical", self.critical_var, "#f87171")
        self._create_severity_row(severity_card, "High", self.high_var, "#f59e0b")
        self._create_severity_row(severity_card, "Medium", self.medium_var, "#facc15")
        self._create_severity_row(severity_card, "Low", self.low_var, "#4ade80")
        self._create_severity_row(severity_card, "Info", self.info_var, "#60a5fa")

        details_card = ttk.Frame(parent, style="Card.TFrame", padding=(12, 10))
        details_card.grid(row=1, column=0, sticky="nsew")
        details_card.columnconfigure(0, weight=1)
        details_card.rowconfigure(1, weight=1)
        ttk.Label(details_card, text="Investigation Details", style="Section.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 6))

        self.details_text = tk.Text(
            details_card,
            bg="#0a1222",
            fg="#dbeafe",
            insertbackground="#f8fafc",
            wrap="word",
            relief="flat",
            state="disabled",
            font=("Consolas", 10),
            padx=10,
            pady=10,
        )
        self.details_text.grid(row=1, column=0, sticky="nsew")

        guidance = ttk.Frame(parent, style="Card.TFrame", padding=(12, 10))
        guidance.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        ttk.Label(guidance, text="Run Intelligence", style="Section.TLabel").pack(anchor="w", pady=(0, 6))
        ttk.Label(guidance, textvariable=self.target_info_var, style="Caption.TLabel").pack(anchor="w", pady=(0, 4))
        ttk.Label(guidance, textvariable=self.risk_var, style="Caption.TLabel").pack(anchor="w", pady=(0, 4))
        ttk.Label(
            guidance,
            style="Caption.TLabel",
            justify="left",
            text=(
                "- Start a run with a valid IP or CIDR target.\n"
                "- Select findings or attack paths for learner guidance.\n"
                "- Refresh to sync UI with the latest in-memory state.\n"
                "- Reports and graph assets are available after execution."
            ),
        ).pack(anchor="w")

    def _create_severity_row(self, parent, label, count_var, color):
        row = ttk.Frame(parent, style="Card.TFrame")
        row.pack(fill="x", pady=2)
        ttk.Label(row, text=label, style="SeverityLabel.TLabel").pack(side="left")
        badge = tk.Label(
            row,
            textvariable=count_var,
            bg=color,
            fg="#071018",
            font=("Segoe UI", 9, "bold"),
            padx=8,
            pady=2,
        )
        badge.pack(side="right")

    def _build_status_bar(self, parent):
        status = ttk.Frame(parent, style="Header.TFrame", padding=(12, 8))
        status.grid(row=4, column=0, sticky="ew", pady=(10, 0))
        ttk.Label(status, textvariable=self.status_var, style="Status.TLabel").pack(side="left")
        ttk.Label(status, textvariable=self.phase_var, style="HeaderSub.TLabel").pack(side="left", padx=(14, 0))
        ttk.Label(status, textvariable=self.last_run_var, style="HeaderSub.TLabel").pack(side="right")

    def _switch_to_tab(self, index):
        if hasattr(self, "main_notebook"):
            self.main_notebook.select(index)

    def _init_tab_fx(self):
        if not hasattr(self, "main_notebook") or not hasattr(self, "tab_fx"):
            return
        try:
            selected = self.main_notebook.index(self.main_notebook.select())
            x, y, w, h = self.main_notebook.bbox(selected)
        except Exception:
            return
        self.tab_fx.delete("all")
        self._tab_fx_rect = self.tab_fx.create_rectangle(
            x,
            0,
            x + max(20, w),
            4,
            fill="#00d4ff",
            outline="",
        )

    def _on_tab_changed(self, _event):
        if not hasattr(self, "main_notebook") or not hasattr(self, "tab_fx"):
            return
        try:
            selected = self.main_notebook.index(self.main_notebook.select())
            x, y, w, h = self.main_notebook.bbox(selected)
        except Exception:
            return

        tab_name = self.main_notebook.tab(selected, "text")
        self.status_var.set(f"Viewing {tab_name} view")
        self._animate_tab_fx(x, max(20, w))

    def _animate_tab_fx(self, target_x, target_w):
        if self._tab_fx_rect is None:
            self._init_tab_fx()
            return
        if self._tab_fx_anim is not None:
            self.root.after_cancel(self._tab_fx_anim)
            self._tab_fx_anim = None

        x1, y1, x2, y2 = self.tab_fx.coords(self._tab_fx_rect)
        current_x = x1
        current_w = max(1, x2 - x1)

        steps = 8
        dx = (target_x - current_x) / steps
        dw = (target_w - current_w) / steps

        def _step(i=0, start_x=current_x, start_w=current_w):
            nx = start_x + (dx * i)
            nw = start_w + (dw * i)
            self.tab_fx.coords(self._tab_fx_rect, nx, 0, nx + nw, 4)
            if i < steps:
                self._tab_fx_anim = self.root.after(12, lambda: _step(i + 1, start_x, start_w))
            else:
                self._tab_fx_anim = None

        _step()

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
        self._set_details("Run bootstrapped", [f"Target: {target}", f"Persistence mode: {self.persistence_var.get()}"])

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
        target_text = state.target.get("ip", "-")
        self.target_info_var.set(f"Target: {target_text}")
        self.ai_status_var.set(
            f"AI: {state.ai_status.get('mode', 'rules')} ({'enabled' if state.ai_status.get('available') else 'fallback'})"
        )
        self.assets_var.set(str(self._estimate_asset_count(target_text)))

        services = state.services_detail or {}
        vulns = state.findings or []
        actions = getattr(state, "action_log", []) or []

        self.ports_var.set(str(len(services)))
        self.vulns_var.set(str(len(vulns)))
        self.actions_var.set(str(len(actions)))

        state.finalize_assessment()
        self.risk_var.set(f"Risk: {state.assessment['risk_rating']} ({state.assessment['risk_score']}/100)")
        self._update_severity_metrics(vulns)
        self._replace_tree_rows(
            self.services_tree,
            [
                (
                    str(port),
                    " ".join(
                        part for part in [service.get("service"), service.get("product"), service.get("version")] if part
                    ) or "unknown",
                )
                for port, service in services.items()
            ],
        )
        self._populate_findings(vulns)
        self._populate_paths(state.attack_paths)

        action_rows = [
            (
                entry.get("timestamp", "")[11:19],
                f"{entry.get('phase')} | {entry.get('action')} | {entry.get('status')}",
            )
            for entry in actions
        ]
        self._replace_tree_rows(self.action_tree, action_rows)

    def _estimate_asset_count(self, target):
        try:
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
                return max(1, network.num_addresses)
        except ValueError:
            pass
        return 1 if target else 0

    def _update_severity_metrics(self, vulnerabilities):
        counts = Counter()
        for vuln in vulnerabilities:
            counts[self._normalize_severity(vuln)] += 1
        self.critical_var.set(str(counts.get("CRITICAL", 0)))
        self.high_var.set(str(counts.get("HIGH", 0)))
        self.medium_var.set(str(counts.get("MEDIUM", 0)))
        self.low_var.set(str(counts.get("LOW", 0)))
        self.info_var.set(str(counts.get("INFO", 0)))

    def _normalize_severity(self, vulnerability):
        sev = str(vulnerability.get("severity", "INFO")).strip().upper()
        if sev in ("CRIT", "CRITICAL"):
            return "CRITICAL"
        if sev in ("HIGH", "SEVERE"):
            return "HIGH"
        if sev in ("MED", "MEDIUM", "MODERATE"):
            return "MEDIUM"
        if sev in ("LOW", "MINOR"):
            return "LOW"
        return "INFO"

    def _populate_findings(self, vulnerabilities):
        self.finding_records.clear()
        for item in self.findings_tree.get_children():
            self.findings_tree.delete(item)

        for idx, vuln in enumerate(vulnerabilities, start=1):
            finding_id = str(vuln.get("id") or f"F-{idx:03d}")
            severity = self._normalize_severity(vuln)
            title = str(vuln.get("title") or vuln.get("cve") or vuln.get("type") or vuln.get("description") or "Unclassified finding")
            evidence = self._build_evidence(vuln)
            self.findings_tree.insert(
                "",
                "end",
                values=(finding_id, severity, title, evidence),
                tags=(severity.lower(),),
            )
            self.finding_records[finding_id] = vuln

        if vulnerabilities:
            first = self.findings_tree.get_children()[0]
            self.findings_tree.selection_set(first)
            self.findings_tree.focus(first)
            self._on_finding_selected(None)
        else:
            self._set_details("No findings available", ["Run a scan and refresh to inspect vulnerabilities here."])

    def _build_evidence(self, vulnerability):
        tokens = []
        if vulnerability.get("affected_service"):
            tokens.append(f"service={vulnerability.get('affected_service')}")
        if vulnerability.get("affected_port"):
            tokens.append(f"port={vulnerability.get('affected_port')}")
        if vulnerability.get("path"):
            tokens.append(f"path={vulnerability.get('path')}")
        if vulnerability.get("port"):
            tokens.append(f"port={vulnerability.get('port')}")
        if vulnerability.get("server"):
            tokens.append(f"server={vulnerability.get('server')}")
        if vulnerability.get("description"):
            tokens.append(vulnerability.get("description"))
        if not tokens:
            tokens.append("No evidence string supplied")
        return " | ".join(str(token) for token in tokens)

    def _populate_paths(self, attack_paths):
        self.path_records.clear()
        for item in self.paths_tree.get_children():
            self.paths_tree.delete(item)
        for attack_path in attack_paths or []:
            self.paths_tree.insert(
                "",
                "end",
                values=(attack_path["id"], attack_path.get("path_kind", "supporting"), attack_path["severity"], attack_path["score"], attack_path["title"]),
            )
            self.path_records[attack_path["id"]] = attack_path
        if attack_paths:
            first = self.paths_tree.get_children()[0]
            self.paths_tree.selection_set(first)
            self.paths_tree.focus(first)

    def _replace_tree_rows(self, tree, rows):
        for item in tree.get_children():
            tree.delete(item)
        for row in rows:
            tree.insert("", "end", values=row)

    def _clear_tables(self):
        self._replace_tree_rows(self.services_tree, [])
        self._replace_tree_rows(self.findings_tree, [])
        self._replace_tree_rows(self.action_tree, [])
        if hasattr(self, "paths_tree"):
            self._replace_tree_rows(self.paths_tree, [])
        self.finding_records.clear()
        self.path_records.clear()
        self.assets_var.set("0")
        self.ports_var.set("0")
        self.vulns_var.set("0")
        self.actions_var.set("0")
        self.critical_var.set("0")
        self.high_var.set("0")
        self.medium_var.set("0")
        self.low_var.set("0")
        self.info_var.set("0")
        self.risk_var.set("Risk: INFO")
        self._set_details("Awaiting session", ["Start a run to populate findings and contextual details."])

    def _on_finding_selected(self, _event):
        selected = self.findings_tree.selection()
        if not selected:
            return
        values = self.findings_tree.item(selected[0], "values")
        if not values:
            return
        finding_id = values[0]
        vuln = self.finding_records.get(finding_id)
        if not vuln:
            return

        lines = []
        lines.append(f"Severity: {self._normalize_severity(vuln)}")
        if vuln.get("confidence") is not None:
            lines.append(f"confidence: {vuln.get('confidence')}")
        for key in ("cve", "type", "description", "path", "port", "server", "affected_service", "affected_port"):
            if vuln.get(key) is not None:
                lines.append(f"{key}: {vuln.get(key)}")
        for field in ("attack_opportunities", "verification_steps", "remediation", "references"):
            values = vuln.get(field)
            if values:
                lines.append(f"{field}:")
                for value in values[:5]:
                    lines.append(f"  - {value}")
        for key, value in vuln.items():
            if key not in {"cve", "type", "description", "path", "port", "server", "severity", "affected_service", "affected_port", "confidence", "attack_opportunities", "verification_steps", "remediation", "references"}:
                lines.append(f"{key}: {value}")

        self._set_details(f"Finding {finding_id}", lines)

    def _on_service_selected(self, _event):
        selected = self.services_tree.selection()
        if not selected:
            return
        values = self.services_tree.item(selected[0], "values")
        if not values:
            return
        port, service = values[0], values[1]
        details = [f"Port: {port}", f"Service: {service}"]
        if self.current_state and port in self.current_state.services_detail:
            for key, value in self.current_state.services_detail[port].items():
                if value is not None:
                    details.append(f"{key}: {value}")
        if self.current_state:
            observations = self.current_state.attack_surface.get("protocol_observations", {})
            if port in observations:
                details.append("protocol_observation:")
                details.append(f"  summary: {observations[port].get('summary')}")
                raw_value = observations[port].get("raw")
                if raw_value:
                    details.append(f"  raw: {raw_value}")
        self._set_details("Service Context", details)

    def _on_action_selected(self, _event):
        selected = self.action_tree.selection()
        if not selected:
            return
        values = self.action_tree.item(selected[0], "values")
        if not values:
            return
        timestamp, action = values[0], values[1]
        self._set_details("Action Timeline Entry", [f"Time: {timestamp}", f"Action: {action}"])

    def _on_path_selected(self, _event):
        selected = self.paths_tree.selection()
        if not selected:
            return
        values = self.paths_tree.item(selected[0], "values")
        if not values:
            return
        path_id = values[0]
        attack_path = self.path_records.get(path_id)
        if not attack_path:
            return
        lines = [
            f"Severity: {attack_path.get('severity')}",
            f"Score: {attack_path.get('score')}",
            f"Confidence: {attack_path.get('confidence')}",
            f"Summary: {attack_path.get('summary')}",
        ]
        for field in ("prerequisites", "steps", "blockers", "evidence", "source_findings"):
            values = attack_path.get(field)
            if values:
                lines.append(f"{field}:")
                for value in values:
                    lines.append(f"  - {value}")
        if attack_path.get("next_action"):
            lines.append(f"next_action: {attack_path.get('next_action')}")
        self._set_details(f"Attack Path {path_id}", lines)

    def _set_details(self, title, lines):
        self.details_text.config(state="normal")
        self.details_text.delete("1.0", "end")
        self.details_text.insert("end", title + "\n")
        self.details_text.insert("end", "-" * len(title) + "\n\n")
        for line in lines:
            self.details_text.insert("end", str(line) + "\n")
        self.details_text.config(state="disabled")

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
            self.root.after(120, self._drain_log_queue)


if __name__ == "__main__":
    root = tk.Tk()
    app = AARTF_GUI(root)
    root.mainloop()
