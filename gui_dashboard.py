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
        self.root.title("Autonomous AI-Driven Red-Team Framework")
        self.root.geometry("1460x900")
        self.root.minsize(1080, 700)
        self.root.configure(bg="#060b14")

        self.tokens = {
            "bg_root": "#060b14",
            "bg_sidebar": "#0a1323",
            "bg_sidebar_elev": "#0d1a2f",
            "bg_surface": "#0f1b2e",
            "bg_surface_alt": "#131f35",
            "bg_card": "#16233c",
            "bg_input": "#0b1628",
            "border_soft": "#213552",
            "border_focus": "#2ec8ff",
            "text_primary": "#e8f3ff",
            "text_secondary": "#9fb6d3",
            "text_muted": "#7f96b5",
            "accent": "#24c8ff",
            "accent_alt": "#2de2c6",
            "critical": "#ff6a7a",
            "high": "#ff9c5b",
            "medium": "#f6c35f",
            "low": "#4ddf9d",
            "info": "#4fa7ff",
        }

        self.running = False
        self.current_state = None
        self.scan_thread = None
        self.log_queue = Queue()
        self.finding_records = {}
        self.path_records = {}
        self._tab_fx_rect = None
        self._tab_fx_anim = None
        self.sidebar_collapsed = False
        self.nav_buttons = []
        self.empty_states = {}
        self.risk_bars = {}

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

        t = self.tokens
        style.configure("App.TFrame", background=t["bg_root"])
        style.configure("Sidebar.TFrame", background=t["bg_sidebar"])
        style.configure("Surface.TFrame", background=t["bg_surface"])
        style.configure("SurfaceAlt.TFrame", background=t["bg_surface_alt"])
        style.configure("Card.TFrame", background=t["bg_card"])
        style.configure("HeaderCard.TFrame", background=t["bg_surface_alt"])
        style.configure("Glass.TFrame", background=t["bg_input"])

        style.configure("Brand.TLabel", background=t["bg_sidebar"], foreground=t["text_primary"], font=("Segoe UI", 16, "bold"))
        style.configure("BrandSub.TLabel", background=t["bg_sidebar"], foreground=t["text_muted"], font=("Segoe UI", 9))
        style.configure("HeaderTitle.TLabel", background=t["bg_surface_alt"], foreground=t["text_primary"], font=("Segoe UI", 16, "bold"))
        style.configure("HeaderSub.TLabel", background=t["bg_surface_alt"], foreground=t["text_secondary"], font=("Segoe UI", 10))
        style.configure("Section.TLabel", background=t["bg_card"], foreground=t["text_primary"], font=("Segoe UI", 11, "bold"))
        style.configure("Caption.TLabel", background=t["bg_card"], foreground=t["text_secondary"], font=("Segoe UI", 9))
        style.configure("KPI.TLabel", background=t["bg_card"], foreground=t["text_primary"], font=("Segoe UI", 22, "bold"))
        style.configure("Status.TLabel", background=t["bg_surface_alt"], foreground=t["accent"], font=("Segoe UI", 10, "bold"))

        style.configure("TCheckbutton", background=t["bg_surface_alt"], foreground=t["text_secondary"], font=("Segoe UI", 9))
        style.map("TCheckbutton", foreground=[("active", t["text_primary"])])

        style.configure(
            "App.TEntry",
            fieldbackground=t["bg_input"],
            foreground=t["text_primary"],
            insertcolor=t["text_primary"],
            bordercolor=t["border_soft"],
            lightcolor=t["border_soft"],
            darkcolor=t["border_soft"],
            padding=8,
            relief="flat",
        )
        style.map("App.TEntry", bordercolor=[("focus", t["border_focus"])], lightcolor=[("focus", t["border_focus"])])
        style.configure(
            "App.TCombobox",
            fieldbackground=t["bg_input"],
            foreground=t["text_primary"],
            bordercolor=t["border_soft"],
            lightcolor=t["border_soft"],
            darkcolor=t["border_soft"],
            arrowcolor=t["text_secondary"],
            padding=6,
            relief="flat",
        )
        style.map("App.TCombobox", bordercolor=[("focus", t["border_focus"])], lightcolor=[("focus", t["border_focus"])])

        style.configure(
            "TNotebook",
            background=t["bg_surface"],
            borderwidth=0,
            tabmargins=(0, 0, 0, 0),
        )
        style.configure(
            "TNotebook.Tab",
            font=("Segoe UI", 10, "bold"),
            padding=(14, 9),
            background=t["bg_surface"],
            foreground=t["text_secondary"],
            borderwidth=0,
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", t["bg_card"]), ("active", "#132743")],
            foreground=[("selected", t["text_primary"]), ("active", t["accent"])],
        )

        style.configure(
            "Treeview",
            background=t["bg_input"],
            foreground=t["text_primary"],
            fieldbackground=t["bg_input"],
            borderwidth=0,
            rowheight=30,
            font=("Segoe UI", 9),
            relief="flat",
        )
        style.configure(
            "Treeview.Heading",
            background="#182c4a",
            foreground=t["text_primary"],
            font=("Segoe UI", 9, "bold"),
            borderwidth=0,
            relief="flat",
        )
        style.map(
            "Treeview",
            background=[("selected", "#1f3e67")],
            foreground=[("selected", t["text_primary"])],
        )
        style.map(
            "Treeview.Heading",
            background=[("active", "#1d375c")],
            foreground=[("active", t["accent"])],
        )

    def _build_layout(self):
        self.root.columnconfigure(1, weight=1)
        self.root.rowconfigure(0, weight=1)

        self.sidebar = tk.Frame(self.root, bg=self.tokens["bg_sidebar"], width=248, highlightthickness=1, highlightbackground=self.tokens["border_soft"])
        self.sidebar.grid(row=0, column=0, sticky="ns")
        self.sidebar.grid_propagate(False)
        self._build_sidebar(self.sidebar)

        workspace = ttk.Frame(self.root, style="App.TFrame", padding=(14, 14, 14, 10))
        workspace.grid(row=0, column=1, sticky="nsew")
        workspace.columnconfigure(0, weight=1)
        workspace.rowconfigure(2, weight=1)

        self._build_toolbar(workspace)
        self._build_kpi_row(workspace)
        self._build_body(workspace)
        self._build_status_bar(workspace)

    def _build_sidebar(self, parent):
        for idx in range(11):
            parent.rowconfigure(idx, weight=0)
        parent.rowconfigure(9, weight=1)
        parent.columnconfigure(0, weight=1)

        self.brand_row = tk.Frame(parent, bg=self.tokens["bg_sidebar"])
        self.brand_row.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 8))
        self.brand_mark = tk.Canvas(self.brand_row, width=18, height=18, bg=self.tokens["bg_sidebar"], bd=0, highlightthickness=0)
        self.brand_mark.create_oval(2, 2, 16, 16, fill=self.tokens["accent"], outline="")
        self.brand_mark.pack(side="left", padx=(0, 8))
        self.brand_name = ttk.Label(self.brand_row, text="AARTF", style="Brand.TLabel")
        self.brand_name.pack(side="left", anchor="w")

        self.toggle_button = self._make_nav_button(parent, "collapse", "< Collapse", self._toggle_sidebar)
        self.toggle_button.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 8))

        nav_items = [
            ("overview", "Overview", lambda: self._switch_to_tab(0)),
            ("services", "Services", lambda: self._switch_to_tab(1)),
            ("activity", "Activity", lambda: self._switch_to_tab(2)),
            ("attack_paths", "Attack Paths", lambda: self._switch_to_tab(3)),
            ("console", "Live Console", lambda: self._switch_to_tab(4)),
            ("graph", "Attack Graph", self.show_graph),
        ]
        self.nav_map = {}
        for row, (key, label, command) in enumerate(nav_items, start=2):
            btn = self._make_nav_button(parent, key, label, command)
            btn.grid(row=row, column=0, sticky="ew", padx=12, pady=4)
            self.nav_map[key] = btn

        self.sidebar_footer = ttk.Label(
            parent,
            text="Design: dark layered surfaces\nInteractions: fast and focused",
            style="BrandSub.TLabel",
            justify="left",
        )
        self.sidebar_footer.grid(row=10, column=0, sticky="sw", padx=18, pady=(0, 14))

        self._set_nav_active("overview")

    def _make_nav_button(self, parent, key, label, command):
        btn = tk.Button(
            parent,
            text=f"  {label}",
            font=("Segoe UI", 10, "bold"),
            bg=self.tokens["bg_sidebar"],
            fg=self.tokens["text_secondary"],
            activebackground=self.tokens["bg_sidebar_elev"],
            activeforeground=self.tokens["text_primary"],
            bd=0,
            relief="flat",
            anchor="w",
            padx=12,
            pady=10,
            command=lambda k=key, c=command: self._on_nav_click(k, c),
        )
        btn.bind("<Enter>", lambda _e, b=btn: self._nav_hover(b, True))
        btn.bind("<Leave>", lambda _e, b=btn: self._nav_hover(b, False))
        self.nav_buttons.append(btn)
        return btn

    def _nav_hover(self, button, entering):
        if getattr(button, "_active_nav", False):
            return
        button.configure(bg=self.tokens["bg_sidebar_elev"] if entering else self.tokens["bg_sidebar"])

    def _set_nav_active(self, key):
        for k, btn in self.nav_map.items():
            active = k == key
            btn._active_nav = active
            if active:
                btn.configure(bg="#14263f", fg=self.tokens["accent"])
            else:
                btn.configure(bg=self.tokens["bg_sidebar"], fg=self.tokens["text_secondary"])

    def _on_nav_click(self, key, command):
        if key in {"overview", "services", "activity", "attack_paths", "console"}:
            self._set_nav_active(key)
        self._button_feedback(self.nav_map.get(key))
        command()

    def _toggle_sidebar(self):
        self.sidebar_collapsed = not self.sidebar_collapsed
        width = 84 if self.sidebar_collapsed else 248
        self.sidebar.configure(width=width)

        if self.sidebar_collapsed:
            self.brand_name.pack_forget()
            self.sidebar_footer.grid_remove()
            self.toggle_button.configure(text="> Expand", anchor="center")
            labels = {
                "overview": "O",
                "services": "S",
                "activity": "A",
                "attack_paths": "P",
                "console": "C",
                "graph": "G",
            }
            for key, btn in self.nav_map.items():
                btn.configure(text=labels[key], anchor="center", padx=4)
        else:
            self.brand_name.pack(side="left", anchor="w")
            self.sidebar_footer.grid()
            self.toggle_button.configure(text="< Collapse", anchor="w")
            labels = {
                "overview": "  Overview",
                "services": "  Services",
                "activity": "  Activity",
                "attack_paths": "  Attack Paths",
                "console": "  Live Console",
                "graph": "  Attack Graph",
            }
            for key, btn in self.nav_map.items():
                btn.configure(text=labels[key], anchor="w", padx=12)

    def _build_toolbar(self, parent):
        header = ttk.Frame(parent, style="HeaderCard.TFrame", padding=(18, 14))
        header.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        header.columnconfigure(0, weight=1)
        header.columnconfigure(1, weight=1)

        title_block = ttk.Frame(header, style="HeaderCard.TFrame")
        title_block.grid(row=0, column=0, sticky="w")
        ttk.Label(title_block, text="Unified Threat Command", style="HeaderTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            title_block,
            text="Modern analyst cockpit for reconnaissance, risk triage, and guided attack-path validation.",
            style="HeaderSub.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        status_chip = tk.Label(
            header,
            textvariable=self.ai_status_var,
            bg="#133a4a",
            fg="#9ff5e7",
            font=("Segoe UI", 9, "bold"),
            padx=10,
            pady=4,
        )
        status_chip.grid(row=0, column=1, sticky="e")

        controls = ttk.Frame(header, style="HeaderCard.TFrame")
        controls.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(12, 0))
        controls.columnconfigure(1, weight=1)
        controls.columnconfigure(6, weight=1)

        ttk.Label(controls, text="Target", style="HeaderSub.TLabel").grid(row=0, column=0, sticky="w")
        target_entry = ttk.Entry(controls, textvariable=self.target_var, style="App.TEntry")
        target_entry.grid(row=0, column=1, sticky="ew", padx=(8, 14))
        target_entry.focus_set()

        ttk.Label(controls, text="Persistence", style="HeaderSub.TLabel").grid(row=0, column=2, sticky="w")
        persistence = ttk.Combobox(
            controls,
            textvariable=self.persistence_var,
            values=["AUTO", "MANUAL", "OFF"],
            state="readonly",
            width=12,
            style="App.TCombobox",
        )
        persistence.grid(row=0, column=3, sticky="w", padx=(8, 14))

        reports_toggle = ttk.Checkbutton(controls, text="Generate reports", variable=self.report_after_run_var)
        reports_toggle.grid(row=0, column=4, sticky="w", padx=(0, 16))

        actions = ttk.Frame(controls, style="HeaderCard.TFrame")
        actions.grid(row=0, column=6, sticky="e")
        self.start_button = self._make_action_button(actions, "Start Scan", self.start_scan, True)
        self.start_button.pack(side="left", padx=(0, 8))
        self.refresh_button = self._make_action_button(actions, "Refresh", self.refresh_results)
        self.refresh_button.pack(side="left", padx=(0, 8))
        self.report_button = self._make_action_button(actions, "Doc  Report", self.open_report)
        self.report_button.pack(side="left", padx=(0, 8))
        self.folder_button = self._make_action_button(actions, "Folder  Reports", self.open_reports_folder)
        self.folder_button.pack(side="left")

        self.progress = ttk.Progressbar(parent, mode="indeterminate")
        self.progress.grid(row=1, column=0, sticky="ew", padx=(2, 2), pady=(2, 12))

    def _make_action_button(self, parent, text, command, primary=False):
        bg = "#1d8eb8" if primary else "#1a2a43"
        hover = "#29b5e7" if primary else "#223758"
        fg = "#01131e" if primary else self.tokens["text_primary"]
        button = tk.Button(
            parent,
            text=text,
            command=lambda b=None: self._run_button_action(button, command),
            bg=bg,
            fg=fg,
            activebackground=hover,
            activeforeground=fg,
            bd=0,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
            padx=12,
            pady=8,
        )
        button._base_bg = bg
        button._hover_bg = hover
        button.bind("<Enter>", lambda _e, b=button: b.configure(bg=b._hover_bg))
        button.bind("<Leave>", lambda _e, b=button: b.configure(bg=b._base_bg))
        return button

    def _run_button_action(self, button, command):
        self._button_feedback(button)
        command()

    def _button_feedback(self, button):
        if not button:
            return
        original = button.cget("bg")
        button.configure(bg="#2b5377")
        self.root.after(90, lambda: button.configure(bg=original))

    def _build_kpi_row(self, parent):
        cards = ttk.Frame(parent, style="App.TFrame")
        cards.grid(row=1, column=0, sticky="ew", pady=(0, 12))
        for i in range(4):
            cards.columnconfigure(i, weight=1, uniform="kpi")
        self._create_kpi_card(cards, 0, "Assets in Scope", self.assets_var)
        self._create_kpi_card(cards, 1, "Services Exposed", self.ports_var)
        self._create_kpi_card(cards, 2, "Open Findings", self.vulns_var)
        self._create_kpi_card(cards, 3, "Actions Logged", self.actions_var)

    def _create_kpi_card(self, parent, column, title, value_var):
        card = ttk.Frame(parent, style="Card.TFrame", padding=(14, 12))
        card.grid(row=0, column=column, sticky="nsew", padx=(0 if column == 0 else 8, 0))
        ttk.Label(card, textvariable=value_var, style="KPI.TLabel").pack(anchor="w")
        ttk.Label(card, text=title, style="Caption.TLabel").pack(anchor="w", pady=(3, 0))

    def _build_body(self, parent):
        body = ttk.Panedwindow(parent, orient="horizontal")
        body.grid(row=2, column=0, sticky="nsew")

        left_panel = ttk.Frame(body, style="Surface.TFrame", padding=(10, 10))
        right_panel = ttk.Frame(body, style="Surface.TFrame", padding=(10, 10))
        body.add(left_panel, weight=7)
        body.add(right_panel, weight=4)

        left_panel.columnconfigure(0, weight=1)
        left_panel.rowconfigure(1, weight=1)
        right_panel.columnconfigure(0, weight=1)
        right_panel.rowconfigure(1, weight=1)

        self.tab_fx = tk.Canvas(left_panel, height=3, bg=self.tokens["bg_surface"], bd=0, highlightthickness=0, relief="flat")
        self.tab_fx.grid(row=0, column=0, sticky="ew", pady=(0, 2))

        self.main_notebook = ttk.Notebook(left_panel)
        self.main_notebook.grid(row=1, column=0, sticky="nsew")

        findings_tab = ttk.Frame(self.main_notebook, style="Surface.TFrame", padding=(8, 8))
        services_tab = ttk.Frame(self.main_notebook, style="Surface.TFrame", padding=(8, 8))
        activity_tab = ttk.Frame(self.main_notebook, style="Surface.TFrame", padding=(8, 8))
        paths_tab = ttk.Frame(self.main_notebook, style="Surface.TFrame", padding=(8, 8))
        console_tab = ttk.Frame(self.main_notebook, style="Surface.TFrame", padding=(8, 8))
        for tab in (findings_tab, services_tab, activity_tab, paths_tab, console_tab):
            tab.columnconfigure(0, weight=1)
            tab.rowconfigure(1, weight=1)

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
        self.root.after(80, self._init_tab_fx)

    def _build_tab_table_shell(self, parent, title):
        card = ttk.Frame(parent, style="Card.TFrame", padding=(12, 12))
        card.grid(row=0, column=0, rowspan=2, sticky="nsew")
        card.columnconfigure(0, weight=1)
        card.rowconfigure(2, weight=1)
        ttk.Label(card, text=title, style="Section.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(card, text="Live data updates with interactive triage context.", style="Caption.TLabel").grid(row=1, column=0, sticky="w", pady=(2, 10))
        table_wrap = ttk.Frame(card, style="Card.TFrame")
        table_wrap.grid(row=2, column=0, sticky="nsew")
        table_wrap.columnconfigure(0, weight=1)
        table_wrap.rowconfigure(0, weight=1)
        return table_wrap

    def _build_findings_table(self, parent):
        table_wrap = self._build_tab_table_shell(parent, "Vulnerability Findings")
        columns = ("id", "severity", "title", "evidence")
        self.findings_tree = ttk.Treeview(table_wrap, columns=columns, show="headings")
        self.findings_tree.heading("id", text="ID")
        self.findings_tree.heading("severity", text="Severity")
        self.findings_tree.heading("title", text="Title")
        self.findings_tree.heading("evidence", text="Evidence")
        self.findings_tree.column("id", width=100, anchor="center")
        self.findings_tree.column("severity", width=110, anchor="center")
        self.findings_tree.column("title", width=360, anchor="w")
        self.findings_tree.column("evidence", width=440, anchor="w")
        self.findings_tree.grid(row=0, column=0, sticky="nsew")
        self.findings_tree.bind("<<TreeviewSelect>>", self._on_finding_selected)
        self._attach_scrollbars(table_wrap, self.findings_tree)

        self.findings_tree.tag_configure("critical", foreground=self.tokens["critical"], background="#1c1520")
        self.findings_tree.tag_configure("high", foreground=self.tokens["high"], background="#1c1820")
        self.findings_tree.tag_configure("medium", foreground=self.tokens["medium"], background="#1f1b1f")
        self.findings_tree.tag_configure("low", foreground=self.tokens["low"], background="#14201f")
        self.findings_tree.tag_configure("info", foreground=self.tokens["info"], background="#162131")
        self.findings_tree.tag_configure("alt", background="#102038")
        self._make_empty_state(table_wrap, "findings", "No findings yet", "Run scan to populate vulnerabilities.")

    def _build_services_table(self, parent):
        table_wrap = self._build_tab_table_shell(parent, "Service Inventory")
        self.services_tree = ttk.Treeview(table_wrap, columns=("port", "service"), show="headings")
        self.services_tree.heading("port", text="Port")
        self.services_tree.heading("service", text="Service / Product Signature")
        self.services_tree.column("port", width=120, anchor="center")
        self.services_tree.column("service", width=760, anchor="w")
        self.services_tree.grid(row=0, column=0, sticky="nsew")
        self.services_tree.bind("<<TreeviewSelect>>", self._on_service_selected)
        self._attach_scrollbars(table_wrap, self.services_tree)
        self._make_empty_state(table_wrap, "services", "No services discovered", "Enumerated services will appear here.")

    def _build_activity_table(self, parent):
        table_wrap = self._build_tab_table_shell(parent, "Execution Timeline")
        self.action_tree = ttk.Treeview(table_wrap, columns=("time", "action"), show="headings")
        self.action_tree.heading("time", text="Timestamp")
        self.action_tree.heading("action", text="Action")
        self.action_tree.column("time", width=160, anchor="center")
        self.action_tree.column("action", width=740, anchor="w")
        self.action_tree.grid(row=0, column=0, sticky="nsew")
        self.action_tree.bind("<<TreeviewSelect>>", self._on_action_selected)
        self._attach_scrollbars(table_wrap, self.action_tree)
        self._make_empty_state(table_wrap, "activity", "No timeline data", "Engine events are streamed during a run.")

    def _build_paths_table(self, parent):
        table_wrap = self._build_tab_table_shell(parent, "AI-Prioritized Attack Paths")
        self.paths_tree = ttk.Treeview(table_wrap, columns=("id", "kind", "severity", "score", "title"), show="headings")
        self.paths_tree.heading("id", text="ID")
        self.paths_tree.heading("kind", text="Kind")
        self.paths_tree.heading("severity", text="Severity")
        self.paths_tree.heading("score", text="Score")
        self.paths_tree.heading("title", text="Path")
        self.paths_tree.column("id", width=90, anchor="center")
        self.paths_tree.column("kind", width=110, anchor="center")
        self.paths_tree.column("severity", width=110, anchor="center")
        self.paths_tree.column("score", width=90, anchor="center")
        self.paths_tree.column("title", width=600, anchor="w")
        self.paths_tree.grid(row=0, column=0, sticky="nsew")
        self.paths_tree.bind("<<TreeviewSelect>>", self._on_path_selected)
        self._attach_scrollbars(table_wrap, self.paths_tree)
        self._make_empty_state(table_wrap, "paths", "No attack paths", "Planner output appears after analysis phases.")

    def _build_console(self, parent):
        console_card = ttk.Frame(parent, style="Card.TFrame", padding=(12, 12))
        console_card.grid(row=0, column=0, rowspan=2, sticky="nsew")
        console_card.columnconfigure(0, weight=1)
        console_card.rowconfigure(1, weight=1)
        ttk.Label(console_card, text="Live Operator Console", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        self.console = tk.Text(
            console_card,
            bg="#091425",
            fg="#99e8ff",
            insertbackground="#f8fafc",
            wrap="word",
            relief="flat",
            font=("Consolas", 10),
            padx=12,
            pady=12,
        )
        self.console.grid(row=1, column=0, sticky="nsew", pady=(10, 0))

    def _attach_scrollbars(self, parent, tree):
        y_scroll = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        x_scroll = ttk.Scrollbar(parent, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")

    def _make_empty_state(self, parent, key, title, subtitle):
        overlay = tk.Frame(parent, bg="#0d192d", bd=1, relief="flat", highlightthickness=1, highlightbackground=self.tokens["border_soft"])
        overlay.columnconfigure(0, weight=1)
        tk.Label(overlay, text=title, bg="#0d192d", fg=self.tokens["text_primary"], font=("Segoe UI", 12, "bold")).grid(row=0, column=0, pady=(20, 4), padx=20)
        tk.Label(overlay, text=subtitle, bg="#0d192d", fg=self.tokens["text_secondary"], font=("Segoe UI", 9)).grid(row=1, column=0, pady=(0, 18), padx=20)
        self.empty_states[key] = overlay
        self.root.after(30, lambda: self._show_empty_state(key, True))

    def _show_empty_state(self, key, visible):
        overlay = self.empty_states.get(key)
        if not overlay:
            return
        if visible:
            overlay.place(relx=0.5, rely=0.46, anchor="center", relwidth=0.7)
        else:
            overlay.place_forget()

    def _build_right_panel(self, parent):
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)

        risk_card = ttk.Frame(parent, style="Card.TFrame", padding=(12, 12))
        risk_card.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        risk_card.columnconfigure(0, weight=1)
        ttk.Label(risk_card, text="Risk Breakdown", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(risk_card, textvariable=self.risk_var, style="Caption.TLabel").grid(row=1, column=0, sticky="w", pady=(3, 10))

        severities = [
            ("Critical", self.critical_var, self.tokens["critical"]),
            ("High", self.high_var, self.tokens["high"]),
            ("Medium", self.medium_var, self.tokens["medium"]),
            ("Low", self.low_var, self.tokens["low"]),
            ("Info", self.info_var, self.tokens["info"]),
        ]
        for idx, (label, var, color) in enumerate(severities, start=2):
            self._create_severity_row(risk_card, idx, label, var, color)

        details_card = ttk.Frame(parent, style="Card.TFrame", padding=(12, 12))
        details_card.grid(row=1, column=0, sticky="nsew")
        details_card.columnconfigure(0, weight=1)
        details_card.rowconfigure(1, weight=1)
        ttk.Label(details_card, text="Investigation Details", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        self.details_text = tk.Text(
            details_card,
            bg="#091425",
            fg="#dbeafe",
            insertbackground="#f8fafc",
            wrap="word",
            relief="flat",
            state="disabled",
            font=("Consolas", 10),
            padx=12,
            pady=12,
        )
        self.details_text.grid(row=1, column=0, sticky="nsew", pady=(8, 0))

        guidance = ttk.Frame(parent, style="Card.TFrame", padding=(12, 12))
        guidance.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        ttk.Label(guidance, text="Run Intelligence", style="Section.TLabel").pack(anchor="w")
        ttk.Label(guidance, textvariable=self.target_info_var, style="Caption.TLabel").pack(anchor="w", pady=(4, 2))
        ttk.Label(
            guidance,
            text="Start scan with a valid IP/CIDR, then select findings\nor paths to inspect triage context and evidence.",
            style="Caption.TLabel",
            justify="left",
        ).pack(anchor="w")

    def _create_severity_row(self, parent, row, label, count_var, color):
        container = ttk.Frame(parent, style="Card.TFrame")
        container.grid(row=row, column=0, sticky="ew", pady=3)
        container.columnconfigure(1, weight=1)
        tk.Label(container, text=label, bg=self.tokens["bg_card"], fg=self.tokens["text_secondary"], font=("Segoe UI", 9, "bold")).grid(row=0, column=0, sticky="w")
        bar_bg = tk.Frame(container, bg="#1b2b44", height=8)
        bar_bg.grid(row=0, column=1, sticky="ew", padx=8)
        bar_bg.grid_propagate(False)
        bar_fill = tk.Frame(bar_bg, bg=color, width=2)
        bar_fill.place(x=0, y=0, relheight=1)
        badge = tk.Label(container, textvariable=count_var, bg=color, fg="#031018", font=("Segoe UI", 8, "bold"), padx=7, pady=2)
        badge.grid(row=0, column=2, sticky="e")
        self.risk_bars[label.upper()] = bar_fill

    def _build_status_bar(self, parent):
        status = ttk.Frame(parent, style="HeaderCard.TFrame", padding=(12, 8))
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
        nav_index_map = {0: "overview", 1: "services", 2: "activity", 3: "attack_paths", 4: "console"}
        if selected in nav_index_map:
            self._set_nav_active(nav_index_map[selected])
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
        self._update_risk_bars()
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
        self._show_empty_state("services", len(services) == 0)
        self._show_empty_state("activity", len(action_rows) == 0)
        self._show_empty_state("paths", len(state.attack_paths or []) == 0)

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

    def _update_risk_bars(self):
        values = {
            "CRITICAL": int(self.critical_var.get() or "0"),
            "HIGH": int(self.high_var.get() or "0"),
            "MEDIUM": int(self.medium_var.get() or "0"),
            "LOW": int(self.low_var.get() or "0"),
            "INFO": int(self.info_var.get() or "0"),
        }
        total = max(1, sum(values.values()))
        for severity, fill in self.risk_bars.items():
            width = max(6, int((values.get(severity, 0) / total) * 180))
            fill.configure(width=width)

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
            if idx % 2 == 0:
                tags = tuple(list(self.findings_tree.item(self.findings_tree.get_children()[-1], "tags")) + ["alt"])
                self.findings_tree.item(self.findings_tree.get_children()[-1], tags=tags)

        if vulnerabilities:
            first = self.findings_tree.get_children()[0]
            self.findings_tree.selection_set(first)
            self.findings_tree.focus(first)
            self._on_finding_selected(None)
        else:
            self._set_details("No findings available", ["Run a scan and refresh to inspect vulnerabilities here."])
        self._show_empty_state("findings", len(vulnerabilities) == 0)

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
        self._show_empty_state("paths", len(attack_paths or []) == 0)

    def _replace_tree_rows(self, tree, rows):
        for item in tree.get_children():
            tree.delete(item)
        for idx, row in enumerate(rows):
            tags = ("alt",) if idx % 2 == 1 else ()
            tree.insert("", "end", values=row, tags=tags)

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
        self._update_risk_bars()
        self._show_empty_state("findings", True)
        self._show_empty_state("services", True)
        self._show_empty_state("activity", True)
        self._show_empty_state("paths", True)

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
