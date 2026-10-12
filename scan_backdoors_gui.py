#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GUI front end for scan_backdoors.py (requires scanner v2.1+ placed next to it).
Python standard library only."""
import csv
import json
import os
import queue
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import ttk, filedialog, messagebox

APP_TITLE = "Scan Backdoors — GUI"
CONFIG_PATH = Path.home() / ".scan_backdoors_gui.json"
MAX_TABLE_ROWS = 5000          # showing more Treeview rows is heavy; the full list is in the CSV
LEVEL_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
# Files whose deletion may "take the site down": ask for an extra confirmation
PROTECTED_FILES = {"configuration.php", "index.php", ".htaccess", "administrator/index.php"}


# ---------------------------------------------------------------------------
# helper functions
# ---------------------------------------------------------------------------

def clean_cell(v):
    """The scanner protects the CSV from formulas: a cell '=x' is written as "'=x". Restore the original name."""
    v = v or ""
    return v[1:] if v[:1] == "'" and v[1:2] in ("=", "+", "-", "@") else v


def fmt_size(v):
    try:
        n = float(v)
    except (TypeError, ValueError):
        return v or ""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%d %s" % (n, unit) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024.0


def fmt_duration(sec):
    sec = int(max(sec, 0))
    m, s = divmod(sec, 60)
    h, m = divmod(m, 60)
    return "%d:%02d:%02d" % (h, m, s) if h else "%d:%02d" % (m, s)


def open_path(path):
    if sys.platform.startswith("win"):
        os.startfile(str(path))
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path)])


def reveal_path(path):
    """Open the folder and highlight the file (if the OS can)."""
    path = Path(path)
    if sys.platform.startswith("win"):
        subprocess.Popen(["explorer", "/select,%s" % path])
    elif sys.platform == "darwin":
        subprocess.Popen(["open", "-R", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path.parent)])


def kill_tree(proc):
    """Stop the scanner TOGETHER with its child processes (--workers)."""
    if proc is None or proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except Exception:
        try:
            proc.terminate()
        except OSError:
            pass


class ScannerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry("%dx%d" % (min(1180, sw - 40), min(900, sh - 90)))
        self.minsize(min(940, sw - 40), min(640, sh - 90))
        self.proc = None
        self.worker = None
        self.events = queue.Queue()
        self.scanning = False
        self.cleaning = False
        self._cleaned = []
        self._stripped = []
        self._replaced = []
        self._clean_summary = None
        self._clean_mode = None
        self._stopped = False
        self._got_done = False
        self._markers = False
        self._report_error = False
        self._last_stats = None
        self._bar_mode = None
        self.scan_t0 = 0.0
        self.scanned_site = None
        self.report_files = {}
        self._all_findings = []
        self._hidden_done = 0
        self._sort_state = {}
        self._setup_dark_theme()

        self.scanner_path = tk.StringVar(value=str(Path(__file__).with_name("scan_backdoors.py")))
        self.site_dir = tk.StringVar()
        self.csv_path = tk.StringVar(value=str(Path.cwd() / "report-data.csv"))
        self.xlsx_path = tk.StringVar()
        self.json_path = tk.StringVar()
        self.baseline_dir = tk.StringVar()
        self.whitelist_path = tk.StringVar()
        self.since = tk.StringVar()
        self.max_size = tk.StringVar(value="5")
        self.max_matches = tk.StringVar(value="60")
        self.min_score = tk.StringVar(value="0")
        self.workers = tk.StringVar(value="0")
        self.exclude_ext = tk.StringVar()
        self.exclude_dir = tk.StringVar()
        self.only_critical = tk.BooleanVar()
        self.no_warnings = tk.BooleanVar()
        self.no_csv = tk.BooleanVar()
        self.auto_open = tk.BooleanVar()
        self.clean_permanent = tk.BooleanVar()
        self.clean_fm = tk.BooleanVar()
        self.clean_core = tk.BooleanVar()
        # what we remember between runs
        self._persist = {k: v for k, v in list(vars(self).items())
                         if isinstance(v, (tk.StringVar, tk.BooleanVar))}
        self._load_config()
        self._build()
        self._refresh_report_buttons()
        self.after(100, self._poll_events)
        self.protocol("WM_DELETE_WINDOW", self._close)

    # ------------------------------------------------------------------ theme
    def _setup_dark_theme(self):
        self.colors = {
            "bg": "#171a21", "panel": "#222733", "field": "#11151c", "fg": "#e6eaf2",
            "muted": "#aab4c5", "accent": "#4f8cff", "accent_active": "#3976e8",
            "border": "#394252", "disabled": "#687386", "select": "#294a7a",
        }
        c = self.colors
        self.configure(bg=c["bg"])
        self.option_add("*TCombobox*Listbox.background", c["field"])
        self.option_add("*TCombobox*Listbox.foreground", c["fg"])
        self.option_add("*TCombobox*Listbox.selectBackground", c["select"])
        self.option_add("*TCombobox*Listbox.selectForeground", c["fg"])
        self.option_add("*TCombobox*Listbox.font", ("Segoe UI", 10))

        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", background=c["bg"], foreground=c["fg"], fieldbackground=c["field"],
                        bordercolor=c["border"], lightcolor=c["border"], darkcolor=c["border"],
                        troughcolor=c["field"], focuscolor=c["accent"], font=("Segoe UI", 10))
        style.configure("TFrame", background=c["bg"])
        style.configure("TLabel", background=c["bg"], foreground=c["fg"])
        style.configure("Muted.TLabel", background=c["bg"], foreground=c["muted"])
        style.configure("TLabelframe", background=c["bg"], foreground=c["fg"], bordercolor=c["border"])
        style.configure("TLabelframe.Label", background=c["bg"], foreground=c["fg"])
        style.configure("TEntry", fieldbackground=c["field"], foreground=c["fg"],
                        insertcolor=c["fg"], bordercolor=c["border"], padding=5)
        style.configure("TCombobox", fieldbackground=c["field"], background=c["panel"],
                        foreground=c["fg"], selectbackground=c["select"], selectforeground=c["fg"],
                        bordercolor=c["border"], arrowcolor=c["fg"])
        style.map("TCombobox", fieldbackground=[("readonly", c["field"])],
                  foreground=[("readonly", c["fg"])],
                  background=[("active", c["select"]), ("readonly", c["field"])])
        style.configure("TButton", background=c["panel"], foreground=c["fg"],
                        bordercolor=c["border"], padding=(10, 6))
        style.map("TButton", background=[("active", c["select"]), ("disabled", c["bg"])],
                  foreground=[("disabled", c["disabled"])])
        style.configure("Accent.TButton", background=c["accent"], foreground="#ffffff", padding=(12, 6))
        style.map("Accent.TButton", background=[("active", c["accent_active"]), ("disabled", c["panel"])],
                  foreground=[("disabled", c["disabled"])])
        style.configure("Danger.TButton", background="#7a2a33", foreground="#ffffff", padding=(10, 6))
        style.map("Danger.TButton", background=[("active", "#9a3440"), ("disabled", c["panel"])],
                  foreground=[("disabled", c["disabled"])])
        style.configure("TCheckbutton", background=c["bg"], foreground=c["fg"])
        style.map("TCheckbutton", background=[("active", c["bg"])], foreground=[("disabled", c["disabled"])])
        style.configure("TProgressbar", background=c["accent"], troughcolor=c["field"], bordercolor=c["border"])
        style.configure("TScrollbar", background=c["panel"], troughcolor=c["field"],
                        arrowcolor=c["fg"], bordercolor=c["border"])
        style.configure("TNotebook", background=c["bg"], bordercolor=c["border"])
        style.configure("TNotebook.Tab", background=c["panel"], foreground=c["muted"],
                        padding=(12, 8), bordercolor=c["border"])
        style.map("TNotebook.Tab", background=[("selected", c["select"]), ("active", c["border"])],
                  foreground=[("selected", c["fg"]), ("active", c["fg"])])
        style.configure("Treeview", background=c["field"], fieldbackground=c["field"],
                        foreground=c["fg"], bordercolor=c["border"], rowheight=24)
        style.configure("Treeview.Heading", background=c["panel"], foreground=c["fg"],
                        relief="flat", padding=(6, 5))
        style.map("Treeview", background=[("selected", c["select"])], foreground=[("selected", c["fg"])])
        style.map("Treeview.Heading", background=[("active", c["select"])])

    # ---------------------------------------------------------------- settings
    def _load_config(self):
        try:
            data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        for key, var in self._persist.items():
            if key in data:
                try:
                    var.set(data[key])
                except tk.TclError:
                    pass
        if not Path(self.scanner_path.get()).is_file():
            self.scanner_path.set(str(Path(__file__).with_name("scan_backdoors.py")))

    def _save_config(self):
        try:
            CONFIG_PATH.write_text(json.dumps({k: v.get() for k, v in self._persist.items()},
                                              ensure_ascii=False, indent=1), encoding="utf-8")
        except OSError:
            pass

    # ------------------------------------------------------------------ window
    def _build(self):
        c = self.colors
        outer = ttk.Frame(self, padding=12)
        outer.pack(fill="both", expand=True)
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(0, weight=1)
        tabs = ttk.Notebook(outer)
        tabs.grid(row=0, column=0, sticky="nsew")

        # ---- tab 1: settings
        settings_tab = ttk.Frame(tabs, padding=12)
        tabs.add(settings_tab, text="Settings")
        settings_tab.columnconfigure(1, weight=1)

        def path_row(parent, row, label, var, browse):
            ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=(0, 8), pady=4)
            ttk.Entry(parent, textvariable=var).grid(row=row, column=1, sticky="ew", pady=4)
            ttk.Button(parent, text="Browse…", command=lambda: browse(var)).grid(row=row, column=2, padx=(8, 0), pady=4)

        path_row(settings_tab, 0, "Scanner script:", self.scanner_path, self._pick_scanner)
        path_row(settings_tab, 1, "Site folder:", self.site_dir, self._pick_directory)
        path_row(settings_tab, 2, "Clean Joomla (optional):", self.baseline_dir, self._pick_directory)
        path_row(settings_tab, 3, "Whitelist (optional):", self.whitelist_path, self._pick_file)
        path_row(settings_tab, 4, "CSV report:", self.csv_path, self._pick_save_csv)
        path_row(settings_tab, 5, "XLSX report (optional):", self.xlsx_path, self._pick_save_xlsx)
        path_row(settings_tab, 6, "JSON report (optional):", self.json_path, self._pick_save_json)

        opts = ttk.LabelFrame(settings_tab, text="Scan options", padding=10)
        opts.grid(row=7, column=0, columnspan=3, sticky="ew", pady=(10, 8))
        for col in range(6):
            opts.columnconfigure(col, weight=1)
        ttk.Label(opts, text="File size, MB").grid(row=0, column=0, sticky="w")
        ttk.Entry(opts, textvariable=self.max_size, width=9).grid(row=0, column=1, sticky="w", padx=(4, 12))
        ttk.Label(opts, text="Max findings/level").grid(row=0, column=2, sticky="w")
        ttk.Entry(opts, textvariable=self.max_matches, width=9).grid(row=0, column=3, sticky="w", padx=(4, 12))
        ttk.Label(opts, text="Minimum score").grid(row=0, column=4, sticky="w")
        ttk.Entry(opts, textvariable=self.min_score, width=9).grid(row=0, column=5, sticky="w", padx=(4, 0))
        ttk.Label(opts, text="Modified after (14d or 2026-09-01)").grid(row=1, column=0, columnspan=2, sticky="w", pady=(8, 0))
        ttk.Entry(opts, textvariable=self.since, width=18).grid(row=1, column=2, sticky="w", pady=(8, 0))
        ttk.Label(opts, text="Processes (0 = auto)").grid(row=1, column=3, sticky="w", pady=(8, 0))
        ttk.Entry(opts, textvariable=self.workers, width=8).grid(row=1, column=4, sticky="w", pady=(8, 0))
        ttk.Label(opts, text="Exclude extensions (comma-separated)").grid(row=2, column=0, columnspan=2, sticky="w", pady=(8, 0))
        ttk.Entry(opts, textvariable=self.exclude_ext).grid(row=2, column=2, columnspan=4, sticky="ew", pady=(8, 0))
        ttk.Label(opts, text="Exclude folders (comma-separated)").grid(row=3, column=0, columnspan=2, sticky="w", pady=(8, 0))
        ttk.Entry(opts, textvariable=self.exclude_dir).grid(row=3, column=2, columnspan=4, sticky="ew", pady=(8, 0))
        flags = ttk.Frame(opts)
        flags.grid(row=4, column=0, columnspan=6, sticky="w", pady=(8, 0))
        ttk.Checkbutton(flags, text="Critical only", variable=self.only_critical).pack(side="left", padx=(0, 14))
        ttk.Checkbutton(flags, text="No warnings", variable=self.no_warnings).pack(side="left", padx=(0, 14))
        ttk.Checkbutton(flags, text="Do not create CSV", variable=self.no_csv).pack(side="left", padx=(0, 14))
        ttk.Checkbutton(flags, text="Open the CSV after scanning", variable=self.auto_open).pack(side="left")

        clean_opts = ttk.LabelFrame(settings_tab, text="Mass cleanup (clean_malware.py)", padding=10)
        clean_opts.grid(row=8, column=0, columnspan=3, sticky="ew", pady=(0, 8))
        ttk.Checkbutton(clean_opts, text="Delete permanently (no quarantine)", variable=self.clean_permanent).pack(side="left", padx=(0, 14))
        ttk.Checkbutton(clean_opts, text="Include web file managers (elp.php etc.)", variable=self.clean_fm).pack(side="left", padx=(0, 14))
        ttk.Checkbutton(clean_opts, text="Replace modified core files with originals (needs a clean Joomla of the same version)", variable=self.clean_core).pack(side="left")

        actions = ttk.Frame(settings_tab)
        actions.grid(row=9, column=0, columnspan=3, sticky="ew", pady=(8, 0))
        ttk.Label(actions, text="Settings are remembered and applied on the next launch.", style="Muted.TLabel").pack(side="left")
        ttk.Button(actions, text="Go to run →", command=lambda: tabs.select(results_tab)).pack(side="right")

        # ---- tab 2: run and results
        results_tab = ttk.Frame(tabs, padding=8)
        tabs.add(results_tab, text="Run and results")
        results_tab.columnconfigure(0, weight=1)
        results_tab.rowconfigure(3, weight=3)
        results_tab.rowconfigure(4, weight=1)

        controls = ttk.Frame(results_tab)
        controls.grid(row=0, column=0, sticky="ew", pady=(0, 4))
        self.start_btn = ttk.Button(controls, text="▶ Start scan", style="Accent.TButton", command=self.start_scan)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(controls, text="■ Stop", command=self.stop_scan, state="disabled")
        self.stop_btn.pack(side="left", padx=8)
        self.progress = ttk.Progressbar(controls, mode="determinate", maximum=100)
        self.progress.pack(side="left", fill="x", expand=True, padx=(8, 0))
        self._bar_mode = "determinate"

        self.progress_info = tk.StringVar(value="")
        ttk.Label(results_tab, textvariable=self.progress_info, style="Muted.TLabel").grid(row=1, column=0, sticky="w", pady=(0, 6))

        reports = ttk.Frame(results_tab)
        reports.grid(row=2, column=0, sticky="ew", pady=(0, 8))
        ttk.Label(reports, text="Reports:").pack(side="left", padx=(0, 8))
        self.report_btns = {}
        for kind, text in (("csv", "📂 CSV"), ("xlsx", "📂 XLSX"), ("json", "📂 JSON")):
            b = ttk.Button(reports, text=text, command=lambda k=kind: self._open_report(k), state="disabled")
            b.pack(side="left", padx=(0, 6))
            self.report_btns[kind] = b
        ttk.Button(reports, text="📁 Reports folder", command=self._open_reports_folder).pack(side="left")

        results_frame = ttk.LabelFrame(results_tab, text="Threats found", padding=6)
        results_frame.grid(row=3, column=0, sticky="nsew", pady=(0, 8))
        results_frame.rowconfigure(2, weight=3)
        results_frame.rowconfigure(3, weight=1)
        results_frame.columnconfigure(0, weight=1)

        filters = ttk.Frame(results_frame)
        filters.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        ttk.Label(filters, text="Level:").pack(side="left")
        self.level_filter = tk.StringVar(value="All")
        level_box = ttk.Combobox(filters, textvariable=self.level_filter, values=("All", "HIGH", "MEDIUM", "LOW"),
                                 state="readonly", width=10)
        level_box.pack(side="left", padx=(5, 12))
        level_box.bind("<<ComboboxSelected>>", lambda _e: self._apply_filters())
        ttk.Label(filters, text="Search (file / signature):").pack(side="left")
        self.search_filter = tk.StringVar()
        search_entry = ttk.Entry(filters, textvariable=self.search_filter, width=28)
        search_entry.pack(side="left", padx=5)
        search_entry.bind("<KeyRelease>", lambda _e: self._apply_filters())
        ttk.Button(filters, text="Reset filters", command=self._reset_filters).pack(side="left", padx=5)
        self.count_var = tk.StringVar(value="")
        ttk.Label(filters, textvariable=self.count_var, style="Muted.TLabel").pack(side="right")

        file_actions = ttk.Frame(results_frame)
        file_actions.grid(row=1, column=0, sticky="ew", pady=(0, 6))
        ttk.Button(file_actions, text="📁 Show file", command=self._open_selected_file_folder).pack(side="left")
        ttk.Button(file_actions, text="📦 Quarantine", command=lambda: self._delete_selected_files(True)).pack(side="left", padx=6)
        ttk.Button(file_actions, text="🗑 Delete from disk", style="Danger.TButton",
                   command=lambda: self._delete_selected_files(False)).pack(side="left")
        self.clean_btn = ttk.Button(file_actions, text="🧹 Mass cleanup", command=self._bulk_clean)
        self.clean_btn.pack(side="left", padx=(12, 0))
        ttk.Label(file_actions, text="Several rows: Ctrl/Shift. 'Mass cleanup' removes the known families (.htaccess locks, filefuns) across the whole site.",
                  style="Muted.TLabel").pack(side="left", padx=12)

        table_wrap = ttk.Frame(results_frame)
        table_wrap.grid(row=2, column=0, sticky="nsew")
        table_wrap.rowconfigure(0, weight=1)
        table_wrap.columnconfigure(0, weight=1)
        cols = ("level", "score", "file", "line", "size", "date", "del", "signature")
        self.threats = ttk.Treeview(table_wrap, columns=cols, show="headings", height=8, selectmode="extended")
        for col, title, width in (("level", "Level", 85), ("score", "Score", 60), ("file", "File", 340),
                                  ("line", "Line", 62), ("size", "Size", 75), ("date", "Date", 120),
                                  ("del", "Delete", 70), ("signature", "Signature", 300)):
            self.threats.heading(col, text=title, command=lambda cc=col: self._sort_by(cc))
            # 'File' and 'Signature' stretch with the window (the other columns are fixed); the minimum prevents an extra scrollbar
            grow = col in ("file", "signature")
            self.threats.column(col, width=width, minwidth={"file": 200, "signature": 180}.get(col, 50),
                                stretch=grow, anchor="w")
        self.threats.tag_configure("HIGH", background="#5a2028", foreground="#ffdce0")
        self.threats.tag_configure("MEDIUM", background="#5b451d", foreground="#fff0c2")
        self.threats.tag_configure("LOW", background="#174a43", foreground="#d5fff5")
        yscroll = ttk.Scrollbar(table_wrap, orient="vertical", command=self.threats.yview)
        xscroll = ttk.Scrollbar(table_wrap, orient="horizontal", command=self.threats.xview)
        self.threats.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        self.threats.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        self.threats.bind("<<TreeviewSelect>>", self._show_selected_snippet)
        self.threats.bind("<Double-1>", lambda _e: self._open_selected_file_folder())
        self.threats.bind("<Delete>", lambda _e: self._delete_selected_files(False))

        self.context_menu = tk.Menu(self, tearoff=0, bg=c["panel"], fg=c["fg"],
                                    activebackground=c["select"], activeforeground=c["fg"], bd=0)
        self.context_menu.add_command(label="📁 Show file", command=self._open_selected_file_folder)
        self.context_menu.add_command(label="📋 Copy path", command=self._copy_path)
        self.context_menu.add_command(label="📋 Copy SHA-256", command=self._copy_sha)
        self.context_menu.add_command(label="✅ To whitelist (false positive)", command=self._add_to_whitelist)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="📦 Move to quarantine", command=lambda: self._delete_selected_files(True))
        self.context_menu.add_command(label="🗑 Delete from disk", command=lambda: self._delete_selected_files(False))
        for ev in ("<Button-3>", "<Button-2>", "<Control-Button-1>"):
            self.threats.bind(ev, self._show_context_menu)

        preview_frame = ttk.LabelFrame(results_frame, text="Suspicious code snippet", padding=5)
        preview_frame.grid(row=3, column=0, sticky="nsew", pady=(7, 0))
        preview_frame.rowconfigure(0, weight=1)
        preview_frame.columnconfigure(0, weight=1)
        self.preview = tk.Text(preview_frame, wrap="none", height=5, state="disabled", bg=c["field"], fg=c["fg"],
                               insertbackground=c["fg"], selectbackground=c["select"], selectforeground=c["fg"],
                               inactiveselectbackground=c["select"], relief="flat", bd=0, padx=8, pady=6, font=("Consolas", 10))
        preview_scroll = ttk.Scrollbar(preview_frame, command=self.preview.yview)
        self.preview.configure(yscrollcommand=preview_scroll.set)
        self.preview.grid(row=0, column=0, sticky="nsew")
        preview_scroll.grid(row=0, column=1, sticky="ns")

        log_frame = ttk.LabelFrame(results_tab, text="Log", padding=6)
        log_frame.grid(row=4, column=0, sticky="nsew")
        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)
        self.log = tk.Text(log_frame, wrap="word", height=6, state="disabled", bg=c["field"], fg=c["fg"],
                           insertbackground=c["fg"], selectbackground=c["select"], selectforeground=c["fg"],
                           inactiveselectbackground=c["select"], relief="flat", bd=0, padx=8, pady=8, font=("Consolas", 10))
        scroll = ttk.Scrollbar(log_frame, command=self.log.yview)
        self.log.configure(yscrollcommand=scroll.set)
        self.log.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")

        self.status = tk.StringVar(value="Ready to run")
        ttk.Label(results_tab, textvariable=self.status).grid(row=5, column=0, sticky="w", pady=(6, 0))
        self._make_copyable(self.preview)
        self._make_copyable(self.log)
        self.threats.bind("<Control-KeyPress>", self._tree_ctrl)
        self.bind_all("<Control-KeyPress>", self._layout_fix)

    # ------------------------------------------------- copying from fields
    def _make_copyable(self, w):
        """A disabled Text: take focus on click, Ctrl+C works on any layout, there is a right-click menu."""
        def copy(_e=None):
            try:
                text = w.get("sel.first", "sel.last")
            except tk.TclError:
                return "break"                      # nothing is selected
            self.clipboard_clear()
            self.clipboard_append(text)
            self.status.set("Copied to the clipboard: %d chars" % len(text))
            return "break"

        def select_all(_e=None):
            w.tag_add("sel", "1.0", "end-1c")
            return "break"

        def on_ctrl(e):
            k = e.keysym.lower()
            if k in ("c", "cyrillic_es", "insert"):
                return copy()
            if k in ("a", "cyrillic_ef"):
                return select_all()

        c = self.colors
        menu = tk.Menu(self, tearoff=0, bg=c["panel"], fg=c["fg"], activebackground=c["select"],
                       activeforeground=c["fg"], bd=0)
        menu.add_command(label="Copy", command=copy)
        menu.add_command(label="Select all", command=select_all)

        def popup(e):
            w.focus_set()
            menu.tk_popup(e.x_root, e.y_root)
            return "break"

        w.bind("<Button-1>", lambda _e: w.focus_set(), add="+")
        w.bind("<Control-KeyPress>", on_ctrl)
        w.bind("<Control-Insert>", copy)
        for ev in ("<Button-3>", "<Button-2>"):
            w.bind(ev, popup)

    def _layout_fix(self, e):
        """Ctrl+C/V/X/A with a Russian keyboard layout: Tk receives the Cyrillic key, not the Latin one."""
        w = e.widget
        k = e.keysym.lower()
        seq = {"cyrillic_es": "<<Copy>>", "cyrillic_em": "<<Paste>>", "cyrillic_che": "<<Cut>>"}.get(k)
        if seq and hasattr(w, "event_generate"):
            try:
                w.event_generate(seq)
            except tk.TclError:
                pass
            return "break"
        if k == "cyrillic_ef" and hasattr(w, "select_range"):
            w.select_range(0, "end")
            w.icursor("end")
            return "break"

    def _tree_ctrl(self, e):
        if e.keysym.lower() in ("c", "cyrillic_es", "insert"):
            self._copy_path()
            return "break"

    # ------------------------------------------------------------- progress
    def _set_indeterminate(self, text):
        if self._bar_mode != "indeterminate":
            self.progress.stop()
            self.progress.configure(mode="indeterminate", value=0)
            self.progress.start(12)
            self._bar_mode = "indeterminate"
        self.progress_info.set(text)

    def _set_progress(self, done, total):
        if self._bar_mode != "determinate":
            self.progress.stop()
            self.progress.configure(mode="determinate")
            self._bar_mode = "determinate"
        self.progress.configure(maximum=max(total, 1), value=done)
        elapsed = time.time() - self.scan_t0
        pct = 100.0 * done / total if total else 100.0
        text = ("Processed" if self.cleaning else "Scanned") + " files: %s of %s (%.0f%%) · elapsed %s" % (
            "{:,}".format(done).replace(",", " "), "{:,}".format(total).replace(",", " "), pct, fmt_duration(elapsed))
        if 0 < done < total and elapsed > 1:
            text += " · ~%s left" % fmt_duration((total - done) / (done / elapsed))
        self.progress_info.set(text)

    def _handle_marker(self, tag, payload):
        """Service lines of the scanner (--progress-lines): they do not go to the log."""
        if tag == "PHASE":
            self._set_indeterminate({"baseline": "Building the clean Joomla baseline…",
                                     "walk": "Collecting the file list…",
                                     "finish": "Generating the report…",
                                     "clean": "Cleaning files…"}.get(payload, "Working…"))
        elif tag == "PROGRESS":
            try:
                done, total = (int(x) for x in payload.split())
                self._set_progress(done, total)
            except ValueError:
                pass
        elif tag == "FILE":
            kind, _, path = payload.partition(" ")
            if path:
                self.report_files[kind] = path
        elif tag == "STATS":
            try:
                self._last_stats = json.loads(payload)
            except ValueError:
                pass
        elif tag == "DONE":
            self._got_done = True
        elif tag == "CLEANED":
            self._cleaned.append(payload)
        elif tag == "STRIPPED":
            self._stripped.append(payload)
        elif tag == "REPLACED":
            self._replaced.append(payload)
        elif tag == "SUMMARY":
            try:
                self._clean_summary = json.loads(payload)
            except ValueError:
                pass

    # ------------------------------------------------------------- reports
    def _abs_from_setting(self, raw):
        path = Path(raw.strip()).expanduser()
        if not path.is_absolute():
            path = Path(self.scanner_path.get()).expanduser().resolve().parent / path
        return path

    def _report_path(self, kind):
        p = self.report_files.get(kind)
        if p:
            path = Path(p)
        else:
            raw = {"csv": "" if self.no_csv.get() else self.csv_path.get(),
                   "xlsx": self.xlsx_path.get(), "json": self.json_path.get()}[kind]
            if not raw.strip():
                return None
            path = self._abs_from_setting(raw)
        return path if path.is_file() else None

    def _refresh_report_buttons(self):
        for kind, btn in self.report_btns.items():
            btn.configure(state="normal" if self._report_path(kind) else "disabled")

    def _open_report(self, kind):
        path = self._report_path(kind)
        if not path:
            messagebox.showwarning("File not found", "The report has not been created yet.")
            return
        try:
            open_path(path)
        except Exception as exc:
            messagebox.showerror("Could not open the file", "%s\n%s" % (path, exc))

    def _reports_directory(self):
        for kind in ("csv", "xlsx", "json"):
            p = self._report_path(kind)
            if p:
                return p.parent
        for raw in ("" if self.no_csv.get() else self.csv_path.get(), self.xlsx_path.get(), self.json_path.get()):
            if raw.strip():
                return self._abs_from_setting(raw).parent
        return Path.cwd()

    def _open_reports_folder(self):
        folder = self._reports_directory()
        folder.mkdir(parents=True, exist_ok=True)
        try:
            open_path(folder)
        except Exception as exc:
            messagebox.showerror("Could not open the folder", "%s\n%s" % (folder, exc))

    # ------------------------------------------------------ findings table
    def _site_root(self):
        return self.scanned_site or self.site_dir.get()

    def _read_csv(self, path):
        with path.open("r", encoding="utf-8-sig", newline="") as f:
            return list(csv.DictReader(f))

    def _read_json(self, path):
        data = json.loads(path.read_text(encoding="utf-8"))
        rows = []
        for fl in data.get("files", []):
            for h in fl.get("hits", []):
                rows.append({"Score": fl.get("score", ""), "Verdict": fl.get("verdict", ""),
                             "Severity": h.get("severity", ""), "File": fl.get("path", ""),
                             "Line": h.get("line") or "", "Signature": h.get("signature", ""),
                             "Snippet": h.get("snippet", ""), "Size": fl.get("size", ""),
                             "Modified": fl.get("modified", ""), "Delete": "No",
                             "SHA-256": fl.get("sha256", "")})
        return rows

    def _load_findings(self):
        self._all_findings = []
        self._hidden_done = 0
        path, loader = self._report_path("csv"), self._read_csv
        if path is None:
            path, loader = self._report_path("json"), self._read_json
        if path is not None:
            try:
                rows = loader(path)
            except (OSError, ValueError, csv.Error) as exc:
                rows = []
                self._append_log("\nCould not read the report: %s\n" % exc)
            root = Path(self._site_root()).expanduser() if self._site_root() else None
            for row in rows:
                rel = clean_cell(row.get("File", ""))
                row["File"] = rel
                # the row is marked 'Yes' and the file no longer exists on disk -> it was deleted/handled, do not show it
                mark = (row.get("Delete") or "").strip().lower()
                if (mark == "yes" and root and root.is_dir() and not os.path.lexists(str(root / rel))) \
                        or mark == "replaced":
                    self._hidden_done += 1
                    continue
                level = (row.get("Verdict") or "").upper().strip()
                if level not in LEVEL_ORDER:
                    level = "LOW"
                row["_level"] = level
                self._all_findings.append(row)
        self._apply_filters()

    def _apply_filters(self):
        if not hasattr(self, "threats"):
            return
        for item in self.threats.get_children():
            self.threats.delete(item)
        level = self.level_filter.get()
        query = self.search_filter.get().casefold().strip()
        shown = matched = 0
        for index, row in enumerate(self._all_findings):
            severity = row.get("_level", "LOW")
            if level != "All" and severity != level:
                continue
            if query and query not in (row.get("File", "") + " " + row.get("Signature", "")).casefold():
                continue
            matched += 1
            if shown >= MAX_TABLE_ROWS:
                continue
            shown += 1
            self.threats.insert("", "end", iid=str(index), tags=(severity,), values=(
                severity, row.get("Score", ""), row.get("File", ""), row.get("Line", ""),
                fmt_size(row.get("Size", "")), row.get("Modified", ""), row.get("Delete", ""),
                row.get("Signature", "")))
        text = "Showing %d of %d" % (shown, len(self._all_findings))
        if matched > shown:
            text += " (table limit %d, narrow the filter or open the CSV)" % MAX_TABLE_ROWS
        if self._hidden_done:
            text += " · hidden as handled: %d" % self._hidden_done
        self.count_var.set(text)
        self._show_selected_snippet()

    def _reset_filters(self):
        self.level_filter.set("All")
        self.search_filter.set("")
        self._apply_filters()

    @staticmethod
    def _sort_key(row, col):
        if col == "level":
            return LEVEL_ORDER.get(row.get("_level"), 3)
        if col in ("score", "line", "size"):
            try:
                return float(row.get({"score": "Score", "line": "Line", "size": "Size"}[col]) or -1)
            except ValueError:
                return -1.0
        if col == "date":
            return row.get("Modified", "")
        if col == "del":
            return row.get("Delete", "")
        if col == "file":
            return row.get("File", "").lower()
        return row.get("Signature", "").lower()

    def _sort_by(self, col):
        rev = (not self._sort_state[col]) if col in self._sort_state else (col == "score")
        self._all_findings.sort(key=lambda r: self._sort_key(r, col), reverse=rev)
        self._sort_state = {col: rev}
        self._apply_filters()

    def _selected_rows(self):
        rows = []
        for iid in self.threats.selection():
            try:
                rows.append(self._all_findings[int(iid)])
            except (ValueError, IndexError):
                pass
        return rows

    def _show_selected_snippet(self, _event=None):
        rows = self._selected_rows()
        text = ""
        if len(rows) == 1:
            row = rows[0]
            text = ("File: %s\nLevel: %s | Score: %s | Line: %s | Size: %s | Date: %s\nSignature: %s\n%s\n%s" % (
                row.get("File", ""), row.get("_level", ""), row.get("Score", ""), row.get("Line", ""),
                fmt_size(row.get("Size", "")), row.get("Modified", ""), row.get("Signature", ""), "-" * 72,
                row.get("Snippet", "") or "(The snippet is not stored in the CSV.)"))
        elif len(rows) > 1:
            text = "Rows selected: %d, files: %d" % (len(rows), len({r.get("File") for r in rows}))
        self.preview.configure(state="normal")
        self.preview.delete("1.0", "end")
        self.preview.insert("1.0", text)
        self.preview.configure(state="disabled")

    def _show_context_menu(self, event):
        item = self.threats.identify_row(event.y)
        if not item:
            return
        if item not in self.threats.selection():
            self.threats.selection_set(item)
        self.context_menu.tk_popup(event.x_root, event.y_root)

    # ------------------------------------------------- actions on files
    def _resolve_target(self, rel):
        """Safely resolve a file path inside the site folder (protection against '..' and symlinks pointing outside)."""
        root = Path(self._site_root()).expanduser()
        if not root.is_dir():
            raise ValueError("Site root folder not found: %s" % root)
        root_real = Path(os.path.realpath(str(root)))
        target = Path(os.path.normpath(str(root_real / rel)))
        try:
            target.relative_to(root_real)
            Path(os.path.realpath(str(target.parent))).relative_to(root_real)
        except ValueError:
            raise ValueError("The path leaves the site folder: %s" % rel)
        return root_real, target

    def _open_selected_file_folder(self):
        rows = self._selected_rows()
        if not rows:
            messagebox.showwarning("Nothing selected", "Select a row with a threat in the table.")
            return
        try:
            _root, target = self._resolve_target(rows[0].get("File", ""))
            if not target.parent.is_dir():
                raise ValueError("The folder does not exist:\n%s" % target.parent)
            reveal_path(target)
        except Exception as exc:
            messagebox.showerror("Could not open the folder", str(exc))

    def _copy_path(self):
        rows = self._selected_rows()
        if rows:
            try:
                text = "\n".join(str(self._resolve_target(r.get("File", ""))[1]) for r in rows)
            except ValueError as exc:
                messagebox.showerror("Error", str(exc))
                return
            self.clipboard_clear()
            self.clipboard_append(text)
            self.status.set("Path copied to the clipboard")

    def _copy_sha(self):
        rows = self._selected_rows()
        if rows and rows[0].get("SHA-256"):
            self.clipboard_clear()
            self.clipboard_append(rows[0]["SHA-256"])
            self.status.set("SHA-256 copied to the clipboard")

    def _add_to_whitelist(self):
        rows = self._selected_rows()
        hashes = {}
        for r in rows:
            if r.get("SHA-256"):
                hashes[r["SHA-256"]] = r.get("File", "")
        if not hashes:
            messagebox.showwarning("No hash", "The report has no SHA-256 for the selected files.")
            return
        if not messagebox.askyesno("Add to whitelist", "Files: %d.\nTheir hashes will be added to the whitelist: the scanner will stop "
                                   "reporting them until the file content changes.\n\nContinue?" % len(hashes)):
            return
        wl = self.whitelist_path.get().strip()
        if not wl:
            wl = filedialog.asksaveasfilename(title="Whitelist file", defaultextension=".txt", initialfile="whitelist.txt")
            if not wl:
                return
            self.whitelist_path.set(wl)
        try:
            wl_path = Path(wl).expanduser()
            prefix = ""
            if wl_path.is_file() and wl_path.stat().st_size and not wl_path.read_bytes().endswith(b"\n"):
                prefix = "\n"
            with wl_path.open("a", encoding="utf-8") as f:
                f.write(prefix + "".join("%s  # %s\n" % (h, rel) for h, rel in hashes.items()))
        except OSError as exc:
            messagebox.showerror("Could not write the whitelist", str(exc))
            return
        self.status.set("Hashes added to the whitelist: %d (effective from the next scan)" % len(hashes))

    def _delete_selected_files(self, quarantine=False):
        rows = self._selected_rows()
        if not rows:
            messagebox.showwarning("Nothing selected", "Select one or more rows in the table.")
            return
        # one file may have many findings -> work with unique files
        by_file = {}
        for r in rows:
            rel = r.get("File", "")
            lvl = r.get("_level", "LOW")
            if rel not in by_file or LEVEL_ORDER.get(lvl, 3) < LEVEL_ORDER.get(by_file[rel], 3):
                by_file[rel] = lvl
        targets, missing = [], []
        try:
            for rel in by_file:
                root, target = self._resolve_target(rel)
                (targets if os.path.lexists(str(target)) else missing).append((rel, target))
        except ValueError as exc:
            messagebox.showerror("Error", str(exc))
            return
        if not targets:
            self._finish_removal([rel for rel, _t in missing], "The files are already missing on disk, removed from the list: %d" % len(missing))
            return

        verb = "move to quarantine" if quarantine else "PERMANENTLY delete"
        listing = "\n".join("  • %s  [%s]" % (rel, by_file[rel]) for rel, _t in targets[:8])
        if len(targets) > 8:
            listing += "\n  … and %d more" % (len(targets) - 8)
        warn = ""
        if any(by_file[rel] != "HIGH" for rel, _t in targets):
            warn = "\n\nThe files include MEDIUM/LOW levels: false positives are possible. Check the code snippet."
        if not messagebox.askyesno("Confirmation", "Action: %s. Files: %d\n\n%s%s" % (verb, len(targets), listing, warn)):
            return
        protected = [rel for rel, _t in targets if rel.lower().replace("\\", "/") in PROTECTED_FILES]
        if protected and not messagebox.askyesno(
                "Important Joomla file", "The list contains system files:\n  %s\n\nDeleting them may take the site down. "
                "Such files are usually cleaned manually. Continue?" % "\n  ".join(protected), icon="warning"):
            return

        qdir = None
        if quarantine:
            root, _t = self._resolve_target(targets[0][0])
            qdir = root.parent / ("_quarantine_" + (root.name or "site")) / datetime.now().strftime("%Y%m%d_%H%M%S")
        done, failed = [], []
        for rel, target in targets:
            try:
                if quarantine:
                    dest = qdir / (rel.replace("\\", "/") + ".quarantine")
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(target), str(dest))
                    with (qdir / "manifest.txt").open("a", encoding="utf-8") as mf:
                        mf.write("%s\t<-\t%s\n" % (dest, target))
                    self._append_log("[QUARANTINE] %s -> %s\n" % (target, dest))
                else:
                    try:
                        target.unlink()
                    except PermissionError:
                        os.chmod(str(target), stat.S_IWRITE | stat.S_IREAD)
                        target.unlink()
                    self._append_log("[DELETED] %s\n" % target)
                done.append(rel)
            except Exception as exc:
                failed.append((rel, exc))
                self._append_log("[ERROR] %s: %s\n" % (target, exc))
        self._finish_removal(done + [rel for rel, _t in missing],
                             "%s: %d" % ("Moved to quarantine" if quarantine else "Deleted", len(done)),
                             failed, qdir if quarantine and done else None)

    def _finish_removal(self, rels, text, failed=(), qdir=None, replaced=()):
        """Remove the files from the in-memory list, mark them 'Yes' in the CSV and refresh the table (without re-reading the CSV)."""
        gone = set(rels) | set(replaced)
        if gone:
            self._all_findings = [r for r in self._all_findings if r.get("File") not in gone]
            err = self._mark_deleted_in_csv(set(rels), set(replaced))
            if err:
                self._append_log("CSV not updated (%s). Close the file in Excel.\n" % err)
        self._apply_filters()
        if qdir:
            text += " · quarantine: %s" % qdir
        if failed:
            text += " · failed: %d" % len(failed)
        self.status.set(text)
        if failed:
            messagebox.showerror("Some files were not processed", "\n".join("%s: %s" % (r, e) for r, e in failed[:8]))

    def _mark_deleted_in_csv(self, rels, replaced=()):
        path = self.report_files.get("csv") and Path(self.report_files["csv"]) or self._report_path("csv")
        if not path or not path.is_file():
            return None
        tmp = path.with_name(path.name + ".tmp")
        try:
            with path.open("r", encoding="utf-8-sig", newline="") as f:
                reader = csv.DictReader(f)
                fields = reader.fieldnames or []
                if "Delete" not in fields:
                    return None
                rows = list(reader)
            for row in rows:
                f = clean_cell(row.get("File", ""))
                if f in rels:
                    row["Delete"] = "Yes"
                elif f in replaced:
                    row["Delete"] = "Replaced"
            with tmp.open("w", encoding="utf-8-sig", newline="") as f:
                w = csv.DictWriter(f, fieldnames=fields)
                w.writeheader()
                w.writerows(rows)
            os.replace(str(tmp), str(path))
            return None
        except (OSError, csv.Error) as exc:
            try:
                tmp.unlink()
            except OSError:
                pass
            return str(exc)

    # ---------------------------------------------------------- selection dialogs
    def _pick_scanner(self, var):
        p = filedialog.askopenfilename(title="Select scan_backdoors.py", filetypes=[("Python", "*.py"), ("All files", "*.*")])
        if p: var.set(p)

    def _pick_directory(self, var):
        p = filedialog.askdirectory(title="Select a folder")
        if p: var.set(p)

    def _pick_file(self, var):
        p = filedialog.askopenfilename(title="Select a file", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if p: var.set(p)

    def _pick_save_csv(self, var):
        p = filedialog.asksaveasfilename(title="Save CSV report", defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if p: var.set(p)

    def _pick_save_xlsx(self, var):
        p = filedialog.asksaveasfilename(title="Save XLSX report", defaultextension=".xlsx", filetypes=[("Excel", "*.xlsx")])
        if p: var.set(p)

    def _pick_save_json(self, var):
        p = filedialog.asksaveasfilename(title="Save JSON report", defaultextension=".json", filetypes=[("JSON", "*.json")])
        if p: var.set(p)

    # ------------------------------------------------------------------ log
    def _append_log(self, text):
        self.log.configure(state="normal")
        self.log.insert("end", text)
        if int(self.log.index("end-1c").split(".")[0]) > 4000:     # do not bloat the memory
            self.log.delete("1.0", "1000.0")
        self.log.see("end")
        self.log.configure(state="disabled")

    # ------------------------------------------------------------------ launch
    def _num(self, var, name, kind=float, minimum=0):
        s = var.get().strip().replace(",", ".")
        if not s:
            return ""
        try:
            v = kind(s)
        except ValueError:
            raise ValueError("The field '%s' must be a number." % name)
        if v < minimum:
            raise ValueError("The field '%s' cannot be less than %s." % (name, minimum))
        return s

    def _build_command(self):
        scanner = Path(self.scanner_path.get()).expanduser()
        site = Path(self.site_dir.get()).expanduser()
        if not scanner.is_file():
            raise ValueError("The scanner file scan_backdoors.py was not found.")
        if not site.is_dir():
            raise ValueError("Select an existing site folder.")
        since = self.since.get().strip()
        if since and not re.match(r"^\d+d$", since):
            try:
                datetime.strptime(since, "%Y-%m-%d")
            except ValueError:
                raise ValueError("The field 'Modified after': use 14d or 2026-09-01.")
        try:
            src = scanner.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            src = ""
        self._markers = "--progress-lines" in src

        cmd = [sys.executable, "-u", str(scanner), str(site)]

        def add(flag, value):
            value = value.strip()
            if value:
                cmd.extend([flag, value])

        add("--max-size", self._num(self.max_size, "File size", float, 0.01))
        add("--max-matches", self._num(self.max_matches, "Max findings", int, 1))
        add("--min-score", self._num(self.min_score, "Minimum score", int, 0))
        add("--workers", self._num(self.workers, "Processes", int, 0))
        add("--since", since)
        add("--exclude-ext", self.exclude_ext.get())
        add("--exclude-dir", self.exclude_dir.get())
        add("--baseline-dir", self.baseline_dir.get())
        add("--whitelist", self.whitelist_path.get())
        outputs = [("--xlsx", self.xlsx_path.get()), ("--json", self.json_path.get())]
        if self.no_csv.get():
            cmd.append("--no-csv")
        else:
            outputs.append(("--csv", self.csv_path.get() or "report-data.csv"))
        for flag, raw in outputs:
            if raw.strip():
                p = self._abs_from_setting(raw)
                p.parent.mkdir(parents=True, exist_ok=True)
                cmd.extend([flag, str(p)])
        if self.only_critical.get():
            cmd.append("--only-critical")
        if self.no_warnings.get():
            cmd.append("--no-warnings")
        if self._markers:
            cmd.append("--progress-lines")
        return cmd

    def start_scan(self):
        if self.scanning or self.cleaning:
            return
        try:
            cmd = self._build_command()
        except (ValueError, OSError) as e:
            messagebox.showerror("Parameters not filled in", str(e))
            return
        self.scanning = True
        self._stopped = self._got_done = self._report_error = False
        self._last_stats = None
        self.report_files = {}
        self.scanned_site = str(Path(self.site_dir.get()).expanduser())
        self.scan_t0 = time.time()
        self._all_findings = []
        self._hidden_done = 0
        self._apply_filters()
        self._refresh_report_buttons()
        self._append_log("\n" + "=" * 76 + "\nCommand: " + subprocess.list2cmdline(cmd) + "\n\n")
        if not self._markers:
            self._append_log("WARNING: old scanner version (no --progress-lines), exact progress is unavailable. Update scan_backdoors.py to 2.1.\n\n")
        self.status.set("Scan in progress…")
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self._bar_mode = None
        self._set_indeterminate("Starting the scanner…")
        self.worker = threading.Thread(target=self._run_process, args=(cmd,), daemon=True)
        self.worker.start()

    def _run_process(self, cmd, done_event="done"):
        try:
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"
            env["PYTHONUTF8"] = "1"
            env["PYTHONUNBUFFERED"] = "1"          # otherwise the output arrives in one batch only at the end
            kwargs = {}
            if os.name == "nt":
                kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            else:
                kwargs["start_new_session"] = True  # so that the whole process group can be killed
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                    encoding="utf-8", errors="replace", bufsize=1, env=env,
                                    cwd=str(Path(self.scanner_path.get()).expanduser().resolve().parent), **kwargs)
            self.proc = proc
            for line in proc.stdout:
                self.events.put(("line", line))
            self.events.put((done_event, proc.wait()))
        except Exception as exc:
            self.events.put(("error", str(exc)))

    def _poll_events(self):
        try:
            for _ in range(300):
                event, value = self.events.get_nowait()
                if event == "line":
                    if value.startswith("@@"):
                        tag, _, payload = value[2:].rstrip("\r\n").partition(" ")
                        self._handle_marker(tag, payload)
                    else:
                        self._append_log(value)
                        if "Could not write the report" in value:
                            self._report_error = True
                elif event == "done":
                    self._on_done(value)
                elif event == "clean_done":
                    self._on_clean_done(value)
                elif event == "error":
                    self._finish_ui()
                    self.progress.configure(value=0)
                    self.progress_info.set("")
                    self.status.set("Could not start the scanner")
                    self._append_log("\nStartup error: " + value + "\n")
                    messagebox.showerror("Startup error", value)
        except queue.Empty:
            pass
        self.after(100, self._poll_events)

    def _finish_ui(self):
        self.proc = None
        self.scanning = False
        self.cleaning = False
        self.clean_btn.configure(state="normal")
        self.progress.stop()
        self._bar_mode = "determinate"
        self.progress.configure(mode="determinate")
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")

    def _on_done(self, code):
        valid = self._got_done or not self._markers    # exit code 2 from argparse != 'there are critical findings'
        self._finish_ui()
        stats = self._last_stats or {}
        summary = ""
        if stats:
            summary = " Files scanned: %s, flagged: %s (HIGH %s, MEDIUM %s, LOW %s)." % (
                stats.get("Files scanned", "?"), stats.get("Files flagged", "?"),
                stats.get("HIGH", 0), stats.get("MEDIUM", 0), stats.get("LOW", 0))
        if self._stopped:
            msg = "Scan stopped by the user."
        elif not valid or code not in (0, 2):
            msg = "The scanner finished with an error (code %s). See the log for details." % code
        elif code == 0:
            msg = "Finished: no critical findings." + summary
        else:
            msg = "Finished: critical findings detected." + summary
        if self._report_error:
            msg += " The report was not written: close the file in Excel and try again."
        if not self._stopped and valid and code in (0, 2):
            self.progress.configure(value=self.progress["maximum"])
            self.progress_info.set("Done in %s" % fmt_duration(time.time() - self.scan_t0))
        else:
            self.progress_info.set("")
        self.status.set(msg)
        self._append_log("\n" + msg + "\n")
        self._load_findings()
        self._refresh_report_buttons()
        if self._stopped or self._report_error:
            return
        if not valid or code not in (0, 2):
            messagebox.showerror("Scan error", msg)
        elif self.auto_open.get() and self._report_path("csv"):
            self._open_report("csv")
        elif code == 2:
            if self._report_path("csv"):
                if messagebox.askyesno("Scan finished", msg + "\n\nOpen the CSV report?"):
                    self._open_report("csv")
            else:
                messagebox.showwarning("Scan finished", msg)

    # ------------------------------------------------------- mass cleanup
    def _cleaner_command(self, apply):
        cleaner = Path(self.scanner_path.get()).expanduser().with_name("clean_malware.py")
        if not cleaner.is_file():
            raise ValueError("clean_malware.py was not found next to the scanner.")
        site = Path(self._site_root() or "").expanduser()
        if not self._site_root() or not site.is_dir():
            raise ValueError("Select an existing site folder.")
        report_dir = self._reports_directory()
        report_dir.mkdir(parents=True, exist_ok=True)
        families = "htaccess,backdoor" + (",filemanager" if self.clean_fm.get() else "")
        cmd = [sys.executable, "-u", str(cleaner), str(site), "--families", families, "--progress-lines",
               "--report", str(report_dir / "cleanup-report.csv")]
        if self.whitelist_path.get().strip():
            cmd += ["--whitelist", self.whitelist_path.get().strip()]
        if self.clean_core.get():
            base = self.baseline_dir.get().strip()
            if not base or not Path(base).expanduser().is_dir():
                raise ValueError("To replace core files, specify the 'Clean Joomla' folder (same version) on the 'Settings' tab.")
            cmd += ["--replace-core", "--baseline-dir", base]
        if apply:
            cmd.append("--apply")
            if self.clean_permanent.get():
                cmd.append("--delete")
        return cmd

    def _bulk_clean(self):
        if self.scanning or self.cleaning:
            return
        try:
            cmd = self._cleaner_command(False)
        except ValueError as exc:
            messagebox.showerror("Mass cleanup", str(exc))
            return
        self._start_cleaner(cmd, "plan")

    def _start_cleaner(self, cmd, mode):
        self.cleaning = True
        self._clean_mode = mode
        self._cleaned, self._stripped, self._replaced, self._clean_summary = [], [], [], None
        self._stopped = False
        self.scan_t0 = time.time()
        self._append_log("\n" + "=" * 76 + "\nCommand: " + subprocess.list2cmdline(cmd) + "\n\n")
        self.status.set("Mass cleanup: searching for malicious files…" if mode == "plan" else "Mass cleanup: working…")
        self.start_btn.configure(state="disabled")
        self.clean_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self._bar_mode = None
        self._set_indeterminate("Starting…")
        threading.Thread(target=self._run_process, args=(cmd, "clean_done"), daemon=True).start()

    def _on_clean_done(self, code):
        mode, summary, stopped = self._clean_mode, self._clean_summary or {}, self._stopped
        self._finish_ui()
        self.progress.configure(value=0)
        self.progress_info.set("")
        if stopped:
            self.status.set("Mass cleanup stopped by the user.")
            return
        if not summary or code not in (0, 2):
            self.status.set("Mass cleanup finished with an error (code %s), see the log." % code)
            messagebox.showerror("Mass cleanup", "The cleanup finished with an error (code %s). See the log for details." % code)
            return
        if mode == "plan":
            n = summary.get("planned", 0)
            if n == 0:
                self.status.set("Mass cleanup: no known malicious files found.")
                extra = ("\n\nFiles with suspicious names but no signatures: %d. Check them manually (list in the log)."
                         % summary["suspects"]) if summary.get("suspects") else ""
                messagebox.showinfo("Mass cleanup", "No known malicious files found." + extra)
                return
            fam = ", ".join("%s: %d" % (k, v) for k, v in sorted(summary.get("families", {}).items()))
            action = "PERMANENTLY DELETED" if self.clean_permanent.get() else "moved to quarantine (can be restored)"
            text = ("Files to process: %d\n(%s)\n\nMalicious files will be %s.\n"
                    "In mixed .htaccess files only the malicious blocks are cut out.\n" % (n, fam, action))
            if summary.get("families", {}).get("core/replace"):
                text += ("Modified Joomla core files (%d) will be replaced with originals"
                         % summary["families"]["core/replace"]
                         + ("." if self.clean_permanent.get() else "; the previous versions will be kept in quarantine.") + "\n")
            if summary.get("extras"):
                text += "%d extra files found in core folders: they are NOT touched (list in the log).\n" % summary["extras"]
            if summary.get("suspects"):
                text += "\n%d more files with suspicious names but no signatures will NOT be touched, check them manually." % summary["suspects"]
            text += "\n\nContinue?"
            if messagebox.askyesno("Mass cleanup", text, icon="warning"):
                try:
                    self._start_cleaner(self._cleaner_command(True), "apply")
                except ValueError as exc:
                    messagebox.showerror("Mass cleanup", str(exc))
            else:
                self.status.set("Mass cleanup cancelled.")
            return
        text = "Deleted/moved: %d · .htaccess cleaned: %d" % (summary.get("removed", 0), summary.get("stripped", 0))
        if summary.get("replaced"):
            text += " · replaced with originals: %d" % summary["replaced"]
        if summary.get("failed"):
            text += " · errors: %d" % summary["failed"]
        q = summary.get("quarantine")
        self._finish_removal(self._cleaned, text, qdir=Path(q) if q else None, replaced=self._replaced)
        if summary.get("failed"):
            messagebox.showwarning("Mass cleanup", text + "\n\nNot all files could be processed, see the log for details.")
        else:
            messagebox.showinfo("Mass cleanup", text + "\n\nChange the passwords, find the cause of the compromise and rescan the site.")

    def stop_scan(self):
        if self.proc is not None:
            self._stopped = True
            self.status.set("Stopping the scan…")
            kill_tree(self.proc)

    def _close(self):
        if self.scanning or self.cleaning:
            if not messagebox.askyesno("Exit", "The scan or the cleanup is still running. Stop it and exit?"):
                return
            self._stopped = True
            kill_tree(self.proc)
        self._save_config()
        self.destroy()


if __name__ == "__main__":
    app = ScannerGUI()
    app.mainloop()
