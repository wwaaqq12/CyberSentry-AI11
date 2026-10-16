
import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from datetime import datetime

from entropy_analyzer import analyze_file


# ===== CyberEntropy-AI Professional Theme =====
BG = "#080D0C"
PANEL = "#101A17"
PANEL_ALT = "#14231D"
BORDER = "#263D33"
GREEN = "#36D995"
TEXT = "#F0F5F2"
MUTED = "#AABCB4"
AMBER = "#E7B75A"
RED = "#F06A70"


class CyberEntropyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CyberEntropy-AI | File Security Analyzer")
        self.root.geometry("1180x740")
        self.root.minsize(900, 600)
        self.root.configure(bg=BG)

        self.folder = None
        self.results = []

        self.configure_styles()
        self.build_header()
        self.build_dashboard()
        self.build_footer()

    def configure_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(
            "Treeview",
            background="#0B1411",
            foreground=TEXT,
            fieldbackground="#0B1411",
            rowheight=34,
            borderwidth=0,
            font=("Segoe UI", 10)
        )

        style.configure(
            "Treeview.Heading",
            background=PANEL_ALT,
            foreground=GREEN,
            relief="flat",
            font=("Segoe UI", 10, "bold"),
            padding=(10, 12)
        )

        style.map(
            "Treeview",
            background=[("selected", "#20563F")],
            foreground=[("selected", "#FFFFFF")]
        )

        style.configure(
            "Vertical.TScrollbar",
            background=PANEL_ALT,
            troughcolor=BG,
            bordercolor=BG,
            arrowcolor=GREEN
        )

    def make_panel(self, parent, bg=PANEL):
        return tk.Frame(
            parent,
            bg=bg,
            highlightbackground=BORDER,
            highlightthickness=1
        )

    def make_button(self, parent, text, command, primary=False):
        if primary:
            bg = GREEN
            fg = "#07130D"
            active_bg = "#65EAB0"
        else:
            bg = PANEL_ALT
            fg = TEXT
            active_bg = "#203B30"

        return tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg,
            fg=fg,
            activebackground=active_bg,
            activeforeground=fg,
            relief="flat",
            bd=0,
            padx=16,
            pady=11,
            cursor="hand2",
            font=("Segoe UI", 10, "bold")
        )

    def build_header(self):
        header = tk.Frame(self.root, bg="#070B0A", height=88)
        header.pack(fill="x")
        header.pack_propagate(False)

        tk.Label(
            header,
            text="⬡",
            fg=GREEN,
            bg="#070B0A",
            font=("Segoe UI Symbol", 38, "bold")
        ).pack(side="left", padx=(24, 13))

        title_box = tk.Frame(header, bg="#070B0A")
        title_box.pack(side="left", pady=15)

        tk.Label(
            title_box,
            text="CyberEntropy-AI",
            fg=TEXT,
            bg="#070B0A",
            font=("Segoe UI", 23, "bold")
        ).pack(anchor="w")

        tk.Label(
            title_box,
            text="FILE SECURITY ANALYZER",
            fg=GREEN,
            bg="#070B0A",
            font=("Segoe UI", 9, "bold")
        ).pack(anchor="w", pady=(2, 0))

        tk.Label(
            header,
            text="●  LOCAL ANALYSIS   |   INTEGRITY CHECKS",
            fg=MUTED,
            bg="#070B0A",
            font=("Segoe UI", 9, "bold")
        ).pack(side="right", padx=24)

        tk.Frame(self.root, bg=GREEN, height=2).pack(fill="x")

    def build_dashboard(self):
        body = tk.Frame(self.root, bg=BG)
        body.pack(fill="both", expand=True, padx=20, pady=18)

        # Overview panel
        overview = self.make_panel(body)
        overview.pack(fill="x", pady=(0, 14))

        intro = tk.Frame(overview, bg=PANEL)
        intro.pack(side="left", fill="y", padx=18, pady=18)

        tk.Label(
            intro,
            text="SECURITY DASHBOARD",
            fg=GREEN,
            bg=PANEL,
            font=("Segoe UI", 10, "bold")
        ).pack(anchor="w")

        tk.Label(
            intro,
            text="Analyze files. Review signals. Export results.",
            fg=TEXT,
            bg=PANEL,
            font=("Segoe UI", 13)
        ).pack(anchor="w", pady=(8, 0))

        tk.Label(
            intro,
            text="High entropy or extension mismatch does not prove malware.",
            fg=MUTED,
            bg=PANEL,
            font=("Segoe UI", 9)
        ).pack(anchor="w", pady=(9, 0))

        # Statistic cards
        stats = tk.Frame(overview, bg=PANEL)
        stats.pack(side="right", padx=12, pady=12)

        self.stat_vars = {}

        cards = [
            ("found", "FILES FOUND", GREEN),
            ("analyzed", "ANALYZED", GREEN),
            ("review", "REVIEW", AMBER)
        ]

        for key, label, color in cards:
            card = tk.Frame(
                stats,
                bg="#0C1512",
                highlightbackground=BORDER,
                highlightthickness=1,
                width=130,
                height=80
            )
            card.pack(side="left", padx=5)
            card.pack_propagate(False)

            tk.Label(
                card,
                text=label,
                fg=MUTED,
                bg="#0C1512",
                font=("Segoe UI", 8, "bold")
            ).pack(anchor="w", padx=11, pady=(10, 2))

            value = tk.StringVar(value="0")
            self.stat_vars[key] = value

            tk.Label(
                card,
                textvariable=value,
                fg=color,
                bg="#0C1512",
                font=("Segoe UI", 21, "bold")
            ).pack(anchor="w", padx=11)

        # Folder selection panel
        controls = self.make_panel(body)
        controls.pack(fill="x", pady=(0, 14))

        folder_box = tk.Frame(controls, bg=PANEL)
        folder_box.pack(
            side="left",
            fill="x",
            expand=True,
            padx=16,
            pady=13
        )

        tk.Label(
            folder_box,
            text="SELECTED FOLDER",
            fg=GREEN,
            bg=PANEL,
            font=("Segoe UI", 9, "bold")
        ).pack(anchor="w")

        self.folder_label = tk.Label(
            folder_box,
            text="No folder selected. Choose a folder to begin.",
            fg=TEXT,
            bg=PANEL,
            anchor="w",
            justify="left",
            wraplength=490,
            font=("Segoe UI", 10)
        )
        self.folder_label.pack(anchor="w", pady=(5, 0))

        actions = tk.Frame(controls, bg=PANEL)
        actions.pack(side="right", padx=10, pady=11)

        self.choose_button = self.make_button(
            actions, "Choose Folder", self.choose_folder
        )
        self.choose_button.pack(side="left", padx=4)

        self.scan_button = self.make_button(
            actions, "Start Scan", self.scan_folder, primary=True
        )
        self.scan_button.pack(side="left", padx=4)

        self.make_button(
            actions, "Export JSON", self.export_report
        ).pack(side="left", padx=4)

        # Status and progress
        progress_panel = self.make_panel(body)
        progress_panel.pack(fill="x", pady=(0, 14))

        progress_row = tk.Frame(progress_panel, bg=PANEL)
        progress_row.pack(fill="x", padx=16, pady=12)

        tk.Label(
            progress_row,
            text="◉",
            fg=GREEN,
            bg=PANEL,
            font=("Segoe UI", 17, "bold")
        ).pack(side="left", padx=(0, 11))

        self.status_var = tk.StringVar(
            value="READY  |  Select a folder to start."
        )

        tk.Label(
            progress_row,
            textvariable=self.status_var,
            fg=TEXT,
            bg=PANEL,
            font=("Segoe UI", 10, "bold")
        ).pack(side="left")

        self.progress = ttk.Progressbar(
            progress_row,
            mode="determinate",
            maximum=100,
            length=250
        )
        self.progress.pack(side="right", padx=(12, 0))

        # Results panel
        results_panel = self.make_panel(body)
        results_panel.pack(fill="both", expand=True)

        results_header = tk.Frame(results_panel, bg=PANEL)
        results_header.pack(fill="x", padx=14, pady=(12, 9))

        tk.Label(
            results_header,
            text="SCAN RESULTS",
            fg=GREEN,
            bg=PANEL,
            font=("Segoe UI", 11, "bold")
        ).pack(side="left")

        self.result_count = tk.Label(
            results_header,
            text="0 records",
            fg=MUTED,
            bg=PANEL,
            font=("Segoe UI", 9)
        )
        self.result_count.pack(side="right")

        table_frame = tk.Frame(results_panel, bg=PANEL)
        table_frame.pack(
            fill="both",
            expand=True,
            padx=12,
            pady=(0, 12)
        )

        columns = (
            "name",
            "status",
            "size",
            "entropy",
            "type",
            "mismatch"
        )

        self.table = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse"
        )

        headings = {
            "name": "FILE NAME",
            "status": "STATUS",
            "size": "SIZE (BYTES)",
            "entropy": "ENTROPY",
            "type": "DETECTED TYPE",
            "mismatch": "EXTENSION MISMATCH"
        }

        widths = {
            "name": 220,
            "status": 110,
            "size": 120,
            "entropy": 95,
            "type": 190,
            "mismatch": 170
        }

        for column in columns:
            self.table.heading(
                column,
                text=headings[column]
            )
            self.table.column(
                column,
                width=widths[column],
                minwidth=80,
                anchor="w" if column in ("name", "type", "status") else "center"
            )

        self.table.tag_configure(
            "normal",
            foreground=TEXT,
            background="#0B1411"
        )
        self.table.tag_configure(
            "review",
            foreground=AMBER,
            background="#19170F"
        )
        self.table.tag_configure(
            "error",
            foreground=RED,
            background="#1B1011"
        )

        scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.table.yview
        )

        self.table.configure(
            yscrollcommand=scrollbar.set
        )

        self.table.grid(
            row=0, column=0, sticky="nsew"
        )
        scrollbar.grid(
            row=0, column=1, sticky="ns"
        )

        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

    def build_footer(self):
        footer = tk.Frame(
            self.root,
            bg="#070B0A",
            height=32
        )
        footer.pack(fill="x", side="bottom")
        footer.pack_propagate(False)

        tk.Label(
            footer,
            text="● SYSTEM READY",
            fg=GREEN,
            bg="#070B0A",
            font=("Segoe UI", 8, "bold")
        ).pack(side="left", padx=20, pady=7)

        tk.Label(
            footer,
            text="CyberEntropy-AI  |  Local file analysis",
            fg=MUTED,
            bg="#070B0A",
            font=("Segoe UI", 8)
        ).pack(side="right", padx=20, pady=7)

    def choose_folder(self):
        selected = filedialog.askdirectory(
            title="Select a folder to analyze"
        )

        if not selected:
            return

        self.folder = Path(selected)
        self.folder_label.config(text=str(self.folder))
        self.status_var.set("FOLDER SELECTED  |  Press Start Scan.")
        self.progress["value"] = 0

    def scan_folder(self):
        if not self.folder or not self.folder.is_dir():
            messagebox.showinfo(
                "Choose Folder",
                "Choose a folder before starting the scan."
            )
            self.choose_folder()

            if not self.folder:
                return

        self.results = []

        for item in self.table.get_children():
            self.table.delete(item)

        self.status_var.set("SCANNING  |  Analyzing files locally...")
        self.progress["value"] = 0
        self.root.update_idletasks()

        try:
            paths = sorted(
                (
                    path for path in self.folder.iterdir()
                    if path.is_file()
                    and path.name != "cyberentropy_report.json"
                ),
                key=lambda path: path.name.lower()
            )
        except OSError as error:
            messagebox.showerror(
                "Folder Error",
                f"Could not read this folder:\n{error}"
            )
            return

        total = len(paths)

        for index, path in enumerate(paths, start=1):
            try:
                result = analyze_file(path)
            except Exception as error:
                result = {
                    "file_name": path.name,
                    "status": "Error",
                    "error": str(error)
                }

            self.results.append(result)

            status = str(result.get("status", ""))
            mismatch = result.get("extension_mismatch", "")

            needs_review = (
                status != "Analyzed"
                or mismatch is True
                or "High entropy" in str(
                    result.get("analysis_note", "")
                )
            )

            if status == "Error":
                tag = "error"
            elif needs_review:
                tag = "review"
            else:
                tag = "normal"

            self.table.insert(
                "",
                "end",
                values=(
                    result.get("file_name", ""),
                    status,
                    result.get("file_size_bytes", ""),
                    result.get("entropy_score", ""),
                    result.get("detected_type", ""),
                    mismatch
                ),
                tags=(tag,)
            )

            percentage = int(index * 100 / total) if total else 100
            self.progress["value"] = percentage
            self.status_var.set(
                f"SCANNING  |  {index} of {total} files"
            )
            self.root.update_idletasks()

        analyzed = sum(
            item.get("status") == "Analyzed"
            for item in self.results
        )

        review_count = sum(
            item.get("status") != "Analyzed"
            or item.get("extension_mismatch") is True
            or "High entropy" in str(
                item.get("analysis_note", "")
            )
            for item in self.results
        )

        self.stat_vars["found"].set(str(len(self.results)))
        self.stat_vars["analyzed"].set(str(analyzed))
        self.stat_vars["review"].set(str(review_count))

        self.result_count.config(
            text=f"{len(self.results)} records"
        )

        self.status_var.set(
            f"SCAN COMPLETE  |  {len(self.results)} files checked"
        )
        self.progress["value"] = 100

    def export_report(self):
        if not self.results:
            messagebox.showinfo(
                "No Results",
                "Choose a folder and run a scan first."
            )
            return

        output = filedialog.asksaveasfilename(
            title="Save analysis report",
            defaultextension=".json",
            initialfile="cyberentropy_report.json",
            filetypes=[("JSON files", "*.json")]
        )

        if not output:
            return

        report = {
            "tool": "CyberEntropy-AI",
            "generated_at": datetime.now().isoformat(
                timespec="seconds"
            ),
            "folder": str(self.folder) if self.folder else None,
            "total_files_found": len(self.results),
            "analyzed_files": sum(
                item.get("status") == "Analyzed"
                for item in self.results
            ),
            "results": self.results
        }

        try:
            Path(output).write_text(
                json.dumps(
                    report,
                    indent=4,
                    ensure_ascii=False
                ),
                encoding="utf-8"
            )

            messagebox.showinfo(
                "Report Saved",
                f"Report saved successfully:\n{output}"
            )

        except OSError as error:
            messagebox.showerror(
                "Save Error",
                str(error)
            )


if __name__ == "__main__":
    root = tk.Tk()
    app = CyberEntropyApp(root)
    root.mainloop()
