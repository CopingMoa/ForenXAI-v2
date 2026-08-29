import os
import threading

import tkinter as tk
from tkinter import messagebox

from tkinterdnd2 import DND_FILES

from services.pipeline_service import (
    run_forensic_pipeline
)


class ForensicTab:
    """
    Tab 1 — PCAP Forensic Analysis.

    Owns:
        - PCAP drop zone
        - dashboard metric cards
        - pipeline log

    The actual forensic processing is delegated to
    services/pipeline_service.py.
    """

    def __init__(
        self,
        notebook,
        root,
        model,
        case_output_dir,
        on_pipeline_complete
    ):

        self.root = root

        self.model = model

        # NEW:
        # Name of the selected model/dataset.
        #
        # MainWindow updates this whenever the user changes
        # the model selector.
        self.model_name = None

        self.case_output_dir = (
            case_output_dir
        )

        self.on_pipeline_complete = (
            on_pipeline_complete
        )

        self.selected_pcap = None

        # NEW:
        # Used by MainWindow to prevent model switching
        # while a forensic analysis is running.
        self.analysis_running = False

        self.frame = tk.Frame(
            notebook,
            bg="#1E1E2E"
        )

        notebook.add(
            self.frame,
            text="PCAP Forensic Analysis"
        )

        self._build_ui()

        self.write_log(
            "System initialized. Awaiting PCAP evidence..."
        )

    # ========================================================
    # UI CONSTRUCTION
    # ========================================================

    def _build_ui(self):

        top_frame = tk.Frame(
            self.frame,
            bg="#1E1E2E"
        )

        top_frame.pack(
            fill="x",
            pady=10
        )

        self._build_input_panel(
            top_frame
        )

        self._build_dashboard(
            top_frame
        )

        self._build_log_console()

    def _build_input_panel(
        self,
        top_frame
    ):

        input_frame = tk.Frame(
            top_frame,
            bg="#27293D",
            highlightbackground="#374151",
            highlightthickness=1
        )

        input_frame.pack(
            side=tk.LEFT,
            fill="both",
            expand=True,
            padx=(0, 10)
        )

        tk.Label(
            input_frame,
            text="ForenXAI Forensic Engine",
            font=("Segoe UI", 16, "bold"),
            bg="#27293D",
            fg="#F8FAFC"
        ).pack(
            pady=(15, 2)
        )

        tk.Label(
            input_frame,
            text=(
                "PCAP Forensic Analysis: Integrity Verification, "
                "ML Detection, Explainable AI, and Human Review"
            ),
            font=("Segoe UI", 9),
            bg="#27293D",
            fg="#9CA3AF"
        ).pack(
            pady=(0, 10)
        )

        drop_area = tk.Label(
            input_frame,
            text="☁️ Drag & Drop PCAP / PCAPNG",
            bg="#1E1E2E",
            fg="#9CA3AF",
            font=("Segoe UI", 11),
            width=35,
            height=4,
            highlightbackground="#4B5563",
            highlightthickness=1
        )

        drop_area.pack(
            pady=10,
            padx=20
        )

        drop_area.drop_target_register(
            DND_FILES
        )

        drop_area.dnd_bind(
            "<<Drop>>",
            self.pcap_drop_file
        )

        self.lbl_pcap_file = tk.Label(
            input_frame,
            text="No PCAP selected",
            font=("Segoe UI", 10),
            bg="#27293D",
            fg="#6B7280"
        )

        self.lbl_pcap_file.pack(
            pady=(0, 10)
        )

        self.btn_analyze = tk.Button(
            input_frame,
            text="Analyze PCAP",
            font=("Segoe UI", 10, "bold"),
            bg="#3B82F6",
            fg="white",
            relief="flat",
            padx=20,
            pady=8,
            command=self.analyze_trigger
        )

        self.btn_analyze.pack(
            pady=(5, 15)
        )

    # ========================================================
    # DASHBOARD
    # ========================================================

    def _build_dashboard(
        self,
        top_frame
    ):

        metrics_frame = tk.Frame(
            top_frame,
            bg="#1E1E2E"
        )

        metrics_frame.pack(
            side=tk.RIGHT,
            fill="both",
            expand=True
        )

        (
            self.card_total,
            self.lbl_val_total
        ) = self._create_metric_card(
            metrics_frame,
            "TOTAL FLOWS",
            color="#F8FAFC"
        )

        self.card_total.grid(
            row=0,
            column=0,
            sticky="nsew",
            padx=5,
            pady=5
        )

        (
            self.card_benign,
            self.lbl_val_benign
        ) = self._create_metric_card(
            metrics_frame,
            "BENIGN AI FINDINGS",
            color="#10B981"
        )

        self.card_benign.grid(
            row=0,
            column=1,
            sticky="nsew",
            padx=5,
            pady=5
        )

        (
            self.card_threat,
            self.lbl_val_threat
        ) = self._create_metric_card(
            metrics_frame,
            "THREAT AI FINDINGS",
            color="#9CA3AF"
        )

        self.card_threat.grid(
            row=1,
            column=0,
            columnspan=2,
            sticky="nsew",
            padx=5,
            pady=5
        )

        metrics_frame.grid_columnconfigure(
            0,
            weight=1
        )

        metrics_frame.grid_columnconfigure(
            1,
            weight=1
        )

    @staticmethod
    def _create_metric_card(
        parent,
        title,
        value="0",
        color="#9CA3AF"
    ):

        card = tk.Frame(
            parent,
            bg="#27293D",
            highlightbackground="#374151",
            highlightthickness=1
        )

        tk.Label(
            card,
            text=title,
            font=("Segoe UI", 10),
            bg="#27293D",
            fg="#9CA3AF"
        ).pack(
            pady=(15, 5)
        )

        val = tk.Label(
            card,
            text=value,
            font=("Segoe UI", 24, "bold"),
            bg="#27293D",
            fg=color
        )

        val.pack(
            pady=(0, 15)
        )

        return card, val

    # ========================================================
    # LOG CONSOLE
    # ========================================================

    def _build_log_console(self):

        terminal_frame = tk.Frame(
            self.frame,
            bg="#0F111A",
            highlightbackground="#374151",
            highlightthickness=1
        )

        terminal_frame.pack(
            fill="both",
            expand=True,
            pady=(10, 0)
        )

        self.log_console = tk.Text(
            terminal_frame,
            bg="#0F111A",
            fg="#A6ACCD",
            font=("Consolas", 10),
            state=tk.DISABLED,
            padx=15,
            pady=15,
            relief="flat"
        )

        self.log_console.pack(
            fill="both",
            expand=True
        )

        self.log_console.tag_config(
            "info",
            foreground="#82AAFF"
        )

        self.log_console.tag_config(
            "success",
            foreground="#C3E88D"
        )

        self.log_console.tag_config(
            "error",
            foreground="#F07178"
        )

    # ========================================================
    # LOGGING / DASHBOARD
    # ========================================================

    def write_log(
        self,
        message,
        tag=None
    ):

        def append():

            self.log_console.config(
                state=tk.NORMAL
            )

            if tag:

                self.log_console.insert(
                    tk.END,
                    message + "\n",
                    tag
                )

            else:

                self.log_console.insert(
                    tk.END,
                    message + "\n"
                )

            self.log_console.see(
                tk.END
            )

            self.log_console.config(
                state=tk.DISABLED
            )

        self.root.after(
            0,
            append
        )

    def update_dashboard_metrics(
        self,
        total,
        benign,
        threat
    ):

        def update():

            self.lbl_val_total.config(
                text=f"{total:,}"
            )

            self.lbl_val_benign.config(
                text=f"{benign:,}"
            )

            self.lbl_val_threat.config(
                text=f"{threat:,}"
            )

            if threat > 0:

                self.card_threat.config(
                    bg="#3F1D24",
                    highlightbackground="#EF4444"
                )

                self.lbl_val_threat.config(
                    bg="#3F1D24",
                    fg="#EF4444"
                )

            else:

                self.card_threat.config(
                    bg="#27293D",
                    highlightbackground="#374151"
                )

                self.lbl_val_threat.config(
                    bg="#27293D",
                    fg="#9CA3AF"
                )

        self.root.after(
            0,
            update
        )

    # ========================================================
    # PCAP DROP
    # ========================================================

    def pcap_drop_file(
        self,
        event
    ):

        raw_path = (
            event.data
            .strip("{}")
            .strip('"')
        )

        if raw_path.lower().endswith(
            (".pcap", ".pcapng")
        ):

            if os.path.getsize(
                raw_path
            ) == 0:

                self.selected_pcap = None

                self.lbl_pcap_file.config(
                    text="Empty file. This PCAP contains no data.",
                    fg="#EF4444"
                )

                self.write_log(
                    "[!] Rejected empty PCAP: "
                    + os.path.basename(
                        raw_path
                    ),
                    "error"
                )

                return

            self.selected_pcap = (
                raw_path
            )

            self.lbl_pcap_file.config(
                text=(
                    "📁 "
                    + os.path.basename(
                        self.selected_pcap
                    )
                ),
                fg="#10B981"
            )

            self.write_log(
                "[+] Evidence selected: "
                + os.path.basename(
                    self.selected_pcap
                ),
                "success"
            )

        else:

            self.selected_pcap = None

            self.lbl_pcap_file.config(
                text=(
                    "Invalid evidence. "
                    "Drop a .pcap or .pcapng file."
                ),
                fg="#EF4444"
            )

    # ========================================================
    # ANALYSIS TRIGGER
    # ========================================================

    def analyze_trigger(self):

        if not self.selected_pcap:

            messagebox.showwarning(
                "Warning",
                "Please upload a PCAP or PCAPNG file first."
            )

            return

        if self.model is None:

            messagebox.showerror(
                "Error",
                "Machine learning model is not loaded."
            )

            return

        if not self.model_name:

            messagebox.showerror(
                "Error",
                "No ML dataset/model has been selected."
            )

            return

        if self.analysis_running:

            return

        # ----------------------------------------------------
        # Mark pipeline as running.
        # ----------------------------------------------------

        self.analysis_running = True

        self.btn_analyze.config(
            state=tk.DISABLED,
            text="Analyzing Evidence...",
            bg="#4B5563"
        )

        self.write_log(
            "",
            None
        )

        self.write_log(
            "[+] Starting forensic analysis...",
            "success"
        )

        self.write_log(
            f"[+] Selected ML dataset: "
            f"{self.model_name}",
            "info"
        )

        self.write_log(
            "[+] Flow extraction engine: "
            "CICFlowMeter v4",
            "info"
        )

        threading.Thread(
            target=self._pipeline_worker,
            args=(self.selected_pcap,),
            daemon=True
        ).start()

    # ========================================================
    # PIPELINE EXECUTION
    # ========================================================

    def _pipeline_worker(
        self,
        pcap_path
    ):

        try:

            current_case, shap_results = (
                run_forensic_pipeline(
                    pcap_path=pcap_path,
                    model=self.model,
                    model_name=self.model_name,
                    case_output_dir=self.case_output_dir,
                    log_fn=self.write_log,
                    on_metrics_ready=self.update_dashboard_metrics
                )
            )

            self.root.after(
                0,
                lambda: self.on_pipeline_complete(
                    current_case,
                    shap_results
                )
            )

        except Exception as err:

            self.write_log(
                "\n[!] FORENSIC PIPELINE FAILED: "
                + str(err),
                "error"
            )

            self.root.after(
                0,
                lambda: messagebox.showerror(
                    "Forensic Pipeline Error",
                    str(err)
                )
            )

        finally:

            self.analysis_running = False

            self.root.after(
                0,
                lambda: self.btn_analyze.config(
                    state=tk.NORMAL,
                    text="Analyze PCAP",
                    bg="#3B82F6"
                )
            )