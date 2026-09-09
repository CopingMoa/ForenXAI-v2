import json
import os
import threading
import tkinter as tk

from tkinter import (
    filedialog,
    messagebox,
    ttk
)

from tkinterdnd2 import DND_FILES

from services.pipeline_service import (
    run_forensic_pipeline
)

from services.model_service import (
    get_family_mapping
)


class ForensicTab:
    """
    Tab 1 — PCAP Forensic Analysis.

    UI responsibilities:

        - PCAP upload
        - PCAP drag & drop
        - 2 fixed dashboard cards
        - 5 dynamic threat cards
        - AI findings table
        - forensic pipeline console

    The actual forensic processing remains inside:

        services/pipeline_service.py

    The UI does NOT perform ML inference itself.

    Dynamic threat cards are generated from the
    selected model's frozen family_mapping.
    """

    # ========================================================
    # FIXED CARD COUNT
    # ========================================================

    FIXED_CARD_COUNT = 2

    DYNAMIC_CARD_COUNT = 4


    # ========================================================
    # COLORS
    # ========================================================

    BG_MAIN = "#1E1E2E"
    BG_PANEL = "#27293D"
    BG_TERMINAL = "#0F111A"
    BORDER = "#374151"

    TEXT_PRIMARY = "#F8FAFC"
    TEXT_SECONDARY = "#9CA3AF"
    TEXT_MUTED = "#6B7280"

    BLUE = "#3B82F6"
    GREEN = "#10B981"
    RED = "#EF4444"
    ORANGE = "#F97316"


    # ========================================================
    # INITIALIZATION
    # ========================================================

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

        self.model_name = None

        self.case_output_dir = (
            case_output_dir
        )

        self.on_pipeline_complete = (
            on_pipeline_complete
        )

        self.selected_pcap = None

        self.analysis_running = False

        # Progress/loading state
        #
        # IMPORTANT: the forensic pipeline runs in a background thread.
        # Tkinter widgets/variables must only be updated by the GUI thread.
        # The queue is created here (not inside the optional toolbar builder)
        # because MainWindow owns the visible toolbar in the current layout.
        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress_status = tk.StringVar(value="Ready")
        self._progress_indeterminate = False
        self._progress_job = None
        self._progress_generation = 0
        self._progress_target = 0.0
        self._gui_progress_job = None
        self._gui_progress_value = 0.0
        self._analysis_completion_pending = False

        # Current table rows
        self.findings_rows = []

        # Current flow-detail data.
        # The selected threat row stores the corresponding
        # CICFlowMeter CSV flow index here.
        self.selected_flow_index = None
        self.current_flow_details = []

        # Current dynamic threat data
        self.dynamic_threats = []

        # ----------------------------------------------------
        # Main tab frame
        # ----------------------------------------------------

        self.frame = tk.Frame(
            notebook,
            bg=self.BG_MAIN
        )

        notebook.add(
            self.frame,
            text="PCAP Forensic Analysis"
        )

        self._build_ui()



    # ========================================================
    # BUILD COMPLETE UI
    # ========================================================

    def _build_ui(self):

        # ----------------------------------------------------
        # SCROLLABLE FORENSIC PAGE
        # ----------------------------------------------------
        # Progress/loading controls are built and hosted by MainWindow
        # on the same horizontal line as the custom Notebook tabs.
        # ----------------------------------------------------
        #
        # CHANGED:
        # The previous version relied on fixed heights for the
        # dashboard/table/log. On smaller windows or when the
        # application layout changes, the log could fall below
        # the visible area.
        #
        # The entire PCAP Forensic Analysis page is now placed
        # inside a vertical Canvas scrollbar. Nothing is removed;
        # the user can simply scroll down to reach the findings
        # table and forensic system log.
        # ----------------------------------------------------

        self.scroll_canvas = tk.Canvas(
            self.frame,
            bg=self.BG_MAIN,
            highlightthickness=0,
            borderwidth=0
        )

        self.scrollbar = ttk.Scrollbar(
            self.frame,
            orient="vertical",
            command=self.scroll_canvas.yview
        )

        self.scroll_canvas.configure(
            yscrollcommand=self.scrollbar.set
        )

        self.scrollbar.pack(
            side=tk.RIGHT,
            fill=tk.Y
        )

        self.scroll_canvas.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True
        )

        self.scrollable_frame = tk.Frame(
            self.scroll_canvas,
            bg=self.BG_MAIN
        )

        self.scroll_window = self.scroll_canvas.create_window(
            (0, 0),
            window=self.scrollable_frame,
            anchor="nw"
        )

        # Keep the content width equal to the visible canvas width.
        self.scrollable_frame.bind(
            "<Configure>",
            self._update_scroll_region
        )

        self.scroll_canvas.bind(
            "<Configure>",
            self._resize_scrollable_frame
        )

        # Mouse-wheel scrolling.
        self.scroll_canvas.bind_all(
            "<MouseWheel>",
            self._on_mousewheel
        )

        # ----------------------------------------------------
        # TOP AREA
        # ----------------------------------------------------

        top_frame = tk.Frame(
            self.scrollable_frame,
            bg=self.BG_MAIN
        )

        top_frame.pack(
            fill="x",
            padx=10,
            pady=(8, 5)
        )

        top_frame.configure(
            height=390
        )

        top_frame.pack_propagate(False)

        top_frame.grid_columnconfigure(
            0,
            weight=5
        )

        top_frame.grid_columnconfigure(
            1,
            weight=6
        )

        self._build_input_panel(
            top_frame
        )

        self._build_dashboard(
            top_frame
        )

        # ----------------------------------------------------
        # FINDINGS TABLE
        # ----------------------------------------------------

        self._build_findings_table()

        # ----------------------------------------------------
        # SELECTED FLOW DETAILS
        # ----------------------------------------------------

        self._build_flow_details_table()

        # The forensic system-log console is intentionally not part
        # of the current UI. Progress/status is shown in the compact
        # toolbar above the Notebook.

        # Make sure the initial content size is registered.
        self.root.after(
            0,
            self._update_scroll_region
        )


    def _update_scroll_region(self, event=None):
        """Update the Canvas scrollable area to match its content."""
        self.scroll_canvas.configure(
            scrollregion=self.scroll_canvas.bbox("all")
        )


    def _resize_scrollable_frame(self, event):
        """Keep the inner page as wide as the visible Canvas."""
        self.scroll_canvas.itemconfigure(
            self.scroll_window,
            width=event.width
        )


    def _on_mousewheel(self, event):
        """Scroll the forensic page vertically with the mouse wheel."""
        self.scroll_canvas.yview_scroll(
            int(-1 * (event.delta / 120)),
            "units"
        )


    # ========================================================
    # INPUT PANEL
    # ========================================================

    def _build_input_panel(
        self,
        parent
    ):

        input_frame = tk.Frame(
            parent,
            bg=self.BG_PANEL,
            highlightbackground=self.BORDER,
            highlightthickness=1
        )

        input_frame.grid(
            row=0,
            column=0,
            sticky="nsew",
            padx=(0, 5)
        )

        # ----------------------------------------------------
        # Title
        # ----------------------------------------------------

        tk.Label(
            input_frame,
            text="ForenXAI Forensic Engine",
            font=("Segoe UI", 16, "bold"),
            bg=self.BG_PANEL,
            fg=self.TEXT_PRIMARY
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
            bg=self.BG_PANEL,
            fg=self.TEXT_SECONDARY,
            wraplength=480,
            justify="center"
        ).pack(
            pady=(0, 10),
            padx=10
        )

        # ----------------------------------------------------
        # Upload / Drop area
        # ----------------------------------------------------

        self.upload_area = tk.Label(
            input_frame,
            text="☁  Upload or Drop PCAP / PCAPNG",
            bg=self.BG_MAIN,
            fg=self.TEXT_SECONDARY,
            font=("Segoe UI", 11),
            width=38,
            height=4,
            cursor="hand2",
            highlightbackground="#4B5563",
            highlightthickness=1
        )

        self.upload_area.pack(
            pady=8,
            padx=20
        )

        # Click = file picker

        self.upload_area.bind(
            "<Button-1>",
            self.open_file_picker
        )

        # Drag and drop

        self.upload_area.drop_target_register(
            DND_FILES
        )

        self.upload_area.dnd_bind(
            "<<Drop>>",
            self.pcap_drop_file
        )

        # ----------------------------------------------------
        # Selected PCAP label
        # ----------------------------------------------------

        self.lbl_pcap_file = tk.Label(
            input_frame,
            text="No PCAP selected",
            font=("Segoe UI", 9),
            bg=self.BG_PANEL,
            fg=self.TEXT_MUTED
        )

        self.lbl_pcap_file.pack(
            pady=(0, 8)
        )

        # ----------------------------------------------------
        # Analyze button
        # ----------------------------------------------------

        self.btn_analyze = tk.Button(
            input_frame,
            text="Analyze PCAP",
            font=("Segoe UI", 10, "bold"),
            bg=self.BLUE,
            fg="white",
            activebackground=self.BLUE,
            activeforeground="white",
            relief="flat",
            padx=25,
            pady=8,
            cursor="hand2",
            command=self.analyze_trigger
        )

        self.btn_analyze.pack(
            pady=(3, 15)
        )


    # ========================================================
    # FILE PICKER
    # ========================================================

    def open_file_picker(
        self,
        event=None
    ):

        selected_file = (
            filedialog.askopenfilename(
                title="Select PCAP / PCAPNG Evidence",
                filetypes=[
                    (
                        "PCAP files",
                        "*.pcap *.pcapng"
                    ),
                    (
                        "PCAP files (*.pcap)",
                        "*.pcap"
                    ),
                    (
                        "PCAPNG files (*.pcapng)",
                        "*.pcapng"
                    ),
                    (
                        "All files",
                        "*.*"
                    )
                ]
            )
        )

        if selected_file:

            self._set_selected_pcap(
                selected_file
            )


    # ========================================================
    # SET SELECTED PCAP
    # ========================================================

    def _set_selected_pcap(
        self,
        raw_path
    ):

        raw_path = (
            raw_path
            .strip("{}")
            .strip('"')
        )

        # ----------------------------------------------------
        # Extension validation
        # ----------------------------------------------------

        if not raw_path.lower().endswith(
            (".pcap", ".pcapng")
        ):

            self.selected_pcap = None

            self.lbl_pcap_file.config(
                text=(
                    "Invalid evidence. "
                    "Select a .pcap or .pcapng file."
                ),
                fg=self.RED
            )

            self.write_log(
                "[!] Invalid evidence format.",
                "error"
            )

            return

        # ----------------------------------------------------
        # File existence
        # ----------------------------------------------------

        if not os.path.isfile(
            raw_path
        ):

            self.selected_pcap = None

            self.lbl_pcap_file.config(
                text="Selected file does not exist.",
                fg=self.RED
            )

            self.write_log(
                "[!] Selected PCAP file does not exist.",
                "error"
            )

            return

        # ----------------------------------------------------
        # Empty file
        # ----------------------------------------------------

        if os.path.getsize(
            raw_path
        ) == 0:

            self.selected_pcap = None

            self.lbl_pcap_file.config(
                text=(
                    "Empty file. "
                    "This PCAP contains no data."
                ),
                fg=self.RED
            )

            self.write_log(
                "[!] Rejected empty PCAP: "
                + os.path.basename(
                    raw_path
                ),
                "error"
            )

            return

        # ----------------------------------------------------
        # Accept
        # ----------------------------------------------------

        self.selected_pcap = raw_path

        self.lbl_pcap_file.config(
            text=(
                "📁 "
                + os.path.basename(
                    raw_path
                )
            ),
            fg=self.GREEN
        )

        if not self.analysis_running:
            self._reset_progress("Ready")

        self.write_log(
            "[+] Evidence selected: "
            + os.path.basename(
                raw_path
            ),
            "success"
        )


    # ========================================================
    # DRAG & DROP
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

        self._set_selected_pcap(
            raw_path
        )


    # ========================================================
    # DASHBOARD
    # ========================================================

    def _build_dashboard(
        self,
        parent
    ):

        metrics_frame = tk.Frame(
            parent,
            bg=self.BG_MAIN
        )

        metrics_frame.grid(
            row=0,
            column=1,
            sticky="nsew",
            padx=(5, 0)
        )

        # Two equal columns.
        for column in range(2):
            metrics_frame.grid_columnconfigure(
                column,
                weight=1
            )

        # Four dashboard rows:
        #   Row 0 = Total Network Flows
        #   Row 1 = Benign / Threat
        #   Row 2 = Top Threat #1 / #2
        #   Row 3 = Top Threat #3 / #4
        for row in range(4):
            metrics_frame.grid_rowconfigure(
                row,
                weight=1
            )

        # ----------------------------------------------------
        # ROW 0 — TOTAL NETWORK FLOWS
        # Full width (2 columns)
        # ----------------------------------------------------

        (
            self.card_total,
            self.lbl_val_total
        ) = self._create_metric_card(
            metrics_frame,
            "TOTAL NETWORK FLOWS",
            color=self.TEXT_PRIMARY
        )

        self.card_total.grid(
            row=0,
            column=0,
            columnspan=2,
            sticky="nsew",
            padx=3,
            pady=3
        )

        # ----------------------------------------------------
        # ROW 1 — BENIGN / THREAT
        # ----------------------------------------------------

        (
            self.card_benign,
            self.lbl_val_benign
        ) = self._create_metric_card(
            metrics_frame,
            "BENIGN NETWORK FLOWS",
            color=self.GREEN
        )

        self.card_benign.grid(
            row=1,
            column=0,
            sticky="nsew",
            padx=3,
            pady=3
        )

        (
            self.card_threat,
            self.lbl_val_threat
        ) = self._create_metric_card(
            metrics_frame,
            "THREAT NETWORK FLOWS",
            color=self.RED
        )

        self.card_threat.grid(
            row=1,
            column=1,
            sticky="nsew",
            padx=3,
            pady=3
        )

        # ----------------------------------------------------
        # ROWS 2–3 — FOUR DYNAMIC TOP-THREAT CARDS
        # ----------------------------------------------------

        self.dynamic_cards = []

        dynamic_positions = [
            (2, 0),  # Top Threat #1
            (2, 1),  # Top Threat #2
            (3, 0),  # Top Threat #3
            (3, 1),  # Top Threat #4
        ]

        for index, (
            row,
            column
        ) in enumerate(
            dynamic_positions,
            start=1
        ):

            card, title_label, value_label = (
                self._create_dynamic_card(
                    metrics_frame,
                    f"TOP THREAT #{index}"
                )
            )

            card.grid(
                row=row,
                column=column,
                sticky="nsew",
                padx=3,
                pady=3
            )

            self.dynamic_cards.append({
                "card": card,
                "title": title_label,
                "value": value_label
            })

        # ----------------------------------------------------
        # Initialize dynamic cards
        # ----------------------------------------------------

        self._reset_dynamic_cards()


    # ========================================================
    # PROGRESS / CLEAR TOOLBAR
    # ========================================================

    def _start_gui_progress_animation(self):
        """
        Start a GUI-only progress animation in fixed 5% steps.

        The visible progress is always:
            0, 5, 10, 15, ... 95

        100% is reserved for the actual successful completion event.
        """
        self._cancel_gui_progress_animation()

        self._gui_progress_value = 0
        self.progress_var.set(0)
        self.lbl_progress_percent.config(text="0%")
        self.progress_status.set("Starting analysis...")

        self._gui_progress_job = self.root.after(
            300,
            self._advance_gui_progress
        )

    def _advance_gui_progress(self):
        """Advance visible progress by exactly 5% while the worker runs."""
        if not self.analysis_running:
            self._gui_progress_job = None
            return

        current = int(self._gui_progress_value)
        new_value = min(95, current + 5)

        self._gui_progress_value = new_value
        self.progress_var.set(new_value)
        self.lbl_progress_percent.config(
            text=f"{new_value}%"
        )

        if new_value < 20:
            status = "Preparing evidence..."
        elif new_value < 45:
            status = "Extracting network flows..."
        elif new_value < 65:
            status = "Running ML inference..."
        elif new_value < 90:
            status = "Generating SHAP explanations..."
        else:
            status = "Finalizing analysis..."

        self.progress_status.set(status)

        # Keep moving in exact 5% increments until the real pipeline
        # completion event tells us to finish at 100%.
        if new_value < 95:
            self._gui_progress_job = self.root.after(
                300,
                self._advance_gui_progress
            )
        else:
            self._gui_progress_job = self.root.after(
                300,
                self._advance_gui_progress
            )

    def _cancel_gui_progress_animation(self):
        """Cancel the running GUI progress timer, if any."""
        job = getattr(self, "_gui_progress_job", None)
        if job is not None:
            try:
                self.root.after_cancel(job)
            except Exception:
                pass
        self._gui_progress_job = None

    def _finish_gui_progress_success(self):
        """
        Finish the progress in exact 5% steps.

        If the worker finishes while the GUI is at, for example, 65%,
        the GUI displays:
            70, 75, 80, 85, 90, 95, 100

        "Ready" is displayed only after 100% is reached.
        """
        self._cancel_gui_progress_animation()

        start = int(getattr(self, "_gui_progress_value", 0))
        start = max(0, min(100, start))

        # Normalize to a 5% boundary.
        start = (start // 5) * 5
        self._gui_progress_value = start
        self.progress_var.set(start)
        self.lbl_progress_percent.config(text=f"{start}%")
        self.progress_status.set("Finalizing analysis...")

        def finish_step():
            current = int(self._gui_progress_value)

            if current >= 100:
                self.progress_var.set(100)
                self.lbl_progress_percent.config(text="100%")
                self.progress_status.set("Ready")
                self._gui_progress_job = None
                self._analysis_completion_pending = False
                self.analysis_running = False
                self._enable_analysis_buttons()
                return

            new_value = min(100, current + 5)

            self._gui_progress_value = new_value
            self.progress_var.set(new_value)
            self.lbl_progress_percent.config(
                text=f"{new_value}%"
            )

            if new_value >= 100:
                self.progress_status.set("Ready")
                self._gui_progress_job = None
                self._analysis_completion_pending = False
                self.analysis_running = False
                self._enable_analysis_buttons()
                return

            self.progress_status.set("Finalizing analysis...")

            self._gui_progress_job = self.root.after(
                300,
                finish_step
            )

        self._gui_progress_job = self.root.after(
            300,
            finish_step
        )

    def _finish_gui_progress_error(self):
        """Stop the GUI progress animation after a failed analysis."""
        self._cancel_gui_progress_animation()
        self.progress_status.set("Failed")
        self._analysis_completion_pending = False
        self._enable_analysis_buttons()

    def _enable_analysis_buttons(self):
        """Restore Analyze/Clear buttons after analysis ends."""
        if hasattr(self, "btn_analyze"):
            self.btn_analyze.config(
                state=tk.NORMAL,
                text="Analyze PCAP",
                bg=self.BLUE
            )

        if hasattr(self, "btn_clear"):
            self.btn_clear.config(
                state=tk.NORMAL,
                bg="#9CA3AF"
            )

    def _set_progress(self, value, status=None, indeterminate=False):
        """
        Thread-safe progress/status notification.

        The percentage itself is controlled by the GUI animation.  This
        method only updates the human-readable status on the GUI thread.
        That prevents the background pipeline from fighting the animation.
        """
        if status is None:
            return

        def update_status():
            if not self.analysis_running:
                return

            # Never show Ready before the successful 100% completion step.
            if str(status).strip().lower() == "ready":
                return

            self.progress_status.set(str(status))

        self.root.after(0, update_status)

    def _reset_progress(self, status="Ready"):
        """Reset the visible progress indicator on the GUI thread."""
        self.root.after(
            0,
            lambda: self._apply_progress_reset(status)
        )

    def _apply_progress_reset(self, status="Ready"):
        """Actually reset progress widgets on the GUI thread."""
        self._cancel_gui_progress_animation()

        self._gui_progress_value = 0.0
        self.progress_var.set(0.0)
        self.lbl_progress_percent.config(text="0%")
        self.progress_status.set(status)
        self._analysis_completion_pending = False

    # ========================================================
    # CLEAR ANALYSIS
    # ========================================================

    def clear_analysis(
        self
    ):
        """Clear the current evidence and all displayed analysis results."""

        if self.analysis_running:
            messagebox.showwarning(
                "Analysis Running",
                "Please wait for the current analysis to finish before clearing."
            )
            return

        self.selected_pcap = None

        if hasattr(self, "lbl_pcap_file"):
            self.lbl_pcap_file.config(
                text="No PCAP selected",
                fg=self.TEXT_MUTED
            )

        self.current_case = None
        self.findings_rows = []
        self.dynamic_threats = []
        self.selected_flow_index = None
        self.current_flow_details = []

        self._clear_findings_table()
        self._clear_flow_details()
        self.reset_dashboard()
        self._reset_progress("Cleared")

        if hasattr(self, "btn_analyze"):
            self.btn_analyze.config(
                state=tk.NORMAL,
                text="Analyze PCAP",
                bg=self.BLUE
            )

        self.write_log(
            "[+] Ready for new PCAP evidence.",
            "success"
        )

    # ========================================================
    # FIXED METRIC CARD
    # ========================================================

    def _create_metric_card(
        self,
        parent,
        title,
        value="0",
        color="#9CA3AF"
    ):

        card = tk.Frame(
            parent,
            bg=self.BG_PANEL,
            highlightbackground=self.BORDER,
            highlightthickness=1
        )

        tk.Label(
            card,
            text=title,
            font=("Segoe UI", 9, "bold"),
            bg=self.BG_PANEL,
            fg=self.TEXT_SECONDARY,
            wraplength=180,
            justify="center"
        ).pack(
            pady=(8, 2),
            padx=5
        )

        value_label = tk.Label(
            card,
            text=value,
            font=("Segoe UI", 20, "bold"),
            bg=self.BG_PANEL,
            fg=color
        )

        value_label.pack(
            pady=(0, 8)
        )

        return card, value_label


    # ========================================================
    # DYNAMIC THREAT CARD
    # ========================================================

    def _create_dynamic_card(
        self,
        parent,
        title
    ):

        card = tk.Frame(
            parent,
            bg=self.BG_PANEL,
            highlightbackground=self.BORDER,
            highlightthickness=1
        )

        title_label = tk.Label(
            card,
            text=title,
            font=("Segoe UI", 8, "bold"),
            bg=self.BG_PANEL,
            fg=self.TEXT_SECONDARY,
            wraplength=180,
            justify="center"
        )

        title_label.pack(
            pady=(8, 2),
            padx=5
        )

        value_label = tk.Label(
            card,
            text="0",
            font=("Segoe UI", 20, "bold"),
            bg=self.BG_PANEL,
            fg=self.ORANGE
        )

        value_label.pack(
            pady=(0, 8)
        )

        return (
            card,
            title_label,
            value_label
        )


    # ========================================================
    # RESET DYNAMIC CARDS
    # ========================================================

    def _reset_dynamic_cards(
        self
    ):

        for index, card_info in enumerate(
            self.dynamic_cards,
            start=1
        ):

            card_info["title"].config(
                text=f"TOP THREAT #{index}",
                bg=self.BG_PANEL,
                fg=self.TEXT_SECONDARY
            )

            card_info["value"].config(
                text="0",
                bg=self.BG_PANEL,
                fg=self.TEXT_MUTED
            )

            card_info["card"].config(
                bg=self.BG_PANEL,
                highlightbackground=self.BORDER
            )


    # ========================================================
    # UPDATE DASHBOARD
    # ========================================================

    def update_dashboard_metrics(
        self,
        total,
        benign,
        threat,
        category_counts=None
    ):
        """
        Update the dashboard.

        Existing pipeline compatibility:

            update_dashboard_metrics(
                total,
                benign,
                threat
            )

        The UI then separately calculates the actual
        multiclass category counts from the prediction
        artifact.

        category_counts is optional.
        """

        if category_counts is None:

            category_counts = {}

        def update():

            # ------------------------------------------------
            # Fixed cards
            # ------------------------------------------------

            self.lbl_val_total.config(
                text=f"{total:,}"
            )

            self.lbl_val_benign.config(
                text=f"{benign:,}"
            )

            self.lbl_val_threat.config(
                text=f"{threat:,}"
            )

            # Highlight the fixed threat card when threats exist.
            if threat > 0:

                self.card_threat.config(
                    bg="#3F1D24",
                    highlightbackground=self.RED
                )

                self.lbl_val_threat.config(
                    bg="#3F1D24",
                    fg=self.RED
                )

            else:

                self.card_threat.config(
                    bg=self.BG_PANEL,
                    highlightbackground=self.BORDER
                )

                self.lbl_val_threat.config(
                    bg=self.BG_PANEL,
                    fg=self.TEXT_MUTED
                )

            # ------------------------------------------------
            # Dynamic threat cards
            # ------------------------------------------------

            threat_items = [
                (
                    name,
                    count
                )
                for name, count
                in category_counts.items()
                if (
                    name.lower()
                    not in {
                        "benign",
                        "normal"
                    }
                    and count > 0
                )
            ]

            threat_items.sort(
                key=lambda item: item[1],
                reverse=True
            )

            # Keep only top four
            threat_items = threat_items[
                :self.DYNAMIC_CARD_COUNT
            ]

            self.dynamic_threats = (
                threat_items
            )

            # Reset first
            self._reset_dynamic_cards()

            # Fill cards
            for index, (
                name,
                count
            ) in enumerate(
                threat_items
            ):

                if index >= len(
                    self.dynamic_cards
                ):
                    break

                card_info = (
                    self.dynamic_cards[
                        index
                    ]
                )

                card_info["title"].config(
                    text=(
                        f"{name.upper()}\n"
                        "NETWORK FLOWS"
                    ),
                    bg="#3F1D24",
                    fg=self.RED
                )

                card_info["value"].config(
                    text=f"{count:,}",
                    bg="#3F1D24",
                    fg=self.RED
                )

                card_info["card"].config(
                    bg="#3F1D24",
                    highlightbackground=self.RED
                )

        self.root.after(
            0,
            update
        )


    # ========================================================
    # RESET DASHBOARD
    # ========================================================

    def reset_dashboard(
        self
    ):

        self.update_dashboard_metrics(
            0,
            0,
            0,
            {}
        )


    # ========================================================
    # FINDINGS TABLE
    # ========================================================

    def _build_findings_table(
        self
    ):

        table_frame = tk.Frame(
            self.scrollable_frame,
            bg=self.BG_MAIN,
            highlightbackground=self.BORDER,
            highlightthickness=1
        )

        # Keep the findings table compact so the selected-flow
        # details remain accessible below it.
        table_frame.pack(
            fill="x",
            padx=10,
            pady=(5, 5)
        )
        table_frame.configure(height=155)
        table_frame.pack_propagate(False)

        # ----------------------------------------------------
        # Table title
        # ----------------------------------------------------

        tk.Label(
            table_frame,
            text="AI Threat Findings",
            font=("Segoe UI", 9, "bold"),
            bg=self.BG_MAIN,
            fg=self.TEXT_PRIMARY,
            anchor="w"
        ).pack(
            fill="x",
            padx=8,
            pady=(5, 3)
        )

        # ----------------------------------------------------
        # Style
        # ----------------------------------------------------

        style = ttk.Style()

        try:
            style.theme_use(
                "clam"
            )
        except tk.TclError:
            pass

        style.configure(
            "ForenXAI.Treeview",
            background=self.BG_PANEL,
            foreground=self.TEXT_PRIMARY,
            fieldbackground=self.BG_PANEL,
            rowheight=28,
            borderwidth=0,
            font=("Segoe UI", 8)
        )

        style.configure(
            "ForenXAI.Treeview.Heading",
            background=self.BG_MAIN,
            foreground=self.TEXT_PRIMARY,
            font=("Segoe UI", 8, "bold"),
            padding=(4, 5)
        )

        style.map(
            "ForenXAI.Treeview",
            background=[
                (
                    "selected",
                    self.BLUE
                )
            ],
            foreground=[
                (
                    "selected",
                    "#FFFFFF"
                )
            ]
        )

        # ----------------------------------------------------
        # Columns
        # ----------------------------------------------------

        columns = (
            "detected_threats",
            "multiclass",
            "confidence",
            "ai_comments",
            "investigator_comment"
        )

        self.findings_table = (
            ttk.Treeview(
                table_frame,
                columns=columns,
                show="headings",
                height=4,
                style="ForenXAI.Treeview"
            )
        )

        self.findings_table.heading(
            "detected_threats",
            text="Detected Threats"
        )

        self.findings_table.heading(
            "multiclass",
            text="Multiclass Classification"
        )

        self.findings_table.heading(
            "confidence",
            text="Confidence Level"
        )

        self.findings_table.heading(
            "ai_comments",
            text="AI Comments"
        )

        self.findings_table.heading(
            "investigator_comment",
            text="Investigator's Comment"
        )

        # ----------------------------------------------------
        # Column sizes
        # ----------------------------------------------------

        self.findings_table.column(
            "detected_threats",
            width=120,
            minwidth=100,
            anchor="center"
        )

        self.findings_table.column(
            "multiclass",
            width=155,
            minwidth=130,
            anchor="center"
        )

        self.findings_table.column(
            "confidence",
            width=110,
            minwidth=100,
            anchor="center"
        )

        self.findings_table.column(
            "ai_comments",
            width=270,
            minwidth=200,
            anchor="w"
        )

        self.findings_table.column(
            "investigator_comment",
            width=270,
            minwidth=200,
            anchor="w"
        )

        # ----------------------------------------------------
        # Scrollbar
        # ----------------------------------------------------

        scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.findings_table.yview
        )

        self.findings_table.configure(
            yscrollcommand=scrollbar.set
        )

        self.findings_table.pack(
            side=tk.LEFT,
            fill="both",
            expand=True,
            padx=(5, 0),
            pady=(0, 5)
        )

        # Clicking a threat row loads that flow's detailed
        # CICFlowMeter information into the table below.
        self.findings_table.bind(
            "<<TreeviewSelect>>",
            self._on_flow_selected
        )

        scrollbar.pack(
            side=tk.RIGHT,
            fill="y",
            padx=(0, 5),
            pady=(0, 5)
        )

        self._clear_findings_table()


    # ========================================================
    # CLEAR TABLE
    # ========================================================

    def _clear_findings_table(
        self
    ):

        if not hasattr(
            self,
            "findings_table"
        ):
            return

        for item in (
            self.findings_table.get_children()
        ):

            self.findings_table.delete(
                item
            )

        self.findings_rows = []

        if hasattr(
            self,
            "flow_details_table"
        ):
            self._clear_flow_details()


    # ========================================================
    # POPULATE FINDINGS TABLE
    # ========================================================

    def _populate_findings_table(
        self,
        current_case,
        shap_results=None
    ):
        """
        Populate the findings table.

        IMPORTANT:

            Only threat flows are displayed.

        Benign flows are excluded because this is an
        investigator-facing threat findings table.
        """

        prediction_path = (
            current_case.get(
                "prediction_path"
            )
        )

        # Log the artifact path used by the table so missing/mismatched
        # pipeline return values are immediately visible during testing.
        self.write_log(
            f"[*] Findings table prediction artifact: {prediction_path}",
            "info"
        )

        if not prediction_path:

            self.write_log(
                "[!] No prediction artifact was returned; "
                "findings table cannot be populated.",
                "error"
            )

            return

        if not os.path.isfile(
            prediction_path
        ):

            self.write_log(
                "[!] Prediction artifact not found:\n"
                + prediction_path,
                "error"
            )

            return

        # ----------------------------------------------------
        # Load predictions
        # ----------------------------------------------------

        try:

            with open(
                prediction_path,
                "r",
                encoding="utf-8"
            ) as file:

                prediction_records = (
                    json.load(file)
                )

        except Exception as err:

            self.write_log(
                "[!] Could not read prediction artifact: "
                + str(err),
                "error"
            )

            return

        self.write_log(
            f"[+] Findings table loaded {len(prediction_records)} prediction record(s).",
            "success"
        )

        # ----------------------------------------------------
        # Get frozen class mapping
        # ----------------------------------------------------

        try:

            family_mapping = (
                get_family_mapping(
                    self.model_name
                )
            )

        except Exception as err:

            family_mapping = {}

            self.write_log(
                "[!] Could not load frozen family mapping: "
                + str(err),
                "error"
            )

        # ----------------------------------------------------
        # Reverse mapping
        #
        # Example:
        #
        # {
        #     "Benign": 0,
        #     "Botnet": 1,
        #     "Bruteforce": 2
        # }
        #
        # becomes:
        #
        # {
        #     "0": "Benign",
        #     "1": "Botnet",
        #     "2": "Bruteforce"
        # }
        # ----------------------------------------------------

        reverse_mapping = {}

        for class_name, class_value in (
            family_mapping.items()
        ):

            reverse_mapping[
                str(class_value)
            ] = str(class_name)

        # ----------------------------------------------------
        # SHAP lookup
        # ----------------------------------------------------

        shap_lookup = {}

        if isinstance(
            shap_results,
            list
        ):

            for shap_record in (
                shap_results
            ):

                if not isinstance(
                    shap_record,
                    dict
                ):
                    continue

                flow_index = (
                    shap_record.get(
                        "flow_index"
                    )
                )

                if flow_index is not None:

                    shap_lookup[
                        str(flow_index)
                    ] = shap_record

        # ----------------------------------------------------
        # Build rows
        # ----------------------------------------------------

        rows = []

        for record in prediction_records:

            if not isinstance(
                record,
                dict
            ):
                continue

            flow_index = (
                record.get(
                    "flow_index"
                )
            )

            raw_prediction = (
                record.get(
                    "ai_prediction"
                )
            )

            prediction_text = str(
                raw_prediction
            ).strip()

            # ------------------------------------------------
            # Translate numeric prediction
            # ------------------------------------------------

            classification = (
                reverse_mapping.get(
                    prediction_text,
                    prediction_text
                )
            )

            # ------------------------------------------------
            # Determine benign
            #
            # By NAME whenever the frozen mapping could translate the
            # prediction. The raw-integer fallback below is only for a
            # model whose mapping failed to load, because "0" does not
            # mean benign in general -- in the 16-class model the classes
            # are alphabetical, so 0 is API, an attack. Applying the
            # numeric rule there would drop every API flow from this
            # table silently.
            # ------------------------------------------------

            translated = prediction_text in reverse_mapping

            is_benign = (
                classification.lower()
                in {
                    "benign",
                    "normal"
                }
            )

            if not translated:

                is_benign = (
                    is_benign
                    or prediction_text
                    in {
                        "0",
                        "0.0",
                        "false"
                    }
                )

            # ------------------------------------------------
            # Ignore benign flows
            # ------------------------------------------------

            if is_benign:
                continue

            detected_threat = (
                f"Flow {flow_index}"
                if flow_index is not None
                else "Threat Flow"
            )

            # ------------------------------------------------
            # Confidence
            # ------------------------------------------------

            confidence = record.get(
                "threat_probability"
            )

            if confidence is None:

                confidence_text = "N/A"

            else:

                try:

                    confidence_text = (
                        f"{float(confidence) * 100:.2f}%"
                    )

                except (
                    TypeError,
                    ValueError
                ):

                    confidence_text = str(
                        confidence
                    )

            # ------------------------------------------------
            # AI comment
            # ------------------------------------------------

            ai_comment = (
                f"AI classified this flow as "
                f"'{classification}'."
            )

            shap_record = (
                shap_lookup.get(
                    str(flow_index)
                )
            )

            if shap_record:

                top_features = (
                    shap_record.get(
                        "top_features",
                        []
                    )
                )

                feature_names = []

                if isinstance(
                    top_features,
                    list
                ):

                    for feature in (
                        top_features[:3]
                    ):

                        if not isinstance(
                            feature,
                            dict
                        ):
                            continue

                        name = feature.get(
                            "feature"
                        )

                        if name:

                            feature_names.append(
                                str(name)
                            )

                if feature_names:

                    ai_comment += (
                        " Key indicators: "
                        + ", ".join(
                            feature_names
                        )
                        + "."
                    )

            rows.append(
                (
                    detected_threat,
                    classification,
                    confidence_text,
                    ai_comment,
                    ""
                )
            )

        # ----------------------------------------------------
        # Save and display
        # ----------------------------------------------------

        self.findings_rows = rows

        self._refresh_findings_table()

        self.write_log(
            f"[+] Findings table populated with "
            f"{len(rows)} threat flow(s).",
            "success"
        )


    # ========================================================
    # REFRESH TABLE
    # ========================================================

    def _refresh_findings_table(
        self
    ):

        # IMPORTANT: Do not call _clear_findings_table() here.
        # That method also resets self.findings_rows, which previously
        # erased the rows immediately before they were inserted.
        # We only clear the Treeview widgets, then insert the saved rows.
        for item in self.findings_table.get_children():
            self.findings_table.delete(item)

        for row in self.findings_rows:
            # Use the flow index as the Treeview item ID so
            # selecting a row can directly locate its source
            # CICFlowMeter flow.
            flow_index = None

            if row:
                try:
                    flow_index = int(
                        str(row[0]).split()[-1]
                    )
                except (
                    TypeError,
                    ValueError
                ):
                    flow_index = None

            if flow_index is not None:
                self.findings_table.insert(
                    "",
                    tk.END,
                    iid=str(flow_index),
                    values=row
                )
            else:
                self.findings_table.insert(
                    "",
                    tk.END,
                    values=row
                )


    # ========================================================
    # SELECTED FLOW DETAILS TABLE
    # ========================================================

    def _build_flow_details_table(
        self
    ):
        """
        Build the investigator-facing flow detail table.

        The table is populated when the investigator selects a
        threat flow in the AI Threat Findings table.

        Data source:
            CICFlowMeter-generated CSV saved by the pipeline.

        The selected row's flow_index is used to locate the
        corresponding CICFlowMeter row.
        """

        self.flow_details_frame = tk.Frame(
            self.scrollable_frame,
            bg=self.BG_MAIN,
            highlightbackground=self.BORDER,
            highlightthickness=1
        )

        self.flow_details_frame.pack(
            fill="x",
            padx=10,
            pady=(5, 5)
        )

        # Keep this section compact. The page itself is scrollable.
        self.flow_details_frame.configure(
            height=220
        )

        self.flow_details_frame.pack_propagate(False)

        tk.Label(
            self.flow_details_frame,
            text="Selected Flow Details",
            font=("Segoe UI", 9, "bold"),
            bg=self.BG_MAIN,
            fg=self.TEXT_PRIMARY,
            anchor="w"
        ).pack(
            fill="x",
            padx=8,
            pady=(5, 3)
        )

        self.lbl_selected_flow = tk.Label(
            self.flow_details_frame,
            text="Select a threat flow above to view its details.",
            font=("Segoe UI", 8),
            bg=self.BG_MAIN,
            fg=self.TEXT_SECONDARY,
            anchor="w"
        )

        self.lbl_selected_flow.pack(
            fill="x",
            padx=8,
            pady=(0, 3)
        )

        # Four-column layout keeps the information compact:
        # Feature | Value | Feature | Value
        columns = (
            "field_1",
            "value_1",
            "field_2",
            "value_2"
        )

        self.flow_details_table = ttk.Treeview(
            self.flow_details_frame,
            columns=columns,
            show="headings",
            height=6,
            style="ForenXAI.Treeview"
        )

        self.flow_details_table.heading(
            "field_1",
            text="Flow Information"
        )

        self.flow_details_table.heading(
            "value_1",
            text="Value"
        )

        self.flow_details_table.heading(
            "field_2",
            text="Flow Information"
        )

        self.flow_details_table.heading(
            "value_2",
            text="Value"
        )

        self.flow_details_table.column(
            "field_1",
            width=180,
            minwidth=130,
            anchor="w"
        )

        self.flow_details_table.column(
            "value_1",
            width=300,
            minwidth=160,
            anchor="w"
        )

        self.flow_details_table.column(
            "field_2",
            width=180,
            minwidth=130,
            anchor="w"
        )

        self.flow_details_table.column(
            "value_2",
            width=300,
            minwidth=160,
            anchor="w"
        )

        detail_scrollbar = ttk.Scrollbar(
            self.flow_details_frame,
            orient="vertical",
            command=self.flow_details_table.yview
        )

        self.flow_details_table.configure(
            yscrollcommand=detail_scrollbar.set
        )

        self.flow_details_table.pack(
            side=tk.LEFT,
            fill="both",
            expand=True,
            padx=(5, 0),
            pady=(0, 5)
        )

        detail_scrollbar.pack(
            side=tk.RIGHT,
            fill="y",
            padx=(0, 5),
            pady=(0, 5)
        )

    def _clear_flow_details(
        self
    ):
        """Clear the selected-flow detail table."""

        if not hasattr(
            self,
            "flow_details_table"
        ):
            return

        for item in (
            self.flow_details_table.get_children()
        ):
            self.flow_details_table.delete(
                item
            )

        self.selected_flow_index = None
        self.current_flow_details = []

        if hasattr(
            self,
            "lbl_selected_flow"
        ):
            self.lbl_selected_flow.config(
                text=(
                    "Select a threat flow above to view "
                    "its details."
                )
            )

    def _on_flow_selected(
        self,
        event=None
    ):
        """
        Handle a click/selection on a threat flow.

        The first column contains text such as:
            Flow 8

        The corresponding Treeview item stores the actual
        flow index as its iid.
        """

        selection = (
            self.findings_table.selection()
        )

        if not selection:
            return

        item_id = selection[0]

        try:
            flow_index = int(
                item_id
            )
        except (
            TypeError,
            ValueError
        ):
            # Fallback: extract the number from "Flow 8".
            values = self.findings_table.item(
                item_id,
                "values"
            )

            if not values:
                return

            try:
                flow_index = int(
                    str(values[0]).split()[-1]
                )
            except (
                TypeError,
                ValueError
            ):
                self.write_log(
                    "[!] Could not determine selected flow index.",
                    "error"
                )
                return

        self._show_flow_details(
            flow_index
        )

    def _show_flow_details(
        self,
        flow_index
    ):
        """
        Load and display the CICFlowMeter row associated
        with the selected threat flow.

        The pipeline stores the original CICFlowMeter CSV
        path in current_case["cicflowmeter_csv_path"].
        """

        self._clear_flow_details()

        self.selected_flow_index = flow_index

        # The current case is retained after analysis.
        current_case = getattr(
            self,
            "current_case",
            None
        )

        if not isinstance(
            current_case,
            dict
        ):
            self.write_log(
                "[!] No forensic case is loaded for flow details.",
                "error"
            )
            return

        csv_path = (
            current_case.get(
                "cicflowmeter_csv_path"
            )
        )

        # Fallback to the normalized inference artifact if
        # the original CICFlowMeter CSV path is unavailable.
        if not csv_path:
            csv_path = (
                current_case.get(
                    "generated_csv_path"
                )
            )

        if not csv_path or not os.path.isfile(
            csv_path
        ):
            self.write_log(
                "[!] Flow detail CSV was not found.",
                "error"
            )
            return

        try:
            import pandas as pd

            df = pd.read_csv(
                csv_path,
                low_memory=False
            )

        except Exception as err:
            self.write_log(
                "[!] Could not read flow detail CSV: "
                + str(err),
                "error"
            )
            return

        if flow_index < 0 or flow_index >= len(df):
            self.write_log(
                f"[!] Flow index {flow_index} is outside "
                f"the CSV range (0-{max(len(df) - 1, 0)}).",
                "error"
            )
            return

        row = df.iloc[
            flow_index
        ]

        self.current_flow_details = []

        for column in df.columns:
            value = row[column]

            # Make NaN display cleanly.
            try:
                if pd.isna(value):
                    value = "N/A"
            except Exception:
                pass

            self.current_flow_details.append(
                (
                    str(column).strip(),
                    str(value)
                )
            )

        # Update title/status.
        self.lbl_selected_flow.config(
            text=(
                f"Flow {flow_index} selected — "
                f"Detailed CICFlowMeter flow information"
            )
        )

        # Insert two field/value pairs per row.
        details = self.current_flow_details

        for i in range(
            0,
            len(details),
            2
        ):
            left = details[i]

            if i + 1 < len(details):
                right = details[i + 1]
            else:
                right = (
                    "",
                    ""
                )

            self.flow_details_table.insert(
                "",
                tk.END,
                values=(
                    left[0],
                    left[1],
                    right[0],
                    right[1]
                )
            )

        self.write_log(
            f"[+] Displaying detailed information for Flow {flow_index}.",
            "success"
        )


    # ========================================================
    # PIPELINE LOG COMPATIBILITY
    # ========================================================

    def write_log(
        self,
        message,
        tag=None
    ):
        """
        Pipeline logging compatibility hook.

        The black system console has been removed from the UI, but
        pipeline_service.py still calls write_log(). Keeping this method
        prevents the pipeline from breaking while allowing the UI to
        remain table-focused.
        """

        # Do not create or display a black console.
        # Progress is handled separately by _set_progress().
        return


    # ========================================================
    # ANALYSIS TRIGGER
    # ========================================================

    def analyze_trigger(
        self
    ):

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
        # Clear previous results
        # ----------------------------------------------------

        self._clear_findings_table()

        self._clear_flow_details()

        self.reset_dashboard()

        # ----------------------------------------------------
        # Start analysis
        # ----------------------------------------------------

        self.analysis_running = True
        self._analysis_completion_pending = False

        # Start the visible progress animation immediately on the GUI
        # thread. The forensic worker starts just after this.
        self._start_gui_progress_animation()

        self.btn_analyze.config(
            state=tk.DISABLED,
            text="Analyzing Evidence...",
            bg="#4B5563"
        )

        if hasattr(self, "btn_clear"):
            self.btn_clear.config(
                state=tk.DISABLED,
                bg="#374151"
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

        # ----------------------------------------------------
        # Run pipeline in background thread
        # ----------------------------------------------------

        threading.Thread(
            target=self._pipeline_worker,
            args=(
                self.selected_pcap,
            ),
            daemon=True
        ).start()


    # ========================================================
    # PIPELINE WORKER
    # ========================================================

    def _pipeline_worker(
        self,
        pcap_path
    ):

        try:

            # ------------------------------------------------
            # DO NOT CHANGE THIS CALL.
            #
            # This matches your working pipeline:
            #
            # run_forensic_pipeline(
            #     pcap_path,
            #     model,
            #     model_name,
            #     case_output_dir,
            #     log_fn,
            #     on_metrics_ready
            # )
            # ------------------------------------------------

            self._set_progress(
                5,
                "Running forensic pipeline..."
            )

            current_case, shap_results = (
                run_forensic_pipeline(
                    pcap_path=pcap_path,
                    model=self.model,
                    model_name=self.model_name,
                    case_output_dir=self.case_output_dir,
                    log_fn=self.write_log,
                    on_metrics_ready=(
                        self.update_dashboard_metrics
                    )
                )
            )

            # Keep the completed case available for the
            # selected-flow detail table.
            self.current_case = current_case

            self._set_progress(
                70,
                "Processing ML predictions..."
            )

            # ------------------------------------------------
            # Read prediction artifact
            # ------------------------------------------------

            category_counts = (
                self._calculate_category_counts(
                    current_case.get(
                        "prediction_path"
                    )
                )
            )

            total = current_case.get(
                "total_flows",
                0
            )

            benign = category_counts.get(
                "Benign",
                current_case.get(
                    "benign_flows",
                    0
                )
            )

            threat = (
                total - benign
            )

            self._set_progress(
                85,
                "Updating forensic findings..."
            )

            # ------------------------------------------------
            # Update dynamic cards
            # ------------------------------------------------

            self.update_dashboard_metrics(
                total,
                benign,
                threat,
                category_counts
            )

            # ------------------------------------------------
            # Populate table
            # ------------------------------------------------

            self.root.after(
                0,
                lambda case=current_case,
                       shap=shap_results:
                self._populate_findings_table(
                    case,
                    shap
                )
            )

            self._set_progress(
                95,
                "Finalizing SHAP & Human Review..."
            )

            # ------------------------------------------------
            # Forward to XAI tab
            # ------------------------------------------------

            self.root.after(
                0,
                lambda case=current_case,
                       shap=shap_results:
                self.on_pipeline_complete(
                    case,
                    shap
                )
            )

            # The pipeline has genuinely completed. Schedule the final
            # 95% -> 100% animation on the GUI thread.
            self.root.after(
                0,
                self._finish_gui_progress_success
            )

        except Exception as err:

            error_message = str(
                err
            )

            self.write_log(
                (
                    "\n[!] FORENSIC PIPELINE FAILED: "
                    + error_message
                ),
                "error"
            )

            self.root.after(
                0,
                lambda msg=error_message:
                messagebox.showerror(
                    "Forensic Pipeline Error",
                    msg
                )
            )

        finally:
            # Keep analysis_running true until the GUI has completed the
            # final 95% -> 100% animation. This also prevents Clear from
            # being enabled while the visible analysis is still finishing.
            if 'error_message' in locals():
                self.root.after(
                    0,
                    self._mark_analysis_failed
                )


    def _mark_analysis_failed(self):
        """Mark the analysis as stopped after a worker-side failure."""
        self.analysis_running = False
        self._finish_gui_progress_error()


    # ========================================================
    # CALCULATE CATEGORY COUNTS
    # ========================================================

    def _calculate_category_counts(
        self,
        prediction_path
    ):
        """
        Read the prediction JSON and convert numeric
        model predictions into their actual class names
        using the selected model's frozen family mapping.

        Example:

            prediction:
                3

            mapping:
                DoS = 3

            result:
                DoS
        """

        counts = {}

        if not prediction_path:

            return counts

        if not os.path.isfile(
            prediction_path
        ):

            self.write_log(
                "[!] Prediction artifact does not exist.",
                "error"
            )

            return counts

        # ----------------------------------------------------
        # Load predictions
        # ----------------------------------------------------

        try:

            with open(
                prediction_path,
                "r",
                encoding="utf-8"
            ) as file:

                records = json.load(
                    file
                )

        except Exception as err:

            self.write_log(
                "[!] Could not calculate category counts: "
                + str(err),
                "error"
            )

            return counts

        # ----------------------------------------------------
        # Load frozen family mapping
        # ----------------------------------------------------

        try:

            family_mapping = (
                get_family_mapping(
                    self.model_name
                )
            )

        except Exception as err:

            self.write_log(
                "[!] Could not load model family mapping: "
                + str(err),
                "error"
            )

            family_mapping = {}

        # ----------------------------------------------------
        # Reverse mapping
        # ----------------------------------------------------

        reverse_mapping = {}

        for class_name, class_value in (
            family_mapping.items()
        ):

            reverse_mapping[
                str(class_value)
            ] = str(class_name)

        # ----------------------------------------------------
        # Count classifications
        # ----------------------------------------------------

        for record in records:

            if not isinstance(
                record,
                dict
            ):
                continue

            prediction = (
                record.get(
                    "ai_prediction"
                )
            )

            prediction_text = str(
                prediction
            ).strip()

            # ----------------------------------------------
            # Translate model class
            # ----------------------------------------------

            category = (
                reverse_mapping.get(
                    prediction_text
                )
            )

            # ----------------------------------------------
            # If mapping doesn't contain the value,
            # preserve the model output rather than
            # inventing a category.
            # ----------------------------------------------

            if category is None:

                category = (
                    prediction_text
                )

            if not category:

                category = "Unknown"

            # ----------------------------------------------
            # Normalize benign naming only
            # ----------------------------------------------

            if category.lower() in {
                "normal",
                "benign"
            }:

                category = "Benign"

            # ----------------------------------------------
            # Increment count
            # ----------------------------------------------

            counts[category] = (
                counts.get(
                    category,
                    0
                )
                + 1
            )

        return counts