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

    DYNAMIC_CARD_COUNT = 5


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

        # Current table rows
        self.findings_rows = []

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

        # IMPORTANT:
        # Keep the original system initialization message.
        self.write_log(
            "System initialized. Awaiting PCAP evidence..."
        )


    # ========================================================
    # BUILD COMPLETE UI
    # ========================================================

    def _build_ui(self):

        # ----------------------------------------------------
        # TOP AREA
        # ----------------------------------------------------

        top_frame = tk.Frame(
            self.frame,
            bg=self.BG_MAIN
        )

        top_frame.pack(
            fill="x",
            padx=10,
            pady=(8, 5)
        )

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
        # SYSTEM LOG
        # ----------------------------------------------------

        self._build_log_console()


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

        for column in range(2):

            metrics_frame.grid_columnconfigure(
                column,
                weight=1
            )

        for row in range(4):

            metrics_frame.grid_rowconfigure(
                row,
                weight=1
            )

        # ----------------------------------------------------
        # FIXED CARD 1
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
            sticky="nsew",
            padx=3,
            pady=3
        )

        # ----------------------------------------------------
        # FIXED CARD 2
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
            row=0,
            column=1,
            sticky="nsew",
            padx=3,
            pady=3
        )

        # ----------------------------------------------------
        # FIVE DYNAMIC CARDS
        # ----------------------------------------------------

        self.dynamic_cards = []

        dynamic_positions = [
            (1, 0),
            (1, 1),
            (2, 0),
            (2, 1),
            (3, 0)
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
        # Initialize cards
        # ----------------------------------------------------

        self._reset_dynamic_cards()


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

            # Keep only top five
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
            self.frame,
            bg=self.BG_MAIN,
            highlightbackground=self.BORDER,
            highlightthickness=1
        )

        table_frame.pack(
            fill="x",
            padx=10,
            pady=(5, 5)
        )

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
            fill="x",
            expand=True,
            padx=(5, 0),
            pady=(0, 5)
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
            # ------------------------------------------------

            is_benign = (
                classification.lower()
                in {
                    "benign",
                    "normal"
                }
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

        self._clear_findings_table()

        for row in (
            self.findings_rows
        ):

            self.findings_table.insert(
                "",
                tk.END,
                values=row
            )


    # ========================================================
    # SYSTEM LOG CONSOLE
    # ========================================================

    def _build_log_console(
        self
    ):

        terminal_frame = tk.Frame(
            self.frame,
            bg=self.BG_TERMINAL,
            highlightbackground=self.BORDER,
            highlightthickness=1
        )

        terminal_frame.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=(0, 10)
        )

        self.log_console = tk.Text(
            terminal_frame,
            bg=self.BG_TERMINAL,
            fg="#A6ACCD",
            font=("Consolas", 9),
            state=tk.DISABLED,
            padx=12,
            pady=10,
            relief="flat",
            wrap=tk.WORD
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
    # LOGGING
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

        self.reset_dashboard()

        # ----------------------------------------------------
        # Start analysis
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

            self.analysis_running = False

            self.root.after(
                0,
                lambda: self.btn_analyze.config(
                    state=tk.NORMAL,
                    text="Analyze PCAP",
                    bg=self.BLUE
                )
            )


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