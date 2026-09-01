import tkinter as tk
from tkinter import ttk, messagebox

from tkinterdnd2 import TkinterDnD

from views.forensic_tab import ForensicTab
from views.xai_tab import XaiTab
from views.evaluation_tab import EvaluationTab

from services.model_service import (
    discover_models,
    load_model,
)


class MainWindow:
    """
    Main application window.

    Responsibilities:
        - Own the root Tkinter window.
        - Detect available trained models.
        - Provide the dataset/model selector.
        - Load the selected model.
        - Pass the selected model to ForensicTab.
        - Wire ForensicTab -> XaiTab.
        - Keep model selection centralized.

    IMPORTANT:
        The actual ML inference is still performed by
        pipeline_service.py.

        This class only handles GUI-level model selection
        and model loading.

    IMPORTANT:
        Progress/loading controls belong to ForensicTab.
        They are NOT created here.
    """

    def __init__(
        self,
        case_output_dir,
        default_model=None
    ):
        self.root = TkinterDnD.Tk()

        self.root.title(
            "ForenXAI"
        )

        self.root.geometry(
            "1150x780"
        )

        self.root.configure(
            bg="#1E1E2E"
        )

        self.case_output_dir = (
            case_output_dir
        )

        # ====================================================
        # MODEL STATE
        # ====================================================

        self.available_models = (
            discover_models()
        )

        self.current_model_name = None
        self.current_model = None

        # ====================================================
        # WINDOW CONFIGURATION
        # ====================================================

        self._enable_resizing_and_fullscreen()
        self._configure_style()

        # ====================================================
        # MODEL SELECTOR
        # ====================================================

        self._build_model_selector()

        # ====================================================
        # TAB BAR
        # ====================================================

        self.tab_header = tk.Frame(
            self.root,
            bg="#1E1E2E",
            height=38
        )

        self.tab_header.pack(
            fill="x",
            padx=15,
            pady=(5, 0)
        )

        self.tab_header.pack_propagate(
            False
        )

        self.tab_buttons_frame = tk.Frame(
            self.tab_header,
            bg="#1E1E2E"
        )

        self.tab_buttons_frame.pack(
            side=tk.LEFT,
            fill=tk.Y
        )

        # ====================================================
        # NOTEBOOK
        # ====================================================

        notebook = ttk.Notebook(
            self.root,
            style="Hidden.TNotebook"
        )

        notebook.pack(
            fill="both",
            expand=True,
            padx=15,
            pady=(0, 15)
        )

        self.notebook = notebook

        # ====================================================
        # XAI FORWARDING
        # ====================================================

        def forward_to_xai(
            current_case,
            shap_results
        ):
            self.xai_tab.update_xai_results(
                current_case,
                shap_results
            )

        # ====================================================
        # FORENSIC TAB
        # ====================================================

        self.forensic_tab = ForensicTab(
            notebook,
            self.root,
            self.current_model,
            case_output_dir,
            on_pipeline_complete=forward_to_xai
        )

        # ====================================================
        # XAI TAB
        # ====================================================

        self.xai_tab = XaiTab(
            notebook,
            case_output_dir
        )

        # ====================================================
        # CUSTOM TAB BUTTONS
        # ====================================================

        self._build_custom_tab_buttons()

        # ====================================================
        # ANALYSIS STATUS / PROGRESS / CLEAR
        # ====================================================
        # IMPORTANT:
        # Build these controls HERE, directly inside tab_header.
        # This guarantees they are physically on the SAME ROW as
        # the custom PCAP / SHAP tab buttons.
        #
        # We do NOT place them inside ForensicTab's dashboard because
        # that dashboard is inside a scrollable Notebook page.
        # ====================================================

        self._build_analysis_toolbar()

        self.notebook.select(0)

        # ====================================================
        # EVALUATION TAB
        # ====================================================

        # KEEPING THIS COMMENTED FOR NOW.
        #
        # The existing project intentionally has the
        # EvaluationTab disabled. We are not changing its
        # behavior in this step.

        # self.evaluation_tab = EvaluationTab(
        #     notebook,
        #     self.root,
        #     self.current_model
        # )

        # ====================================================
        # INITIAL MODEL LOAD
        # ====================================================

        if self.available_models:

            if (
                default_model
                and default_model in self.available_models
            ):
                selected_model = default_model

            else:

                # CIDS2018 becomes the default when available.
                # Otherwise use the first discovered model.

                if "CIDS2018" in self.available_models:

                    selected_model = "CIDS2018"

                else:

                    selected_model = next(
                        iter(
                            self.available_models
                        )
                    )

            self.model_selector.set(
                selected_model
            )

            self._load_selected_model()

        else:

            self.model_status.config(
                text="● No trained models found",
                fg="#EF4444"
            )

            self.model_selector["values"] = []

            self._show_model_error(
                "No trained model artifacts were found.\n\n"
                "Expected structure:\n\n"
                "artifacts/\n"
                "├── CIDS2018/\n"
                "│   └── forensic_tab/model.joblib\n"
                "└── TII/\n"
                "    └── forensic_tab/model.joblib"
            )

    # ========================================================
    # CUSTOM TAB BAR
    # ========================================================

    def _build_custom_tab_buttons(
        self
    ):
        """
        Build the visible tab buttons.
        """

        self.btn_forensic_tab = tk.Button(
            self.tab_buttons_frame,
            text="PCAP Forensic Analysis",
            font=("Segoe UI", 9, "bold"),
            bg="#3B82F6",
            fg="white",
            activebackground="#3B82F6",
            activeforeground="white",
            relief="flat",
            bd=0,
            padx=12,
            pady=5,
            cursor="hand2",
            command=lambda: self._select_custom_tab(
                0,
                self.btn_forensic_tab,
                self.btn_xai_tab
            )
        )

        self.btn_forensic_tab.pack(
            side=tk.LEFT,
            fill=tk.Y
        )

        self.btn_xai_tab = tk.Button(
            self.tab_buttons_frame,
            text="SHAP & Human Review",
            font=("Segoe UI", 9, "bold"),
            bg="#27293D",
            fg="white",
            activebackground="#27293D",
            activeforeground="white",
            relief="flat",
            bd=0,
            padx=12,
            pady=5,
            cursor="hand2",
            command=lambda: self._select_custom_tab(
                1,
                self.btn_xai_tab,
                self.btn_forensic_tab
            )
        )

        self.btn_xai_tab.pack(
            side=tk.LEFT,
            fill=tk.Y
        )

    # ========================================================
    # ANALYSIS TOOLBAR
    # ========================================================

    def _build_analysis_toolbar(self):
        """
        Build Analysis status, progress bar, percentage and Clear
        directly inside the top tab-header row.

        This is intentionally owned by MainWindow so the controls
        cannot be hidden by the Notebook's content area.
        """

        # The toolbar is packed on the RIGHT first so it reserves
        # its width before the tab buttons consume the remaining area.
        self.analysis_toolbar = tk.Frame(
            self.tab_header,
            bg="#BFC0C4",
            highlightbackground="#9CA3AF",
            highlightthickness=1,
            width=470,
            height=32
        )

        self.analysis_toolbar.pack(
            side=tk.RIGHT,
            fill=tk.Y,
            padx=(8, 2),
            pady=3
        )

        self.analysis_toolbar.pack_propagate(False)

        # Analysis status
        tk.Label(
            self.analysis_toolbar,
            text="Analysis:",
            bg="#BFC0C4",
            fg="#1F2937",
            font=("Segoe UI", 8, "bold")
        ).pack(
            side=tk.LEFT,
            padx=(8, 2)
        )

        self.analysis_status_label = tk.Label(
            self.analysis_toolbar,
            textvariable=self.forensic_tab.progress_status,
            bg="#BFC0C4",
            fg="#1F2937",
            font=("Segoe UI", 8)
        )

        self.analysis_status_label.pack(
            side=tk.LEFT,
            padx=(0, 8)
        )

        # Progress bar style
        style = ttk.Style()

        try:
            style.configure(
                "ForenXAI.Header.Horizontal.TProgressbar",
                troughcolor="#D1D5DB",
                background="#3B82F6",
                bordercolor="#9CA3AF",
                lightcolor="#3B82F6",
                darkcolor="#3B82F6",
                thickness=10
            )
        except tk.TclError:
            pass

        self.analysis_progress_bar = ttk.Progressbar(
            self.analysis_toolbar,
            orient="horizontal",
            mode="determinate",
            maximum=100,
            variable=self.forensic_tab.progress_var,
            style="ForenXAI.Header.Horizontal.TProgressbar",
            length=150
        )

        self.analysis_progress_bar.pack(
            side=tk.LEFT,
            fill=tk.X,
            expand=True,
            padx=(0, 5)
        )

        self.analysis_percent_label = tk.Label(
            self.analysis_toolbar,
            text="0%",
            bg="#BFC0C4",
            fg="#1F2937",
            font=("Segoe UI", 8, "bold"),
            width=4,
            anchor="e"
        )

        self.analysis_percent_label.pack(
            side=tk.LEFT,
            padx=(0, 8)
        )

        # IMPORTANT: ForensicTab._set_progress() is the single source
        # of truth for the analysis progress.  The visible progress bar
        # and percentage label live in MainWindow, so expose these exact
        # widgets back to ForensicTab.
        #
        # Without these aliases, ForensicTab sees no ``progress_bar``
        # and returns before updating anything. That is why the UI could
        # remain stuck at "Ready / 0%" even though the pipeline finished.
        self.forensic_tab.progress_bar = self.analysis_progress_bar
        self.forensic_tab.lbl_progress_percent = self.analysis_percent_label

        # Clear button
        self.analysis_clear_button = tk.Button(
            self.analysis_toolbar,
            text="Clear",
            font=("Segoe UI", 8, "bold"),
            bg="#6B7280",
            fg="white",
            activebackground="#4B5563",
            activeforeground="white",
            relief="flat",
            bd=0,
            padx=10,
            pady=3,
            cursor="hand2",
            command=self.forensic_tab.clear_analysis
        )

        self.analysis_clear_button.pack(
            side=tk.LEFT,
            padx=(0, 6)
        )

        # Keep the percentage label synchronized with the shared
        # DoubleVar used by ForensicTab.
        self._sync_header_progress()

    def _sync_header_progress(self):
        """Keep the header percentage synchronized with the forensic progress."""
        try:
            value = float(self.forensic_tab.progress_var.get())
            value = max(0.0, min(100.0, value))

            if hasattr(self, "analysis_percent_label"):
                self.analysis_percent_label.config(
                    text=f"{value:.0f}%"
                )
        except Exception:
            pass

        self.root.after(100, self._sync_header_progress)

    # ========================================================
    # CUSTOM TAB SELECTION
    # ========================================================

    def _select_custom_tab(
        self,
        tab_identifier,
        selected_button,
        other_button
    ):
        """
        Select a Notebook page through the custom tab buttons.
        """

        self.notebook.select(
            tab_identifier
        )

        selected_button.config(
            bg="#3B82F6",
            activebackground="#3B82F6"
        )

        other_button.config(
            bg="#27293D",
            activebackground="#27293D"
        )

    # ========================================================
    # MODEL SELECTOR UI
    # ========================================================

    def _build_model_selector(
        self
    ):

        self.model_frame = tk.Frame(
            self.root,
            bg="#27293D",
            highlightbackground="#374151",
            highlightthickness=1
        )

        self.model_frame.pack(
            fill="x",
            padx=15,
            pady=(15, 0)
        )

        # ----------------------------------------------------
        # Title
        # ----------------------------------------------------

        tk.Label(
            self.model_frame,
            text="Dataset / ML Model",
            bg="#27293D",
            fg="#F8FAFC",
            font=("Segoe UI", 10, "bold")
        ).pack(
            side=tk.LEFT,
            padx=(15, 8),
            pady=10
        )

        # ----------------------------------------------------
        # Dropdown
        # ----------------------------------------------------

        self.model_selector = ttk.Combobox(
            self.model_frame,
            state="readonly",
            width=25
        )

        self.model_selector.pack(
            side=tk.LEFT,
            padx=5,
            pady=8
        )

        self.model_selector.bind(
            "<<ComboboxSelected>>",
            self._on_model_selected
        )

        # ----------------------------------------------------
        # Model status
        # ----------------------------------------------------

        self.model_status = tk.Label(
            self.model_frame,
            text="● Waiting for model...",
            bg="#27293D",
            fg="#9CA3AF",
            font=("Segoe UI", 9)
        )

        self.model_status.pack(
            side=tk.LEFT,
            padx=15
        )

        # ----------------------------------------------------
        # Detected models
        # ----------------------------------------------------

        model_names = list(
            self.available_models.keys()
        )

        self.model_selector["values"] = (
            model_names
        )

    # ========================================================
    # MODEL SELECTION
    # ========================================================

    def _on_model_selected(
        self,
        event=None
    ):

        selected_name = (
            self.model_selector.get()
        )

        if not selected_name:
            return

        self._load_selected_model(
            selected_name
        )

    # ========================================================
    # MODEL LOADING
    # ========================================================

    def _load_selected_model(
        self,
        model_name=None
    ):
        """
        Load the selected trained model.

        This is the central point where the GUI changes
        between CIDS2018, TII, and future models such as
        Combined.
        """

        if model_name is None:

            model_name = (
                self.model_selector.get()
            )

        if not model_name:
            return

        if model_name not in self.available_models:

            self.model_status.config(
                text="● Model unavailable",
                fg="#EF4444"
            )

            return

        # ----------------------------------------------------
        # Prevent switching while analysis is running.
        # ----------------------------------------------------

        if hasattr(
            self,
            "forensic_tab"
        ):

            if (
                getattr(
                    self.forensic_tab,
                    "analysis_running",
                    False
                )
            ):

                messagebox.showwarning(
                    "Model Selection",
                    "A forensic analysis is currently running.\n\n"
                    "Please wait for it to finish before "
                    "switching models."
                )

                if self.current_model_name:

                    self.model_selector.set(
                        self.current_model_name
                    )

                return

        try:

            self.model_status.config(
                text=f"● Loading {model_name}...",
                fg="#F59E0B"
            )

            self.root.update_idletasks()

            # ------------------------------------------------
            # Load selected model
            # ------------------------------------------------

            model = load_model(
                model_name
            )

            # ------------------------------------------------
            # Update application state
            # ------------------------------------------------

            self.current_model = model

            self.current_model_name = (
                model_name
            )

            # ------------------------------------------------
            # Update ForensicTab
            # ------------------------------------------------

            if hasattr(
                self,
                "forensic_tab"
            ):

                self.forensic_tab.model = (
                    model
                )

                self.forensic_tab.model_name = (
                    model_name
                )

                self.forensic_tab.write_log(
                    "",
                    None
                )

                self.forensic_tab.write_log(
                    f"[+] ML model switched to: "
                    f"{model_name}",
                    "success"
                )

            # ------------------------------------------------
            # Update status
            # ------------------------------------------------

            self.model_status.config(
                text=f"● {model_name} model loaded",
                fg="#10B981"
            )

            print(
                f"[+] Active ML model: {model_name}"
            )

            print(
                f"[+] Model artifact: "
                f"{self.available_models[model_name]['model_path']}"
            )

            print(
                f"[+] Feature schema: "
                f"{self.available_models[model_name]['schema_path']}"
            )

        except Exception as err:

            self.current_model = None

            self.model_status.config(
                text=f"● Failed to load {model_name}",
                fg="#EF4444"
            )

            print(
                f"[!] Error loading model "
                f"'{model_name}': {err}"
            )

            if hasattr(
                self,
                "forensic_tab"
            ):

                self.forensic_tab.model = None

                self.forensic_tab.write_log(
                    f"[!] Failed to load model "
                    f"{model_name}: {err}",
                    "error"
                )

            messagebox.showerror(
                "Model Loading Error",
                f"Unable to load the {model_name} model.\n\n"
                f"{err}"
            )

    # ========================================================
    # MODEL ERROR
    # ========================================================

    def _show_model_error(
        self,
        message
    ):

        print(
            "[!] " + message
        )

    # ========================================================
    # WINDOW
    # ========================================================

    def _enable_resizing_and_fullscreen(
        self
    ):

        self.root.resizable(
            True,
            True
        )

        self._fullscreen_on = False

        def toggle_fullscreen(
            event=None
        ):

            self._fullscreen_on = (
                not self._fullscreen_on
            )

            self.root.attributes(
                "-fullscreen",
                self._fullscreen_on
            )

        def exit_fullscreen(
            event=None
        ):

            self._fullscreen_on = False

            self.root.attributes(
                "-fullscreen",
                False
            )

        self.root.bind(
            "<F11>",
            toggle_fullscreen
        )

        self.root.bind(
            "<Escape>",
            exit_fullscreen
        )

    # ========================================================
    # STYLE
    # ========================================================

    def _configure_style(
        self
    ):

        style = ttk.Style()

        style.theme_use(
            "default"
        )

        # ----------------------------------------------------
        # Hide native Notebook tabs.
        # ----------------------------------------------------

        try:

            style.layout(
                "Hidden.TNotebook.Tab",
                []
            )

        except tk.TclError:

            pass

        style.configure(
            "Hidden.TNotebook",
            background="#1E1E2E",
            borderwidth=0
        )

        style.configure(
            "TNotebook",
            background="#1E1E2E",
            borderwidth=0
        )

        style.configure(
            "TNotebook.Tab",
            background="#27293D",
            foreground="white",
            font=("Segoe UI", 10, "bold"),
            padding=[15, 5]
        )

        style.map(
            "TNotebook.Tab",
            background=[
                (
                    "selected",
                    "#3B82F6"
                )
            ]
        )

        # ----------------------------------------------------
        # Combobox
        # ----------------------------------------------------

        style.configure(
            "TCombobox",
            fieldbackground="#1E1E2E",
            background="#27293D",
            foreground="#F8FAFC"
        )

    # ========================================================
    # RUN
    # ========================================================

    def run(
        self
    ):

        self.root.mainloop()