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

        # NEW:
        # Discover all available model artifacts when the
        # application starts.
        #
        # This replaces the old single-model architecture
        # where main.py loaded one hardcoded model.
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
        # NOTEBOOK
        # ====================================================

        notebook = ttk.Notebook(
            self.root
        )

        notebook.pack(
            fill="both",
            expand=True,
            padx=15,
            pady=(5, 15)
        )

        self.notebook = notebook

        # ====================================================
        # XAI FORWARDING
        # ====================================================

        # XaiTab does not exist yet when ForensicTab is
        # created, so we resolve it lazily through this
        # callback after XaiTab has been initialized.
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

        # ForensicTab still receives the actual model object.
        #
        # When the user changes the dataset through the
        # selector, self.forensic_tab.model is replaced.
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
        # EVALUATION TAB
        # ====================================================

        # KEEPING THIS COMMENTED FOR NOW.
        #
        # The existing project intentionally has the
        # EvaluationTab disabled. We are not changing its
        # behavior in this step.
        #
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
    # MODEL SELECTOR UI
    # ========================================================

    def _build_model_selector(self):

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
        # Prevent switching while forensic analysis is
        # actively running.
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

            # NEW:
            # Load the model based on the selected dataset.
            #
            # Old behavior:
            #     load_model()
            #
            # New behavior:
            #     load_model("CIDS2018")
            #     load_model("TII")
            #     load_model("Combined")
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

                # NEW:
                # Store the selected dataset name as well.
                #
                # This will be used in the next step when
                # pipeline_service.py receives the dataset
                # schema.
                self.forensic_tab.model_name = (
                    model_name
                )

                # Write a visible message to the forensic
                # pipeline console.
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

        # NEW:
        # Style the model selector so it fits the existing
        # dark ForenXAI UI.
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