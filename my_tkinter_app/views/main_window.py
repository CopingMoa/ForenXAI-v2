import tkinter as tk
from tkinter import ttk
from tkinterdnd2 import TkinterDnD

from views.forensic_tab import ForensicTab
from views.xai_tab import XaiTab
from views.evaluation_tab import EvaluationTab


class MainWindow:
    """
    Owns the root Tk window and wires the three tabs together.
    ForensicTab doesn't know XaiTab exists -- it just calls
    on_pipeline_complete when a case finishes, and MainWindow
    forwards that to XaiTab.update_xai_results().
    """

    def __init__(self, model, case_output_dir):
        self.root = TkinterDnD.Tk()
        self.root.title("ForenXAI")
        self.root.geometry("1150x780")
        self.root.configure(bg="#1E1E2E")

        self._enable_resizing_and_fullscreen()
        self._configure_style()

        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=15, pady=15)

        # xai_tab doesn't exist yet when forensic_tab is built, so it's
        # created first, then this forwarding function looks it up lazily
        # -- keeps tab creation order (and therefore on-screen order)
        # matching the original app: Forensic Analysis, SHAP & Review,
        # Model Evaluation.
        def forward_to_xai(current_case, shap_results):
            self.xai_tab.update_xai_results(current_case, shap_results)

        self.forensic_tab = ForensicTab(
            notebook, self.root, model, case_output_dir,
            on_pipeline_complete=forward_to_xai
        )

        self.xai_tab = XaiTab(notebook, case_output_dir)

        # self.evaluation_tab = EvaluationTab(notebook, self.root, model) --> DO NOT REMOVE (ito yung eval tab.) ginawa ko lang comment

    def _enable_resizing_and_fullscreen(self):
        self.root.resizable(True, True)

        self._fullscreen_on = False

        def toggle_fullscreen(event=None):
            self._fullscreen_on = not self._fullscreen_on
            self.root.attributes("-fullscreen", self._fullscreen_on)

        def exit_fullscreen(event=None):
            self._fullscreen_on = False
            self.root.attributes("-fullscreen", False)

        self.root.bind("<F11>", toggle_fullscreen)
        self.root.bind("<Escape>", exit_fullscreen)

    def _configure_style(self):
        style = ttk.Style()
        style.theme_use("default")

        style.configure("TNotebook", background="#1E1E2E", borderwidth=0)
        style.configure(
            "TNotebook.Tab", background="#27293D", foreground="white",
            font=("Segoe UI", 10, "bold"), padding=[15, 5]
        )
        style.map("TNotebook.Tab", background=[("selected", "#3B82F6")])

    def run(self):
        self.root.mainloop()
