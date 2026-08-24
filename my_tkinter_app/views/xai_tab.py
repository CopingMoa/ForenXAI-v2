import tkinter as tk
from tkinter import ttk, messagebox

from services.pipeline_service import save_investigator_review


class XaiTab:
    """
    Tab 2 — SHAP explanation display + human investigator review.
    Receives finished case data from ForensicTab (via MainWindow)
    once a pipeline run completes.
    """

    def __init__(self, notebook, case_output_dir):
        self.case_output_dir = case_output_dir
        self.current_case = {}

        self.frame = tk.Frame(notebook, bg="#1E1E2E")
        notebook.add(self.frame, text="SHAP & Human Review")

        self._build_ui()

    # ========================================================
    # UI CONSTRUCTION
    # ========================================================

    def _build_ui(self):
        self.lbl_case_id = tk.Label(
            self.frame, text="Case ID: Waiting for analysis",
            bg="#1E1E2E", fg="#F8FAFC", font=("Segoe UI", 11, "bold")
        )
        self.lbl_case_id.pack(anchor="w", padx=15, pady=(10, 3))

        self.lbl_hash = tk.Label(
            self.frame, text="Evidence SHA-256: Not available",
            bg="#1E1E2E", fg="#9CA3AF", font=("Consolas", 9)
        )
        self.lbl_hash.pack(anchor="w", padx=15)

        self.lbl_xai_summary = tk.Label(
            self.frame, text="No analysis available.",
            bg="#27293D", fg="#34D399", font=("Segoe UI", 11, "bold")
        )
        self.lbl_xai_summary.pack(fill="x", padx=15, pady=10)

        tk.Label(
            self.frame, text="SHAP Explanation: AI Feature Contributions",
            bg="#1E1E2E", fg="#F8FAFC", font=("Segoe UI", 10, "bold")
        ).pack(anchor="w", padx=15)

        self.txt_xai = tk.Text(
            self.frame, bg="#0F111A", fg="#A6ACCD",
            font=("Consolas", 9), height=18, state=tk.DISABLED, relief="flat"
        )
        self.txt_xai.pack(fill="both", expand=True, padx=15, pady=5)

        self._build_review_panel()

    def _build_review_panel(self):
        review_frame = tk.Frame(self.frame, bg="#27293D")
        review_frame.pack(fill="x", padx=15, pady=10)

        tk.Label(
            review_frame, text="Investigator Decision:",
            bg="#27293D", fg="#F8FAFC", font=("Segoe UI", 10, "bold")
        ).pack(side=tk.LEFT, padx=10)

        self.investigator_decision = ttk.Combobox(
            review_frame,
            values=[
                "Pending",
                "Accept AI Finding",
                "Reject AI Finding",
                "Modify AI Finding",
                "Insufficient Evidence"
            ],
            state="readonly", width=25
        )
        self.investigator_decision.set("Pending")
        self.investigator_decision.pack(side=tk.LEFT, padx=5, pady=10)

        tk.Label(
            review_frame, text="Investigator Comment:",
            bg="#27293D", fg="#F8FAFC", font=("Segoe UI", 10, "bold")
        ).pack(side=tk.LEFT, padx=10)

        self.txt_investigator_comment = tk.Text(
            review_frame, height=3, width=40,
            bg="#0F111A", fg="#F8FAFC", relief="flat"
        )
        self.txt_investigator_comment.pack(side=tk.LEFT, padx=5, pady=5)

        tk.Button(
            review_frame, text="Save Review", bg="#10B981", fg="white",
            relief="flat", font=("Segoe UI", 9, "bold"),
            command=self.save_investigator_review
        ).pack(side=tk.RIGHT, padx=10)

    # ========================================================
    # PUBLIC UPDATE ENTRY POINT (called by ForensicTab/MainWindow)
    # ========================================================

    def update_xai_results(self, current_case, shap_results):
        self.current_case = current_case

        self.lbl_case_id.config(text=f"Case ID: {current_case['case_id']}")
        self.lbl_hash.config(
            text=f"Evidence SHA-256: {current_case['pcap_sha256']}"
        )
        self.lbl_xai_summary.config(
            text=(
                f"Flows: {current_case['total_flows']} | "
                f"Benign AI Findings: {current_case['benign_flows']} | "
                f"Threat AI Findings: {current_case['threat_flows']}"
            )
        )

        self.txt_xai.config(state=tk.NORMAL)
        self.txt_xai.delete("1.0", tk.END)

        if shap_results:
            for result in shap_results[:20]:
                self.txt_xai.insert(
                    tk.END,
                    f"\nFlow {result['flow_index']} → "
                    f"AI Prediction: {result['prediction']}\n"
                )
                self.txt_xai.insert(tk.END, "Top Contributing Features:\n")

                for feature in result["top_features"]:
                    direction = (
                        "supports" if feature["shap_value"] > 0 else "opposes"
                    )
                    self.txt_xai.insert(
                        tk.END,
                        f"  • {feature['feature']} = {feature['feature_value']} "
                        f"| SHAP = {feature['shap_value']:.5f} "
                        f"| {direction} threat prediction\n"
                    )

                self.txt_xai.insert(tk.END, "\n")
        else:
            self.txt_xai.insert(tk.END, "No SHAP explanation available.")

        self.txt_xai.config(state=tk.DISABLED)

    # ========================================================
    # EVENT HANDLERS
    # ========================================================

    def save_investigator_review(self):
        if not self.current_case.get("case_id"):
            messagebox.showwarning(
                "Review", "No forensic case is currently loaded."
            )
            return

        comment = self.txt_investigator_comment.get("1.0", tk.END).strip()
        decision = self.investigator_decision.get()

        try:
            review_hash = save_investigator_review(
                self.current_case, self.case_output_dir, decision, comment
            )
        except Exception as err:
            messagebox.showerror("Review Error", str(err))
            return

        messagebox.showinfo(
            "Review Saved",
            "Investigator review saved successfully.\n\n"
            f"Decision: {decision}\n\n"
            f"Review SHA-256:\n{review_hash}"
        )
