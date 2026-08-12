import threading

import tkinter as tk
from tkinter import messagebox
from tkinterdnd2 import DND_FILES

import seaborn as sns
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from services.evaluation_service import run_evaluation


class EvaluationTab:
    """
    Tab 3 — Model Evaluation against a labeled validation/test CSV.
    Separate from live forensic PCAP analysis (that has unknown
    ground truth and can't produce these metrics).
    """

    def __init__(self, notebook, root, model):
        self.root = root
        self.model = model

        self.frame = tk.Frame(notebook, bg="#1E1E2E")
        notebook.add(self.frame, text="Model Evaluation")

        self._build_ui()

    # ========================================================
    # UI CONSTRUCTION
    # ========================================================

    def _build_ui(self):
        tk.Label(
            self.frame, text="Validation Mode",
            bg="#1E1E2E", fg="#F8FAFC", font=("Segoe UI", 12, "bold")
        ).pack(anchor="w", padx=15, pady=(10, 2))

        tk.Label(
            self.frame,
            text=(
                "This is separate from forensic PCAP analysis. "
                "A random PCAP has unknown ground truth and "
                "cannot be used to calculate confusion-matrix metrics."
            ),
            bg="#1E1E2E", fg="#9CA3AF", font=("Segoe UI", 9),
            wraplength=900, justify="left"
        ).pack(anchor="w", padx=15, pady=(0, 10))

        self._build_drop_header()
        self._build_results_body()

    def _build_drop_header(self):
        eval_header = tk.Frame(
            self.frame, bg="#27293D",
            highlightbackground="#374151", highlightthickness=1
        )
        eval_header.pack(fill="x", pady=10)

        lbl_eval_drop = tk.Label(
            eval_header,
            text="☁️ Drop Labeled Validation/Test CSV (must contain label_binary)",
            bg="#1E1E2E", fg="#9CA3AF", font=("Segoe UI", 11), height=2,
            highlightbackground="#4B5563", highlightthickness=1
        )
        lbl_eval_drop.pack(pady=10, padx=20, fill="x")
        lbl_eval_drop.drop_target_register(DND_FILES)
        lbl_eval_drop.dnd_bind("<<Drop>>", self.eval_drop_file)

        self.lbl_eval_file = tk.Label(
            eval_header, text="Waiting for labeled evaluation dataset...",
            font=("Segoe UI", 10, "italic"), bg="#27293D", fg="#6B7280"
        )
        self.lbl_eval_file.pack(pady=(0, 10))

    def _build_results_body(self):
        eval_body = tk.Frame(self.frame, bg="#1E1E2E")
        eval_body.pack(fill="both", expand=True)

        self.cm_frame = tk.Frame(
            eval_body, bg="#27293D",
            highlightbackground="#374151", highlightthickness=1, width=400
        )
        self.cm_frame.pack(side=tk.LEFT, fill="y", padx=(0, 10))
        self.cm_frame.pack_propagate(False)

        stats_frame = tk.Frame(eval_body, bg="#1E1E2E")
        stats_frame.pack(side=tk.RIGHT, fill="both", expand=True)

        self.lbl_acc, self.lbl_prec = self._make_stat_row(
            stats_frame, "Accuracy:", "Precision:"
        )
        self.lbl_rec, self.lbl_spec = self._make_stat_row(
            stats_frame, "Recall / TPR:", "Specificity / TNR:"
        )
        self.lbl_f1, self.lbl_macro = self._make_stat_row(
            stats_frame, "F1 Score:", "Macro F1:"
        )
        self.lbl_roc, self.lbl_pr = self._make_stat_row(
            stats_frame, "ROC-AUC:", "PR-AUC:"
        )
        self.lbl_fpr, self.lbl_fnr = self._make_stat_row(
            stats_frame, "False Pos (FPR):", "False Neg (FNR):"
        )
        self.lbl_weight, _ = self._make_stat_row(
            stats_frame, "Weighted F1:", ""
        )

        tk.Label(
            stats_frame, text="Per-Class Performance Report",
            font=("Segoe UI", 10, "bold"), bg="#1E1E2E", fg="#F8FAFC"
        ).pack(anchor="w", padx=10, pady=(20, 5))

        self.txt_report = tk.Text(
            stats_frame, bg="#0F111A", fg="#A6ACCD",
            font=("Consolas", 9), height=8, state=tk.DISABLED,
            relief="flat", padx=10, pady=10
        )
        self.txt_report.pack(fill="x", padx=10)

    @staticmethod
    def _make_stat_row(parent, title1, title2):
        f = tk.Frame(parent, bg="#1E1E2E")
        f.pack(fill="x", pady=2)

        tk.Label(
            f, text=title1, font=("Segoe UI", 10, "bold"),
            bg="#1E1E2E", fg="#9CA3AF", width=15, anchor="w"
        ).pack(side=tk.LEFT, padx=10)

        v1 = tk.Label(
            f, text="-", font=("Segoe UI", 11),
            bg="#1E1E2E", fg="#34D399", width=10, anchor="w"
        )
        v1.pack(side=tk.LEFT)

        tk.Label(
            f, text=title2, font=("Segoe UI", 10, "bold"),
            bg="#1E1E2E", fg="#9CA3AF", width=15, anchor="w"
        ).pack(side=tk.LEFT, padx=10)

        v2 = tk.Label(
            f, text="-", font=("Segoe UI", 11),
            bg="#1E1E2E", fg="#34D399", width=10, anchor="w"
        )
        v2.pack(side=tk.LEFT)

        return v1, v2

    # ========================================================
    # EVENT HANDLERS
    # ========================================================

    def eval_drop_file(self, event):
        raw_path = event.data.strip("{}").strip('"')

        if raw_path.lower().endswith(".csv"):
            import os
            self.lbl_eval_file.config(
                text=f"Evaluation dataset: {os.path.basename(raw_path)}",
                fg="#10B981"
            )
            threading.Thread(
                target=self._run_evaluation, args=(raw_path,), daemon=True
            ).start()
        else:
            self.lbl_eval_file.config(
                text="Invalid file. Drop a labeled evaluation CSV.",
                fg="#EF4444"
            )

    def _run_evaluation(self, csv_path):
        try:
            metrics = run_evaluation(self.model, csv_path)
            self.root.after(0, lambda: self._update_ui(metrics))

        except Exception as err:
            self.root.after(
                0, lambda: messagebox.showerror("Evaluation Error", str(err))
            )

    # ========================================================
    # RESULTS RENDERING (runs on main thread via root.after)
    # ========================================================

    def _update_ui(self, metrics):
        self.lbl_acc.config(text=f"{metrics['accuracy']:.4f}")
        self.lbl_prec.config(text=f"{metrics['precision']:.4f}")
        self.lbl_rec.config(text=f"{metrics['recall']:.4f}")
        self.lbl_spec.config(text=f"{metrics['specificity']:.4f}")
        self.lbl_f1.config(text=f"{metrics['f1']:.4f}")
        self.lbl_fpr.config(text=f"{metrics['fpr']:.4f}")
        self.lbl_fnr.config(text=f"{metrics['fnr']:.4f}")
        self.lbl_roc.config(text=f"{metrics['roc_auc']:.4f}")
        self.lbl_pr.config(text=f"{metrics['pr_auc']:.4f}")
        self.lbl_macro.config(text=f"{metrics['macro_f1']:.4f}")
        self.lbl_weight.config(text=f"{metrics['weighted_f1']:.4f}")

        report = metrics["classification_report"]
        report_str = ""

        if "0" in report:
            report_str += (
                "Class 0 (Benign)\n"
                f"Precision: {report['0']['precision']:.4f}\n"
                f"Recall: {report['0']['recall']:.4f}\n"
                f"F1: {report['0']['f1-score']:.4f}\n"
                f"Support: {report['0']['support']}\n\n"
            )

        if "1" in report:
            report_str += (
                "Class 1 (Threat)\n"
                f"Precision: {report['1']['precision']:.4f}\n"
                f"Recall: {report['1']['recall']:.4f}\n"
                f"F1: {report['1']['f1-score']:.4f}\n"
                f"Support: {report['1']['support']}\n"
            )

        self.txt_report.config(state=tk.NORMAL)
        self.txt_report.delete("1.0", tk.END)
        self.txt_report.insert(tk.END, report_str)
        self.txt_report.config(state=tk.DISABLED)

        for widget in self.cm_frame.winfo_children():
            widget.destroy()

        fig, ax = plt.subplots(figsize=(4.5, 3.5))
        sns.heatmap(
            metrics["confusion_matrix"], annot=True, fmt="d",
            cmap="Blues", cbar=False,
            xticklabels=["Benign (0)", "Threat (1)"],
            yticklabels=["Benign (0)", "Threat (1)"],
            ax=ax
        )
        ax.set_xlabel("Predicted Label")
        ax.set_ylabel("True Label")
        ax.set_title("Confusion Matrix")
        fig.tight_layout()

        canvas = FigureCanvasTkAgg(fig, master=self.cm_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        plt.close(fig)
