"""
xai_tab.py
==========

Tab 2 -- the three explanation panels, plus the investigator review.

    1  Flow summary      what the flow table holds, and who talked to whom
    2  Why this decision SHAP attributions for the selected finding
    3  Recommendations   what to do, quoting retrieved documentation

Nothing is computed here. services/panels_service.py returns plain dicts and
this file renders them, so the analysis can be tested without a display and
the layout can change without touching the analysis.

The public entry point ``update_xai_results(current_case, shap_results)`` is
unchanged, so MainWindow needs no edit. The panels are driven by
``current_case["generated_csv_path"]`` -- the CICFlowMeter output ForensicTab
already produces.
"""

import os
import queue
import threading
import tkinter as tk
from tkinter import ttk, messagebox

from services.pipeline_service import save_investigator_review
from services.panels_service import build_panels, bundle_available


# ============================================================
# PALETTE (matches the existing tabs)
# ============================================================

BG = "#1E1E2E"
PANEL = "#27293D"
TEXT_BG = "#0F111A"
FG = "#F8FAFC"
MUTED = "#9CA3AF"
BODY = "#A6ACCD"
GOOD = "#34D399"
WARN = "#FBBF24"
BAD = "#F87171"


class XaiTab:
    """Explanation panels and human review."""

    def __init__(self, notebook, case_output_dir):
        self.case_output_dir = case_output_dir
        self.current_case = {}
        self.panels = None

        # Worker threads put results here; _poll drains it on the main
        # thread. Calling widget.after() from a worker raises
        # "main thread is not in main loop" whenever the loop has not
        # started yet, and a background analysis can finish before it has.
        self._results = queue.Queue()

        self.frame = tk.Frame(notebook, bg=BG)
        notebook.add(self.frame, text="SHAP & Human Review")

        self._build_ui()

    # ========================================================
    # UI CONSTRUCTION
    # ========================================================

    def _build_ui(self):
        self.lbl_case_id = tk.Label(
            self.frame, text="Case ID: Waiting for analysis",
            bg=BG, fg=FG, font=("Segoe UI", 11, "bold")
        )
        self.lbl_case_id.pack(anchor="w", padx=15, pady=(10, 3))

        self.lbl_hash = tk.Label(
            self.frame, text="Evidence SHA-256: Not available",
            bg=BG, fg=MUTED, font=("Consolas", 9)
        )
        self.lbl_hash.pack(anchor="w", padx=15)

        self.lbl_xai_summary = tk.Label(
            self.frame, text="No analysis available.",
            bg=PANEL, fg=GOOD, font=("Segoe UI", 11, "bold")
        )
        self.lbl_xai_summary.pack(fill="x", padx=15, pady=8)

        # The three panels get their own notebook so each has the full
        # width. Stacked vertically none of them is tall enough to read.
        self.panel_nb = ttk.Notebook(self.frame)
        self.panel_nb.pack(fill="both", expand=True, padx=15, pady=(0, 5))

        self.txt_summary = self._add_panel("1 - Flow Summary")
        self._build_shap_panel()
        self.txt_recommend = self._add_panel("3 - Recommendations")

        self._build_review_panel()
        self._poll()

    def _poll(self):
        """Drain finished analyses on the main thread. Tk is not thread-safe."""
        try:
            while True:
                kind, result = self._results.get_nowait()
                if kind == "all":
                    self._render_all(result)
                else:
                    self._render_selected(result)
        except queue.Empty:
            pass
        self.frame.after(120, self._poll)

    def _add_panel(self, title):
        """A scrollable read-only text panel."""
        frame = tk.Frame(self.panel_nb, bg=BG)
        self.panel_nb.add(frame, text=title)

        bar = tk.Scrollbar(frame)
        bar.pack(side=tk.RIGHT, fill="y")

        txt = tk.Text(
            frame, bg=TEXT_BG, fg=BODY, font=("Consolas", 9),
            state=tk.DISABLED, relief="flat", wrap="word",
            yscrollcommand=bar.set
        )
        txt.pack(fill="both", expand=True)
        bar.config(command=txt.yview)

        self._tag(txt)
        return txt

    @staticmethod
    def _tag(txt):
        txt.tag_config("h", foreground=FG, font=("Segoe UI", 10, "bold"))
        txt.tag_config("muted", foreground=MUTED)
        txt.tag_config("good", foreground=GOOD)
        txt.tag_config("warn", foreground=WARN)
        txt.tag_config("bad", foreground=BAD)

    def _build_shap_panel(self):
        """
        Panel 2 needs a findings list beside the explanation, because SHAP
        runs per finding rather than over the whole capture.
        """
        frame = tk.Frame(self.panel_nb, bg=BG)
        self.panel_nb.add(frame, text="2 - Why This Decision")

        left = tk.Frame(frame, bg=BG)
        left.pack(side=tk.LEFT, fill="y", padx=(0, 8))

        tk.Label(left, text="Findings", bg=BG, fg=FG,
                 font=("Segoe UI", 10, "bold")).pack(anchor="w")
        tk.Label(left, text="class · flows · confidence", bg=BG, fg=MUTED,
                 font=("Segoe UI", 8)).pack(anchor="w", pady=(0, 4))

        self.lst_findings = tk.Listbox(
            left, bg=TEXT_BG, fg=BODY, font=("Consolas", 9),
            width=34, height=18, relief="flat",
            selectbackground=PANEL, activestyle="none"
        )
        self.lst_findings.pack(fill="y", expand=True)

        # [UI CONNECTION: selecting a finding recomputes panels 2 and 3 for
        #  that class. SHAP costs 8.1 ms per flow against 20 microseconds to
        #  classify -- a 400x difference -- so it runs only for the two
        #  representative flows of the selected finding, never the capture.]
        self.lst_findings.bind("<<ListboxSelect>>", self._on_finding_selected)

        right = tk.Frame(frame, bg=BG)
        right.pack(side=tk.LEFT, fill="both", expand=True)

        bar = tk.Scrollbar(right)
        bar.pack(side=tk.RIGHT, fill="y")

        self.txt_shap = tk.Text(
            right, bg=TEXT_BG, fg=BODY, font=("Consolas", 9),
            state=tk.DISABLED, relief="flat", wrap="word",
            yscrollcommand=bar.set
        )
        self.txt_shap.pack(fill="both", expand=True)
        bar.config(command=self.txt_shap.yview)

        self._tag(self.txt_shap)

    def _build_review_panel(self):
        review_frame = tk.Frame(self.frame, bg=PANEL)
        review_frame.pack(fill="x", padx=15, pady=10)

        tk.Label(
            review_frame, text="Investigator Decision:",
            bg=PANEL, fg=FG, font=("Segoe UI", 10, "bold")
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
            bg=PANEL, fg=FG, font=("Segoe UI", 10, "bold")
        ).pack(side=tk.LEFT, padx=10)

        self.txt_investigator_comment = tk.Text(
            review_frame, height=3, width=40,
            bg=TEXT_BG, fg=FG, relief="flat"
        )
        self.txt_investigator_comment.pack(side=tk.LEFT, padx=5, pady=5)

        tk.Button(
            review_frame, text="Save Review", bg="#10B981", fg="white",
            relief="flat", font=("Segoe UI", 9, "bold"),
            command=self.save_investigator_review
        ).pack(side=tk.RIGHT, padx=10)

    # ========================================================
    # WRITING HELPER
    # ========================================================

    @staticmethod
    def _write(widget, blocks):
        """blocks is a list of (text, tag) pairs; tag may be None."""
        widget.config(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        for text, tag in blocks:
            widget.insert(tk.END, text, tag or ())
        widget.config(state=tk.DISABLED)

    # ========================================================
    # PUBLIC UPDATE ENTRY POINT (called by ForensicTab/MainWindow)
    # ========================================================

    def update_xai_results(self, current_case, shap_results=None):
        """
        Signature unchanged, so MainWindow needs no edit.

        `shap_results` is the legacy per-flow list. It is accepted and
        ignored: these panels compute their own attributions from the flow
        CSV using the sixteen-class bundle, which the legacy path does not
        have.
        """
        self.current_case = current_case

        self.lbl_case_id.config(
            text=f"Case ID: {current_case.get('case_id', 'unknown')}"
        )
        self.lbl_hash.config(
            text=f"Evidence SHA-256: {current_case.get('pcap_sha256')}"
        )
        self.lbl_xai_summary.config(
            text=(
                f"Flows: {current_case.get('total_flows', 0):,} | "
                f"Benign AI Findings: {current_case.get('benign_flows', 0):,} | "
                f"Threat AI Findings: {current_case.get('threat_flows', 0):,}"
            )
        )

        # [UI CONNECTION: the panels are driven by the CICFlowMeter CSV that
        #  ForensicTab already writes, not by the legacy shap_results.]
        csv_path = current_case.get("generated_csv_path")

        if not csv_path or not os.path.isfile(csv_path):
            self._write(self.txt_summary, [
                ("No flow table available.\n\n", "bad"),
                ("Run an analysis in the Forensic tab first. This panel "
                 "reads the CICFlowMeter CSV that step produces.", "muted"),
            ])
            return

        ok, detail = bundle_available()
        if not ok:
            self._write(self.txt_summary, [
                ("Explanation bundle not available.\n\n", "bad"),
                (detail + "\n\n", None),
                ("Copy the ForenXAI deploy bundle into models/forenxai/.",
                 "muted"),
            ])
            return

        self._write(self.txt_summary, [("Analysing flows...\n", "muted")])

        # Loading the model and computing SHAP takes seconds. On the Tk
        # thread that freezes the window, which reads as a crash.
        threading.Thread(
            target=self._compute, args=(csv_path, current_case), daemon=True
        ).start()

    def _compute(self, csv_path, current_case):
        source = os.path.basename(current_case.get("pcap_path") or csv_path)
        try:
            result = build_panels(csv_path, source, finding_index=0)
        except Exception as e:                      # never lose a worker crash
            result = {"error": f"{type(e).__name__}: {e}"}
        self._results.put(("all", result))

    # ========================================================
    # RENDERERS -- one per panel
    # ========================================================

    def _render_all(self, result):
        if "error" in result:
            self._write(self.txt_summary, [
                ("Analysis failed.\n\n", "bad"),
                (result["error"], None),
            ])
            return

        self.panels = result
        self._render_summary(result["summary"])
        self._render_findings(result["findings"])

        if result.get("shap"):
            self._render_shap(result["shap"], result["selected"])
            self._render_recommend(result["recommend"])
        else:
            note = result.get("note", "Nothing to explain.")
            self._write(self.txt_shap, [(note, "muted")])
            self._write(self.txt_recommend, [(note, "muted")])

    def _render_summary(self, summary):
        """[UI CONNECTION: facts -> stat lines, lines -> prose]"""
        f = summary["facts"]
        blocks = [("FLOW SUMMARY\n\n", "h")]

        for line in summary["lines"]:
            if line.startswith("WARNING"):
                blocks.append(("\n" + line + "\n", "warn"))
            elif line:
                blocks.append((line + "\n", None))

        blocks.append(("\nCLASS DISTRIBUTION\n", "h"))
        total = max(1, f["total_flows"])
        for cls, n in f["class_counts"].items():
            bar = "#" * max(1, int(28 * n / total))
            blocks.append((f"  {cls:<16}{n:>6,}  {bar}\n",
                           "good" if cls == "Benign" else None))

        if "longest_flow_seconds" in f:
            blocks.append(("\nFLOW DURATION\n", "h"))
            blocks.append((
                f"  longest   {f['longest_flow_seconds']:>12,.1f} s\n"
                f"  median    {f['median_flow_seconds']:>12,.3f} s\n"
                f"  total     {f['total_flow_seconds']:>12,.1f} s"
                f"   (sum of all flows; they overlap, so not a span)\n",
                "muted"))

        self._write(self.txt_summary, blocks)

    def _render_findings(self, findings):
        self.lst_findings.delete(0, tk.END)
        for f in findings:
            tgt = (f.get("endpoints", {}).get("targets") or [{}])[0]
            suffix = f"  {tgt['address']}" if tgt.get("address") else ""
            self.lst_findings.insert(
                tk.END,
                f"{f['class']:<15}{f['flow_count']:>5}  "
                f"{f['confidence_mean']:.2f}{suffix}"
            )
        if findings:
            self.lst_findings.selection_set(0)

    def _render_shap(self, shap_panel, finding):
        """[UI CONNECTION: attributions -> bars; `plain` is the label]"""
        blocks = [
            (f"WHY THIS IS {finding['class'].upper()}\n\n", "h"),
            (f"{finding['flow_count']:,} flows, mean confidence "
             f"{finding['confidence_mean']:.2f}\n", None),
        ]

        tgt = (finding.get("endpoints", {}).get("targets") or [{}])[0]
        src = (finding.get("endpoints", {}).get("sources") or [{}])[0]
        if tgt.get("address"):
            blocks.append((
                f"Mainly against {tgt['address']} ({tgt['flows']:,} flows)"
                + (f", from {src['address']}" if src.get("address") else "")
                + ".\n", None))

        if finding["dominant_runner_up_share"] > 0.25:
            blocks.append((
                f"The model nearly said {finding['dominant_runner_up']} for "
                f"{finding['dominant_runner_up_share']:.0%} of these flows.\n",
                "warn"))

        blocks.append((
            f"\nContributions are {shap_panel['units']}. They rank evidence "
            f"against each other. They are NOT percentages and do not say "
            f"how far the probability moved.\n", "muted"))

        labels = ["most confident flow", "least confident flow"]

        for i, d in enumerate(shap_panel["detections"]):
            label = labels[i] if i < len(labels) else f"flow {d['row']}"
            blocks.append((f"\n{'-' * 62}\n", "muted"))
            blocks.append((f"{label.upper()}  (row {d['row']})\n", "h"))
            blocks.append((
                f"predicted {d['predicted']} at {d['confidence']:.3f}; "
                f"runner-up {d['runner_up']} at "
                f"{d['runner_up_confidence']:.3f}\n\n", None))

            top = max(abs(a["contribution"]) for a in d["attributions"]) or 1
            for a in d["attributions"]:
                n = max(1, int(18 * abs(a["contribution"]) / top))
                bar = ("+" if a["contribution"] > 0 else "-") * n
                blocks.append((f"  {bar:<19}",
                               "good" if a["contribution"] > 0 else "bad"))
                blocks.append((f"{a['contribution']:+7.3f}  {a['plain']}\n",
                               None))
                blocks.append((
                    f"  {'':<19}         value {a['raw_value']:,.4f}\n",
                    "muted"))

            if d["class_typical"]:
                blocks.append((
                    f"\n  Typical drivers for {d['predicted']}: "
                    f"{', '.join(d['class_typical'][:4])}\n", "muted"))

        self._write(self.txt_shap, blocks)

    def _render_recommend(self, rec):
        """[UI CONNECTION: sections -> headed blocks, citations -> sources]"""
        blocks = [(f"RECOMMENDATIONS -- {rec['class']}\n\n", "h")]

        if rec["mitre"]:
            blocks.append((
                f"MITRE ATT&CK: {', '.join(rec['mitre'])}   "
                "(unverified -- review before citing)\n\n", "muted"))

        for s in rec["sections"]:
            blocks.append((f"{s['heading'].upper()}\n",
                           "warn" if s["heading"] == "Ambiguity" else "h"))
            blocks.append((s["body"] + "\n\n", None))

        if rec["citations"]:
            blocks.append(("SOURCES\n", "h"))
            for c in rec["citations"]:
                blocks.append((f"  {c}\n", "good"))

        if rec["missing_documents"]:
            blocks.append(("\nNOT AVAILABLE\n", "h"))
            for m in rec["missing_documents"]:
                blocks.append((f"  {m}\n", "bad"))
            blocks.append((
                "\nNothing is recommended for the missing documents. Any "
                "advice there would come from outside the evidence.\n",
                "muted"))

        self._write(self.txt_recommend, blocks)

    # ========================================================
    # EVENT HANDLERS
    # ========================================================

    def _on_finding_selected(self, _event=None):
        """Recompute panels 2 and 3 for the chosen finding."""
        if not self.panels or not self.panels.get("findings"):
            return

        sel = self.lst_findings.curselection()
        if not sel:
            return

        csv_path = self.current_case.get("generated_csv_path")
        if not csv_path:
            return

        index = sel[0]
        self._write(self.txt_shap, [("Computing SHAP...\n", "muted")])

        def work():
            source = os.path.basename(
                self.current_case.get("pcap_path") or csv_path
            )
            try:
                result = build_panels(csv_path, source, finding_index=index)
            except Exception as e:
                result = {"error": f"{type(e).__name__}: {e}"}
            self._results.put(("selected", result))

        threading.Thread(target=work, daemon=True).start()

    def _render_selected(self, result):
        if "error" in result:
            self._write(self.txt_shap, [(result["error"], "bad")])
            return

        self.panels = result
        if result.get("shap"):
            self._render_shap(result["shap"], result["selected"])
            self._render_recommend(result["recommend"])

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
