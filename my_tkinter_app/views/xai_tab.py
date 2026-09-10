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

from services.llm_provider import OLLAMA_MODEL
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
        self._progress_lines = []
        # Which analysis the panels currently belong to. Narration
        # takes 45-60 s, which is long enough for a second capture to
        # be uploaded while the first is still being explained. The
        # worker carries the id it started under; a result whose id is
        # no longer current is dropped rather than rendered.
        self._run_id = 0

        # Narration is part of the pipeline, not a setting.
        #
        # It used to be two checkboxes, both off. That made the plain-English
        # layer something a user had to know to ask for, and it meant the
        # panels an investigator saw depended on a preference rather than on
        # the evidence. All three panels are narrated, every run.
        #
        # What has NOT changed is that narration is additive: every number,
        # label, quote and citation is computed and rendered without it, so
        # an unavailable model costs prose and never evidence. That is now
        # enforced rather than offered -- see _compute(), which still builds
        # the panels when the provider cannot be reached.
        self.provider_name = "ollama"

        self.frame = tk.Frame(notebook, bg=BG)
        notebook.add(self.frame, text="SHAP & Human Review")

        self._build_ui()
        self._warm_source_cache()

    @staticmethod
    def _warm_source_cache():
        """Extract and cache the source PDFs in the background, at start-up.

        Turning 3.7M characters of PDF into text costs about 30 seconds the
        first time. Left to the first finding, that 30 seconds lands in the
        middle of an analysis and reads as a hang. Done here it overlaps
        with the user choosing a capture, and every later verification is a
        0.2 s disk read.

        Daemon, and failures are swallowed on purpose: a warm cache is an
        optimisation, and source_guard rebuilds anything missing on demand.
        """
        def work():
            try:
                from services.source_guard import (normalised_source,
                                                   raw_source)
                import fetch_knowledge as fk
                for key in fk.SOURCES:
                    normalised_source(key)
                    raw_source(key)
            except Exception:
                pass

            # Then the model, for the same reason and at a larger saving.
            # Ollama loads 4.7 GB on the first request and holds it for five
            # minutes; paying that inside the first analysis costs 30 s of
            # the 89 s an analyst waits (25 s of 25 s on a 3B model). Loading
            # it here spends that while they are still choosing a capture.
            #
            # One token, not a real prompt: the cost being avoided is
            # resident weights, and generating anything more would occupy
            # the model when the analysis wants it.
            try:
                from services.llm_provider import get_provider
                provider = get_provider("ollama")
                ok, _ = provider.available()
                if ok:
                    provider.complete("You are a warm-up.", "Reply: ok",
                                      max_tokens=1, retries=0)
            except Exception:
                pass

        threading.Thread(target=work, daemon=True).start()

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

        bar = tk.Frame(self.frame, bg=PANEL)
        bar.pack(fill="x", padx=15, pady=8)

        self.lbl_xai_summary = tk.Label(
            bar, text="No analysis available.",
            bg=PANEL, fg=GOOD, font=("Segoe UI", 11, "bold")
        )
        self.lbl_xai_summary.pack(side=tk.LEFT, padx=10, pady=6)

        # Narration is stated, not offered. The checkboxes that used to sit
        # here made the plain-English layer opt-in; it now runs on every
        # panel, so what belongs in the bar is a label saying which model
        # wrote the prose and that it is checked before it is shown.
        self.lbl_narrator = tk.Label(
            bar, text=f"Plain English by {OLLAMA_MODEL} (local) - every claim "
                      "checked against the evidence",
            bg=PANEL, fg=MUTED, font=("Segoe UI", 9)
        )
        self.lbl_narrator.pack(side=tk.RIGHT, padx=(12, 8))

        # Appears only when a retrieved document's quotes no longer match the
        # PDF they name. Repair is never automatic: it edits a sourced file,
        # so it is a decision someone takes and sees the result of.
        self._quarantined = []
        self.btn_repair = tk.Button(
            bar, text="Repair quoted sources", command=self._on_repair,
            state=tk.DISABLED, bg=PANEL, fg=MUTED,
            activebackground=TEXT_BG, activeforeground=FG,
            font=("Segoe UI", 9), relief="flat", bd=0,
            highlightthickness=0, cursor="hand2"
        )
        self.btn_repair.pack(side=tk.RIGHT, padx=(0, 10))

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
                kind, result, run_id = self._results.get_nowait()
                # A result from a capture that is no longer loaded. The
                # worker had no way to know; this is where it is noticed.
                if run_id != self._run_id:
                    continue
                if kind == "status":
                    self._show_progress(result)
                elif kind == "all":
                    self._render_all(result)
                else:
                    self._render_selected(result)
        except queue.Empty:
            pass
        self.frame.after(120, self._poll)

    def _reset_panels(self, message):
        """Clear every panel, and stop caring about work already running.

        A new capture must not share the screen with the last one. Panel 1
        used to be overwritten with "Analysing flows..." while panels 2 and
        3 kept the PREVIOUS capture's explanation and recommendations --
        for the 45-60 s narration takes, and permanently on the two paths
        that return early. The header said one capture; two thirds of the
        window described another.

        In a forensics tool that is not a cosmetic bug. The recommendation
        panel names an attack class and cites a playbook, and it would have
        been describing evidence the investigator was no longer looking at.

        Returns the id this analysis runs under.
        """
        self._run_id += 1

        # Anything the outgoing analysis already queued is now about the
        # wrong capture. _poll would render it into the cleared panels.
        try:
            while True:
                self._results.get_nowait()
        except queue.Empty:
            pass

        self._progress_lines = []
        self.panels = None
        self._quarantined = []
        self.btn_repair.config(state=tk.DISABLED)
        self.lst_findings.delete(0, tk.END)

        for widget in (self.txt_summary, self.txt_shap, self.txt_recommend):
            self._write(widget, [(message + "\n", "muted")])

        # The review belongs to the case it was written about. Carrying a
        # decision across to a different capture would attribute it to
        # evidence the investigator never saw.
        self.investigator_decision.set("Pending")
        self.txt_investigator_comment.delete("1.0", tk.END)

        return self._run_id

    def _show_progress(self, sentence):
        """One line per stage, in the summary panel, while the work runs.

        Appended rather than replaced: by the end the analyst has a short
        account of what was done to their capture, which is worth more than
        a spinner and is already most of an audit trail. _render_all()
        overwrites the panel when the real summary arrives.
        """
        self._progress_lines.append(sentence)
        self._write(self.txt_summary,
                    [(line + "\n", "muted")
                     for line in self._progress_lines])

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
    def _step_blocks(text):
        """Lay out the recommendation steps for a reader, not a debugger.

        The model returns markdown bold and an `ANCHOR:` line per step. Both
        are machinery: the asterisks render literally in a Text widget, and
        the anchor is provenance rather than instruction. So the step is
        shown as a numbered sentence with its reference markers, and the
        anchor is demoted to a quiet line beneath it -- still visible,
        because it is what makes the step checkable, but no longer competing
        with the advice for the reader's attention.
        """
        import re as _re

        blocks, step = [], 0
        for para in _re.split(r"\n\s*\n", text.strip()):
            para = para.strip()
            if not para:
                continue

            if para.lower().startswith("not covered"):
                blocks.append(("\n  Not covered by this playbook\n", "h"))
                body = para.split(":", 1)[-1].strip()
                blocks.append((f"    {body}\n", "muted"))
                continue

            anchor = ""
            m = _re.search(r"ANCHOR:\s*(.+?)\s*$", para, _re.M | _re.I)
            if m:
                anchor = m.group(1).strip()
                para = para[:m.start()].strip()

            # Markers travel with the sentence, not with the anchor.
            markers = "".join(_re.findall(r"\[\d{1,2}\]", anchor))
            anchor = _re.sub(r"\s*\[\d{1,2}\]", "", anchor).strip()

            sentence = _re.sub(r"\*\*|__", "", para).strip()
            sentence = _re.sub(r"^\s*\d+[.)]\s*", "", sentence).strip()
            sentence = _re.sub(r"\s+", " ", sentence)
            if not sentence:
                continue

            step += 1
            blocks.append((f"  {step}. {sentence} {markers}\n".rstrip() + "\n",
                           None))
            if anchor:
                blocks.append((f"       from the playbook: \"{anchor}\"\n",
                               "muted"))
            blocks.append(("\n", None))

        return blocks

    @staticmethod
    def _narration_blocks(panel):
        """
        The model's paragraph, above the evidence it describes.

        Labelled every time. An investigator must be able to tell which
        words came from a language model and which are measurements, and
        the answer cannot depend on remembering a setting.
        """
        text = panel.get("narrative")
        withheld = panel.get("narration_withheld")

        if not text:
            # No paragraph at all, from any source. The panel below is
            # complete on its own, so it is shown without a heading rather
            # than with an explanation of an absence.
            return []

        if text and "ANCHOR:" in text.upper():
            # No heading of its own -- panel 3 numbers its own sections, and
            # two headings for one block reads as a formatting fault. What
            # is left is the attribution, which must stay: these sentences
            # are model-written and the reader has to know that.
            out = [("  Written by a local model from the playbook below. "
                    "Each step quotes the line that prescribes it.\n\n",
                    "muted")]
            out += XaiTab._step_blocks(text)
        else:
            # The heading names who wrote the paragraph, which is what a
            # reader needs in order to weigh it. When the model's own words
            # fail their checks the panel now shows the same summary written
            # from the figures instead, so the honest label is "summarised
            # from the figures" -- never an explanation of an absent
            # paragraph.
            source = ("summarised from the figures below"
                      if panel.get("narration_fallback")
                      else "written by a local model from the figures below")
            out = [
                (f"PLAIN ENGLISH  ({source})\n", "h"),
                (text.strip() + "\n", None),
            ]

        # NOTHING ABOUT THE MACHINERY IS PRINTED HERE.
        #
        # This block used to carry, in turn: a note that the context was
        # truncated, a line naming the words the neutraliser cut, a verdict,
        # and one row per finding tagged "[high] anchors:". All of it
        # describes how the text was produced rather than what was found, and
        # an investigator reading a capture has no use for any of it. The
        # panel now shows the text and its source, or -- when the model's
        # words did not survive their checks -- the same summary composed
        # from the figures. Either way it reads as a report about the
        # capture.
        #
        # None of it is lost. Every finding, edit, verdict and note stays on
        # the panel for the saved case, and narrate() prints them to the
        # console as they happen, which is where whoever is running the tool
        # can see them.

        # Who wrote it and from what, in words. The token count and the
        # prompt hash are an audit record, not a caption; they stay in
        # narration_provenance for the saved case.
        pr = panel.get("narration_provenance") or {}
        if panel.get("narration_fallback"):
            # Attributing this paragraph to the model would be false: the
            # model's words were withheld and this one was composed from the
            # panel's own figures. What ran is still recorded in
            # narration_provenance for the saved case.
            out.append(("  Composed from the figures on this panel, not "
                        "written by a language model.\n", "muted"))
        elif pr.get("model"):
            docs = pr.get("sources_supplied")
            out.append((
                f"  Written by {pr['model']} running on this machine, "
                + (f"from {', '.join(docs)}." if docs
                   else "from the figures above.")
                + "\n", "muted"))

        out.append(("\n" + "-" * 62 + "\n\n", "muted"))
        return out

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
        # Before anything else, including the two early returns below. The
        # panels must never describe a capture other than the one named in
        # the header.
        run_id = self._reset_panels("Waiting for the analysis to start.")

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
            target=self._compute, args=(csv_path, current_case, run_id),
            daemon=True
        ).start()

    def _compute(self, csv_path, current_case, run_id):
        source = os.path.basename(current_case.get("pcap_path") or csv_path)
        try:
            result = build_panels(
            csv_path, source, finding_index=0,
            narrate_with=self.provider_name,
            narrate_panels=self._panels_to_narrate(),
            # Same queue as the result, so Tk is still touched only from the
            # main thread. Narration is 50 s of the ~50 s this takes, and one
            # unchanging "Analysing flows..." over that reads as a hung
            # window rather than a working one.
            on_progress=lambda m: self._results.put(("status", m, run_id)),
            # So the flow table can be checked against the capture actually
            # loaded, not merely against the path the extractor recorded.
            # The digest is reused from the case rather than recomputed.
            current_pcap=current_case.get("pcap_path"),
            current_pcap_sha=current_case.get("pcap_sha256"))
        except Exception as e:                      # never lose a worker crash
            result = {"error": f"{type(e).__name__}: {e}"}
        self._results.put(("all", result, run_id))

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

        # A model that could not be reached is a fact about the run, not a
        # detail for a log file: the panels below are the deterministic
        # ones, and the reader has to know that is all they are.
        if result.get("narration_unavailable"):
            self._write(self.txt_summary, [
                ("PLAIN ENGLISH\n", "h"),
                (f"  unavailable: {result['narration_unavailable']}\n"
                 "  The panels below are unchanged -- narration is "
                 "additive.\n\n", "warn"),
            ])

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
        blocks = self._narration_blocks(summary) + [("FLOW SUMMARY\n\n", "h")]

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

        # The evidence this all came from, in the panel rather than only in
        # the header labels -- a saved or screenshotted panel has to identify
        # its own capture.
        case = self.current_case or {}
        pcap = case.get("pcap_path")
        if pcap:
            blocks.append(("\nEVIDENCE\n", "h"))
            blocks.append((f"  file      {os.path.basename(pcap)}\n", None))
            try:
                size = os.path.getsize(pcap)
                blocks.append((f"  size      {size:,} bytes "
                               f"({size / 1e6:,.1f} MB)\n", "muted"))
            except OSError:
                pass
            if case.get("pcap_sha256"):
                blocks.append((f"  SHA-256   {case['pcap_sha256']}\n",
                               "muted"))
            csv_name = os.path.basename(case.get("generated_csv_path") or "-")
            blocks.append((f"  flow table {csv_name}\n", "muted"))

        # Whether this flow table was made from THIS capture. Every other
        # figure on the panel is recomputed from the table, so a table from
        # another capture would satisfy all of them and still be wrong.
        link = summary.get("capture_link") or {}
        if link:
            state = link.get("state")
            label = {"verified": "VERIFIED against this capture",
                     "mismatch": "MISMATCH -- NOT from this capture",
                     "unrecorded": "not recorded"}.get(state, state)
            tag = {"verified": "good", "mismatch": "bad"}.get(state, "warn")
            blocks.append((f"  chain     {label}\n", tag))
            blocks.append((f"            {link.get('detail', '')}\n", "muted"))
            for name, ok in link.get("checks", []):
                blocks.append((f"            {'ok  ' if ok else 'FAIL'} "
                               f"{name}\n", "good" if ok else "bad"))

        inv = f.get("inventory") or {}
        if inv:
            blocks.append(("\nNETWORK INVENTORY\n", "h"))
            blocks.append((
                f"  hosts         {inv.get('distinct_sources', '-')} source"
                f"(s), {inv.get('distinct_targets', '-')} target(s)\n"
                f"  conversations {inv.get('distinct_conversations', '-')} "
                f"distinct source-to-target pairs\n"
                f"  ports         {inv.get('distinct_dst_ports', '-')} "
                f"destination, {inv.get('distinct_src_ports', '-')} source\n",
                None))

            if inv.get("protocols"):
                blocks.append(("  protocols     " + ", ".join(
                    f"{p['name']} {p['flows']:,}"
                    for p in inv["protocols"]) + "\n", None))

            b, p = inv.get("bytes"), inv.get("packets")
            if b:
                blocks.append((
                    f"  volume        {b['total']:,} bytes "
                    f"({b['total'] / 1e6:,.2f} MB) -- "
                    f"{b['forward']:,} forward, {b['backward']:,} backward\n",
                    None))
            if p:
                blocks.append((
                    f"  packets       {p['total']:,} -- {p['forward']:,} "
                    f"forward, {p['backward']:,} backward\n", None))

            if inv.get("top_conversations"):
                blocks.append(("\n  Busiest conversations\n", "muted"))
                for c in inv["top_conversations"]:
                    blocks.append((f"    {c['pair']:<34}{c['flows']:>7,} "
                                   f"flows\n", None))

        # Who is actually implicated. "1,283 attack flows" does not say how
        # many hosts that involves, which is the first question asked.
        ai, ae = f.get("attack_inventory") or {}, f.get("attack_endpoints") or {}
        if ai:
            blocks.append(("\nHOSTS INVOLVED IN ATTACK FLOWS\n", "h"))
            blocks.append((
                f"  {ai.get('flows', 0):,} attack flows across "
                f"{ai.get('distinct_sources', '-')} source(s) and "
                f"{ai.get('distinct_targets', '-')} target(s), "
                f"{ai.get('distinct_conversations', '-')} conversation(s)\n",
                None))
            for role, label in (("sources", "Attacking sources"),
                                ("targets", "Targets")):
                if ae.get(role):
                    blocks.append((f"\n  {label}\n", "muted"))
                    for e in ae[role]:
                        blocks.append((f"    {e['address']:<24}"
                                       f"{e['flows']:>7,} flows\n", "warn"))
            if ae.get("ports"):
                blocks.append(("\n  Ports targeted\n", "muted"))
                for e in ae["ports"]:
                    blocks.append((f"    {e['port']:<24}{e['flows']:>7,} "
                                   f"flows\n", None))

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
        blocks = self._narration_blocks(shap_panel) + [
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
                f"{d['runner_up_confidence']:.3f}\n", None))

            # 1. WHAT THE MODEL OUTPUT -- before any explanation of it.
            mo = d.get("model_output") or {}
            if mo.get("probabilities"):
                blocks.append(("\n  MODEL OUTPUT  (XGBoost predict_proba, "
                               "16 classes)\n", "h"))
                for p in mo["probabilities"]:
                    mark = " <- predicted" if p["class"] == d["predicted"] \
                        else ""
                    blocks.append((
                        f"    {p['class']:<16}{p['probability']:>12.6f}"
                        f"{mark}\n",
                        "good" if mark else "muted"))
                blocks.append((
                    f"    {'raw margin':<16}{mo['margin']:>12.6f}   "
                    f"(log-odds, before softmax)\n", None))

            # 2. DOES THE EXPLANATION RECONSTRUCT IT -- shown, not asserted.
            sc = d.get("shap_check") or {}
            if sc:
                ok = sc["agrees"] and sc["reconstruction_picks_predicted"]
                blocks.append(("\n  TreeSHAP CONSISTENCY CHECK\n", "h"))
                blocks.append((
                    f"    base value           {sc['base_value']:>12.6f}\n"
                    f"  + sum of all {sc['features_total']} features "
                    f"{sc['sum_all_features']:>12.6f}\n"
                    f"  = reconstructed       {sc['reconstructed_margin']:>12.6f}\n"
                    f"    model margin        {sc['model_margin']:>12.6f}\n",
                    None))
                blocks.append((
                    f"    difference          {sc['additivity_error']:>12.2e}"
                    f"   {'AGREES' if ok else 'DOES NOT AGREE'}\n",
                    "good" if ok else "bad"))
                blocks.append((
                    f"    reconstruction picks the predicted class: "
                    f"{'yes' if sc['reconstruction_picks_predicted'] else 'NO'}"
                    f"\n", "good" if sc["reconstruction_picks_predicted"]
                    else "bad"))
                blocks.append((
                    f"    the {sc['features_shown']} features below carry "
                    f"{sc['shown_share_of_total']:.1%} of the total "
                    f"attribution weight\n", "muted"))
                if not ok:
                    blocks.append((
                        "    These attributions do not reconstruct this "
                        "model's decision. Do not read them as an "
                        "explanation of it.\n", "bad"))

            blocks.append(("\n  ATTRIBUTIONS\n", "h"))

            top = max(abs(a["contribution"]) for a in d["attributions"]) or 1
            for a in d["attributions"]:
                n = max(1, int(18 * abs(a["contribution"]) / top))
                bar = ("+" if a["contribution"] > 0 else "-") * n
                blocks.append((f"  {bar:<19}",
                               "good" if a["contribution"] > 0 else "bad"))
                blocks.append((f"{a['contribution']:+7.3f}  {a['plain']}\n",
                               None))
                blocks.append((
                    f"  {'':<19}         value {a['raw_value']:,.4f}"
                    + (f" {a['unit']}" if a.get("unit") else "") + "\n",
                    "muted"))
                if a.get("caution"):
                    blocks.append((
                        f"  {'':<19}         CAUTION: {a['caution']}\n",
                        "warn"))

            if d["class_typical"]:
                blocks.append((
                    f"\n  Typical drivers for {d['predicted']}: "
                    f"{', '.join(d['class_typical'][:4])}\n", "muted"))

        # How to read what is above it, on the panel that shows it. These
        # sections used to sit on the RECOMMENDATIONS panel, where they
        # explained an attribution the reader had left two panels ago.
        guidance = [s for s in (self.panels or {}).get("recommend", {})
                    .get("sections", []) if s.get("panel") == "shap"]
        if guidance:
            blocks.append(("\n" + "=" * 58 + "\n", "muted"))
            blocks.append(("HOW TO READ THIS\n", "h"))
            for s in guidance:
                blocks.append((f"\n{s['heading']}\n", "h"))
                blocks += self._digest_blocks(s)

        self._write(self.txt_shap, blocks)

    @staticmethod
    def _digest_blocks(s):
        """One retrieved document, rendered in the shape it was written in.

        Shared by panels 2 and 3 so a document reads the same wherever it is
        shown. A retrieved file is never pasted in full: nine documents in
        full ran to about 30,000 characters, and burying the two lines that
        matter inside that is a way of not saying them. The file is named so
        it can be opened.
        """
        blocks = []
        dg = s.get("digest") or {}

        if dg.get("style") == "glossary":
            # A term list, rendered as one. Summarised as prose it became
            # "Class. One of the sixteen labels... Held-out test set.
            # 280,000 flows..." -- four definitions run into one sentence --
            # above an "In short" list of bare terms with their meanings
            # stripped off.
            #
            # Shown in full rather than capped at five like the explanatory
            # sections. Completeness is what a glossary is for, the entries
            # are one line each, and cutting it risks removing the term the
            # reader was looking up.
            if dg.get("summary"):
                blocks.append(("\n    " + dg["summary"] + "\n", "muted"))
            for d in dg.get("definitions", []):
                blocks.append(("\n    " + d["term"] + "\n", None))
                blocks.append(("      " + d["meaning"] + "\n", "muted"))

        elif dg.get("style") == "explainer":
            # An explanatory document is read, not worked through. This used
            # to render as the playbook shape -- two truncated fragments over
            # five quotations about regression-tree leaf scores and the
            # definition of explainable AI -- which explained nothing and
            # buried the 997 words that did. The paragraph is the document's
            # own opening prose and the points are the statements its author
            # bolded; the quotations stay in the file and are still verified
            # against the cited work, which the source line below reports.
            if dg.get("summary"):
                blocks.append(("\n    " + dg["summary"] + "\n", None))
            if dg.get("actions"):
                blocks.append(("\n  In short\n", "muted"))
                for a in dg["actions"]:
                    blocks.append(("    - " + a + "\n", None))

        else:
            if dg.get("actions"):
                blocks.append(("\n  What the document prescribes\n",
                               "muted"))
                for a in dg["actions"]:
                    blocks.append(("    - " + a + "\n", None))
            for q in dg.get("quotes", []):
                blocks.append(("\n  Quoted from " + q["source"]
                               + "\n", "muted"))
                blocks.append(('    "' + q["text"] + '"\n', "good"))

        n = s.get("quotes_verified", 0)
        blocks.append((
            "\n  Source: knowledge/" + s["source"] + " - "
            + format(len(s["body"].split()), ",") + " words, " + str(n) + " "
            + ("quote" if n == 1 else "quotes")
            + " verified against the cited document.\n", "muted"))
        return blocks

    def _render_recommend(self, rec):
        """[UI CONNECTION: sections -> headed blocks, citations -> sources]"""
        # Narration is NOT prepended here, unlike panels 1 and 2.
        #
        # On those panels the paragraph is a summary and belongs on top. On
        # this one it is a conclusion: the steps were rendering before the
        # reader had been told what was found, which read as advice arriving
        # ahead of its own justification. It is inserted after the evidence
        # instead -- found, why, then what to do.
        blocks = [(f"RECOMMENDATIONS -- {rec['class']}\n",
                   "h"),
                  ("=" * 58 + "\n\n", "muted")]

        # No MITRE ATT&CK line. ATT&CK describes host-observed adversary
        # behaviour; this tool sees flow records, which cannot establish it.
        # See the note above KNOWLEDGE_MAP in services/panels_service.py.

        # Guidance about the attack comes first, then guidance about the
        # model's own output, with a divider between them. Without it the
        # model documents -- which are long -- push the response playbook
        # off the top of the panel, and the reader has no way to tell which
        # sections are about the traffic and which are about how far the
        # classification can be trusted.
        divider_written = False

        def evidence_blocks():
            """Why the model chose this class -- shown after the finding.

            Order on this panel is what was found, then why, then what to
            do. Placed before the finding it read as an answer to a question
            that had not been asked yet.
            """
            if not rec.get("evidence"):
                return []
            out = [("  Strongest evidence, in log-odds. Positive supports "
                    "the class.\n", "muted")]
            for a in rec["evidence"]:
                out.append((f"    {a['contribution']:+7.3f}  {a['plain']}\n",
                            "good" if a["contribution"] > 0 else "bad"))
                out.append((f"             observed "
                            f"{a.get('readable', a['raw_value'])}"
                            f"  --  {a.get('magnitude', '')}\n", "muted"))
            out.append(("  Full attributions are in Panel 2.\n\n", "muted"))
            return out

        evidence_pending = bool(rec.get("evidence"))
        step = [0]

        def head(title, tag="h"):
            """A numbered heading, so the panel reads as one document."""
            step[0] += 1
            return [(f"\n{step[0]} - {title}\n", tag)]

        for s in rec["sections"]:
            # Guidance about reading an attribution belongs with the
            # attributions. Three of these sections explain SHAP, and on a
            # panel whose subject is what to DO they pushed the response
            # playbook down the page. They are rendered on panel 2 instead.
            if s.get("panel") == "shap":
                continue

            # Evidence and the model's steps go in once the finding has been
            # stated and before any guidance: found -> why -> what to do.
            if evidence_pending and s.get("source"):
                evidence_pending = False
                blocks += head("Why the model chose this class")
                blocks += evidence_blocks()
                narration = self._narration_blocks(rec)
                if narration:
                    blocks += head("Recommended steps")
                    blocks += narration
                    blocks.append(("\n", None))

            if s.get("kind") == "model" and not divider_written:
                divider_written = True
                blocks.append((
                    "\n" + "-" * 58 + "\n"
                    "HOW FAR TO TRUST THIS RESULT\n"
                    + "-" * 58 + "\n\n", "h"))
                blocks.append((
                    "Retrieved because of what the model actually returned "
                    "for this finding -- its confidence, its measured "
                    "reliability for this class, and how the flows were "
                    "extracted. Each carries a citation below.\n\n", "muted"))

            # "GUIDANCE FROM INCIDENT_RESPONSE/SLOWLORIS.MD" is a path
            # shouted at the reader. The document is named properly on its
            # own source line below; the heading says what the section is.
            title = s["heading"]
            if s.get("source", "").startswith("incident_response/"):
                stem = os.path.basename(s["source"])[:-3].replace("_", " ")
                title = f"Response playbook - {stem}"
            # Model-guidance sections already carry a readable heading of
            # their own ("How reliable this class is"). Prefixing them with
            # "Guidance -" only made them longer.
            blocks += head(title,
                           "warn" if s["heading"] == "Ambiguity" else "h")

            # A retrieved document is shown as its shape, its prescriptive
            # lines and its verified quotes -- not pasted in full. Nine
            # documents in full ran to about 30,000 characters, and burying
            # the two lines that matter inside that is a way of not saying
            # them. The file is named so it can be opened.
            if s.get("digest") and s.get("source"):
                blocks += self._digest_blocks(s)
            else:
                blocks.append((s["body"] + "\n", None))

        # Every recommendation is shown with the work it came from. A
        # response step without its source is an assertion; with the
        # citation it is something an investigator can check and an auditor
        # can follow.
        if rec.get("references"):
            blocks += head("References")
            blocks.append(("  The works the documents above cite. The "
                           "numbers match the markers on each step.\n",
                           "muted"))
            for i, ref in enumerate(rec["references"], 1):
                blocks.append((f"  [{i}] {ref}\n", "good"))

        if rec["citations"]:
            blocks += head("Files quoted")
            for c in rec["citations"]:
                blocks.append((f"  {c}\n", "muted"))
            if not rec.get("references"):
                blocks.append((
                    "  No IEEE citation found in the quoted file. Add a "
                    "'> Source:' line to its provenance header.\n", "warn"))

        # A document whose quotes no longer match the PDF it names is a
        # provenance failure, not a formatting one, and the reader has to be
        # told which document and why -- it is the only signal that the
        # evidence chain behind a recommendation has broken.
        self._quarantined = rec.get("unverified_documents") or []
        self.btn_repair.config(
            state=tk.NORMAL if self._quarantined else tk.DISABLED,
            fg=BAD if self._quarantined else MUTED)

        for u in self._quarantined:
            blocks.append(("\nWITHHELD -- QUOTES DO NOT MATCH THE SOURCE\n",
                           "h"))
            blocks.append((f"  {u['source']} was not shown. Its quoted "
                           f"passages were checked against the source PDF on "
                           f"disk and did not match:\n", "bad"))
            for f in u["verification"]["failures"][:3]:
                blocks.append((f"    [{f['source']}] {f['why']}\n", "bad"))
                if f["quote"]:
                    blocks.append((f"      \"{f['quote']}...\"\n", "muted"))
            blocks.append(("  Re-run `python fetch_knowledge.py --verify` "
                           "after fixing the document or restoring the "
                           "source.\n", "muted"))

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

    def _on_repair(self):
        """Realign quarantined documents to the sources they quote.

        Drift is repaired from the source's own words; a passage that is not
        in the source is refused, because that is a wrong citation rather
        than wrong wording and only the author can say what was meant. Both
        outcomes are reported before anything is re-run.
        """
        from services.source_guard import repair_document

        if not self._quarantined:
            return
        if not messagebox.askyesno(
                "Repair quoted sources",
                f"{len(self._quarantined)} document(s) quote passages that no "
                f"longer match the source PDF.\n\n"
                f"Passages that have DRIFTED will be rewritten using the "
                f"source's own words. Passages that are not in the source at "
                f"all will be refused and left quarantined.\n\n"
                f"A .bak copy is kept of every file changed. Continue?"):
            return

        repaired, refused = [], []
        for u in self._quarantined:
            r = repair_document(u["source"], apply=True)
            repaired += [(u["source"], x) for x in r["repaired"]]
            refused += [(u["source"], x) for x in r["refused"]]

        lines = [f"Repaired {len(repaired)}, refused {len(refused)}.", ""]
        for src, x in repaired[:6]:
            lines.append(f"REPAIRED  {src}  ({x['ratio']:.0%} match)")
            lines.append(f"   now: {x['now'][:70]}...")
        for src, x in refused[:6]:
            lines.append(f"REFUSED   {src}")
            lines.append(f"   {x.get('why_refused', '')[:100]}")
        if refused:
            lines += ["", "Refused documents stay withheld. Fix the quote or "
                          "restore the source, then re-run the analysis."]
        messagebox.showinfo("Repair complete", "\n".join(lines))

        # Re-run so the panels reflect the repaired documents.
        if self.current_case:
            self.update_xai_results(self.current_case)

    @staticmethod
    def _panels_to_narrate():
        """All three panels, every run.

        Panel 3 used to be excluded unless a second checkbox was ticked,
        on the reasoning that rewording a quoted playbook risks the
        guarantee the panel exists to provide. That risk is now handled
        where it belongs -- the model's steps must each carry a span copied
        out of the playbook, the span is verified against the document, and
        the citation number is derived from it rather than written. The
        verbatim quotes are still on screen underneath.
        """
        from services.narration_service import ALL_PANELS
        return ALL_PANELS

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

        run_id = self._run_id

        def work():
            source = os.path.basename(
                self.current_case.get("pcap_path") or csv_path
            )
            try:
                result = build_panels(
                csv_path, source, finding_index=index,
                narrate_with=self.provider_name,
                narrate_panels=self._panels_to_narrate())
            except Exception as e:
                result = {"error": f"{type(e).__name__}: {e}"}
            self._results.put(("selected", result, run_id))

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
