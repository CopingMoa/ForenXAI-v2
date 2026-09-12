# Chapter 3 — completion and corrections

Paste-ready text for the sections that are empty, and exact replacements for
the passages that no longer describe what was built. Every figure below was
read out of `forenxai_binary/results/` or the running application, not
recalled.

---

## ⚠ Read this before anything else: the chapter describes a different study

Section 3.2 as written describes **a seven-class problem trained on
CSE-CIC-IDS2018 and TII-SSRC-23**, with Table 3 listing Benign, Botnet,
Bruteforce, DoS, Infiltration, Info-Gathering and Web Attack.

That is not the study. The pipeline in `forenxai_binary` ran **two
experiments**, and **TRUSTLab — the dataset the deployed model is trained
on — is not mentioned anywhere in the chapter.**

| | Experiment A (binary) | Experiment B (multiclass) |
|---|---|---|
| Scripts | `01`–`07` | `08`–`12` |
| Question | does a detector transfer to an unseen network? | which of sixteen attacks is this? |
| Train on | CSE-CIC-IDS2018, TII-SSRC-23 | TRUSTLab, 80% |
| Test on | **TRUSTLab**, never trained on | TRUSTLab, held-out 20% |
| Models | 5 architectures × 3 training arms = 15 | 5 architectures |
| Headline | mean ROC-AUC **0.4665** | accuracy **0.9337**, macro F1 **0.9287** |
| Ships in the tool? | no | **yes — XGBoost** |

The seven-class taxonomy belongs to Experiment A, where every label
collapses to attack-or-benign anyway. The tool classifies **sixteen**
classes: Benign, API, Bruteforce, BufferOverflow, C2Beaconing, DDoS, DNS,
DoS, Evasion, Exfiltration, Exploitation, MITM, PortScan, Slowloris,
TLSSSL, WebBased. Six of those — API, MITM, Evasion, TLSSSL, Exfiltration,
C2Beaconing — exist in no other public dataset, which is why the multiclass
experiment cannot cross datasets and why TRUSTLab is not optional to the
design.

**Minimum fix:** add TRUSTLab to §3.2 Datasets, add the sixteen-class
taxonomy, and say in §3.1 that the study runs two experiments with
TRUSTLab in opposite roles. Draft text for all three is in §3.2 below.

**The two scores must never be printed side by side without a sentence
separating them.** The binary models sat an exam on a network they had
never seen; the multiclass models sat one on the network they studied.
Different difficulty, not different engineering quality. A reader — or an
examiner — who sees 0.47 and 0.93 in the same table will draw the wrong
conclusion.

---

## 3.1 Research Design — two edits

**Delete** the template block beginning *"General Guidelines: Discuss
thoroughly the research methodology…"* and the inline note *"(add GenAI,
indicate, RAG based)"*.

**Insert** after the paragraph ending *"…in their post-incident analysis
workflows."*:

> The study is organised as two complementary experiments rather than one.
> The first asks whether a detector trained on public benchmark traffic
> transfers to a network it has never seen, and is answered by training
> fifteen binary detectors on CSE-CIC-IDS2018 and TII-SSRC-23 and scoring
> them on TRUSTLab, which none of them was trained on. The second asks
> which of sixteen attack classes a flow belongs to, and is answered by
> training and testing within TRUSTLab. The same dataset therefore occupies
> opposite roles in the two experiments — an unseen examination set in the
> first, the training environment in the second — and their results are
> reported separately throughout, because they measure tasks of different
> difficulty.
>
> The explanation layer is retrieval-augmented rather than generative
> alone. Response guidance shown to the investigator is retrieved from a
> curated corpus of standards documents by a deterministic, result-
> conditioned retriever, and a locally hosted language model rewrites the
> retrieved text into prose without contributing any claim of its own. This
> arrangement is adopted because a recommendation attributed to a source it
> did not come from is more damaging in a forensic setting than no
> recommendation at all.

---

## 3.2 Research Environment — additions

### Add to *Datasets*, after the TII-SSRC-23 paragraph

> The TRUSTLab dataset, introduced by Villafranca, Tasic and Cano (2026),
> provides the sixteen-class taxonomy the deployed classifier uses. Each
> attack family was captured in an isolated session, which yields
> unambiguous labels and supplies six classes absent from both other
> datasets: API abuse, MITM, Evasion, TLS/SSL attacks, Exfiltration and C2
> Beaconing. It is used in two distinct roles. In the binary experiment it
> is held out entirely — never trained on, never split — and serves as the
> external examination set, capped at 30,000 rows per class across sixteen
> classes for 480,000 test rows. In the multiclass experiment it is the
> training environment, capped at 80,000 rows per attack class and 200,000
> for Benign.

### Add Table 3b

> **TABLE 3b. Multiclass split, TRUSTLab (seed 42)**
>
> | Stage | Setting | Rows | Share |
> |---|---|---:|---:|
> | Capped pool | `MC_PER_CLASS` 80,000 · `MC_BENIGN_CAP` 200,000 | 1,400,000 | 100% |
> | → Test | `MC_TEST_FRACTION` 0.20 | 280,000 | 20% |
> | → Training pool | remainder | 1,120,000 | 80% |
> |  → Validation | `MC_VAL_FRACTION` 0.15 of the pool | 168,000 | 12% |
> |  → Final training | remainder | 952,000 | 68% |
>
> Each of the fifteen attack classes contributes 64,000 training and 16,000
> test rows; Benign contributes 160,000 and 40,000.

**State the ratio as 68/12/20, not 65/15/20.** The validation fraction is
taken from the remaining 80%, not from the whole. It does not change any
result, but the written figure should be the one the code produces.

### Add after the feature-alignment paragraph

> Alignment across the three datasets reduced the shared feature set to 74
> columns, matched by name rather than by position because two of the
> sources order identically named columns differently. Name matching does
> not guarantee equivalent meaning, and two discrepancies were identified
> and are reported rather than corrected. Training flows terminate at the
> extractor's default 120-second timeout, whereas TRUSTLab flows run to
> 15,716,702,208 microseconds — approximately 4.4 hours — so every timing
> feature occupies a different scale, and 21 of the 74 features differ by
> more than three training standard deviations. Separately, five features
> are constant zero throughout training but reach 1,250,659 in TRUSTLab; a
> scaler fitted on a constant cannot rescale them, so they enter the network
> unscaled. The cross-dataset results in §3.6 therefore measure genuine
> failure to generalise **together with** feature incompatibility, and the
> two cannot be separated under this design. This limitation is stated
> rather than resolved.

### One correction to the existing text

The chapter says CSE-CIC-IDS2018 contains **16,233,002** instances, and
Table 3 totals it at **16,137,183**. Reconcile the two, and cite which figure
is the dataset author's and which is the count after curation.

---

## 3.3 Data Gathering Procedures — scaffold only

**I have not drafted 3.3.1–3.3.3.** They describe human participants,
sampling and ethics, and inventing those would fabricate a research record.
What the chapter needs from you:

- **3.3.1** — who evaluates the prototype (cybersecurity practitioners,
  forensic analysts), how many, how they were recruited, the sampling
  method, and the inclusion criteria. §3.1 already commits you to ISO/IEC
  25010 expert evaluation, so this section must name that panel.
- **3.3.2** — how the Likert responses are coded and aggregated, and which
  descriptive statistics are reported per characteristic.
- **3.3.3** — storage, anonymisation, retention and disposal.

One thing you can state factually: **the machine-learning experiments
involve no human participants and no personal data.** All traffic is from
published benchmark datasets captured in controlled laboratory
environments. The ethics section applies to the evaluation panel only, and
saying so explicitly is worth a sentence.

---

## 3.4 System Architecture — full draft

> ForenXAI is a **layered desktop application**, organised so that every
> analytical result is computed before any explanation is written, and so
> that the explanation layer can fail without removing evidence from the
> screen.
>
> **Layer 1 — Evidence acquisition.** The investigator supplies a PCAP or
> PCAPng capture. The file is hashed with SHA-256 before anything reads it,
> and converted to flow records by CICFlowMeter v4. Where the reference
> extractor is unavailable — its native libraries frequently cannot be
> installed on Windows — a pure-Python extractor substitutes automatically.
> The two segment flows on slightly different activity, bulk and subflow
> boundaries, so the engine that produced a given flow table is recorded
> beside it and displayed, because a timing feature is only interpretable
> against the extractor that computed it.
>
> **Layer 2 — Classification.** The frozen feature schema is applied, the
> scaler fitted during training is applied without refitting, and the
> sixteen-class XGBoost classifier produces a predicted class and a
> probability distribution for every flow. Flows are then aggregated into
> **findings** — one per predicted class — because a response decision is
> taken about a class and its flows, not about a single flow.
>
> **Layer 3 — Attribution.** Exact TreeSHAP, with
> `feature_perturbation="tree_path_dependent"`, is computed for
> representative flows of the selected finding. Values are log-odds
> contributions. Each attribution is rendered with its plain-English
> feature name, its observed value converted to a readable unit, its
> distance from the training mean, and its direction. The additivity
> identity — base value plus all 74 contributions equals the model's own
> margin — is recomputed on every run and reported to the interface, so the
> panel demonstrates the arithmetic rather than asserting it.
>
> **Layer 4 — Retrieval.** The predicted class indexes a response playbook
> through a dictionary. An unmapped class raises an error; it never falls
> back to a similar one. Further documents are retrieved on the basis of the
> **result** rather than the class alone: a weak-F1 class retrieves the
> reliability guidance, a low-confidence finding retrieves the confidence
> guidance, and a dominant runner-up retrieves the second class's playbook
> as well, so that an inseparable pair is reported as a pair. Every quoted
> passage is re-verified against the source document it cites, on the file
> as it exists at run time; a document whose quotations no longer match is
> withheld from both the interface and the language model.
>
> **Layer 5 — Narration.** A locally hosted language model (qwen2.5:7b via
> Ollama) rewrites the retrieved and computed material into prose. It runs
> on the analyst's machine because a capture contains the internal
> addressing of a network the investigator is responsible for, and
> transmitting it is a disclosure decision the tool should not make
> silently. Generation for the recommendations panel is constrained to a
> JSON schema in which a step without a verbatim anchor from the retrieved
> playbook cannot be expressed. Nine grounding checks then compare the
> output against its input; prose that fails a high-severity check is
> withheld and replaced by a paragraph composed deterministically from the
> panel's own figures.
>
> **The layers degrade independently.** Every figure, label, attribution and
> citation is produced by layers 1–4 and rendered whether or not layer 5
> responds. Narration is additive: an unavailable language model costs prose
> and never evidence.

### Figure 1 — insert this diagram

```
        ┌──────────────────────────────────────────────────────┐
        │  TAB 1 — FORENSIC ANALYSIS                           │
        │                                                      │
        │  PCAP ──► SHA-256 ──► flow extraction ──► 74 features│
        │                       (CICFlowMeter v4                │
        │                        or Python fallback)           │
        │                            │                          │
        │                            ▼                          │
        │              XGBoost, 16 classes ──► TreeSHAP         │
        │                            │                          │
        │                            ▼                          │
        │        case file: 6 artefacts, each with SHA-256      │
        └────────────────────────────┬─────────────────────────┘
                                     │ flow table + capture hash
        ┌────────────────────────────▼─────────────────────────┐
        │  TAB 2 — EXPLANATION                                 │
        │                                                      │
        │  Panel 1          Panel 2           Panel 3          │
        │  what is in       why this class    what to do       │
        │  the capture      (TreeSHAP)        (retrieval)      │
        │      │                │                  │            │
        │      └────────────────┴──────────────────┘            │
        │                       │                               │
        │         local language model — rewrites only          │
        │         (nothing leaves the machine)                  │
        └──────────────────────────────────────────────────────┘

   knowledge corpus ──► deterministic retriever ──► quote verification
   (26 documents,       (class → document,          (against the cited
    18 cited sources)    result → guidance)          source, at run time)
```

---

## 3.5 Experimental Procedures — full draft

> ### 3.5.1 Experimental setup
>
> All experiments were executed on the environment reported in Table 2a,
> on CPU; no GPU was used, so the durations below are comparable with one
> another but not with GPU-trained figures. A fixed random seed of 42 was
> applied throughout — to dataset sampling, to every train/validation split,
> and to model initialisation — so that every split and every result is
> reproducible. The pipeline is organised as sixteen numbered scripts
> executed in order, each writing its outputs to disk before the next reads
> them, so that any stage can be re-run without repeating those before it.
>
> ### 3.5.2 Data pre-processing
>
> Scripts `01`–`03` convert the three raw sources into typed tables. The
> TRUSTLab reader addresses two defects in the published distribution.
> `PortScan.csv.gz` is truncated — the compressed stream terminates
> mid-file, and downloads repeated over separate networks produced
> byte-identical files, establishing the fault as originating in the
> published archive. The reader drives zlib directly rather than through
> Python's `gzip` module, because the latter discards already-decompressed
> bytes on encountering the break; this recovers 107,579 of approximately
> 171,147 rows (62.9%), against 98,819 by the alternative path. The
> half-written final record is discarded so that no row receives shifted
> column values. Because the per-class cap is 80,000, the recovery is
> sufficient and no class is short of rows; the cost is confined to
> provenance, in that PortScan's rows originate from the first 62.9% of its
> recording, which weakens that one class in the temporal split.
>
> Script `04` aligns the schemas to the 74 shared features described in
> §3.2 and freezes the column order. The scaler is fitted on the training
> portion alone and thereafter only applied, so that no distributional
> information from any evaluation set reaches the fitted parameters.
>
> ### 3.5.3 Model training and testing
>
> **Experiment A — binary detection and external validation (`05`–`07`).**
> Five architectures — MLP, CNN1D, LSTM, CNN-BiLSTM and XGBoost — were
> trained on each of three training arms: CSE-CIC-IDS2018 alone, TII-SSRC-23
> alone, and the two combined. Fifteen resulting detectors were scored on
> TRUSTLab at threshold 0.445, the operating point at which the published
> baseline was measured, so that the comparison reflects the models rather
> than a mismatched cutoff. A validation slice of 15% was carved from each
> training file for early stopping only and is never reported as a result.
>
> **Experiment B — sixteen-class identification (`08`–`10`).** The same five
> architectures were trained on the TRUSTLab split in Table 3b and evaluated
> on the held-out 20%. Per-class F1 is compared against the dataset
> authors' published figures, with the protocol difference stated on every
> table: their classifier received only traffic a detector had already
> flagged, whereas this one receives everything.
>
> ### 3.5.4 Diagnostic procedures
>
> Two procedures were added because the primary results alone would have
> been misleading.
>
> **Session-artifact testing (`11`).** TRUSTLab captures each attack family
> in an isolated session, which guarantees clean labels but also means any
> property peculiar to a session aligns perfectly with the class label. To
> test whether the classifier had learned the attack or the recording, the
> identical model and data were evaluated under two splitting protocols: a
> random split, and a temporal split in which the test partition is the last
> 20% of each class by capture order. A feature-ablation test was run
> alongside it, removing the four features most likely to encode capture
> conditions.
>
> **Protocol reconstruction (`12`).** To make the comparison with the
> published baseline like-for-like, the authors' two-stage arrangement was
> rebuilt three ways: an oracle filter passing every attack and no benign
> traffic; a matched filter reconstructing their Phase-1 operating point;
> and a learned filter using the detector from script `05`. Only the third
> describes a system that could actually run; the first two are
> counterfactual controls and are labelled as such.
>
> ### 3.5.5 Explanation and retrieval (`13`–`15`)
>
> Script `13` computes global and per-flow TreeSHAP attributions over the
> deployed classifier and verifies the additivity identity on every
> execution, terminating if it fails. Script `14` constructs the three
> explanation panels from a capture and the curated corpus. Script `15`
> scores the generated prose against the material it was given.
>
> ### 3.5.6 Model and prototype integration
>
> The trained classifier is exported as a frozen deployment bundle — the
> estimator, the fitted scaler, the label encoder, the feature order, and a
> manifest of SHA-256 hashes — and the application verifies that manifest
> before loading any serialised object, because a pickle is executed when it
> is read.
>
> The prototype is a Python desktop application with two tabs. The forensic
> tab drives Layers 1–3 and writes a case file in which every artefact is
> paired with its SHA-256. The explanation tab consumes that case file and
> renders Layers 3–5 as three panels. The two communicate through a single
> field, the path of the generated flow table, and the explanation tab
> re-verifies that the flow table corresponds to the capture named in the
> case rather than trusting the path.
>
> Integration is verified by an automated suite of 122 checks executed
> without a language model and 154 with one, together with a 166-check
> panel suite. One section of the suite feeds different input and asserts
> that the output changes with it, on the principle that a panel producing
> identical output for every capture is not analysing anything.

---

## 3.6 Evaluation Metrics and Validation — missing entirely, full draft

> ### 3.6.1 Classification metrics
>
> Accuracy, precision, recall and F1 are reported per class, with macro F1
> as the summary statistic because it weights all sixteen classes equally
> and therefore exposes a collapsed minority class that weighted averaging
> would conceal. ROC-AUC is reported for the binary experiment because it is
> independent of the decision threshold: a model whose AUC is below 0.5
> ranks attacks beneath benign traffic, and no choice of cutoff repairs
> that.
>
> ### 3.6.2 Results
>
> **TABLE 4. Binary detectors evaluated on TRUSTLab (unseen)**
>
> | | Value |
> |---|---:|
> | Mean ROC-AUC, 15 detectors | 0.4665 |
> | Detectors below 0.50 | 11 of 15 |
> | Best external accuracy | 0.6329 |
> | Internal F1 range, own data | 0.95 – 0.99 |
> | Published baseline accuracy | 0.8963 |
>
> **TABLE 5. Sixteen-class classifiers, TRUSTLab held-out 20%**
>
> | Model | Accuracy | Macro F1 | Weighted F1 | Train time |
> |---|---:|---:|---:|---:|
> | **XGBoost** | **0.9337** | **0.9287** | **0.9337** | **388 s** |
> | CNN1D | 0.9264 | 0.9208 | 0.9262 | 4,730 s |
> | CNN-BiLSTM | 0.9263 | 0.9199 | 0.9255 | 27,781 s |
> | LSTM | 0.9223 | 0.9174 | 0.9228 | 30,850 s |
> | MLP | 0.9220 | 0.9164 | 0.9217 | 885 s |
>
> The five architectures fall within 1.2 percentage points of one another,
> and the simplest leads. That convergence is itself a finding: no
> architecture unlocks the difficult classes, which locates the remaining
> difficulty in the feature representation rather than in model capacity.
> XGBoost was selected for deployment on that basis, at 1/80th of the
> training cost of the slowest alternative.
>
> **TABLE 6. Session-artifact diagnostic — same model, two splits**
>
> | Class | Random | Temporal | Δ |
> |---|---:|---:|---:|
> | WebBased | 0.9940 | 0.5321 | −0.4619 |
> | Slowloris | 0.7563 | 0.3300 | −0.4263 |
> | DoS | 0.6806 | 0.4352 | −0.2454 |
> | PortScan | 0.9941 | 0.8346 | −0.1595 |
> | *macro F1* | *0.9305* | *0.8325* | *−0.0980* |
>
> The macro drop of 0.098 is modest and must not be reported alone: eleven
> classes are essentially unchanged while four collapse. Feature ablation
> moved macro F1 by 0.0002, indicating that the features most likely to
> encode capture conditions are not carrying the result — a positive finding
> for the dataset's capture methodology.
>
> ### 3.6.3 Interpreting two kinds of failure
>
> Comparing each class's error distribution across both protocols separates
> two distinct phenomena. **Consistent confusion with one similar class
> indicates a feature-space limit**: Slowloris and DoS remain mutually
> confused under both protocols, which is consistent with a boundary defined
> by a rate threshold rather than a categorical difference. **Dispersal
> across unrelated classes indicates session memorisation**: WebBased does
> not collide with a lookalike but scatters across four unconnected classes,
> a pattern invisible under random splitting and therefore invisible in the
> protocol the dataset authors used.
>
> ### 3.6.4 Explanation validation
>
> The attribution layer is validated numerically rather than by inspection.
> The additivity identity is recomputed on every execution, with a measured
> error of 1.2 × 10⁻⁶; the reconstruction is confirmed to select the
> predicted class; and the features on which no tree splits are confirmed to
> carry exactly zero contribution.
>
> Generated prose is validated by nine automated grounding checks covering
> units, citations, numerical figures, verbatim anchors, magnitude claims,
> reference markers, attribution direction, the decision statement, and
> named mechanisms. Prose failing a high-severity check is withheld from
> display and replaced by a deterministic summary; the model's original text
> is retained in the case file for audit. Every retrieved quotation is
> additionally re-verified against its source document at render time.
>
> ### 3.6.5 Prototype evaluation
>
> The prototype is evaluated by cybersecurity practitioners and forensic
> analysts against ISO/IEC 25010, across Functional Suitability, Usability,
> Reliability and Performance Efficiency, with explanation quality rated
> separately for clarity, logical consistency and usefulness. The
> instrument, panel and analysis procedure are described in §3.3.
>
> ### 3.6.6 Scope of the claim
>
> All classification figures are measured on TRUSTLab held-out data — the
> same capture environment the models were trained in. The binary experiment
> is the direct evidence that such results do not transfer automatically:
> the same architectures score 0.95–0.99 on their own data and below chance
> on an unseen network. The claim this study supports is therefore
> **validated on TRUSTLab; performance in other capture environments is not
> established.** This is a statement of scope rather than a hedge, and it is
> what the evidence permits.

---

## Checklist

| Section | State | Action |
|---|---|---|
| 3.1 | written | delete two template blocks; insert the two-experiment paragraph |
| 3.2 | **wrong dataset** | add TRUSTLab, Table 3b, the 16 classes, the alignment limitation; reconcile 16,233,002 vs 16,137,183 |
| 3.3.1–3.3.3 | template only | **yours to write** — participants and ethics |
| 3.4 | empty | draft above + Figure 1 |
| 3.5 | empty | draft above |
| 3.6 | **absent** | draft above |
