"""
panels_service.py
=================

The three XAI panels, as plain functions that return dicts.

Nothing here builds widgets. Each function returns a dictionary and
views/xai_tab.py renders it, so the panels can be tested without a
display and the rendering can change without touching the analysis.

    1  summarise_capture()   what the flow table holds
    2  explain_detections()  why the model decided what it did
    3  recommend()           what to do, quoting retrieved documentation

The model is the sixteen-class XGBoost trained in the ForenXAI pipeline
(phase 09) and explained with exact TreeSHAP (phase 13). The bundle lives
in models/forenxai/ and is loaded once per process.

SCOPE
Trained and validated on TRUSTLab only. Accuracy on other capture
environments is not established -- see knowledge/datasets/scope.md.
"""

import os
import json
import re

import numpy as np
import pandas as pd

from services.config import BASE_DIR
from services.flow_intake import (IntakeError, read_flows, to_matrix,
                                  describe, identity_columns,
                                  capture_window, endpoints)


# ============================================================
# PATHS
# ============================================================

BUNDLE_DIR = os.path.join(
    BASE_DIR,
    "models",
    "forenxai"
)

KNOWLEDGE_DIR = os.path.join(
    BASE_DIR,
    "knowledge"
)


# ============================================================
# CLASS -> DOCUMENTS
#
# This IS the retrieval step. The classifier has already named one of
# sixteen classes, so the right documents are known exactly and the lookup
# is a dictionary access -- no embeddings, no vector store.
#
# A class with no entry raises rather than falling back to a similar one:
# a recommendation attached to the wrong playbook is worse than none.
#
# REPLACE THESE PATHS WITH YOUR OWN DOCUMENTS.
# Only denial_of_service.md is present as a sample; the rest are declared
# so the panel reports what is missing instead of inventing guidance.
#
# MITRE ATT&CK IDs were verified against attack.mitre.org. Every ID below is
# real and correctly named. Three classes have no honest mapping and carry an
# empty list rather than a plausible-looking wrong one:
#
#   Evasion   TRUSTLab means network-IDS evasion -- overlapping IP
#             fragmentation, TTL creeping. T1205 Traffic Signaling is port
#             knocking, a different thing; T1027 explicitly does not cover
#             packet-level evasion. Enterprise ATT&CK has no technique for
#             it, so none is claimed.
#   TLSSSL    TRUSTLab means Heartbleed, POODLE, BEAST, certificate
#             anomalies -- exploiting TLS weaknesses. T1573 Encrypted
#             Channel is the opposite: an adversary USING encryption to hide
#             C2. T1600 Weaken Encryption is device-level, not protocol.
#             Heartbleed alone would be T1190/T1210; the class is broader
#             than any single technique.
#   Benign    not an attack.
# ============================================================

KNOWLEDGE_MAP = {
    # One document per class. A file covering three classes cannot say
    # anything specific to any of them, and the panel quotes the whole file
    # -- so a DoS finding was showing Slowloris guidance and the reverse.
    "API":            {"doc": "incident_response/api.md",             "mitre": ["T1190"]},
    "Benign":         {"doc": "incident_response/benign.md",          "mitre": []},
    "Bruteforce":     {"doc": "incident_response/bruteforce.md",      "mitre": ["T1110"]},
    # T1203 is CLIENT-side exploitation (browsers, documents). TRUSTLab's
    # BufferOverflow is against a listening network service, which is T1210.
    "BufferOverflow": {"doc": "incident_response/bufferoverflow.md",  "mitre": ["T1210"]},
    "C2Beaconing":    {"doc": "incident_response/c2beaconing.md",     "mitre": ["T1071"]},
    "DDoS":           {"doc": "incident_response/ddos.md",            "mitre": ["T1498"]},
    "DNS":            {"doc": "incident_response/dns.md",             "mitre": ["T1071.004"]},
    "DoS":            {"doc": "incident_response/dos.md",             "mitre": ["T1499"]},
    "Evasion":        {"doc": "incident_response/evasion.md",         "mitre": []},
    "Exfiltration":   {"doc": "incident_response/exfiltration.md",    "mitre": ["T1041"]},
    "Exploitation":   {"doc": "incident_response/exploitation.md",    "mitre": ["T1190"]},
    "MITM":           {"doc": "incident_response/mitm.md",            "mitre": ["T1557"]},
    "PortScan":       {"doc": "incident_response/portscan.md",        "mitre": ["T1046"]},
    "Slowloris":      {"doc": "incident_response/slowloris.md",       "mitre": ["T1499.002"]},
    "TLSSSL":         {"doc": "incident_response/tlsssl.md",          "mitre": []},
    "WebBased":       {"doc": "incident_response/webbased.md",        "mitre": ["T1190"]},
}

# Pairs the model provably cannot separate, with the evidence.
# Slowloris and DoS have a per-feature SHAP importance correlation of
# 0.9040 and share six of their top ten features, so a single confident
# answer between them misrepresents what the model knows.
AMBIGUOUS_PAIRS = [
    {
        "classes": {"Slowloris", "DoS"},
        "margin": 0.25,
        "note": ("This model cannot reliably separate Slowloris from DoS: "
                 "per-feature SHAP importance correlates at 0.90 and six of "
                 "the top ten features are shared. Treat as one finding with "
                 "two candidate sub-types."),
    },
    {
        "classes": {"Exploitation", "BufferOverflow"},
        "margin": 0.30,
        "note": ("Exploitation is confused with BufferOverflow in about 9% "
                 "of cases. Both are exploitation of a listening service and "
                 "the response overlaps substantially."),
    },
]


# ============================================================
# RESULT CONDITION -> DOCUMENTS
#
# The map above answers "what is this attack". It cannot answer the other
# half of what is on screen: what a 0.55 confidence means, why a class
# scoring F1 0.67 needs different handling, whether a SHAP value is a
# cause, or whether the flow features are even comparable to the ones the
# model was trained on.
#
# Those answers used to be prose written in this file with no source behind
# them, while every attack claim carried an IEEE citation. That asymmetry
# is the thing this fixes: guidance about the MODEL is retrieved from
# sourced documents on the same terms as guidance about the ATTACK.
#
# `when` is given the finding and the capture summary and returns True if
# the document applies. Entries are evaluated in order and every match is
# retrieved, so a weak-F1 finding with low-confidence flows gets both.
# ============================================================

def _has_low_confidence(finding, summary):
    return bool(finding.get("low_confidence_count"))


def _is_weak_class(finding, summary):
    return finding.get("reliability_f1") is not None


def _has_ambiguity(finding, summary):
    runner = finding.get("dominant_runner_up")
    share = finding.get("dominant_runner_up_share", 0.0)
    return any(
        {finding["class"], runner} == pair["classes"]
        and share >= pair["margin"]
        for pair in AMBIGUOUS_PAIRS
    )


def _is_small_share_of_large_capture(finding, summary):
    """
    The base-rate case: few attack flows in a big capture.

    This is where a low false-positive rate still produces mostly false
    findings, and it is also the case that looks most alarming on screen.
    """
    facts = (summary or {}).get("facts", {})
    total = facts.get("total_flows", 0)
    return total >= 1000 and finding.get("share_of_capture", 1.0) < 0.05


def _extraction_is_questionable(finding, summary):
    facts = (summary or {}).get("facts", {})
    return bool(
        facts.get("flow_timeout_warning")
        or facts.get("flow_engine") == "python"
    )


MODEL_GUIDANCE = [
    {
        "id": "shap",
        "doc": "interpretability/shap_reading.md",
        "heading": "How to read the attributions",
        "when": lambda f, s: True,
    },
    {
        "id": "shap_limits",
        "doc": "interpretability/caveats.md",
        "heading": "Limits to quote alongside the explanation",
        "when": lambda f, s: True,
    },
    {
        "id": "reliability",
        "doc": "interpretability/reliability.md",
        "heading": "How reliable this class is",
        "when": _is_weak_class,
    },
    {
        "id": "confidence",
        "doc": "interpretability/confidence.md",
        "heading": "What the confidence number means",
        "when": _has_low_confidence,
    },
    {
        "id": "base_rate",
        "doc": "interpretability/confidence.md",
        "heading": "Base rates in a mostly-benign capture",
        "when": _is_small_share_of_large_capture,
    },
    {
        "id": "ambiguity",
        "doc": "interpretability/class_ambiguity.md",
        "heading": "Why two classes are competing",
        "when": _has_ambiguity,
    },
    {
        "id": "extraction",
        "doc": "datasets/extraction_validity.md",
        "heading": "Whether these features are comparable",
        "when": _extraction_is_questionable,
    },
    {
        "id": "scope",
        "doc": "datasets/scope.md",
        "heading": "Where this model has been shown to work",
        "when": lambda f, s: True,
    },
]

# Measured test F1, random split. Classes absent from this map are at 0.94
# or above. Used to hedge the confidence line rather than to score.
LOW_CONFIDENCE_CLASSES = {
    "DoS": 0.6703,
    "Exploitation": 0.7860,
    "Slowloris": 0.7593,
    "BufferOverflow": 0.8021,
}


# ============================================================
# BUNDLE LOADING
# ============================================================

_BUNDLE = None


def check_manifest():
    """
    Compare every bundle file against the fingerprint script 13 recorded.

    A .pkl is not data -- it is a list of instructions Python follows, so
    joblib.load() on a swapped file runs whatever that file says. The
    manifest already carries a SHA-256 per file, so checking it before
    loading makes a silent substitution impossible.

    This is a tamper-EVIDENT seal, not a lock: anyone who can replace a .pkl
    can also edit manifest.json to match. Real protection needs a signature
    with a key that does not live in the same folder. What this does buy is
    real -- a corrupt copy, a half-finished download, a wrong-version file
    and a casual swap all fail loudly instead of loading.

    Returns a list of problems; empty means everything matched.
    """

    import hashlib

    manifest_path = os.path.join(BUNDLE_DIR, "manifest.json")

    if not os.path.isfile(manifest_path):
        return ["manifest.json is missing, so the bundle cannot be verified"]

    try:
        with open(manifest_path, encoding="utf-8") as fh:
            recorded = json.load(fh).get("files", {})
    except (json.JSONDecodeError, OSError) as e:
        return [f"manifest.json could not be read: {e}"]

    problems = []

    for name, meta in recorded.items():
        path = os.path.join(BUNDLE_DIR, name)

        if not os.path.isfile(path):
            problems.append(f"{name} is missing")
            continue

        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for block in iter(lambda: fh.read(1 << 20), b""):
                digest.update(block)

        if digest.hexdigest()[:16] != meta.get("sha256_16"):
            problems.append(f"{name} does not match the manifest")

    return problems


def load_bundle():
    """
    Load the model, scaler, feature list, label encoder and SHAP explainer.

    Cached at module level. Building the TreeExplainer walks every tree in
    the ensemble -- about 1.7 seconds -- so it happens once per process and
    never per request.
    """

    global _BUNDLE

    if _BUNDLE is not None:
        return _BUNDLE

    # Verified before the first joblib.load, because after it the file has
    # already had its say.
    problems = check_manifest()
    if problems:
        raise IntakeError(
            "Refusing to load the model bundle.\n\n"
            + "\n".join(f"  - {p}" for p in problems)
            + "\n\nA .pkl file is executed when it is loaded, so a modified "
              "bundle is not analysed -- it is run. Reinstall "
              "models/forenxai/ from a known-good copy."
        )

    import joblib
    import shap

    model = joblib.load(
        os.path.join(BUNDLE_DIR, "XGBoost.pkl")
    )

    with open(
        os.path.join(BUNDLE_DIR, "shap_global.json"),
        encoding="utf-8"
    ) as fh:
        shap_global = json.load(fh)

    _BUNDLE = {
        "model": model,
        "scaler": joblib.load(os.path.join(BUNDLE_DIR, "scaler.pkl")),
        "features": list(joblib.load(os.path.join(BUNDLE_DIR, "features.pkl"))),
        "encoder": joblib.load(os.path.join(BUNDLE_DIR, "label_encoder.pkl")),
        "explainer": shap.TreeExplainer(model),
        "shap_global": shap_global,
    }

    return _BUNDLE


def bundle_available():
    """(ok, detail) -- so the tab can show a clear message instead of a stack trace."""

    needed = [
        "XGBoost.pkl", "scaler.pkl", "features.pkl",
        "label_encoder.pkl", "shap_global.json"
    ]

    missing = [
        f for f in needed
        if not os.path.isfile(os.path.join(BUNDLE_DIR, f))
    ]

    if missing:
        return False, f"models/forenxai/ is missing: {', '.join(missing)}"

    try:
        import shap  # noqa: F401
        import joblib  # noqa: F401
    except ImportError as e:
        return False, f"missing package: {e.name}"

    # Reported here as well as raised in load_bundle, so the tab can show a
    # clear message before any analysis is attempted.
    problems = check_manifest()
    if problems:
        return False, "bundle does not match its manifest: " + "; ".join(problems)

    return True, "bundle verified"


# ============================================================
# FEATURE PREPARATION AND CLASSIFICATION
# ============================================================

def prepare(flows, bundle):
    """
    A validated flow table -> the scaled matrix the model expects.

    Column presence, coercion limits and size are checked by
    services/flow_intake.py before this is reached. Returns (X, report) so
    the summary panel can report what had to be coerced.
    """

    raw, report = to_matrix(flows, bundle["features"])

    # transform, never fit: the scaler carries the training distribution and
    # refitting it on an uploaded capture would silently redefine what every
    # feature value means.
    return bundle["scaler"].transform(raw), report


def classify(flows, bundle):
    """
    Predict a class for every flow.

    Batched deliberately: 20 microseconds per flow in a batch against
    5,168 microseconds one at a time.
    """

    X, report = prepare(flows, bundle)

    proba = bundle["model"].predict_proba(X)
    k = proba.argmax(1)
    names = bundle["encoder"].inverse_transform(k)

    return X, proba, k, names, report


# ============================================================
# PANEL 1 -- FLOW SUMMARY
# ============================================================

def summarise_capture(flows, names, proba, source_name="capture.pcap"):
    """
    What is in this capture.

    [UI CONNECTION: source_name  <- os.path.basename(current_case["pcap_path"])]
    [UI CONNECTION: flows        <- pd.read_csv(current_case["generated_csv_path"])]
    [UI CONNECTION: returns      -> XaiTab._render_summary().
                                    `facts` fills the stat grid,
                                    `lines` fill the text area.]
    """

    from collections import Counter

    counts = Counter(names)

    attack = int(
        sum(v for c, v in counts.items() if c != "Benign")
    )

    conf = proba.max(1)

    facts = {
        "source": source_name,
        "total_flows": int(len(names)),
        "benign_flows": int(counts.get("Benign", 0)),
        "attack_flows": attack,
        "attack_share": round(attack / max(1, len(names)), 4),
        "distinct_attack_classes": len([c for c in counts if c != "Benign"]),
        "mean_confidence": round(float(conf.mean()), 4),
        "low_confidence_flows": int((conf < 0.60).sum()),
        "class_counts": dict(counts.most_common()),
    }

    # WHO and WHEN. CICFlowMeter writes 79 columns; the model uses 74. The
    # five it does not use are exactly what a forensic summary needs, and
    # every one is optional -- a table without them still analyses.
    facts["identity_columns"] = identity_columns(flows)

    window = capture_window(flows)
    if window:
        # The REAL span, from first flow to last. Distinct from the sum of
        # flow durations below, which counts overlapping seconds repeatedly.
        facts["capture_window"] = window

    ends = endpoints(flows)
    if ends:
        facts["endpoints"] = ends

    # Flow-duration facts, only where the extractor supplied the column.
    if "Flow Duration" in flows.columns:

        d = pd.to_numeric(
            flows["Flow Duration"],
            errors="coerce"
        ).dropna()

        if len(d):

            # NOT a capture span: flows overlap in time, so summing their
            # durations double-counts. Named for what it actually is.
            facts["total_flow_seconds"] = round(float(d.sum() / 1e6), 1)
            facts["longest_flow_seconds"] = round(float(d.max() / 1e6), 1)
            facts["median_flow_seconds"] = round(float(d.median() / 1e6), 3)

            # The single setting that silently invalidates every timing
            # feature. Training flows cap at 120 s; TRUSTLab runs to
            # 15,717 s. A capture extracted with the default timeout is
            # not comparable, so this is surfaced rather than buried.
            #
            # Both engines are tested because they cap at different values:
            # CICFlowMeter v4 at 120 s, the Python fallback at 240 s.
            # Checking only one would miss the other.
            longest = float(d.max())
            facts["flow_timeout_warning"] = bool(
                abs(longest - 120_000_000) < 1_000_000
                or abs(longest - 240_000_000) < 1_000_000
            )
            facts["flow_timeout_seconds"] = (
                120 if abs(longest - 120_000_000) < 1_000_000
                else 240 if abs(longest - 240_000_000) < 1_000_000
                else None
            )

    lines = [
        f"{facts['total_flows']:,} flows extracted from {source_name}.",
        f"{facts['attack_flows']:,} flagged as attack "
        f"({facts['attack_share']:.1%}), {facts['benign_flows']:,} benign.",
        f"{facts['distinct_attack_classes']} distinct attack classes present.",
        f"Mean confidence {facts['mean_confidence']:.2f}; "
        f"{facts['low_confidence_flows']:,} flows below 0.60.",
    ]

    w = facts.get("capture_window")
    if w:
        lines.insert(1, f"Capture ran {w['first_flow']} to {w['last_flow']} "
                        f"({w['span_human']}).")
    else:
        lines.append("No Timestamp column, so the capture window is unknown. "
                     "Flow durations below are a sum, not a span.")

    e = facts.get("endpoints", {})
    if e.get("targets"):
        lines.append("Busiest targets: " + ", ".join(
            f"{t['address']} ({t['flows']:,})" for t in e["targets"][:3]))
    if e.get("sources"):
        lines.append("Busiest sources: " + ", ".join(
            f"{t['address']} ({t['flows']:,})" for t in e["sources"][:3]))

    if facts.get("flow_timeout_warning"):
        cap = facts.get("flow_timeout_seconds") or 120
        lines.append("")
        lines.append(
            f"WARNING: the longest flow is almost exactly {cap} seconds, "
            f"which means these flows were extracted with the extractor's "
            f"default flow timeout. The model was trained on flows "
            f"extracted with a much longer timeout, so every timing feature "
            f"is on a different scale. Re-extract before trusting these "
            f"results."
        )

    return {
        "panel": "flow_summary",
        "facts": facts,
        "lines": lines,
    }


# ============================================================
# EXTRACTION PROVENANCE
# ============================================================

def read_extraction_record(csv_path):
    """
    Load flow_extraction.json from the directory holding the flow CSV.

    Written by cicflowmeter_service when the PCAP was converted. It records
    which engine ran, because CICFlowMeter v4 and the Python fallback do not
    segment flows identically -- a timing feature is only interpretable
    against the engine that produced it.

    Returns None when the CSV was supplied directly rather than extracted
    here, which is a normal case and not an error.
    """

    try:
        folder = os.path.dirname(os.path.abspath(csv_path))
        path = os.path.join(folder, "flow_extraction.json")
        if not os.path.isfile(path):
            return None
        with open(path, "r", encoding="utf-8") as fh:
            record = json.load(fh)
    except (OSError, ValueError):
        return None

    if not isinstance(record, dict) or "engine" not in record:
        return None

    # Only trust the record if it describes the CSV actually being read.
    named = os.path.basename(str(record.get("flow_csv", "")))
    if named and named != os.path.basename(csv_path):
        return None

    return record


def _engine_lines(extraction):
    """One line naming the extractor, plus a caveat when it is the fallback."""

    if not extraction:
        return []

    engine = extraction.get("engine")
    detail = extraction.get("engine_detail", engine)
    timeout = extraction.get("flow_timeout_seconds")

    line = f"Flows extracted by: {detail}"
    if timeout:
        line += f" (flow timeout {timeout} s)"
    lines = [line]

    if engine == "python":
        lines.append(
            "This is the fallback extractor, used because CICFlowMeter v4 "
            "was not available. It computes the same 74 features on the "
            "same 120-second flow timeout, but its activity, bulk and "
            "subflow boundaries are not identical to v4's, so those columns "
            "can differ from a CICFlowMeter v4 run on the same capture."
        )

    return lines


# ============================================================
# AGGREGATION -- one finding per class, not one per flow
# ============================================================

def aggregate(names, proba, k, bundle, flows=None):
    """
    Group flows into findings.

    A capture holds thousands of flows and tens of findings. One row per
    flow is unreadable and repeats the same playbook for every row, so
    findings are grouped by class.

    Two representative flows are carried per finding: the MOST and LEAST
    confident. The most confident shows what the class looks like when the
    model is sure; the least confident is where an investigator's judgement
    is actually needed, and is exactly what a per-flow list buries.

    [UI CONNECTION: returns -> the findings table. One row per class,
                               sorted by flow count. Selecting a row drives
                               panels 2 and 3.]
    """

    from collections import Counter

    findings = []

    for cls in sorted(set(names)):

        if cls == "Benign":
            continue

        mask = np.flatnonzero(names == cls)
        conf = proba[mask, k[mask]]

        runner = np.argsort(proba[mask], axis=1)[:, -2]
        runner_names = bundle["encoder"].inverse_transform(runner)
        rc = Counter(runner_names)

        findings.append({
            "class": cls,
            "flow_count": int(len(mask)),
            "share_of_capture": round(len(mask) / max(1, len(names)), 4),
            "confidence_mean": round(float(conf.mean()), 4),
            "confidence_min": round(float(conf.min()), 4),
            "confidence_max": round(float(conf.max()), 4),
            "low_confidence_count": int((conf < 0.60).sum()),

            # A dominant runner-up is a group-level ambiguity signal that no
            # single flow reveals.
            "dominant_runner_up": rc.most_common(1)[0][0] if rc else None,
            "dominant_runner_up_share": (
                round(rc.most_common(1)[0][1] / len(mask), 4) if rc else 0.0
            ),

            "representative_rows": [
                int(mask[int(conf.argmax())]),
                int(mask[int(conf.argmin())]),
            ],

            "reliability_f1": LOW_CONFIDENCE_CLASSES.get(cls),
        })

        # Which hosts this finding actually involves. "133 Slowloris flows"
        # is not actionable; "133 Slowloris flows against 10.0.0.5" is.
        if flows is not None:
            sel = np.zeros(len(names), dtype=bool)
            sel[mask] = True
            who = endpoints(flows, sel, top=3)
            if who:
                findings[-1]["endpoints"] = who

    findings.sort(key=lambda f: -f["flow_count"])

    return findings


# ============================================================
# PANEL 2 -- SHAP EXPLANATION
# ============================================================

def explain_detections(X, proba, k, names, bundle, rows, top=6):
    """
    Why the model decided what it did, for the rows the investigator opened.

    [UI CONNECTION: rows <- the representative_rows of the selected finding.
                            Do NOT pass every row: SHAP costs 8.1 ms per
                            flow against 20 microseconds to classify, a
                            400x difference. Explain on demand only.]
    [UI CONNECTION: returns -> XaiTab._render_shap().
                               `attributions` drives the bar display;
                               `plain` is the label, `caution` a warning.]

    UNITS
    Contributions are LOG-ODDS (the model margin), not probability. They sum
    to the margin plus the base value, verified to 1.8e-05. A contribution of
    +2.49 means the score rose 2.49 in log-odds -- NOT "added 249%". Never
    render one as a percentage.
    """

    sv = bundle["explainer"].shap_values(X[rows])

    # SHAP returns (n, features, classes) on current versions and a list of
    # per-class arrays on older ones.
    if isinstance(sv, list):
        sv = np.stack(sv, axis=-1)

    glossary = _load_glossary()

    detections = []

    for j, r in enumerate(rows):

        cls_i = int(k[r])
        cls = str(names[r])

        contrib = sv[j, :, cls_i]
        order = np.abs(contrib).argsort()[::-1][:top]

        runner = int(np.argsort(proba[r])[::-1][1])

        # Raw values for display: "Flow Duration 4.2 s" means something to
        # an investigator, "3.87 z-score" does not.
        raw_row = bundle["scaler"].inverse_transform(X[r:r + 1])[0]

        detections.append({
            "row": int(r),
            "predicted": cls,
            "confidence": round(float(proba[r, cls_i]), 4),
            "runner_up": str(bundle["encoder"].inverse_transform([runner])[0]),
            "runner_up_confidence": round(float(proba[r, runner]), 4),

            "attributions": [
                {
                    "feature": bundle["features"][i],
                    "plain": glossary.get(bundle["features"][i],
                                          bundle["features"][i]),
                    "raw_value": round(float(raw_row[i]), 4),
                    "contribution": round(float(contrib[i]), 6),
                    "direction": (
                        "supports" if contrib[i] > 0 else "argues against"
                    ),
                }
                for i in order
            ],

            # What usually drives this class across the whole test set, so
            # the investigator can see whether this flow is typical.
            "class_typical": [
                e["feature"]
                for e in bundle["shap_global"]["per_class"].get(cls, [])[:5]
            ],
        })

    return {
        "panel": "shap_explanation",
        "detections": detections,
        "units": "log-odds (model margin), not probability",
    }


def _load_glossary():
    """
    Feature name -> plain English, parsed from the Markdown table.

    Returns an empty dict when the file is absent; the panel then shows the
    raw feature names rather than inventing definitions.
    """

    path = os.path.join(KNOWLEDGE_DIR, "features", "glossary.md")

    if not os.path.isfile(path):
        return {}

    out = {}

    with open(path, encoding="utf-8") as fh:
        for line in fh:
            m = re.match(r"\|\s*`([^`]+)`\s*\|\s*(.+?)\s*\|", line)
            if m:
                out[m.group(1)] = m.group(2)

    return out


# ============================================================
# PANEL 3 -- RECOMMENDATIONS
# ============================================================

def _citations_in(text):
    """
    Pull the IEEE citations out of a knowledge file's provenance header.

    Every generated or hand-written file carries one "> Source: ..." line
    per document it draws on. Lifting them here means the panel shows a
    citation for every recommendation without a second lookup table that
    could drift away from the file.
    """
    out = []
    for line in (text or "").splitlines():
        m = re.match(r"^\s*>\s*Sources?:\s*(.+?)\s*$", line)
        if m and m.group(1) and not m.group(1).startswith("**"):
            out.append(m.group(1))
        elif out and re.match(r"^\s*>\s+retrieved ", line):
            # The retrieval line belongs to the citation above it.
            out[-1] += "  [" + line.split(">", 1)[1].strip() + "]"
    return out


def recommend(finding, detections=None, summary=None):
    """
    What to do about one finding, quoting the retrieved documentation.

    `summary` is the Flow Summary panel's output. It is optional so existing
    callers keep working, but without it the capture-level conditions --
    base rate, extraction validity -- cannot be evaluated and their guidance
    is silently not retrieved. Pass it.

    Takes the aggregate, not a single row, so the advice can account for
    scale: three PortScan flows and thirty thousand are the same class and a
    different situation.

    Scale comes from the finding itself (flow_count, share_of_capture), not
    from a separate capture summary -- one source for a number the advice
    depends on.

    [UI CONNECTION: finding <- the selected row of the findings table]
    [UI CONNECTION: returns -> XaiTab._render_recommend().
                               `sections` render as headed blocks,
                               `citations` as a source list,
                               `missing_documents` as a plain notice.]

    No language model is called here. The retrieved text is presented
    verbatim with its source, which is the strongest form of grounding
    available: nothing can be invented because nothing is generated. When a
    model is added later it must rewrite this text, never replace it.
    """

    cls = finding["class"]

    entry = KNOWLEDGE_MAP.get(cls)

    if entry is None:
        raise KeyError(
            f"{cls!r} has no entry in KNOWLEDGE_MAP. Add one rather than "
            f"falling back to a similar class -- a recommendation attached "
            f"to the wrong playbook is worse than none."
        )

    # Ambiguity: when the runner-up dominates the group, both playbooks are
    # relevant and the report says the pair is indistinguishable.
    ambiguity = None
    runner = finding.get("dominant_runner_up")
    share = finding.get("dominant_runner_up_share", 0.0)

    for pair in AMBIGUOUS_PAIRS:
        if {cls, runner} == pair["classes"] and share >= pair["margin"]:
            ambiguity = pair["note"]
            break

    documents, missing = {}, []

    for name in filter(None, [entry["doc"],
                              KNOWLEDGE_MAP.get(runner, {}).get("doc")
                              if ambiguity else None]):
        path = os.path.join(KNOWLEDGE_DIR, name)
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as fh:
                documents[name] = fh.read()
        elif name not in missing:
            missing.append(name)

    model_guidance = []

    f1 = finding.get("reliability_f1")

    # The measured figures. What they MEAN is not asserted here any more --
    # that comes from the retrieved documents below, which carry citations.
    # This block previously told the reader to "treat the classification as
    # uncertain" on no authority but its own, while every attack claim on
    # the same screen was sourced.
    confidence_note = (
        f"Mean confidence {finding['confidence_mean']:.2f} across "
        f"{finding['flow_count']:,} flows "
        f"(range {finding['confidence_min']:.2f}-"
        f"{finding['confidence_max']:.2f}). "
    )

    if f1 is not None:
        confidence_note += (
            f"This class scores F1 {f1:.4f} on the held-out test set, one of "
            f"the weakest of the sixteen. See the reliability guidance below."
        )
    else:
        confidence_note += (
            "This class scores above 0.94 F1 on the held-out test set."
        )

    if finding["low_confidence_count"]:
        confidence_note += (
            f" {finding['low_confidence_count']:,} of these flows are below "
            f"0.60 confidence. See the confidence guidance below for what "
            f"that threshold does and does not establish."
        )

    sections = [
        {
            "heading": "What was found",
            "body": (
                f"{finding['flow_count']:,} flows "
                f"({finding['share_of_capture']:.1%} of the capture) were "
                f"classified as {cls}."
            ),
        },
        {
            "heading": "How confident to be",
            "body": confidence_note,
        },
    ]

    if ambiguity:
        sections.append({
            "heading": "Ambiguity",
            "body": (
                f"{ambiguity} The model named {runner} as the runner-up for "
                f"{share:.0%} of these flows."
            ),
        })

    references = []
    if documents:
        for path, text in documents.items():
            cites = _citations_in(text)
            references += [c for c in cites if c not in references]
            sections.append({
                "heading": f"Guidance from {path}",
                "body": text.strip(),
                "source": path,
                # Attached to the section, so a recommendation and the work
                # it came from cannot be separated in rendering.
                "citations": cites,
            })
    else:
        sections.append({
            "heading": "Guidance",
            "body": (
                "No documentation is available for this class. Nothing is "
                "recommended, because any advice here would come from "
                "outside the evidence.\n\nAdd a document at: "
                + ", ".join(missing)
            ),
        })

    # Guidance about the MODEL'S OUTPUT, retrieved on the same terms as the
    # attack guidance above: by condition, from a sourced document, with the
    # citation attached. Each document is retrieved once however many
    # conditions selected it -- a reader does not want the same file twice.
    seen = set()
    for rule in MODEL_GUIDANCE:
        try:
            applies = rule["when"](finding, summary)
        except Exception:
            # A predicate that cannot evaluate must not take the panel down.
            # Omitting guidance is recoverable; an empty panel is not.
            applies = False

        if not applies or rule["doc"] in seen:
            continue

        path = os.path.join(KNOWLEDGE_DIR, rule["doc"])
        if not os.path.isfile(path):
            if rule["doc"] not in missing:
                missing.append(rule["doc"])
            continue

        seen.add(rule["doc"])
        with open(path, encoding="utf-8") as fh:
            text = fh.read()

        cites = _citations_in(text)
        references += [c for c in cites if c not in references]
        model_guidance.append(rule["id"])
        sections.append({
            "heading": rule["heading"],
            "body": text.strip(),
            "source": rule["doc"],
            "citations": cites,
            # Marks this as guidance about the model rather than about the
            # attack, so the tab can group or collapse it separately.
            "kind": "model",
        })

    return {
        "panel": "recommendations",
        "class": cls,
        "mitre": entry["mitre"],
        "ambiguity": ambiguity,
        "sections": sections,
        "citations": list(documents.keys()) + sorted(seen),
        # [UI CONNECTION: `references` -> the REFERENCES block. Full IEEE
        #  citations lifted from each document's own provenance header, so
        #  no recommendation is ever shown without the work it came from.]
        "references": references,
        # Which result conditions fired, for the report and for testing.
        "model_guidance": model_guidance,
        "missing_documents": missing,
    }


# ============================================================
# ONE CALL FOR THE TAB
# ============================================================

def build_panels(csv_path, source_name="capture.pcap", finding_index=0,
                 narrate_with=None, narrate_panels=None):
    """
    Everything XaiTab needs, from a CICFlowMeter CSV.

    [UI CONNECTION: csv_path      <- current_case["generated_csv_path"]]
    [UI CONNECTION: narrate_with  <- a provider name ("ollama") to add plain
     English beside the numbers, or None for numbers only. Narration is
     additive: every figure, label and citation stays on screen either way,
     so a missing or broken model degrades the panel rather than emptying
     it.]
    [UI CONNECTION: narrate_panels <- which panels to narrate. Defaults to
     panels 1 and 2. Panel 3 is excluded on purpose: it quotes a response
     playbook verbatim with its source, and a quote cannot be invented.
     Pass narration_service.ALL_PANELS to include it.]

    Returns a dict with `summary`, `findings`, `shap` and `recommend`, or
    an `error` string the tab can display verbatim.
    """

    ok, detail = bundle_available()

    if not ok:
        return {"error": detail}

    try:
        bundle = load_bundle()

        # Every check on an uploaded file lives in flow_intake, and every
        # refusal carries a message fit for a dialog box. A file that fails
        # here must not reach the model: it will return confident
        # predictions from a table whose columns mean something else.
        flows, intake_report = read_flows(csv_path, bundle["features"])

        X, proba, k, names, matrix_report = classify(flows, bundle)

    except IntakeError as e:
        return {"error": str(e), "kind": "intake"}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}", "kind": "internal"}

    summary = summarise_capture(flows, names, proba, source_name)

    # Put the intake facts in front of the investigator rather than in a log:
    # a truncated file or a high coercion rate changes what the numbers mean.
    summary["intake"] = {**intake_report, **matrix_report}

    # Which extractor produced these flows. Two engines segment flows
    # differently, so a timing feature only means something against the one
    # that computed it -- that belongs on screen, not in a log file.
    extraction = read_extraction_record(csv_path)
    if extraction:
        summary["facts"]["flow_engine"] = extraction.get("engine")
        summary["extraction"] = extraction

    # describe() names the CSV, which is what was read; the investigator
    # uploaded a PCAP and thinks in those terms. Report both, in that order,
    # so the provenance chain PCAP -> CSV -> analysis is visible on screen
    # rather than implied.
    summary["lines"] = (
        [f"Evidence: {source_name}"]
        + describe(intake_report, matrix_report)
        + _engine_lines(extraction)
        + summary["lines"][1:]
    )
    findings = aggregate(names, proba, k, bundle, flows)

    if not findings:
        return {
            "summary": summary,
            "findings": [],
            "shap": None,
            "recommend": None,
            "note": "No attack flows were found, so there is nothing to explain.",
        }

    finding = findings[min(finding_index, len(findings) - 1)]

    shap_panel = explain_detections(
        X, proba, k, names, bundle,
        rows=finding["representative_rows"]
    )

    result = {
        "summary": summary,
        "findings": findings,
        "selected": finding,
        "shap": shap_panel,
        "recommend": recommend(finding, shap_panel["detections"],
                               summary=summary),
    }

    if narrate_with:
        # Imported here rather than at module load so the panels work with
        # no language model installed at all.
        from services.llm_provider import get_provider
        from services.narration_service import narrate_all

        provider = get_provider(narrate_with)
        ok, detail = provider.available()

        if ok:
            from services.narration_service import DEFAULT_PANELS
            result = narrate_all(result, provider,
                                 narrate_panels or DEFAULT_PANELS)
            result["narrated_by"] = f"{provider.name}/{provider.model}"
        else:
            result["narration_unavailable"] = detail

    return result
