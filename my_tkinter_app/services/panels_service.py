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
import hashlib

import numpy as np
import pandas as pd

from services.config import BASE_DIR
from services.flow_intake import (IntakeError, read_flows, to_matrix,
                                  describe, identity_columns,
                                  capture_window, endpoints,
                                  inventory)


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
# NO MITRE ATT&CK MAPPING.
#
# The IDs that used to be here were real and correctly named, and they were
# still removed. Enterprise ATT&CK describes adversary behaviour observed at
# the HOST -- process creation, credential access, registry, file writes.
# This tool sees CICFlowMeter flow records, which carry none of that. A flow
# table can suggest a technique; it cannot establish one.
#
# Two consequences that made the mapping worse than nothing:
#
#   * It read as corroboration. An analyst copying "T1046" into a report was
#     citing a host-behaviour framework for evidence that was never host
#     behaviour. The UI's "(unverified)" label did not stop that.
#   * Coverage was uneven and the gaps were not random. Evasion, TLSSSL and
#     Benign had no honest mapping at all; the classes that did map, mapped
#     coarsely -- three separate classes all landing on T1190.
#
# IoT traffic makes it worse again: ATT&CK for ICS is a separate matrix, and
# neither matrix describes the device behaviour TRUSTLab captures.
#
# If ATT&CK is wanted later, map it where the evidence lives -- endpoint
# telemetry -- not from flow records.
# ============================================================

KNOWLEDGE_MAP = {
    # One document per class. A file covering three classes cannot say
    # anything specific to any of them, and the panel quotes the whole file
    # -- so a DoS finding was showing Slowloris guidance and the reverse.
    "API":            {"doc": "incident_response/api.md"},
    "Benign":         {"doc": "incident_response/benign.md"},
    "Bruteforce":     {"doc": "incident_response/bruteforce.md"},
    "BufferOverflow": {"doc": "incident_response/bufferoverflow.md"},
    "C2Beaconing":    {"doc": "incident_response/c2beaconing.md"},
    "DDoS":           {"doc": "incident_response/ddos.md"},
    "DNS":            {"doc": "incident_response/dns.md"},
    "DoS":            {"doc": "incident_response/dos.md"},
    "Evasion":        {"doc": "incident_response/evasion.md"},
    "Exfiltration":   {"doc": "incident_response/exfiltration.md"},
    "Exploitation":   {"doc": "incident_response/exploitation.md"},
    "MITM":           {"doc": "incident_response/mitm.md"},
    "PortScan":       {"doc": "incident_response/portscan.md"},
    "Slowloris":      {"doc": "incident_response/slowloris.md"},
    "TLSSSL":         {"doc": "incident_response/tlsssl.md"},
    "WebBased":       {"doc": "incident_response/webbased.md"},
}

# ============================================================
# CLASS -> WHAT THE ANALYST DOES NEXT
#
# Deterministic on purpose. This is the shortest, most operational thing on
# the panel and the most damaging to get wrong, so no language model touches
# it -- the text below is what renders, verbatim.
#
# Why data and not sixteen more .md files:
#
#   * incident_response/<class>.md already carries the CONTAINMENT advice,
#     sourced and citation-checked. Sixteen analyst documents would restate
#     it in an unsourced voice, and the panel would show both.
#   * What actually varies per class for the ANALYST is three short fields.
#     Three fields is a table, not a document.
#   * Only the matching row renders. A single .md holding all sixteen would
#     put fifteen irrelevant rows on screen, because the panel quotes whole
#     files.
#
# `evidence`     what to pull from the capture beyond the flow record
# `corroborate`  the check that decides whether the classification holds
# `urgency`      when to act, given the reversibility ranking in
#                analyst/triage.md -- reversible steps first
#
# Not sourced, and says so on screen. NIST SP 800-61r3 and the CISA
# playbooks prescribe the general procedure, not per-class packet checks.
# ============================================================

ANALYST_ACTIONS = {
    "API": {
        "evidence": "Full request URIs, methods, auth headers and response "
                    "codes for the flagged flows.",
        "corroborate": "Do the requests hit API paths, and is the "
                       "4xx/5xx rate abnormal for this endpoint?",
        "urgency": "Same day. Rate-limit the source first; blocking an API "
                   "client can break a production integration.",
    },
    "Benign": {
        "evidence": "None beyond retention with the rest of the capture.",
        "corroborate": "Only where benign was a low-confidence call, or was "
                       "runner-up on an attack finding.",
        "urgency": "None. Do not act on a benign classification.",
    },
    "Bruteforce": {
        "evidence": "Authentication logs for the target service over the "
                    "capture window; success-after-failure sequences.",
        "corroborate": "Repeated auth attempts from one source, and whether "
                       "any SUCCEEDED. A successful login changes this from "
                       "an attempt to an intrusion.",
        "urgency": "Immediate if any attempt succeeded. Lock the account and "
                   "preserve the session before blocking the source.",
    },
    "BufferOverflow": {
        "evidence": "Packet payloads for the flagged flows; service logs and "
                    "crash dumps on the target host.",
        "corroborate": "Oversized or malformed input to a listening service, "
                       "and whether the service crashed or restarted.",
        "urgency": "Immediate. Assume code execution until the host is "
                   "examined. Image before isolating.",
    },
    "C2Beaconing": {
        "evidence": "Full destination list, JA3/JA3S if TLS, timing of every "
                    "flow to the destination, DNS that resolved it.",
        "corroborate": "Regular interval to one external destination that "
                       "persists across the capture. Check the destination "
                       "against threat intelligence.",
        "urgency": "Immediate, but do NOT block first -- blocking tells the "
                   "operator they were seen. Monitor, scope, then contain.",
    },
    "DDoS": {
        "evidence": "Source address distribution, upstream provider logs, "
                    "service availability during the window.",
        "corroborate": "Many distinct sources to one target, and whether the "
                       "service actually degraded.",
        "urgency": "Immediate. Upstream filtering, not host-level blocking "
                   "-- the traffic has already consumed the link.",
    },
    "DNS": {
        "evidence": "Queried names, record types, response sizes, resolver "
                    "logs.",
        "corroborate": "Query volume, name length and entropy. Tunnelling "
                       "shows as long encoded labels or high TXT volume.",
        "urgency": "Same day. Point the host at a controlled resolver before "
                   "blocking DNS outright.",
    },
    "DoS": {
        "evidence": "Request rate over time, service logs, resource metrics "
                    "on the target.",
        "corroborate": "Single source, sustained rate, measurable service "
                       "degradation. WEAK CLASS -- see the reliability "
                       "guidance; confirm before reporting.",
        "urgency": "Same day. Rate-limit first; the source may be a "
                   "misconfigured client rather than an attacker.",
    },
    "Evasion": {
        "evidence": "Raw packets with IP fragment offsets and TTL values "
                    "intact. Do not work from a reassembled view.",
        "corroborate": "Do fragments actually overlap, or do TTLs vary within "
                       "one flow? Both occur naturally.",
        "urgency": "Immediate for the DETECTOR, not the host. If evasion "
                   "succeeded, every other finding in this capture is less "
                   "reliable.",
    },
    "Exfiltration": {
        "evidence": "Outbound byte volume per destination, timing, and the "
                    "identity of the internal source host.",
        "corroborate": "Outbound volume far above this host's baseline to a "
                       "destination it does not normally contact.",
        "urgency": "Immediate. Preserve first -- isolating the host destroys "
                   "the session state that shows what left.",
    },
    "Exploitation": {
        "evidence": "Packet payloads, target service version, host logs from "
                    "the exploitation window onward.",
        "corroborate": "Does the payload match a known exploit for the "
                       "service, and did behaviour change afterwards?",
        "urgency": "Immediate. Treat the host as compromised until examined.",
    },
    "MITM": {
        "evidence": "ARP tables, certificate chains presented, gateway MAC "
                    "over time.",
        "corroborate": "Two MACs claiming one address, or a certificate not "
                       "signed by the expected authority.",
        "urgency": "Immediate. Anything observed on this segment during the "
                   "window may have been read or altered in transit.",
    },
    "PortScan": {
        "evidence": "Ports contacted, order, and which responded. Source "
                    "address and whether it is internal.",
        "corroborate": "One source to many ports in a short window. Confirm "
                       "it is not an authorised scanner before acting.",
        "urgency": "Low on its own -- reconnaissance, not compromise. Check "
                   "what the source did AFTER the scan; that is the finding "
                   "that matters.",
    },
    "Slowloris": {
        "evidence": "Concurrent connection count on the target, per-connection "
                    "duration, server worker pool state.",
        "corroborate": "Many long-lived, low-data connections held open. WEAK "
                       "CLASS and confusable with DoS -- report the pair, not "
                       "one name.",
        "urgency": "Same day. Connection timeouts and per-source limits fix "
                   "this without blocking anyone.",
    },
    "TLSSSL": {
        "evidence": "Full handshake, cipher suites offered and selected, "
                    "certificate chain, TLS version.",
        "corroborate": "Deprecated version or cipher, or a handshake pattern "
                       "matching a known weakness. Legacy clients look "
                       "similar and are not attacks.",
        "urgency": "Same day unless the handshake shows active exploitation, "
                   "then immediate.",
    },
    "WebBased": {
        "evidence": "Full request URIs and bodies, web server and "
                    "application logs, response codes.",
        "corroborate": "Injection or traversal patterns in the requests, and "
                       "whether the application returned data rather than an "
                       "error.",
        "urgency": "Immediate if any request succeeded. A 200 on an injection "
                   "attempt is a breach, not an attempt.",
    },
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
        "panel": "shap",
        "when": lambda f, s: True,
    },
    {
        "id": "shap_limits",
        "doc": "interpretability/caveats.md",
        "heading": "Limits to quote alongside the explanation",
        "panel": "shap",
        "when": lambda f, s: True,
    },
    {
        # Every panel uses these terms -- confidence, margin, log-odds, base
        # value, macro F1, spurious correlation -- and until this entry
        # existed the file defining them was the ONE knowledge document no
        # finding could ever reach. Twenty sourced definitions, invisible.
        # Retrieved with the guidance that uses the vocabulary.
        "id": "glossary",
        "doc": "interpretability/glossary.md",
        "heading": "What these terms mean in this interface",
        "panel": "shap",
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
        "panel": "shap",
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
    {
        "id": "triage",
        "doc": "analyst/triage.md",
        "heading": "What to do with this finding",
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

    # WHO and WHAT, for the whole capture and for the attack flows alone.
    # The second is the forensically useful half: "1,283 attack flows" does
    # not say how many hosts are implicated, and that is the first question
    # asked of any capture.
    facts["inventory"] = inventory(flows)
    attack_mask = np.asarray(names) != "Benign"
    if attack_mask.any():
        facts["attack_inventory"] = inventory(flows, attack_mask)
        facts["attack_endpoints"] = endpoints(flows, attack_mask)

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


def verify_capture_link(csv_path, pcap_path=None, known_sha256=None):
    """Does this flow table actually describe this capture?

    WHAT WAS BEING VERIFIED BEFORE, AND WHAT WAS NOT
    Every other check in this project recomputes a panel figure from the
    flow TABLE. That proves the panels agree with the CSV. It proves nothing
    about whether the CSV describes the PCAP in front of the investigator --
    a stale table, or one extracted from a different capture, would pass
    every one of those checks while describing other traffic.

    This closes that. The extraction record now carries the capture's
    SHA-256, so the chain PCAP -> CSV -> panels can be checked end to end
    rather than assumed at its first link.

    Returns a dict with `state`:
      verified     the digest recorded at extraction matches this capture
      mismatch     it does not -- the flow table is not from this PCAP
      unrecorded   extracted before digests were recorded, or CSV supplied
                   directly. Reported as unknown, never as verified.
    """
    out = {"state": "unrecorded", "checks": []}
    record = read_extraction_record(csv_path)
    if not record:
        out["detail"] = ("No extraction record beside the flow table, so the "
                         "table cannot be tied to a capture.")
        return out

    recorded = record.get("capture_sha256")
    pcap = pcap_path or record.get("capture")

    if not recorded:
        out["detail"] = ("This flow table was extracted before capture "
                         "digests were recorded. Re-extract to bind it to "
                         "the PCAP.")
        return out

    actual = known_sha256
    if not actual and pcap and os.path.isfile(pcap):
        h = hashlib.sha256()
        try:
            with open(pcap, "rb") as fh:
                for block in iter(lambda: fh.read(1 << 20), b""):
                    h.update(block)
            actual = h.hexdigest()
        except OSError:
            actual = None

    if not actual:
        out["detail"] = ("The capture named by the extraction record is not "
                         "readable, so the link cannot be checked.")
        return out

    out["recorded_sha256"] = recorded
    out["capture_sha256"] = actual
    out["state"] = "verified" if actual.lower() == recorded.lower() \
        else "mismatch"
    out["checks"].append(("capture digest", out["state"] == "verified"))

    # Size is redundant when the digest matches and useful when it does not:
    # it separates "a different capture" from "the same capture, truncated".
    if pcap and os.path.isfile(pcap) and record.get("capture_bytes"):
        same = os.path.getsize(pcap) == record["capture_bytes"]
        out["checks"].append(("capture size", same))

    # Modification time, only when the digest did NOT settle it. A matching
    # digest proves the table came from these bytes; mtime after that is
    # noise -- copying a file rewrites it -- and a red line under a VERIFIED
    # result reads as a contradiction.
    if out["state"] != "verified":
        try:
            if pcap and os.path.isfile(pcap) and os.path.isfile(csv_path):
                fresh = os.path.getmtime(csv_path) >= os.path.getmtime(pcap) - 1
                out["checks"].append(
                    ("flow table not older than capture", fresh))
        except OSError:
            pass

    if out["state"] == "mismatch":
        out["detail"] = ("The flow table was extracted from a DIFFERENT "
                         "capture than the one loaded. Every figure in these "
                         "panels describes that other capture. Re-extract "
                         "before relying on anything here.")
    else:
        out["detail"] = ("The flow table was extracted from this exact "
                         "capture; the digest recorded at extraction matches "
                         "the file on disk.")
    return out


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

# Features whose value depends on how long the extractor kept a flow open.
# When the capture was extracted with a default timeout these are not
# comparable with the model's training data, and they are exactly the
# features this class of model leans on hardest.
_TIMING_FEATURE = re.compile(r"IAT|Duration|Active|Idle|/s\b", re.I)


# What a feature's raw value is MEASURED IN. CICFlowMeter reports timings in
# microseconds and sizes in bytes, and the column name says neither.
#
# Measured consequence of leaving it out: given "Flow IAT Min (observed
# value 1,169,002)" the narration wrote "the shortest gap observed at
# 1,169,002 bytes". The figure traced to the input, so every grounding check
# passed and the sentence was still wrong. Supplying the unit is the
# cheapest fix for a whole class of wrong sentence, and it is cheaper than
# any instruction telling the model not to guess.
#
# Order matters: "Flow Bytes/s" is a rate, not a size, so rates match first.
_UNITS = [
    (re.compile(r"IAT|Duration|Active |Idle ", re.I), "microseconds"),
    (re.compile(r"Bytes/s", re.I), "bytes per second"),
    (re.compile(r"Packets/s", re.I), "packets per second"),
    (re.compile(r"Bulk Rate", re.I), "bytes per second"),
    (re.compile(r"Variance", re.I), "bytes squared"),
    (re.compile(r"Ratio", re.I), "ratio"),
    (re.compile(r"Port", re.I), "port number"),
    (re.compile(r"Protocol", re.I), "IP protocol number"),
    (re.compile(r"Flag|Flags|Packet/Bulk|Subflow \w+ Packets"
                r"|Total (Fwd|Bwd) [Pp]acket", re.I), "count"),
    (re.compile(r"Length|Size|Bytes|Win Bytes", re.I), "bytes"),
]


def _unit_of(feature):
    """The unit of a feature's raw value, or None when it is a bare count."""
    for pattern, unit in _UNITS:
        if pattern.search(feature):
            return unit
    return None


def _readable(raw, unit):
    """The value as a person would say it, unit included.

    A microsecond figure is unreadable at scale -- 1,169,002 microseconds is
    1.17 seconds, and a reader who has to do that division will not do it.
    The model will not do it either: told only the raw figure it called
    1,169,002 microseconds a "very short gap", which is wrong by three
    orders of magnitude.
    """
    if unit == "microseconds" and abs(raw) >= 1000:
        secs = raw / 1e6
        return (f"{raw:,.0f} microseconds ({secs:,.2f} seconds)" if secs >= 1
                else f"{raw:,.0f} microseconds ({raw / 1000:,.1f} ms)")
    if unit:
        return f"{raw:,.4f} {unit}".replace(".0000 ", " ")
    return f"{raw:,.4f}".replace(".0000", "")


def _magnitude(z):
    """How unusual this value is, against the distribution the model learnt.

    The scaled matrix IS the z-score -- StandardScaler centred each feature
    on the training mean and divided by its standard deviation -- so this
    costs nothing to compute and it is the comparison the model kept trying
    to make with an adjective and getting wrong.

    Supplying the comparison is what makes "do not describe a value as large
    or small" a followable instruction rather than a prohibition with no
    alternative.
    """
    a = abs(z)
    where = "above" if z > 0 else "below"
    if a < 1:
        return "typical for this feature in the training data"
    if a < 3:
        return f"{a:.1f} standard deviations {where} the training mean"
    return (f"{a:.1f} standard deviations {where} the training mean, "
            f"far outside the usual range")


def explain_detections(X, proba, k, names, bundle, rows, top=6, summary=None):
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

    `summary` is the Flow Summary panel. It is optional and used for one
    thing: when the capture carries a flow-timeout warning, every timing
    feature in the attribution list is marked with a caution. Without it the
    panels disagree -- panel 1 says the timing features are not comparable
    with the training data, and panel 2 goes on ranking them unmarked.
    """

    caution = None
    if (summary or {}).get("facts", {}).get("flow_timeout_warning"):
        cap = (summary or {}).get("facts", {}).get("flow_timeout_seconds")
        caution = (
            f"Timing feature, and this capture's longest flow is almost "
            f"exactly the extractor's {cap or 120}-second default timeout. "
            f"The model was trained on flows extracted with a longer "
            f"timeout, so this value is not on the same scale as the data "
            f"the attribution was learned from. See the Flow Summary "
            f"warning."
        )

    sv = bundle["explainer"].shap_values(X[rows])

    # The model's own output, alongside the explanation of it.
    #
    # TreeSHAP explains a margin, and the panel showed only the attributions
    # -- so a reader had to take on trust that the attributions belonged to
    # the decision above them. They are computed here so the panel can show
    # the arithmetic: base value + every contribution == the margin XGBoost
    # actually produced. If that identity fails the attributions explain a
    # different decision, and the panel says so instead of drawing bars.
    margins = np.atleast_2d(bundle["model"].predict(X[rows],
                                                    output_margin=True))
    base_values = np.atleast_1d(
        np.asarray(bundle["explainer"].expected_value, dtype=float))

    # SHAP returns (n, features, classes) on current versions and a list of
    # per-class arrays on older ones.
    if isinstance(sv, list):
        sv = np.stack(sv, axis=-1)

    glossary = _load_glossary()
    feature_cautions = _load_feature_cautions()

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

        # What the MODEL said, before any explanation of it.
        order_p = np.argsort(proba[r])[::-1][:5]
        model_output = {
            "predicted": cls,
            "confidence": round(float(proba[r, cls_i]), 4),
            "margin": round(float(margins[j, cls_i]), 6),
            "probabilities": [
                {"class": str(bundle["encoder"].inverse_transform([c])[0]),
                 "probability": round(float(proba[r, c]), 6)}
                for c in order_p],
        }

        # Whether the explanation reconstructs it. The sum is over ALL 74
        # features, not the six the panel draws -- additivity is a property
        # of the whole attribution vector, and checking only the visible
        # rows would always fail.
        total = float(contrib.sum())
        recon = float(base_values[cls_i]) + total
        shown = float(np.abs(contrib[order]).sum())
        allabs = float(np.abs(contrib).sum()) or 1.0
        shap_check = {
            "base_value": round(float(base_values[cls_i]), 6),
            "sum_all_features": round(total, 6),
            "reconstructed_margin": round(recon, 6),
            "model_margin": round(float(margins[j, cls_i]), 6),
            "additivity_error": round(abs(recon - float(margins[j, cls_i])), 9),
            "agrees": bool(abs(recon - float(margins[j, cls_i])) < 1e-3),
            "features_shown": len(order),
            "features_total": len(bundle["features"]),
            "shown_share_of_total": round(shown / allabs, 4),
            # The strongest form: does the reconstruction pick the class the
            # model picked? A vector can sum correctly and still be sliced
            # against the wrong class axis.
            "reconstruction_picks_predicted": bool(
                int(np.argmax(sv[j].sum(0) + base_values)) == cls_i),
        }

        detections.append({
            "row": int(r),
            "predicted": cls,
            "confidence": round(float(proba[r, cls_i]), 4),
            "model_output": model_output,
            "shap_check": shap_check,
            "runner_up": str(bundle["encoder"].inverse_transform([runner])[0]),
            "runner_up_confidence": round(float(proba[r, runner]), 4),

            "attributions": [
                {
                    "feature": bundle["features"][i],
                    "plain": glossary.get(bundle["features"][i],
                                          bundle["features"][i]),
                    "raw_value": round(float(raw_row[i]), 4),
                    "unit": _unit_of(bundle["features"][i]),
                    # Pre-rendered so neither the reader nor the model has to
                    # convert, and so the comparison the model kept getting
                    # wrong is supplied rather than left to it.
                    "readable": _readable(float(raw_row[i]),
                                          _unit_of(bundle["features"][i])),
                    "magnitude": _magnitude(float(X[r, i])),
                    "contribution": round(float(contrib[i]), 6),
                    "direction": (
                        "supports" if contrib[i] > 0 else "argues against"
                    ),
                    # Two sources, and the capture-specific one wins.
                    #
                    # `caution` above is about THIS capture (its flows hit
                    # the extractor's timeout, so the timing features are
                    # off-scale). The glossary's are about the FEATURE
                    # wherever it appears -- the destination port may be the
                    # lab's service layout, the initial window sizes are
                    # partly an OS fingerprint. Only the first was ever
                    # attached, so eight features the corpus explicitly says
                    # to warn about reached the panel unmarked.
                    **({"caution": (
                        caution
                        if caution and _TIMING_FEATURE.search(
                            bundle["features"][i])
                        else feature_cautions.get(bundle["features"][i]))}
                       if ((caution and _TIMING_FEATURE.search(
                            bundle["features"][i]))
                           or feature_cautions.get(bundle["features"][i]))
                       else {}),
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


def _load_feature_cautions():
    """Feature name -> the warning the glossary says to show with it.

    knowledge/features/glossary.md carries a section headed "Features that
    need a warning shown with them": Dst Port may be the lab's service
    layout rather than the attack, the initial window sizes are partly an OS
    fingerprint, and so on. The author wrote them to be displayed, and
    nothing read them -- _load_glossary() parses only the description table,
    so every attribution reached the panel with caution=None.

    The cost was not only a missing line on screen. prompt_shap() gives a
    cautioned feature its caution INSTEAD OF the standard-deviation
    comparison, precisely so the distance cannot be over-read; with no
    caution ever set, that branch never ran, and qwen2.5:3b turned "1.4
    standard deviations above the training mean" on the destination port
    into "indicating a service that is unusual or not typical" -- an
    inference about the service from a fact about the model, which is the
    exact reading this warning exists to prevent.
    """
    path = os.path.join(KNOWLEDGE_DIR, "features", "glossary.md")
    if not os.path.isfile(path):
        return {}

    out, in_section = {}, False
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("## "):
                in_section = "warning" in line.lower()
                continue
            if not in_section:
                continue
            m = re.match(r"\s*-\s*\*\*`([^`]+)`\*\*\s*[-—:]+\s*(.+)",
                         line)
            if m:
                out[m.group(1)] = m.group(2).strip()
    return out


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


def readable_markup(text):
    """Author's markup out, prose in.

    The knowledge files cross-reference each other with `[[shap-reading]]`
    wiki links and end with a "Related:" line. Both are navigation for
    whoever maintains the documents; on screen they are noise, and in a
    prompt they are something the model will copy into a sentence an
    investigator then has to decode.

    Links become their own words -- "[[class-ambiguity]]" reads as "class
    ambiguity" -- and the trailing Related line is dropped entirely.
    """
    out = re.sub(r"^\s*Related:.*$", "", text or "", flags=re.M)
    out = re.sub(r"\[\[([^\]]+)\]\]",
                 lambda m: m.group(1).replace("-", " ").replace("_", " "),
                 out)
    return re.sub(r"\n{3,}", "\n\n", out).strip()


# A section whose content is its heading rather than its prose: the quoted
# passages, and the closing honesty section every knowledge file carries.
_NOT_PROSE = re.compile(r"not covered|^#{1,6}\s+From\s", re.I)


def _lede(text, max_words=90):
    """The opening paragraph of each section, as one readable paragraph.

    WHY THIS EXISTS
    digest_document() was written for a response playbook, where the content
    IS the prescriptive lines and the quoted passages. Applied to an
    explanatory document it produces neither: `interpretability/
    shap_reading.md` is 997 words across seven sections explaining how to
    read an attribution, and the playbook digest reduced it to two truncated
    fragments -- "It is not a cause." -- under five quotations about
    regression-tree leaf scores and the definition of explainable AI. The
    document's whole value is its prose, and the prose was the one part not
    shown.

    So an explanatory document is summarised by what its author wrote first
    in each section, which is where the point of the section is made. `From`
    sections are skipped because they are quotations rather than exposition,
    and the closing "Not covered by these sources" section is skipped
    because out of context it reads as a description of the panel rather
    than of the document.
    """
    out, words = [], 0
    for section in re.split(r"\n(?=#{1,6} )", readable_markup(text)):
        head = section.split("\n", 1)[0].strip()
        if not re.match(r"#{2,6}\s", head) or _NOT_PROSE.search(head):
            continue
        for para in re.split(r"\n\s*\n", section.partition("\n")[2]):
            flat = re.sub(r"\s+", " ", re.sub(r"\*\*", "", para)).strip()
            # Blockquotes, bullets and tables are structure; the first plain
            # paragraph is the one written to be read on its own.
            if not flat or flat[0] in ">-*|" or flat.startswith("#"):
                continue
            out.append(flat)
            words += len(flat.split())
            break
        if words >= max_words:
            break

    joined = " ".join(out).split()
    if len(joined) <= max_words:
        return " ".join(joined)
    # Trim to a sentence boundary rather than mid-clause.
    clipped = " ".join(joined[:max_words])
    cut = max(clipped.rfind(". "), clipped.rfind("? "), clipped.rfind("! "))
    return clipped[:cut + 1] if cut > 60 else clipped + "..."


# A bolded lead-in at the start of a line, or of a list item. The knowledge
# files write their prescriptive statements this way -- "**Do not add SHAP
# values to a probability.**", "**It is not a cause.**" -- as complete
# sentences, so the bold run IS the point and needs no reassembly.
_KEY_POINT = re.compile(r"^(?:[-*+]\s+)?\*\*([A-Z][^*]{3,}?)\*\*", re.M)


def _key_points(text, limit=5):
    """The prescriptive statements of an explanatory document.

    Scanned across the whole document rather than section by section, which
    is what the playbook digest does and why this section showed two points
    where the author wrote five. Two causes, both structural:

      - Three of the five sit in prose that FOLLOWS a `## From` quotation.
        Splitting on headings puts that prose inside the quote section, and
        the playbook digest skips quote sections wholesale.
      - The other two are consecutive bullets in one list. Paragraph
        splitting treats the list as a single block, so only the first
        bullet survived.

    Neither is a property of the document -- both are artefacts of reading it
    with a splitter built for a different shape of file. Quoted lines are
    still excluded, because a passage from a cited work is evidence for a
    point rather than a point of its own.
    """
    body = "\n".join(
        line for line in readable_markup(text).splitlines()
        if not line.lstrip().startswith(">"))

    points, seen = [], set()
    for m in _KEY_POINT.finditer(body):
        point = re.sub(r"\s+", " ", m.group(1)).strip()
        if not point.endswith((".", "!", "?")):
            point += "."
        key = point.lower()
        if key in seen:
            continue
        seen.add(key)
        points.append(point)
        if len(points) == limit:
            break
    return points


def _definitions(text):
    """Term and its first sentence, for a document written as a term list.

    The bolded lead-in IS the term and the prose after it IS the definition,
    so both are already marked up; nothing is inferred.
    """
    body = "\n".join(
        line for line in readable_markup(text).splitlines()
        if not line.lstrip().startswith(">"))

    out, seen = [], set()
    for m in _KEY_POINT.finditer(body):
        term = re.sub(r"\s+", " ", m.group(1)).strip().rstrip(".")
        rest = re.sub(r"\s+", " ", body[m.end():]).strip()
        # Stop at the next term, so a definition never absorbs the one after
        # it -- which is exactly what made the paragraph form unreadable.
        nxt = _KEY_POINT.search(body, m.end())
        if nxt:
            rest = re.sub(r"\s+", " ",
                          body[m.end():nxt.start()]).strip()
        rest = re.sub(r"^[\s.:—-]+", "", rest)
        sentence = re.match(r"(.+?[.!?])(?:\s|$)", rest)
        meaning = (sentence.group(1) if sentence else rest).strip()
        key = term.lower()
        if not term or not meaning or key in seen:
            continue
        seen.add(key)
        out.append({"term": term, "meaning": meaning})
    return out


def _is_term_list(text):
    """Is this document a glossary rather than an argument?

    Measured across the nine explanatory documents in the corpus rather than
    guessed: the glossary carries 24 bolded lead-ins with a median length of
    2 words, and no other document has more than 6. Reliability and
    extraction-validity are the closest on length -- 2-word lead-ins -- and
    are nowhere near on count. A four-fold gap is wide enough to read off
    the document's shape and not have to tag it by hand, so a term list
    added later renders correctly without anyone remembering to declare it.

    Getting this wrong costs a section rendered in the other form, which is
    a presentation fault and not a claim about the evidence.
    """
    points = [re.sub(r"\s+", " ", m.group(1)).strip()
              for m in _KEY_POINT.finditer(
                  "\n".join(line for line in readable_markup(text).splitlines()
                            if not line.lstrip().startswith(">")))]
    if len(points) < 10:
        return False
    lengths = sorted(len(p.split()) for p in points)
    return lengths[len(lengths) // 2] <= 3


def _preamble(text, max_words=60):
    """The document's own opening line, before the first section heading.

    A glossary's summary must not be built from its definitions: running
    them together produced "Class. One of the sixteen labels... Held-out
    test set. 280,000 flows..." which reads as one broken sentence. The
    author already wrote the one-line statement of what the list is for.
    """
    body = readable_markup(text)
    body = re.split(r"\n#{1,6} ", body, maxsplit=1)[0]
    for para in re.split(r"\n\s*\n", body):
        flat = re.sub(r"\s+", " ", re.sub(r"\*\*", "", para)).strip()
        if not flat or flat[0] in ">-*|#":
            continue
        words = flat.split()
        return " ".join(words[:max_words]) + ("..." if len(words) > max_words
                                               else "")
    return ""


def digest_document(text, style="playbook"):
    """A document reduced to what a panel should actually show.

    Panel 3 rendered every retrieved file in full -- up to 30,000 characters
    across nine documents. Nobody reads that, and burying the two lines that
    matter inside it is a way of not saying them.

    So the panel gets three things instead of the whole file:

      outline  the section headings, so the shape of the document is visible
      quotes   the `## From` passages verbatim, with the source they name.
               These are the provenance: verified against the PDF, and the
               only part that cannot be paraphrased without detection.
      actions  lines that prescribe something, taken from the containment
               and detection sections -- the operational half

    The full document stays on disk and is named on screen, so nothing is
    hidden; it is simply not pasted into a text widget.
    """
    text = readable_markup(text)
    outline, quotes, actions = [], [], []
    current_source = None

    for section in re.split(r"\n(?=#{1,6} )", text):
        head = section.split("\n", 1)[0].strip()
        m = re.match(r"#{1,6}\s+From\s+([\w.\-]+)\s*$", head)
        if m:
            current_source = m.group(1)
            for block in _quoted_blocks(section.partition("\n")[2]):
                if len(block) >= 60:
                    quotes.append({"source": current_source, "text": block})
            continue

        h = re.match(r"#{2,6}\s+(.+?)\s*$", head)
        if h:
            outline.append(h.group(1))

        # A prescriptive statement: bolded lead-in, or an imperative bullet.
        #
        # Read as a whole SENTENCE, not a whole line. These documents wrap at
        # 72 columns, so taking the line gave "Per-connection duration --
        # long-lived connections carrying almost no" and stopped there.
        for para in re.split(r"\n\s*\n", section):
            flat = re.sub(r"\s+", " ", para).strip()
            if not (re.match(r"^\*\*[A-Z][^*]{3,}\*\*", flat)
                    or re.match(r"^[-*]\s+\*\*", flat)):
                continue
            flat = re.sub(r"\*\*", "", flat).strip("-* ").strip()
            # The lead-in sentence is the instruction; what follows is
            # rationale, and it belongs in the document rather than in a
            # summary line.
            m = re.match(r"(.+?[.!?])(?:\s|$)", flat)
            actions.append((m.group(1) if m else flat).strip())

    if style == "explainer":
        # A term list is not an argument, and summarising one as prose runs
        # its definitions together into a single broken sentence. Detected
        # from the document's shape; see _is_term_list().
        if _is_term_list(text):
            return {"outline": outline, "quotes": quotes, "actions": [],
                    "summary": _preamble(text),
                    "definitions": _definitions(text), "style": "glossary"}

        # Five at most, and the paragraph above them carries the reasoning.
        # Eight fragments with no connective prose is what made this section
        # unreadable in the first place.
        return {"outline": outline, "quotes": quotes,
                "actions": _key_points(text, 5), "summary": _lede(text),
                "style": "explainer"}

    return {"outline": outline, "quotes": quotes, "actions": actions[:8],
            "style": "playbook"}


def _quoted_blocks(chunk):
    """Blockquote passages in a section, joined into whole quotes."""
    lines, blocks, current = chunk.split("\n"), [], []
    for line in lines:
        s = line.lstrip()
        if s.startswith(">"):
            current.append(s[1:].strip())
        elif current:
            blocks.append(" ".join(current).strip())
            current = []
    if current:
        blocks.append(" ".join(current).strip())
    return [b for b in blocks if b]


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

    # What to do next, for THIS class. Deterministic and never narrated: it
    # is the shortest and most operational text on the panel, so it is also
    # the worst thing to let a language model rewrite.
    actions = ANALYST_ACTIONS.get(cls)
    if actions:
        sections.append({
            "heading": "Analyst actions",
            "body": (
                f"Collect: {actions['evidence']}\n\n"
                f"Corroborate: {actions['corroborate']}\n\n"
                f"Urgency: {actions['urgency']}\n\n"
                f"These three are this project's own operating notes, not "
                f"claims from a cited source. The sourced procedure is in "
                f"analyst/triage.md below."
            ),
            "kind": "actions",
        })

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
                "body": readable_markup(text),
                "source": path,
                # Attached to the section, so a recommendation and the work
                # it came from cannot be separated in rendering.
                "citations": cites,
                "digest": digest_document(text),
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
            "body": readable_markup(text),
            "source": rule["doc"],
            "citations": cites,
            "digest": digest_document(text, style="explainer"),
            # Which panel this guidance belongs on. Reading an attribution
            # is panel 2's subject, so its documents were three of the ten
            # sections on the RECOMMENDATIONS panel, pushing the response
            # playbook down the page. Untagged entries stay where they were.
            "panel": rule.get("panel", "recommend"),
            # Marks this as guidance about the model rather than about the
            # attack, so the tab can group or collapse it separately.
            "kind": "model",
        })

    # Every retrieved document is re-checked against the PDF it quotes,
    # here, on the file as it is on disk right now -- not on the state it
    # was in when `--verify` last ran. A document whose quotes no longer
    # match is quarantined: withheld from the panel and from the model, and
    # named below so the author can see which one and why.
    #
    # 0.20 s for the whole corpus from a content-addressed cache, 0.68 ms
    # once memoised, so this costs nothing per finding.
    from services.source_guard import verify_sections
    sections, unverified = verify_sections(sections)

    return {
        "panel": "recommendations",
        "unverified_documents": unverified,
        "class": cls,
        "ambiguity": ambiguity,
        "sections": sections,
        "citations": list(documents.keys()) + sorted(seen),
        # Numbered, so a sentence can point at one. The number is the
        # position in `references`, which is the order the reader sees --
        # a citation the model writes as [2] and a reader looks up as [2]
        # must be the same work, or the marker is decoration.
        "reference_map": [
            {"n": i + 1, "citation": c,
             "sources": sorted({s["source"] for s in sections
                                if c in (s.get("citations") or [])})}
            for i, c in enumerate(references)],

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
                 narrate_with=None, narrate_panels=None,
                 current_pcap=None, current_pcap_sha=None):
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
    # Does this flow table describe THIS capture? Checked, not assumed --
    # every other figure in these panels is recomputed from the table, so a
    # table from another capture would satisfy all of them.
    summary["capture_link"] = verify_capture_link(
        csv_path, current_pcap, current_pcap_sha)

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
        rows=finding["representative_rows"],
        summary=summary
    )

    result = {
        "summary": summary,
        "findings": findings,
        "selected": finding,
        "shap": shap_panel,
        "recommend": recommend(finding, shap_panel["detections"],
                               summary=summary),
    }

    # Panel 3 carries the evidence its recommendation rests on, so the
    # reader goes prediction -> why -> what to do without changing tabs.
    # Taken from panel 2 rather than recomputed, so the two cannot disagree.
    if result.get("shap") and result.get("recommend"):
        det = (result["shap"].get("detections") or [{}])[0]
        result["recommend"]["evidence"] = det.get("attributions", [])[:3]

    if narrate_with:
        # Narration runs on every analysis now, which makes this block the
        # one place a prose failure could take the evidence down with it.
        # It could: get_provider() raises on an unknown name, and a model
        # that dies mid-generation raises out of narrate_all(). Either would
        # have propagated out of build_panels() and the tab would have shown
        # "Analysis failed" with no panels at all -- for a paragraph.
        #
        # So the whole layer is contained. The deterministic result is
        # already complete above; anything that goes wrong from here is
        # reported as narration being unavailable, which is what it is.
        try:
            # Imported here rather than at module load so the panels work
            # with no language model installed at all.
            from services.llm_provider import get_provider
            from services.narration_service import narrate_all, ALL_PANELS

            provider = get_provider(narrate_with)
            ok, detail = provider.available()

            if ok:
                result = narrate_all(result, provider,
                                     narrate_panels or ALL_PANELS)
                result["narrated_by"] = f"{provider.name}/{provider.model}"
            else:
                result["narration_unavailable"] = detail
        except Exception as e:
            result["narration_unavailable"] = (
                f"{type(e).__name__}: {e}. The figures, attributions and "
                f"quoted guidance below are unaffected."
            )

    return result
