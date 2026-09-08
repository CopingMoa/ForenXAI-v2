"""
narration_service.py
====================

Turns the three panels' structured output into plain English, using a local
language model.

THE ONE RULE
Narration is ADDITIVE. Every number, label, citation and bar the panels
already show stays exactly where it is; the model writes a paragraph beside
them. If the model is unavailable, slow, or wrong, the panel still works and
the investigator still has the evidence.

That is not caution for its own sake. The whole reason panel 3 quotes your
documents verbatim is that a quote cannot be invented. Replacing the quote
with a paraphrase would throw that away for the sake of nicer prose.

WHAT EACH PANEL ASKS FOR

  1  Flow summary      describe the shape of the capture. Facts only; the
                       counts are already on screen, so the model's job is
                       to say what they add up to.
  2  Why this decision translate feature attributions into observable
                       network behaviour, using the glossary definitions
                       supplied. Never as percentages -- the values are
                       log-odds.
  3  Recommendations   rewrite the retrieved document into ordered steps.
                       This is the one that must not invent: if the document
                       does not cover something, say so.

WHY LOCAL
A capture holds internal addressing and service layout for a network the
investigator is responsible for. Sending it to a third party is a disclosure
decision the tool should not make silently. Ollama for development,
llama-cpp for a packaged build; Claude only on explicit opt-in.

WHAT A SMALL MODEL GETS WRONG
qwen2.5:3b is weakest at exactly the thing panel 3 needs -- saying "not
covered" instead of filling a gap. Measured on the pipeline's grounding eval
it scored 1.00 on refusal in isolated cases but invented citations on a
full-length prompt. So panel 3's prompt is kept short, the document is the
only source offered, and the deterministic quote stays on screen underneath.
"""

from services.narration_schema import provenance, check, summary_line


SYSTEM = "\n".join([
    "You are assisting a qualified network forensics investigator.",
    "Be precise and brief. Plain English, no marketing language.",
    "Never invent a fact, a recommendation, a citation or a technique ID.",
    "If the information given does not cover something, say so and move on.",
    "SHAP contributions are log-odds. Never express one as a percentage or "
    "as a change in probability.",
])

# Short enough that a 3b model stays on task; long enough to be useful.
# Raised after the first run cut panels 2 and 3 mid-sentence. A narration
# that stops halfway reads as a crash, and an investigator cannot tell a
# truncated answer from a model that had nothing more to say.
MAX_TOKENS = {"flow_summary": 400, "shap_explanation": 700,
              "recommendations": 900}


# ============================================================
# PROMPTS -- one per panel
# ============================================================

def _facts_block(facts):
    """The numbers the model may use, and nothing else."""
    keep = ("total_flows", "benign_flows", "attack_flows", "attack_share",
            "distinct_attack_classes", "mean_confidence",
            "low_confidence_flows", "flow_timeout_warning")
    lines = [f"  {k}: {facts[k]}" for k in keep if k in facts]

    w = facts.get("capture_window")
    if w:
        lines.append(f"  capture_ran: {w['first_flow']} to {w['last_flow']} "
                     f"({w['span_human']})")

    e = facts.get("endpoints", {})
    for role in ("targets", "sources"):
        if e.get(role):
            top = ", ".join(f"{r['address']} ({r['flows']} flows)"
                            for r in e[role][:3])
            lines.append(f"  busiest_{role}: {top}")

    counts = facts.get("class_counts", {})
    if counts:
        lines.append("  classes: " + ", ".join(
            f"{c} {n}" for c, n in list(counts.items())[:8]))

    return "\n".join(lines)


def prompt_flow_summary(panel):
    facts = panel["facts"]
    warn = ""
    if facts.get("flow_timeout_warning"):
        warn = ("\n\nflow_timeout_warning is true: these flows were extracted "
                "with a 120-second timeout, which does not match the model's "
                "training data. Say plainly that the results should not be "
                "trusted until the capture is re-extracted.")

    return f"""Describe this network capture for an investigator opening it
for the first time. Three or four sentences, no bullet points, no headings.

FACTS
{_facts_block(facts)}

Say what the capture holds, which activity dominates, and anything about its
shape that deserves a second look. Do not recommend actions -- another panel
does that. Do not speculate about who the attacker is or what they wanted.
Use only the numbers above.{warn}"""


def prompt_shap(panel, finding):
    """Attributions are already ranked; the model's job is translation."""
    d = panel["detections"][0]

    rows = []
    for a in d["attributions"]:
        rows.append(f"  {a['contribution']:+.3f}  {a['plain']}"
                    f"   (observed value {a['raw_value']:,.4f})")
        if a.get("caution"):
            rows.append(f"           CAUTION: {a['caution']}")

    ambiguity = ""
    if finding.get("dominant_runner_up_share", 0) > 0.25:
        ambiguity = (
            f"\n\nThe model named {finding['dominant_runner_up']} as the "
            f"runner-up for {finding['dominant_runner_up_share']:.0%} of "
            f"these flows. Say that the classification is uncertain between "
            f"the two.")

    return f"""Explain to a network investigator who is not a
machine-learning specialist why the model reached this decision.

DECISION
  predicted: {d['predicted']} at confidence {d['confidence']:.3f}
  runner-up: {d['runner_up']} at {d['runner_up_confidence']:.3f}
  this finding covers {finding['flow_count']:,} flows

EVIDENCE, strongest first. Values are LOG-ODDS: positive supports the
prediction, negative argues against it. They rank evidence against each
other and say nothing about how far the probability moved.
{chr(10).join(rows)}

Write two short paragraphs. First: what was detected, in one or two
sentences. Second: what the evidence means as observable network behaviour,
using the descriptions given. Do not convert any value to a percentage. Do
not claim a feature caused the attack -- the model weighted it, which is a
different statement.{ambiguity}"""


def prompt_recommend(panel):
    """
    The document is the only source. Everything else is context.

    The deterministic panel already shows the document verbatim with its
    path; this asks for an ordered reading of it, and says plainly what to do
    when there is nothing to read.
    """
    doc_sections = [s for s in panel["sections"] if s.get("source")]

    if not doc_sections:
        return f"""No response documentation was retrieved for a
{panel['class']} finding.

Write two sentences stating that no guidance is available for this class and
that none should be inferred, and naming the files that are missing:
{', '.join(panel['missing_documents']) or 'unknown'}

Do not suggest any action of your own."""

    docs = "\n\n".join(f"=== {s['source']} ===\n{s['body']}"
                       for s in doc_sections)

    context = [s["body"] for s in panel["sections"]
               if s["heading"] in ("What was found", "How confident to be",
                                   "Ambiguity")]

    return f"""Turn this response documentation into ordered steps for an
investigator handling a {panel['class']} finding.

SITUATION
{chr(10).join('  ' + c for c in context)}

DOCUMENTATION -- the only source you may use
{docs}

Write the steps in the order the documentation gives them, numbered, one
sentence each. After the steps, add a short paragraph headed "Not covered"
naming anything this situation needs that the documentation above does not
address.

Every step must come from the documentation. If you cannot point to a
sentence in it that prescribes a step, do not write that step."""


BUILDERS = {
    "flow_summary": lambda p, ctx: prompt_flow_summary(p),
    "shap_explanation": lambda p, ctx: prompt_shap(p, ctx["finding"]),
    "recommendations": lambda p, ctx: prompt_recommend(p),
}


# ============================================================
# RUNNING
# ============================================================

def narrate(panel, provider, context=None):
    """
    Add a `narrative` to one panel. Returns the panel either way.

    Never raises. A model that is missing, slow or broken degrades the panel
    to what it already showed, with a line saying why -- it does not take the
    tab down with it.
    """
    name = panel.get("panel")
    build = BUILDERS.get(name)

    if build is None:
        return panel

    try:
        prompt = build(panel, context or {})
        text, usage = provider.complete(
            system=SYSTEM,
            user=prompt,
            max_tokens=MAX_TOKENS.get(name, 400),
        )
        panel["narrative"] = (text or "").strip() or None
        panel["narration_usage"] = usage
        if usage.get("context_note"):
            panel["narration_note"] = usage["context_note"]

        # What the model was shown, and whether its output stayed inside it.
        # Recorded on the panel so a saved case can be audited later without
        # re-running anything.
        sources = [s["source"] for s in panel.get("sections", [])
                   if s.get("source")]
        panel["narration_provenance"] = provenance(panel, prompt, usage,
                                                   sources)
        findings, stats = check(panel["narrative"], prompt, sources)
        panel["narration_findings"] = findings
        panel["narration_stats"] = stats
        panel["narration_verdict"] = summary_line(stats, findings)

    except Exception as e:
        panel["narrative"] = None
        panel["narration_error"] = f"{type(e).__name__}: {e}"

    return panel


# Which panels a language model is allowed to narrate by default.
#
# Panel 3 is absent deliberately. Its content is a response playbook someone
# else already wrote carefully; the deterministic panel quotes it verbatim
# with its source, and a quote cannot be invented. Asking a model to reorder
# that prose buys presentation and risks the one guarantee the panel exists
# to provide.
#
# Panels 1 and 2 are different. Panel 1 turns counts into a sentence, and
# panel 2 does the thing no template can: combining a feature's definition,
# its observed value and the direction of its contribution into "unusually
# long for automated traffic". That judgement is why a model is here at all.
#
# Narrating panel 3 stays possible -- pass it explicitly -- but it is a
# decision someone makes, not the default.
DEFAULT_PANELS = ("summary", "shap")

ALL_PANELS = ("summary", "shap", "recommend")


def narrate_all(result, provider, panels=DEFAULT_PANELS):
    """
    Narrate the requested panels.

    `panels` defaults to the two where prose adds information. Pass
    ALL_PANELS to include recommendations, and see the note above for why
    that is not the default.
    """
    finding = result.get("selected")

    for key in panels:
        panel = result.get(key)
        if isinstance(panel, dict):
            narrate(panel, provider, {"finding": finding})

    result["narrated_panels"] = list(panels)
    return result
