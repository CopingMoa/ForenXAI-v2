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

import re

from services.narration_schema import (provenance, check, summary_line,
                                       neutralise_magnitude)


SYSTEM = "\n".join([
    "You are assisting a qualified network forensics investigator.",
    "Be precise and brief. Plain English, no marketing language.",
    "Never invent a fact, a recommendation, a citation or a technique ID.",
    "If the information given does not cover something, say so and move on.",
    "SHAP contributions are log-odds. Never express one as a percentage or "
    "as a change in probability.",
])


# ============================================================
# WORKED EXAMPLES
#
# This is how a 3b model is taught, given that fine-tuning is not on the
# table. Instructions tell it what not to do; an example shows it what a
# correct answer LOOKS like, which is the thing a small model actually
# copies. Two examples cost about 200 tokens of a 32,768-token window.
#
# Each pair is chosen to demonstrate one failure this project has actually
# seen:
#
#   flow_summary     stick to the supplied numbers; no invented totals
#   shap_explanation say "raises the score for X" -- never a percentage,
#                    never "increases the probability by N%"
#
# The BAD line is included on purpose. Showing only the good answer leaves
# the model to guess what was wrong with its instinct; showing the
# rejected form next to it is what stops the percentage phrasing coming
# back, which was the most persistent error.
# ============================================================

# Prefixed to every example. Without it the model pasted the REJECTED block
# of the panel-3 example into its own answer, verbatim, where an
# investigator would read it as output.
_ILLUSTRATION = ("\nILLUSTRATION ONLY -- this shows the SHAPE of an answer. "
                 "Do not repeat any of its words, and do not reproduce these "
                 "labels in your reply.\n")

EXAMPLES = {
    # No worked GOOD answer here, on purpose. The first version of this
    # example used two real lines out of dos.md, and qwen2.5:3b copied both
    # into a Slowloris answer -- an example that concrete is a source the
    # model will draw on. The shape is shown instead, and the rejected form
    # is kept, because the rejected form is the half that stopped the
    # model returning section headings.
    "recommendations": """
THE SHAPE OF THE ANSWER
1. <what to do, one sentence> ANCHOR: <five or more words copied from the
playbook above>
2. <what to do next> ANCHOR: <five or more words copied from the playbook
above>

Not covered: <what this situation needs that the playbook does not address>

REJECTED, and why: "1. Check the flows are comparable. 2. Apply the class
playbook." -- these are section headings, not steps, they carry no anchor,
and neither tells the investigator what to do.
""",

    "flow_summary": """
THE SHAPE OF THE ANSWER
"The capture holds <total_flows> flows over <span>, of which <attack_flows>
were classified as attack traffic and <benign_flows> as benign. <N> attack
classes are present, <names>, and <address> is the source of almost every
flow. Mean confidence is <mean>, with <low> flows below 0.60."

Nothing in that shape is a judgement. Whether the classifications are weak
or strong follows from the figures you were given -- do not carry a verdict
across from this illustration.

REJECTED, and why: "Roughly 7,000 flows were seen, indicating a targeted
campaign against the network." -- rounds a supplied figure, and speculates
about intent, which is not in the facts.
""",

    "shap_explanation": """
EXAMPLE OF A GOOD ANSWER
"The strongest signal is the backward bulk rate, contributing +2.56 log-odds
toward API. The server sent data back in large bursts rather than a steady
stream, which is what the model associates with this class. The FIN flag
count adds a further +1.16: connections closed cleanly and quickly, so many
short complete sessions rather than a few long ones."

REJECTED, and why: "Bwd Bulk Rate Avg increases the probability of API by
256%." -- expresses a log-odds contribution as a percentage. The values are
log-odds; they do not convert to a percentage without the softmax.

ALSO REJECTED: a sentence naming the application protocol the traffic was
carried over, or calling an observed value "very small" instead of stating
it. A flow record carries counts, sizes and timings; it does not establish
a protocol, and the reader cannot check an adjective.
""",
}

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

    # low_confidence_flows is a count against a threshold, and the panel
    # states that threshold on screen. Supplying the count without it left
    # the model to name 0.60 from nowhere -- correct prose, scored as an
    # invented figure, panel withheld.
    if "low_confidence_flows" in facts:
        lines.append("  low_confidence_threshold: 0.60")

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
        # The feature glossary gives example ports for Dst Port -- "22 SSH,
        # 80 HTTP, 443 HTTPS". Sent to the model, that reads as evidence:
        # it wrote "typical for the HTTP/HTTPS protocols" from a DEFINITION,
        # not an observation. The examples stay on screen for the analyst
        # and are stripped from the prompt, so the word is not available to
        # be asserted -- and if it appears anyway the mechanism check now
        # rates it high rather than medium, because it was never supplied.
        plain = re.sub(r"\s*\([^)]*\b(?:SSH|HTTP|HTTPS|DNS|FTP|SMTP|TLS)\b"
                       r"[^)]*\)", "", a["plain"])
        rows.append(f"  {a['contribution']:+.3f}  {plain}")
        rows.append(f"           observed: {a.get('readable', a['raw_value'])}"
                    f"  --  {a.get('magnitude', 'no comparison available')}")
        if a.get("caution"):
            rows.append(f"           CAUTION: {a['caution']}")

    ambiguity = ""
    if finding.get("dominant_runner_up_share", 0) > 0.25:
        ambiguity = (
            f"\n\nThe model named {finding['dominant_runner_up']} as the "
            f"runner-up for {finding['dominant_runner_up_share']:.0%} of "
            f"these flows. Say that the classification is uncertain between "
            f"the two.")

    # The decision sentence is NOT asked for any more.
    #
    # Panel 2 used to want two paragraphs: what was detected, then what the
    # evidence means. The first is pure restatement of numbers already on
    # screen, and it was the source of both surviving errors -- "100%
    # confidence" for 1.000, and "0% confidence" for a runner-up at 0.310.
    # Measured 3/3 runs, every run.
    #
    # So it is no longer generated. The figures are rendered deterministically
    # by the panel, and the model is asked only for the part where prose adds
    # something a number cannot: what the features mean as behaviour. Less
    # generated surface is less to get wrong, and it is the cheapest way to
    # buy accuracy from a small model.
    return f"""Explain to a network investigator who is not a
machine-learning specialist what the evidence below means.

CONTEXT, already on screen -- do not restate it, do not put any of these
numbers in your answer, and never write a confidence as a percentage:
  the model chose {d['predicted']}, with {d['runner_up']} second
  this finding covers {finding['flow_count']:,} flows

EVIDENCE, strongest first. Values are LOG-ODDS: positive supports the
prediction, negative argues against it. They rank evidence against each
other and say nothing about how far the probability moved.
{chr(10).join(rows)}

Write ONE short paragraph: what the evidence above means as observable
network behaviour, using the descriptions given.

Four things not to do:
  - Do not convert any value to a percentage.
  - Do not claim a feature caused the attack -- the model weighted it,
    which is a different statement.
  - Do not name a protocol, port, service or tool. The evidence above is
    packet counts, sizes and timings; it does not say what protocol this
    was, and neither may you.
  - Do not describe an observed value as large, small, short or long, and
    do not convert one. Each value is given already converted, with a
    comparison against the training data on the same line -- use those
    words. If you want to say a value is unusual, say how many standard
    deviations it is from the training mean, which is supplied.{ambiguity}

HARD RULE, applies to every sentence: describe ONLY the values listed above.
Do not explain what this attack class usually does. The class name is a
label the model produced, not an observation of what protocol was carried."""


def _playbook_for_prompt(text):
    """The playbook with its headings removed.

    Measured failure: the model returned six steps all anchored to
    "From OWASP.A05.2025" -- a `## From <source>` heading copied straight
    out of the document it was handed. The anchor check caught it and the
    paragraph was withheld, which is right for a wrong answer but the wrong
    thing to keep producing.

    A heading is structure, not instruction, so it is not sent. What remains
    is the prose and the quoted passages -- all a step can legitimately be
    anchored to. The model cannot copy what it never saw.
    """
    kept = [ln for ln in text.splitlines()
            if not re.match(r"\s*#{1,6}\s", ln)]
    joined = chr(10).join(kept)
    return re.sub(r"(?:\r?\n){3,}", chr(10) * 2, joined).strip()


def _evidence_line(finding, shap):
    """What was actually found, in one short block.

    A recommendation that ignores the finding is generic advice. The class,
    the confidence and the features that drove it are what make one step
    matter more than another, so they are supplied -- and marked
    unanchorable, because steps must still come from the playbook.
    """
    if not finding:
        return ""
    lines = [f"  class: {finding['class']}",
             f"  flows: {finding['flow_count']:,} "
             f"({finding['share_of_capture']:.1%} of the capture)",
             f"  mean confidence: {finding['confidence_mean']:.2f}"]
    if finding.get("reliability_f1") is not None:
        lines.append(f"  held-out F1 for this class: "
                     f"{finding['reliability_f1']} -- one of the weaker ones")
    if finding.get("dominant_runner_up"):
        lines.append(f"  runner-up {finding['dominant_runner_up']} on "
                     f"{finding.get('dominant_runner_up_share', 0):.0%} of "
                     f"these flows")
    det = (shap or {}).get("detections") or []
    if det:
        lines.append("  strongest evidence the model used:")
        for a in det[0].get("attributions", [])[:3]:
            lines.append(f"    {a['contribution']:+.2f}  {a['plain']} "
                         f"(observed {a.get('readable', a['raw_value'])})")
    return chr(10).join(lines)


def prompt_recommend(panel, finding=None, shap=None):
    """
    The retrieved playbook is the only source, and every step must show
    where in it the step came from.

    WHY ONLY THE PLAYBOOK
    `panel["sections"]` also carries the model-guidance documents --
    reliability, confidence, ambiguity, scope, triage. Handing all nine to
    qwen2.5:3b measured 38,646 characters (9,720 input tokens) and came back
    with six bare headings copied out of analyst/triage.md: the class
    playbook was buried, and the model summarised whichever document was
    easiest to skim. The guidance documents are already on screen
    deterministically and are not response steps, so the model is given the
    class playbook -- both playbooks when the finding is ambiguous -- and
    nothing else.

    WHY ANCHORS
    "Every step must come from the documentation" cannot be checked after
    the fact. A span copied out of the playbook can be: see the anchors
    check in narration_schema. Asking for the span also constrains
    generation, which is the part a small model needs most.

    WHY THE SITUATION COMES AFTER THE PLAYBOOK
    A 3b model weights the end of a long prompt most heavily. The playbook
    is what it must copy from; the situation is what selects among the
    playbook's steps, so it sits closest to the instruction.
    """
    doc_sections = [s for s in panel["sections"]
                    if s.get("source", "").startswith("incident_response/")]

    if not doc_sections:
        return f"""No response documentation was retrieved for a
{panel['class']} finding.

Write two sentences stating that no guidance is available for this class and
that none should be inferred, and naming the files that are missing:
{', '.join(panel['missing_documents']) or 'unknown'}

Do not suggest any action of your own."""

    # No filenames and no headings in the playbook text.
    #
    # Twice measured: with headings present the model anchored six steps to
    # "From OWASP.A05.2025"; with headings stripped it anchored five to
    # "incident_response/slowloris.md". It reaches for whatever looks like a
    # label. Nothing structural is sent now -- only prose and quotes, which
    # is the only thing a step may legitimately be anchored to.
    docs = "\n\n----\n\n".join(_playbook_for_prompt(s["body"])
                               for s in doc_sections)

    # The numbered references, so a step can point at one. The numbers are
    # the panel's own -- position in `references` -- so [2] in the prose and
    # [2] in the REFERENCES block below it are the same work. A marker that
    # does not survive that check is decoration, not a citation.
    supplied = {s["source"] for s in doc_sections}
    usable = [m for m in (panel.get("reference_map") or [])
              if not m["sources"] or (set(m["sources"]) & supplied)]
    refs = "\n".join(f"  [{m['n']}] {m['citation']}" for m in usable)
    numbers = ", ".join(f"[{m['n']}]" for m in usable) or "none"

    context = [s["body"] for s in panel["sections"]
               if s["heading"] in ("What was found", "How confident to be",
                                   "Ambiguity")]

    return f"""PLAYBOOK -- the only source you may use
{docs}

WHAT WAS FOUND -- this decides which of the playbook's steps matter here.
Do not anchor to any of it; anchors come from the playbook only.
{_evidence_line(finding, shap)}
{chr(10).join('  ' + c for c in context)}

TASK
Write the response steps for this {panel['class']} finding, numbered, in the
order the playbook gives them. At most six steps, one sentence each.

After each step put ANCHOR: followed by at least five consecutive words
copied exactly from the playbook above that prescribe that step. If you
cannot copy such a span, do not write the step.

Then a short paragraph headed "Not covered" naming anything this situation
needs that the playbook does not address.

Do not restate the situation, and do not add a step of your own.

HARD RULE, and the last thing to check before you answer: every ANCHOR must
be words COPIED from the playbook above, character for character. It is not
a description of the step, not a reason for the step, and not a section
heading. If you cannot copy a run of at least five words from the playbook
that tells the investigator to do the thing, delete that step."""


def attach_references(text, panel):
    """Put [n] on each step, derived from the anchor rather than asked for.

    The model was asked for the number at first. It is one more constraint
    to satisfy per step, and a 3b degrades on the constraint it was already
    weakest at -- measured: all four steps came back sharing one anchor, and
    every one cited [1] whether or not [1] supported it. A citation that is
    always [1] is not a citation.

    The anchor already says where the step came from: it is a span copied
    out of one retrieved document. That document's own `> Source:` header
    gives the works behind it, and those have numbers in `reference_map`.
    So the marker is computed, and cannot point at a work the step did not
    come from.

    Returns (text, [markers attached]).
    """
    docs = {s["source"]: s for s in panel.get("sections", [])
            if s.get("source", "").startswith("incident_response/")}
    if not docs:
        return text, []

    ref_n = {}
    for m in panel.get("reference_map") or []:
        for src in m["sources"]:
            ref_n.setdefault(src, []).append(m["n"])

    # Markup is stripped on BOTH sides. The playbook writes
    # "**Set a connection timeout** on the server"; the model returns it
    # without the asterisks, and an anchor that is genuinely from the
    # document then failed to match it.
    def flatten(s):
        return re.sub(r"\s+", " ", re.sub(r"[*_`#>]", "", s)).strip().lower()

    flat = {p: flatten(s["body"]) for p, s in docs.items()}
    attached, out = [], []

    for line in (text or "").split("\n"):
        m = re.search(r"ANCHOR:\s*(.+?)\s*$", line, re.I)
        if not m:
            out.append(line)
            continue
        needle = flatten(m.group(1))[:60].rstrip(" .,;:")
        hit = next((p for p, body in flat.items() if needle and needle in body),
                   None)
        numbers = sorted(set(ref_n.get(hit, []))) if hit else []
        if numbers:
            marker = "".join(f"[{n}]" for n in numbers)
            attached.append(marker)
            line = f"{line.rstrip()}  {marker}"
        out.append(line)

    return "\n".join(out), attached


BUILDERS = {
    "flow_summary": lambda p, ctx: prompt_flow_summary(p),
    "shap_explanation": lambda p, ctx: prompt_shap(p, ctx["finding"]),
    "recommendations": lambda p, ctx: prompt_recommend(
        p, ctx.get("finding"), ctx.get("shap")),
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
        # `evidence` is what the model was GIVEN: instructions plus the
        # figures or documents. `prompt` is that plus a worked example.
        #
        # The two are kept apart because every check downstream asks "was
        # this in the input?", and a worked example is not input -- it is
        # illustration. Checking against the full prompt scored an invented
        # protocol and an echoed figure as supported, because the example
        # mentioned them. Measured, not hypothetical.
        evidence = build(panel, context or {})

        # In-context learning. A worked example is the only training signal
        # available without fine-tuning, and for a 3b model it outperforms
        # more instructions -- the model copies the shape it is shown. That
        # copying is exactly why the example is excluded above.
        # The example goes FIRST. It used to go last, and a 3b weights the
        # end of a prompt most heavily -- so it continued from the example
        # and pasted its "REJECTED, and why:" block into the answer, where
        # an investigator would read it as output. The task belongs at the
        # end; the illustration belongs before the evidence.
        example = EXAMPLES.get(name)
        prompt = (_ILLUSTRATION + example + "\n" + evidence) if example \
            else evidence

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
        # WHAT THE MODEL WAS ACTUALLY GIVEN, not what the panel holds.
        #
        # The panel carries nine documents -- the class playbook plus the
        # model-guidance and analyst files. prompt_recommend() sends only
        # the playbooks. Passing all nine here made the citation check
        # useless in exactly the case it exists for: a citation to
        # interpretability/reliability.md, which the model never saw,
        # scored as grounded, and the provenance record claimed nine
        # documents were supplied when two were.
        #
        # Derived from the built prompt rather than from a second copy of
        # the builder's filter, so it cannot drift away from it.
        # What the model was actually given. Panel 3 sends the response
        # playbooks and nothing else; panels 1 and 2 send no documents at
        # all. This used to be derived by looking for a "=== path ===" marker
        # in the prompt, which stopped working when the markers were removed
        # -- the model was anchoring steps to the filenames.
        supplied = ([s["source"] for s in panel.get("sections", [])
                     if s.get("source", "").startswith("incident_response/")]
                    if name == "recommendations" else [])

        panel["narration_provenance"] = provenance(panel, prompt, usage,
                                                   supplied)

        # The retrieved text on its own, so an anchor is checked against the
        # playbook rather than against the instructions and the example that
        # surround it in the prompt.
        grounding = "\n\n".join(
            s["body"] for s in panel.get("sections", [])
            if s.get("source") in supplied) or None

        # A judgement word about a quantity is removed rather than merely
        # flagged: left in place it contradicts the measured comparison
        # printed directly beneath it, and prose is what gets read. The cut
        # only ever deletes an unsupported claim, the original is kept for
        # audit, and what was removed is named on screen.
        if name == "shap_explanation" and panel["narrative"]:
            cleaned, removed = neutralise_magnitude(panel["narrative"])
            if removed:
                panel["narration_original"] = panel["narrative"]
                panel["narration_edits"] = removed
                panel["narrative"] = cleaned

        # The numbers the panel will print beneath the prose. A marker the
        # model writes must resolve to one of them.
        valid_refs = ([m["n"] for m in panel.get("reference_map") or []]
                      if name == "recommendations" else None)

        findings, stats = check(panel["narrative"], evidence, supplied,
                                grounding_text=grounding,
                                strict_mechanism=(name == "shap_explanation"),
                                valid_references=valid_refs)
        panel["narration_findings"] = findings
        panel["narration_stats"] = stats
        panel["narration_verdict"] = summary_line(stats, findings)

        # Reference markers go on AFTER the checks. Attached before, the
        # marker became part of the anchor text and every anchor then failed
        # to match the playbook -- the check was reading "[1][2]" as part of
        # the copied span.
        if name == "recommendations" and panel.get("narrative"):
            marked, added = attach_references(panel["narrative"], panel)
            if added:
                panel["narrative"] = marked
                panel["reference_markers"] = added

        # A high-severity finding means the model asserted something it was
        # not given: an invented figure, or a citation for a document that
        # was never supplied.
        #
        # Showing that prose under a warning does not work. The paragraph is
        # the readable part of the panel, so it gets read and the warning
        # does not. Generation cannot be prevented without fine-tuning, and
        # fine-tuning would not remove this check anyway -- but DISPLAY can
        # be prevented, and that is the whole lever. The deterministic panel
        # underneath is complete on its own, so withholding costs nothing.
        #
        # Kept under narration_withheld rather than dropped, so a saved case
        # can still be audited for what the model actually said.
        if stats.get("highest_severity") == "high":
            panel["narration_withheld"] = panel["narrative"]
            panel["narrative"] = None

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
# Every panel, every run. Narration is part of the pipeline rather than a
# preference, so there is no "default subset" any more.
#
# DEFAULT_PANELS is kept as an alias because narrate_all() takes it as a
# default argument and callers outside the app may pass it.
ALL_PANELS = ("summary", "shap", "recommend")

DEFAULT_PANELS = ALL_PANELS


def narrate_all(result, provider, panels=DEFAULT_PANELS):
    """
    Narrate the requested panels.

    `panels` defaults to all three. Panel 3 was excluded until its steps
    were made anchor-verified and its citations derived rather than
    written; with those in place there is no panel where prose is offered
    without a check behind it.
    """
    finding = result.get("selected")

    for key in panels:
        panel = result.get(key)
        if isinstance(panel, dict):
            narrate(panel, provider,
                    {"finding": finding, "shap": result.get("shap")})

    result["narrated_panels"] = list(panels)
    return result
