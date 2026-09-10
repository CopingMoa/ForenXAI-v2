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

import json
import os
import re

from services.narration_schema import (provenance, check, summary_line,
                                       neutralise_magnitude, plain_reason)


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
    #
    # NOTHING QUOTED HERE IS USABLE AS A STEP. The rejection used to name
    # two -- "Check the flows are comparable" and "Apply the class
    # playbook" -- and the model was seen returning the second of them
    # verbatim as a step. A rejected example is still an example: a 3b model
    # copies the shape it is shown, and it does not reliably carry the
    # minus sign. The rejection now describes the shape instead of
    # exhibiting it, so there is nothing in this block to lift.
    #
    # The schema is what makes that safe to do. A step needs an anchor
    # copied from the playbook, and a section heading has none, so the
    # failure this example was written to prevent is now prevented by the
    # grammar. The wording is the belt to that brace, not the only guard.
    "recommendations": """
THE SHAPE OF THE ANSWER
{"steps": [{"step": "<what to do, one sentence>",
            "anchor": "<five or more words copied from the playbook above>"},
           {"step": "<what to do next>",
            "anchor": "<five or more words copied from the playbook above>"}],
 "not_covered": "<what this situation needs that the playbook does not
address>"}

REJECTED, and why: a step that restates a heading from the playbook, or that
tells the reader to consult the playbook, instead of naming the action the
playbook prescribes. The playbook does not instruct anyone to do either, so
no anchor can be copied for it, and it leaves the investigator with nothing
to carry out.
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

    # NO CLASS NAME APPEARS HERE, in either the accepted or the rejected
    # form. Both read "API" until 2026-09-09.
    #
    # The prompt itself withholds the class deliberately: handed one,
    # qwen2.5:3b reaches for the protocol that class is usually carried
    # over -- "http", "handshake" -- which a flow record cannot establish,
    # and the paragraph is withheld two runs in three. Leaving a class name
    # in the illustration put the same material back in the prompt through
    # a side door. It had not been copied in measurement, which is what
    # made it worth removing rather than urgent: the recommendations
    # example above records what happens when an example IS concrete
    # enough to be copied.
    #
    # "the predicted class" costs nothing to copy. It is true of every
    # finding, and it names none of them.
    "shap_explanation": """
EXAMPLE OF A GOOD ANSWER
"The strongest signal is the backward bulk rate, contributing +2.56 log-odds
toward the predicted class. The server sent data back in large bursts rather
than a steady stream, which is what the model associates with this class. The
FIN flag count adds a further +1.16: connections closed cleanly and quickly,
so many short complete sessions rather than a few long ones."

REJECTED, and why: "Bwd Bulk Rate Avg increases the probability of the
predicted class by 256%." -- expresses a log-odds contribution as a
percentage. The values are log-odds; they do not convert to a percentage
without the softmax.

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
    # Labels, not field names.
    #
    # Two failures come from handing a model a raw key/value dump. It echoes
    # the key -- "the flow_timeout_warning is true" is not a sentence an
    # investigator should read -- and a boolean is the easiest thing in the
    # block to invert, because "flow_timeout_warning: False" contains the
    # word the model is looking for. A reviewer caught exactly that on a
    # sibling implementation: a false flag reported as true, telling the
    # investigator to discard a sound capture.
    #
    # So the keys are described, and the flag is not a field at all.
    LABELS = {
        "total_flows": "flows in the capture",
        "benign_flows": "classified benign",
        "attack_flows": "classified as attack traffic",
        "attack_share": "attack share of the capture",
        "distinct_attack_classes": "distinct attack classes present",
        "mean_confidence": "mean confidence across all flows",
        "low_confidence_flows": "flows below the 0.60 review threshold",
    }
    lines = [f"  {LABELS[k]}: {facts[k]}" for k in LABELS if k in facts]

    # Stated only when it is TRUE, and stated as a sentence. A flag that is
    # absent cannot be misread; a flag printed as "False" can.
    if facts.get("flow_timeout_warning"):
        lines.append("  WARNING: the longest flow is almost exactly the "
                     "extractor's default timeout, so every timing feature "
                     "in this capture may be truncated. Say this.")

    w = facts.get("capture_window")
    if w:
        # The duration is its own labelled fact, not a parenthetical after
        # the two timestamps. Given the range and the answer together,
        # qwen2.5:3b subtracted the clock times itself and wrote "over a
        # 25-minute period" for a capture the facts said ran 45 min 19 s --
        # 47 minus 22, arithmetic on the digits rather than the figure it
        # was handed. It did this on every run, and the grounding check
        # withheld the paragraph every time, so panel 1 never showed prose
        # at all.
        #
        # Same rule as the rest of the pipeline: a number the model can
        # recompute is a number it will recompute, and get wrong. Give it
        # the answer, and label it so the worked example's <span> has an
        # obvious field to draw on.
        lines.append(f"  capture_duration: {w['span_human']}")
        lines.append(f"  first_flow_seen: {w['first_flow']}")
        lines.append(f"  last_flow_seen: {w['last_flow']}")

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


def _shared_note(a, shared):
    """"...the same value as X" when two features report one observation.

    Empty for a value that appears once, which is the common case, so the
    line is unchanged for every feature that does not need this.
    """
    peers = [p for p in shared.get(a.get("readable", a["raw_value"]), [])
             if p != a["plain"].split(" -- ")[0]]
    if not peers:
        return ""
    return f"  (the same observed value as {' and '.join(peers[:2])})"


def prompt_shap(panel, finding):
    """Attributions are already ranked; the model's job is translation."""
    d = panel["detections"][0]

    # Half the detections in the sample capture (15 of 30) list the same
    # observed value on two lines -- Slowloris gets 1.17 seconds twice,
    # PortScan gets 0 bytes twice AND 60 bytes twice. Nothing says they are
    # the same observation, so the model restates it, and the paragraph
    # reads as a list of figures rather than a description of traffic.
    #
    # They are NOT merged into one attribution. Two features sharing a value
    # can pull in opposite directions, and a combined contribution is a
    # number TreeSHAP never produced. The lines stay; they are told they
    # share a value, which is the fact that lets the model say it once.
    withheld = []
    shared = {}
    for a in d["attributions"]:
        shared.setdefault(a.get("readable", a["raw_value"]), []).append(
            a["plain"].split(" -- ")[0])

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
        # `direction` is stated, not left to be read off the sign. A
        # reviewer caught a sibling implementation describing a feature
        # marked "argues against" as supporting the class -- the sign was
        # there to be read and the model read it backwards.
        if a.get("caution"):
            # WITHHELD FROM THE MODEL ENTIRELY, and this is the third
            # attempt at this line.
            #
            # 1. Caution AND the standard-deviation figure: 3b read the
            #    figure off the destination port and concluded the SERVICE
            #    was unusual -- an inference about the world from a fact
            #    about the model, which is what the caution warns against.
            # 2. Caution, figure withheld: every other line ends in a
            #    comparison and this one ended in nothing, so both sizes
            #    invented one on most findings.
            # 3. Caution, plus an explicit "no comparison is supplied, do
            #    not call it unusual": 3b wrote "far from the training
            #    mean, indicating it is unusual" anyway. The judgement is
            #    not coming from the prompt -- a 5-digit port number reads
            #    as unusual to any model that has seen the internet, and no
            #    instruction outranks that prior at this size.
            #
            # So the line goes. The panel still prints the feature, its
            # contribution, its comparison and its caution, deterministically
            # and in full; what the model no longer gets is the chance to
            # editorialise about the one feature we already distrust. This
            # is the same move that fixed the class name in panel 2 and the
            # worked examples in panel 3: withhold the material, do not
            # instruct against it.
            withheld.append(plain)
            continue

        rows.append(f"  {a['contribution']:+.3f}  [{a['direction']}]  {plain}")
        rows.append(f"           observed: "
                    f"{a.get('readable', a['raw_value'])}"
                    f"{_shared_note(a, shared)}"
                    f"  --  {a.get('magnitude', 'no comparison available')}")

    # Console, not the panel. Dropping the top-ranked attribution from
    # the prompt reads as a bug the first time someone compares the
    # prose against the figures, so it is stated where whoever runs the
    # tool can see it and an investigator reading a report is not made to.
    if withheld:
        try:
            print("[narration] shap_explanation: cautioned feature not "
                  "shown to the model: " + ", ".join(withheld))
        except Exception:
            pass

    # NO CLASS NAME REACHES THE MODEL, and the ambiguity note is gone with
    # it. The comment below records that the decision SENTENCE was removed
    # because restating the figures was where the errors lived; the class
    # names stayed in CONTEXT, and the same failure came back attached to
    # them. Measured 3/3 runs on an ambiguous finding: "with DoS being the
    # top choice for 100% of the flows", where DoS was the runner-up and
    # Slowloris the classification. Rewording the instruction twice did not
    # move it -- the second attempt also produced a direction inversion.
    #
    # Which class won, which came second, and that the pair cannot be
    # separated are all rendered deterministically: the panel prints the
    # decision, and "Why two classes are competing" is its own retrieved
    # section. The model is left with the one job no template does, turning
    # attributions into observable behaviour. A name it never sees is a name
    # it cannot swap.
    ambiguity = ""

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
  this finding covers {finding['flow_count']:,} flows

EVIDENCE, strongest first. Values are LOG-ODDS: positive supports the
prediction, negative argues against it. They rank evidence against each
other and say nothing about how far the probability moved.
{chr(10).join(rows)}

Write ONE short paragraph: what the evidence above means as observable
network behaviour, using the descriptions given. Describe the traffic in
terms of the counts, sizes and timings you were given -- how much was sent
each way, how far apart the packets were -- rather than restating each
figure on its own.

NO CLASS NAME IS GIVEN, and none may be written. Measured over five prompt
revisions: handed the chosen class, qwen2.5:3b reaches for the protocol
that class is usually carried over -- "http", "handshake" -- which a flow
record does not establish, and the paragraph is withheld two runs in three.
Without the name it stays inside the evidence on every run. Which class was
chosen is printed above this paragraph by the panel itself.

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


def playbook_sections(panel):
    """The sections panel 3 sends to the model, and only those.

    `panel["sections"]` also carries the model-guidance and analyst files,
    which are context for the deterministic panel and are never handed to
    the model. Two places need this distinction -- the prompt builder, which
    sends them, and narrate(), which records what was supplied and grounds
    the anchor check against it -- and they were filtering separately with
    the same prefix test. They agreed, but nothing made them agree: a change
    to one would have made the citation check validate against a document
    set the model never saw, which is the exact failure the check exists to
    catch.
    """
    return [s for s in (panel.get("sections") or [])
            if s.get("source", "").startswith("incident_response/")]


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
    doc_sections = playbook_sections(panel)

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
Return JSON matching the schema. Give the response steps for this
{panel['class']} finding in `steps`, in the order the playbook gives them,
at most six, one sentence each in `step`.

Each step's `anchor` is at least five consecutive words copied exactly from
the playbook above that prescribe that step. There is no field for a step
without one: if you cannot copy such a span, leave the step out.

`not_covered` names anything this situation needs that the playbook does not
address, or is an empty string.

Do not restate the situation, and do not add a step of your own.

HARD RULE, and the last thing to check before you answer: every ANCHOR must
be words COPIED from the playbook above, character for character. It is not
a description of the step, not a reason for the step, and not a section
heading. If you cannot copy a run of at least five words from the playbook
that tells the investigator to do the thing, delete that step."""


# ============================================================
# PANEL 3 -- constrained generation
# ============================================================
# The anchor rule used to be an instruction: "after each step put ANCHOR:
# followed by five words copied from the playbook, and if you cannot copy
# such a span, do not write the step." A 3b model obeys that most of the
# time, and `check()` catches it when it does not -- by which point the
# paragraph is withheld and the reader gets nothing.
#
# Ollama and llama.cpp both constrain generation to a JSON schema, and
# services/llm_provider.py has taken a `schema=` argument all along. Given
# this schema there is no shape in the grammar for a step without an anchor,
# so the model cannot emit one. Detection becomes prevention.
#
# The checks stay. A schema guarantees an anchor is PRESENT; only
# check() can tell whether it was actually copied from the playbook, which
# is the claim that matters. This narrows what has to be caught after the
# fact, it does not replace catching it.
RECOMMENDATION_STEPS_SCHEMA = {
    "type": "object",
    "properties": {
        "steps": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "step": {
                        "type": "string",
                        "description": "One sentence saying what to do. "
                                       "Not a section heading, not a "
                                       "restatement of the finding.",
                    },
                    "anchor": {
                        "type": "string",
                        "description": "At least five consecutive words "
                                       "copied character for character from "
                                       "the playbook, which prescribe this "
                                       "step.",
                    },
                },
                "required": ["step", "anchor"],
            },
        },
        "not_covered": {
            "type": "string",
            "description": "What this situation needs that the playbook does "
                           "not address. Empty string if nothing.",
        },
    },
    "required": ["steps", "not_covered"],
}

# Only panel 3 is constrained. Panel 1 writes a paragraph and panel 2 writes
# a sentence per feature; neither has a per-item claim to bind a field to, so
# a schema there would buy structure without buying a guarantee.
SCHEMAS = {"recommendations": RECOMMENDATION_STEPS_SCHEMA}


def steps_to_text(payload):
    """Constrained JSON back into the line format the rest of panel 3 reads.

    attach_references(), check() and XaiTab._step_blocks() all consume
    "N. step" followed by "ANCHOR: span", separated by blank lines. Rendering
    back to that keeps generation the only thing that changed -- the
    provenance markers, the grounding checks and the widget layout are
    untouched, and a model that ignores the schema still degrades through the
    same path as before.

    Returns None when the payload carries nothing usable, so the caller can
    fall back to the raw text rather than showing an empty panel.
    """
    lines, n = [], 0
    for item in (payload.get("steps") or []):
        if not isinstance(item, dict):
            continue
        step = (item.get("step") or "").strip()
        anchor = (item.get("anchor") or "").strip()
        # The schema requires both. This is the belt to its braces: a
        # provider that ignores the grammar must not reach the reader with a
        # step carrying no provenance.
        if not step or not anchor:
            continue
        n += 1
        lines.append(str(n) + ". " + step + chr(10) + "ANCHOR: " + anchor)

    not_covered = (payload.get("not_covered") or "").strip()
    if not_covered:
        lines.append("Not covered: " + not_covered)

    return (chr(10) + chr(10)).join(lines) or None


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

# ============================================================
# DETERMINISTIC FALLBACK -- what the panel says when the model's paragraph
# does not survive its checks
# ============================================================
# A withheld narration used to render as a notice: "PLAIN ENGLISH (not
# shown) -- the local model's summary is not shown, because it described
# evidence as pointing the opposite way to the measurement." That is a
# report about the tool, in the place a reader came to for a report about
# the capture, and it appeared whenever the 3b model slipped -- which on an
# ambiguous finding was every run.
#
# Withholding the model's words is still right. Printing an apology instead
# is not. These write the same paragraph from the same figures, in code, so
# the panel always has a readable summary and the reader never has to care
# which one produced it. Nothing here can be wrong in the way the model was
# wrong: there is no inference, only formatting.
def _fallback_flow_summary(panel):
    f = panel.get("facts") or {}
    total = f.get("total_flows") or 0
    attack = f.get("attack_flows") or 0
    benign = f.get("benign_flows") or 0

    window = f.get("capture_window") or {}
    span = window.get("span_human")
    opening = (f"The capture holds {total:,} flows"
               + (f" recorded over {span}." if span else "."))

    counts = f.get("class_counts") or {}
    ranked = [(c, n) for c, n in sorted(counts.items(), key=lambda kv: -kv[1])
              if c != "Benign"]
    dominant = ""
    if ranked:
        name, n = ranked[0]
        dominant = (f" {name} is the most common attack class at {n:,} "
                    f"flow{'s' if n != 1 else ''}.")

    classes = f.get("distinct_attack_classes") or 0
    body = (f" {attack:,} were classified as attack traffic and {benign:,} "
            f"as benign")
    body += (f", across {classes} attack class{'es' if classes != 1 else ''}."
             if classes else ".")

    mean = f.get("mean_confidence")
    low = f.get("low_confidence_flows") or 0
    tail = ""
    if mean is not None:
        tail = (f" Mean confidence is {mean:.4f}, with {low:,} flow"
                f"{'s' if low != 1 else ''} below the 0.60 review threshold.")

    warn = ""
    if f.get("flow_timeout_warning"):
        warn = (" The longest flow is almost exactly the extractor's default "
                "timeout, so every timing feature here may be truncated.")

    return opening + body + dominant + tail + warn


def _fallback_shap(panel):
    d = (panel.get("detections") or [{}])[0]
    attrs = d.get("attributions") or []
    if not attrs:
        return None

    supports = [a for a in attrs if a.get("direction") == "supports"]
    against = [a for a in attrs if a.get("direction") != "supports"]

    def phrase(a):
        return (f"{a['plain']} at {a.get('readable', a.get('raw_value'))}, "
                f"{a.get('magnitude', 'no comparison available')}")

    parts = []
    if supports:
        parts.append("The evidence for this classification is "
                     + "; ".join(phrase(a) for a in supports[:3]) + ".")
    if against:
        parts.append("Arguing against it: "
                     + "; ".join(phrase(a) for a in against[:2]) + ".")

    chk = d.get("shap_check") or {}
    if chk.get("shown_share_of_total") is not None:
        parts.append(
            f"The {chk.get('features_shown', len(attrs))} features shown "
            f"carry {chk['shown_share_of_total']:.0%} of the total "
            f"attribution weight for this flow.")
    return " ".join(parts)


def _fallback_recommendations(panel):
    n = sum(len((s.get("digest") or {}).get("actions") or [])
            for s in panel.get("sections", [])
            if (s.get("source") or "").startswith("incident_response/"))
    srcs = sorted({s["source"] for s in panel.get("sections", [])
                   if (s.get("source") or "").startswith("incident_response/")})
    if not srcs:
        return None
    where = ", ".join(os.path.basename(s)[:-3] for s in srcs)
    return (f"The steps below are read directly from the response playbook "
            f"for this class ({where}), each shown with the line that "
            f"prescribes it."
            + (f" {n} prescriptive steps were found." if n else ""))


FALLBACKS = {
    "flow_summary": _fallback_flow_summary,
    "shap_explanation": _fallback_shap,
    "recommendations": _fallback_recommendations,
}


def fallback_summary(panel):
    """A readable paragraph for a panel, written from its own figures."""
    fn = FALLBACKS.get(panel.get("panel"))
    if not fn:
        return None
    try:
        text = fn(panel)
    except Exception:
        return None
    return (text or "").strip() or None


def _report(panel):
    """Say on the console what happened to this panel's narration.

    The UI shows the capture; this shows the machinery. Everything that used
    to be printed into the panel -- the words the neutraliser cut, the
    verdict, each finding with its severity and check name, a truncated
    context -- goes here instead, where whoever is running the tool can see
    it and an investigator reading a report is not made to.

    Printed rather than logged: this is a desktop application started from a
    console, and a print lands where its operator is already looking. It is
    wrapped because a broken console must never take a panel down.
    """
    try:
        name = panel.get("panel", "?")
        prov = panel.get("narration_provenance") or {}
        model = prov.get("model") or "the local model"

        if panel.get("narration_error"):
            print(f"[narration] {name}: {panel['narration_error']} "
                  f"-- panel summarised from its own figures instead")
            return

        edits = panel.get("narration_edits")
        if edits:
            print(f"[narration] {name}: removed {', '.join(repr(e) for e in edits)}"
                  f" -- judgement words about a quantity that is measured "
                  f"below")

        if panel.get("narration_note"):
            print(f"[narration] {name}: {panel['narration_note']}")

        findings = panel.get("narration_findings") or []
        if findings:
            # The same sentence the panel used to print, now on the console
            # where it belongs -- followed by the detail an operator needs
            # and an investigator does not.
            said = plain_reason(findings, name, withheld=False)
            if said:
                print(f"[narration] {name}: {said}")
        for f in findings:
            print(f"[narration] {name}:   [{f['severity']}] {f['check']}: "
                  f"{f['detail']}")

        if panel.get("narration_fallback"):
            print(f"[narration] {name}: {model} output withheld; panel shows "
                  f"a summary composed from the figures")
        elif panel.get("narrative"):
            usage = panel.get("narration_usage") or {}
            print(f"[narration] {name}: {model} ok, "
                  f"{usage.get('output', 0)} tokens")
    except Exception:
        pass


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
            schema=SCHEMAS.get(name),
        )

        # A constrained panel comes back as JSON and is rendered into the
        # same lines the unconstrained one produced, so everything after this
        # point -- references, checks, the widget -- is unchanged.
        #
        # A provider that ignores the grammar, or returns JSON with no usable
        # step, falls through to the raw text and the existing checks judge
        # it exactly as before. The schema is a narrowing, never a new way to
        # end up with an empty panel.
        if SCHEMAS.get(name) and text:
            try:
                rendered = steps_to_text(json.loads(text))
            except (ValueError, TypeError, AttributeError):
                rendered = None
            if rendered:
                text = rendered
                panel["narration_constrained"] = True

        panel["narrative"] = (text or "").strip() or None
        panel["narration_usage"] = usage
        if usage.get("context_note"):
            panel["narration_note"] = usage["context_note"]

        # What the model was ACTUALLY GIVEN, which is not what the panel
        # holds: the panel carries the class playbook plus the model-guidance
        # and analyst files, and only the playbooks are sent. Recording all
        # of them made the citation check useless in the case it exists for
        # -- a citation to a document the model never saw scored as grounded.
        # Read through the same helper the prompt builder uses, so the two
        # cannot disagree. Panels 1 and 2 send no documents at all.
        supplied = ([s["source"] for s in playbook_sections(panel)]
                    if name == "recommendations" else [])

        panel["narration_provenance"] = provenance(panel, prompt, usage,
                                                   supplied)

        # The retrieved text on its own, so an anchor is checked against the
        # playbook rather than against the instructions and the example that
        # surround it in the prompt.
        #
        # Passed through the same heading-stripper the prompt uses. Grounding
        # against the raw body would accept an anchor quoting a "## From
        # <source>" heading -- text the model was never shown, and the exact
        # string _playbook_for_prompt() exists to withhold.
        grounding = ("\n\n".join(
            _playbook_for_prompt(sec["body"])
            for sec in playbook_sections(panel)) or None
            if name == "recommendations" else None)

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

        # The attributions the SHAP panel showed, so a sentence can be
        # tested against the direction each one was supplied with.
        attrs = ((panel.get("detections") or [{}])[0].get("attributions")
                 if name == "shap_explanation" else None)

        # The decision the panel is explaining: which class won, which was
        # second, and by how much. Check 8 reads a feature's sign; this lets
        # check 9 read the sentence framing it, where the chosen class and
        # the runner-up were being swapped with nothing to catch it.
        decision = None
        if name == "shap_explanation":
            decision = dict((panel.get("detections") or [{}])[0])
            # Whether the PROMPT asserted ambiguity, on the same threshold
            # prompt_shap() uses. Without it the uncertainty rule reads the
            # representative row and flags a sentence the prompt asked for.
            f = (context or {}).get("finding") or {}
            decision["group_ambiguous"] = (
                f.get("dominant_runner_up_share", 0) > 0.25)

        findings, stats = check(panel["narrative"], evidence, supplied,
                                grounding_text=grounding,
                                strict_mechanism=(name == "shap_explanation"),
                                valid_references=valid_refs,
                                attributions=attrs,
                                decision=decision)
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
            # The model's words go to the case file; the panel gets the same
            # paragraph written from the figures instead. A reader should
            # never be shown an explanation of why there is no explanation.
            panel["narrative"] = fallback_summary(panel)
            panel["narration_fallback"] = bool(panel["narrative"])

    except Exception as e:
        panel["narration_error"] = f"{type(e).__name__}: {e}"
        panel["narrative"] = fallback_summary(panel)
        panel["narration_fallback"] = bool(panel["narrative"])

    _report(panel)
    return panel


# Every panel, every run. Narration is part of the pipeline rather than a
# preference, so there is no "default subset".
#
# Panel 3 was excluded for a long time, on the grounds that its content is a
# playbook someone wrote carefully and the deterministic panel already quotes
# it verbatim with its source. It was included once its steps became
# anchor-verified and its citations derived rather than written: there is now
# no panel where prose is offered without a check behind it.
#
# DEFAULT_PANELS is kept as an alias because narrate_all() takes it as a
# default argument and callers outside the app may pass it.
ALL_PANELS = ("summary", "shap", "recommend")

DEFAULT_PANELS = ALL_PANELS


def narrate_all(result, provider, panels=DEFAULT_PANELS, on_progress=None):
    """
    Narrate the requested panels.

    `panels` defaults to all three. Panel 3 was excluded until its steps
    were made anchor-verified and its citations derived rather than
    written; with those in place there is no panel where prose is offered
    without a check behind it.
    """
    finding = result.get("selected")
    label = (finding or {}).get("class") or "the selected finding"

    # What each panel is about, in the analyst's terms rather than the
    # code's. These are the only sentences shown during the wait, and the
    # wait is almost entirely here, so they name the finding's own figures.
    det = ((result.get("shap") or {}).get("detections") or [{}])[0]
    said = {
        "summary": lambda: (
            f"Summarising the capture: "
            f"{(result.get('summary') or {}).get('facts', {}).get('total_flows', 0):,}"
            f" flows, {len(result.get('findings') or [])} findings"),
        "shap": lambda: (
            f"Explaining why {label} was chosen -- "
            f"{len(det.get('attributions') or [])} attributions, "
            f"strongest first"),
        "recommend": lambda: (
            f"Reading the {label} response playbook for what to do next"
            if (finding or {}).get("class")
            else "Reading the response playbook for what to do next"),
    }

    for key in panels:
        panel = result.get(key)
        if isinstance(panel, dict):
            if on_progress and key in said:
                try:
                    on_progress(said[key]())
                except Exception:
                    pass
            narrate(panel, provider,
                    {"finding": finding, "shap": result.get("shap")})

    result["narrated_panels"] = list(panels)
    return result
