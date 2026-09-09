"""
narration_schema.py
===================

Makes the language model's contribution auditable.

THE PROBLEM WITH A PARAGRAPH
Panel narration reads as authoritative whether or not it is. A sentence the
model inferred looks exactly like a sentence it read off a number, and an
investigator has no way to tell them apart -- which matters because one is
evidence and the other is a guess.

THE APPROACH
Two layers, in order of strength:

  1  PROVENANCE   record, for every narration, exactly what was put in front
                  of the model: which panel, which figures, which document
                  paths, which model, how many tokens, how long. A reader can
                  then reconstruct the input that produced any sentence.

  2  GROUNDING    check the output against that input. Numbers the model
                  states must appear in what it was given; document paths it
                  cites must be ones actually supplied; a log-odds value must
                  never be written as a percentage.

Neither proves a sentence is true. Together they prove where it could have
come from, and catch the three failures measured on qwen2.5:3b: inventing a
figure, citing a source that was not supplied, and converting log-odds into
a percentage.

WHY NOT JUST CONSTRAIN THE OUTPUT TO JSON
The pipeline does exactly that for its recommendations stage, and it is the
stronger tool. Here the panels want readable prose beside the numbers, so
the check runs after generation rather than shaping it. A claim that fails
is flagged, not deleted -- deleting a sentence from a paragraph leaves prose
that no longer reads, whereas a flagged paragraph with its problems listed
is still usable and is honest about what it is.
"""

import re


# ============================================================
# PROVENANCE
# ============================================================

def provenance(panel, prompt, usage, sources=None):
    """
    What the model was shown, and what it cost.

    Stored on the panel as `narration_provenance`. Everything here is
    reconstructable from the panel itself, so a saved case can be audited
    without re-running anything.
    """
    return {
        "panel": panel.get("panel"),
        "model": usage.get("model"),
        "provider": usage.get("provider"),
        "prompt_chars": len(prompt),
        "prompt_sha256_12": _digest(prompt),
        "input_tokens": usage.get("input"),
        "output_tokens": usage.get("output"),
        "seconds": usage.get("seconds"),
        # The document paths the model was allowed to draw on. Empty means
        # it was given figures only.
        "sources_supplied": sorted(sources or []),
        "context_truncated": bool(usage.get("context_note")),
    }


def _digest(text, n=12):
    import hashlib
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()[:n]


# ============================================================
# GROUNDING CHECKS
# ============================================================

# A number written as a percentage next to language about probability or
# confidence. SHAP contributions are log-odds; expressing one as a percentage
# overstates its effect on a saturated prediction.
_PERCENT = re.compile(
    r"\d+(?:\.\d+)?\s*%\s*(?:of\s+the\s+)?"
    r"(?:probability|confidence|likelihood|chance)", re.I)

_PERCENT_CONTRIB = re.compile(
    r"(?:contribut\w*|increas\w*|decreas\w*|rais\w*|push\w*)[^.]{0,40}"
    r"\d+(?:\.\d+)?\s*%", re.I)

# Every number, decimal or grouped. What to IGNORE is decided in _numbers()
# rather than by magnitude: the old rule needed three leading digits, so
# "0.94" never matched, and every confidence, F1 and log-odds value in this
# interface went unchecked.
_NUMBER = re.compile(r"(?<![\w.])\d+(?:,\d{3})*(?:\.\d+)?(?![\w])")

# "1." / "2)" at the start of a line is a list marker, not a claim.
_LIST_MARKER = re.compile(r"^\s*\d+[.)]\s", re.M)

# An address is an identifier, not a quantity. Without this, 192.168.1.77
# parses as the figures 192.168 and 1.77, and a narration that names the
# busiest host is accused of inventing them.
#
# Word boundaries are written as explicit lookarounds, never as a
# backslash-b. Twice in this file's history that escape was written
# through a shell heredoc and arrived as U+0008, which compiles
# happily and then matches nothing -- this guard and the adjective
# check were both silently inert. Lookarounds cannot be mangled
# that way.
_IPV4 = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){2,3}(?!\.?\d)")
#
# Three or four dotted groups, not two: an address may reach the text
# truncated ("10.0.0"), and a two-group rule would also swallow every
# real decimal -- 1.17 seconds, 0.9372 confidence -- which are exactly
# the figures this check exists to verify.


# Markdown emphasis, code ticks and heading or quote markers. These are how
# the playbook is formatted, not words in it, and the model is shown the raw
# file -- so "**Set a connection timeout** on the server" reaches it as one
# sentence and comes back without the asterisks. Folding them is the same
# argument as folding ligatures when tracing a quote to a PDF.
# Judgement words about a quantity. Every attribution now arrives
# with a comparison against the training distribution, so an
# adjective is the model substituting its own sense of scale for
# the one it was given.
_ADJECTIVE = re.compile(
    r"(?<![a-z])(?:very |unusually |extremely |remarkably "
    r"|exceptionally |fairly |relatively |quite )?"
    r"(?:short|long|small|large|high|low|rapid|brief|tiny|huge"
    r"|massive|minimal|negligible|substantial|significant"
    r"|considerable|excessive|slow|fast|quick|frequent|infrequent"
    r"|elevated|sharp|steep|dramatic|enormous|modest|slight|heavy"
    r"|wide|narrow)(?![a-z])", re.I)


# Nouns that are not feature magnitudes. An adjective on one of these is
# not a judgement about a measured value -- it is a statement about the
# model's own certainty, and the panel prints that figure too. Cutting
# "low" out of "low confidence" leaves "confidence", asserting the opposite
# of what the model wrote.
_PROTECTED_NOUN = re.compile(
    r"\s*(confidence|certainty|reliability|severity|probability|precision"
    r"|recall|accuracy|score|f1|support|risk|priority|quality|margin"
    r"|variance|correlation)\b", re.I)


# Verbs that assert a feature backs the prediction. Used only to test
# a NEGATIVE attribution, where such a verb contradicts the direction
# the model was given.
_SUPPORTS = re.compile(
    r"support|indicat|consistent with|typical of|characteristic of"
    r"|points to|evidence (?:for|of)|confirms|suggests", re.I)


# Verbs that present a class as the one the model settled on, and words
# that claim the decision was close. Used only against the chosen class
# and the runner-up, which the panel supplies.
_CHOSE = re.compile(
    r"chose|chosen|selected|identified|classified as|top choice"
    r"|most likely|primary|settled on|predicted|the answer is", re.I)

_UNDECIDED = re.compile(
    r"uncertain|undecided|not sure|close call|nearly tied|too close"
    r"|could be either|ambiguous between|hard to separate", re.I)


_MARKUP = re.compile(r"[*_`#>]+")


def _flatten(text):
    """Lowercase, markup dropped, runs of whitespace collapsed.

    Words and their order are NOT folded. An anchor is meant to be a span
    copied out of the playbook, so a model that paraphrases one should fail
    this comparison rather than be rescued by it.
    """
    return re.sub(r"\s+", " ", _MARKUP.sub("", text or "")).strip().lower()


def _numbers(text):
    """The numbers in `text` that assert something.

    Decimals always count -- there is no innocent reason to write 0.94
    unless 0.94 was supplied. Integers above ten count. Ten and below are
    ignored, and list markers are stripped first, because "two short
    paragraphs" and "the top 6 features" are prose about the answer rather
    than claims about the evidence. That noise is what the old
    three-digit rule was avoiding, at the cost of every decimal.
    """
    body = _IPV4.sub(" ", _LIST_MARKER.sub(" ", text or ""))
    out = set()
    for m in _NUMBER.finditer(body):
        raw = m.group(0).replace(",", "")
        try:
            value = float(raw)
        except ValueError:
            continue
        if "." in raw or value > 10:
            out.add(value)
    return out


# Protocols, services and named techniques. A flow record carries ports,
# counts and timings -- it does not carry an application protocol, and the
# model is given neither. Naming one is an assertion about the evidence,
# so a token here that is absent from the model's input is treated the same
# way as an invented figure.
#
# Deliberately NOT a general noun list: only terms whose appearance would
# change what an investigator believes was observed.
_MECHANISM = (
    "http", "https", "ftp", "smtp", "imap", "pop3", "ssh", "telnet", "rdp",
    "smb", "nfs", "ldap", "kerberos", "ntp", "snmp", "sip", "mqtt",
    "quic", "icmp", "arp", "bgp", "ospf", "dhcp", "tftp", "vpn", "tor",
    "syn flood", "ack flood", "handshake", "payload", "malware",
    "ransomware", "botnet", "beacon", "exploit kit", "shellcode",
)


def _mechanisms_in(text):
    low = _flatten(text)
    return {t for t in _MECHANISM
            if re.search(r"(?<![a-z0-9])" + re.escape(t) + r"(?![a-z0-9])",
                         low)}


def neutralise_magnitude(text):
    """Delete judgement words about quantities. Returns (text, removed).

    Every attribution is supplied with a measured comparison -- "typical for
    this feature in the training data", "3.9 standard deviations above the
    training mean". When the model writes "unusually short" instead, the
    panel shows a sentence that contradicts the figure printed directly
    beneath it, and a reader who reads prose and skips warnings is misled.
    Flagging alone does not fix that: the contradiction stays on screen.

    So the word is removed. This edit can only ever REMOVE an unsupported
    claim -- it never adds, rewords or reorders -- the original is kept on
    the panel as `narration_original`, and what was cut is recorded in
    `narration_edits`. "unusually short gaps between packets" becomes "gaps
    between packets", with the measured comparison one line below it.

    Applied to the SHAP panel only: that is the panel where the comparison
    is supplied, so the adjective is always avoidable there.

    TWO POSITIONS WHERE THE CUT IS NOT SAFE, AND SO IS NOT MADE
    An adjective in predicate position carries the sentence, and an
    adjective on a noun that is not a feature magnitude is not a magnitude
    judgement at all. Both are left in place for check() to flag instead:
    flagging a sentence is always better than rewriting it into a different
    claim.
    """
    text = text or ""
    removed = []

    def cut(m):
        after = text[m.end():]
        # Predicative position: nothing follows but punctuation or the end.
        # "the gaps were unusually short." would become "the gaps were" --
        # not a weaker claim, a broken sentence.
        if not re.match(r"\s*[A-Za-z]", after):
            return m.group(0)
        # Modifying the model's own certainty, not a measurement.
        if _PROTECTED_NOUN.match(after):
            return m.group(0)
        removed.append(m.group(0).strip())
        return ""

    out = _ADJECTIVE.sub(cut, text)
    if not removed:
        return text, []

    # Tidy the seams: doubled spaces, a space before punctuation, and "an"
    # left in front of what is now a consonant.
    out = re.sub(r"[ 	]{2,}", " ", out)
    # The captured punctuation is restored. This held a literal
    # 0x01 byte instead of the \1 backreference, so every space
    # before a comma or full stop became an invisible control
    # character and the sentences ran together on screen.
    out = re.sub(r"\s+([,.;:])", r"\1", out)
    out = re.sub(r"(?<![a-z])an\s+(?=[bcdfghjklmnpqrstvwxyz])", "a ",
                 out, flags=re.I)
    return out.strip(), removed


def check(narrative, prompt, sources_supplied, grounding_text=None,
          strict_mechanism=False, valid_references=None,
          attributions=None, decision=None):
    """
    Compare a narration against the input that produced it.

    `grounding_text` is the retrieved document text alone, with the
    instructions and the worked example excluded. Anchors are checked
    against it rather than against the whole prompt: a model that copies an
    anchor out of the example has not read the playbook, and checking
    against the prompt would score that as a pass. Falls back to the prompt
    when not supplied, which is the weaker check.

    Returns (findings, stats). `findings` is a list of dicts, each with a
    `check`, a `detail` and a `severity`:

      high    the model asserted something it was not given
      medium  a presentational rule was broken
    """
    findings = []
    text = narrative or ""

    # 1. Units. The panel states these are log-odds; the prompt says so too.
    for pattern, why in ((_PERCENT, "a percentage of probability or confidence"),
                         (_PERCENT_CONTRIB, "a contribution as a percentage")):
        m = pattern.search(text)
        if m:
            findings.append({
                "check": "units",
                "severity": "medium",
                "detail": f"expresses {why}: {m.group(0)!r}. SHAP values are "
                          f"log-odds.",
            })
            break

    # 2. Citations. A path the model names must be one that was supplied.
    cited = set(re.findall(r"[\w/]+\.md", text))
    unsupplied = sorted(cited - set(sources_supplied or []))
    if unsupplied:
        findings.append({
            "check": "citation",
            "severity": "high",
            "detail": f"cites {', '.join(unsupplied)}, which "
                      f"{'was' if len(unsupplied) == 1 else 'were'} not "
                      f"supplied to the model.",
        })

    # 3. Figures. Every substantial number in the output should appear in the
    #    input. Percentages the model derived from two supplied numbers are
    #    tolerated -- it is arithmetic, not invention -- so only integers and
    #    large values are compared.
    in_prompt = _numbers(prompt)

    # Rounding tolerance scales with the figure. A flat half-unit is right
    # for a flow count and far too coarse for a confidence -- it would
    # accept 0.94 as a rounding of the 0.68 actually supplied.
    def _supplied(n):
        return any(abs(n - p) <= max(0.005, abs(p) * 0.005) for p in in_prompt)

    invented = sorted(n for n in _numbers(text) if not _supplied(n))
    if invented:
        findings.append({
            "check": "figures",
            "severity": "high",
            "detail": f"states {', '.join(f'{n:,.0f}' for n in invented[:5])}"
                      f"{'...' if len(invented) > 5 else ''}, which "
                      f"{'does' if len(invented) == 1 else 'do'} not appear "
                      f"in what the model was given.",
        })

    # 4. Anchors. A recommendation step must carry a span copied out of the
    #    playbook it was written from, and that span must really be there.
    #    This is the check that catches the failure the other three cannot:
    #    an answer that invents nothing because it says nothing. Measured on
    #    qwen2.5:3b, six section headings copied from the wrong document
    #    passed every other check on this page.
    steps = re.findall(r"^\s*\d+[.)]\s+\S", text, re.M)
    if steps:
        anchors = re.findall(r"ANCHOR:\s*(.+?)\s*$", text, re.M | re.I)
        flat = _flatten(grounding_text if grounding_text is not None
                        else prompt)
        unfound = [a for a in anchors if _flatten(a)[:60] not in flat]

        # A heading is structure, not instruction. Anchoring a step to
        # "3. Containment" shows WHERE in the playbook the step came from,
        # not what prescribes it -- measured as the failure mode of a
        # section-scaffolded prompt, which returned five steps anchored to
        # five headings and nothing else.
        headings = {_flatten(h) for h in re.findall(
            r"^#{1,6}\s+(.+?)\s*$", grounding_text or prompt or "", re.M)}
        as_heading = [a for a in anchors
                      if any(h and h in _flatten(a) for h in headings)]
        if as_heading:
            findings.append({
                "check": "anchors",
                "severity": "high",
                "detail": f"{len(as_heading)} anchor"
                          f"{'s are' if len(as_heading) != 1 else ' is'} a "
                          f"section heading rather than a prescribed "
                          f"action: {as_heading[0][:60]!r}.",
            })
        missing = len(steps) - len(anchors)

        if missing > 0:
            findings.append({
                "check": "anchors",
                "severity": "high",
                "detail": f"{missing} of {len(steps)} steps carry no anchor "
                          f"back to the playbook, so they cannot be traced "
                          f"to a prescribed action.",
            })
        # An anchor proves the span is in the playbook. It does not prove
        # the span prescribes THAT step, and the cheapest visible form of
        # that gap is one anchor pasted under several steps.
        seen = [_flatten(a) for a in anchors]
        if len(seen) != len(set(seen)):
            findings.append({
                "check": "anchors",
                "severity": "medium",
                "detail": f"{len(seen) - len(set(seen))} step"
                          f"{'s reuse' if len(seen) - len(set(seen)) != 1 else ' reuses'}"
                          f" an anchor already given for another step, so it "
                          f"is not shown what prescribes it.",
            })

        if unfound:
            findings.append({
                "check": "anchors",
                "severity": "high",
                "detail": f"{len(unfound)} anchor"
                          f"{'s do' if len(unfound) != 1 else ' does'} not "
                          f"appear in the playbook supplied, so the step "
                          f"came from somewhere else: {unfound[0][:60]!r}.",
            })

    # 5. Mechanism. A protocol or named technique the model was not given.
    #
    # `strict_mechanism` drops the comparison entirely, for the SHAP panel:
    # its prompt carries the feature glossary, and some definitions give
    # example ports, so comparing against the prompt scored "this was an
    # HTTP attack" as supported on the strength of a word inside a
    # definition. Attributions are counts, sizes and timings; naming a
    # protocol beside them is an assertion in every case.
    # 6. Magnitude adjectives. Each attribution is supplied with a
    #    comparison against the training distribution -- "typical for this
    #    feature", "3.9 standard deviations above the training mean". An
    #    adjective used INSTEAD of that comparison is the model's own
    #    judgement of a distribution it cannot see, and it has been measured
    #    getting it backwards: 1,169,002 microseconds, supplied as typical,
    #    described as "a very short gap". Flagged, not withheld -- the
    #    figure beside it is correct and the reader can see the word.
    if strict_mechanism:
        adj = _ADJECTIVE.findall(text)
        if adj:
            findings.append({
                "check": "magnitude",
                "severity": "medium",
                "detail": "describes a value as "
                          + ", ".join(sorted({a.lower().strip()
                                              for a in adj})[:4])
                          + ". Each value was supplied with a comparison "
                            "against the training distribution; an adjective "
                            "is the model's own judgement, not that "
                            "comparison.",
            })

    # 7. Reference markers. A step ending in [2] is a claim that reference 2
    #    supports it, and a number outside the supplied list points the
    #    reader at nothing -- worse than no marker, because it looks
    #    checkable. `valid_references` is the set the panel will actually
    #    print, so a marker either resolves in the REFERENCES block below or
    #    it is reported here.
    if valid_references is not None:
        cited_n = {int(x) for x in re.findall(r"\[(\d{1,2})\]", text or "")}
        unknown = sorted(cited_n - set(valid_references))
        if unknown:
            findings.append({
                "check": "reference",
                "severity": "high",
                "detail": "cites "
                          + ", ".join(f"[{n}]" for n in unknown)
                          + ", which "
                          + ("is" if len(unknown) == 1 else "are")
                          + " not in the reference list shown with this "
                            "finding, so the marker resolves to nothing.",
            })
        # A step with no marker is NOT a finding any more. Markers are
        # attached deterministically after these checks, from each step's
        # verified anchor, so the model is told not to write them -- this
        # check would fire on every correct answer. What stays is the case
        # that still matters: a number that resolves to nothing.

    # 8. Direction. A feature marked "argues against" described as
    #    supporting the class contradicts a field the model was handed.
    #    Caught on a sibling implementation: Subflow Bwd Bytes at -1.43,
    #    direction "argues against", narrated as "typical of Slowloris".
    #    The sign is in the prompt; reading it backwards is not a wording
    #    slip, it inverts the explanation.
    if attributions:
        low = _flatten(text)
        flipped = []
        for a in attributions:
            if a.get("contribution", 0) >= 0:
                continue
            name = _flatten(a.get("plain") or a.get("feature") or "")
            if not name or name not in low:
                continue
            at = low.index(name) + len(name)
            window = low[at:at + 90]
            if _SUPPORTS.search(window):
                flipped.append(a.get("plain") or a.get("feature"))
        if flipped:
            findings.append({
                "check": "direction",
                "severity": "high",
                "detail": "describes " + ", ".join(flipped[:3])
                          + " as supporting the class, but the attribution "
                            "is negative and was supplied as 'argues "
                            "against'. The explanation is inverted.",
            })

    # 9. The decision itself: which class the model chose, and how close it
    #    was. Check 8 reads a feature's sign; this reads the framing sentence
    #    around it, and nothing did before.
    #
    #    Measured on this corpus, one paragraph, no findings raised: "with
    #    DoS being the top choice for 100% of the flows" on a finding whose
    #    chosen class was Slowloris at 0.9999 and DoS the runner-up at
    #    0.0001, and in the same paragraph "the model's classification is
    #    uncertain between these two attack classes". The chosen class and
    #    the runner-up swapped, and a decision made at a margin of 0.9998
    #    described as uncertain. Both are inversions of a field supplied in
    #    the prompt, both would mislead an investigator about what was
    #    detected, and a feature-level check cannot see either.
    if decision:
        low = _flatten(text)
        chosen = _flatten(decision.get("predicted") or "")
        runner = _flatten(decision.get("runner_up") or "")

        # The runner-up named as what the model settled on.
        if runner and runner != chosen:
            for m in re.finditer(re.escape(runner), low):
                before = low[max(0, m.start() - 60):m.start()]
                after = low[m.end():m.end() + 60]
                if _CHOSE.search(before) or _CHOSE.search(after):
                    findings.append({
                        "check": "decision",
                        "severity": "high",
                        "detail": f"presents {decision['runner_up']!r} as the "
                                  f"class the model settled on. It was the "
                                  f"runner-up; the model chose "
                                  f"{decision['predicted']!r}.",
                    })
                    break

        # Uncertainty asserted on a decision that was not close. The margin
        # is the number the prompt supplies; 0.15 is the same threshold the
        # panel uses to decide whether to call a decision close at all.
        # Not flagged when the finding is ambiguous ACROSS ITS GROUP. The
        # representative row can lead by 0.9998 while the runner-up takes
        # second place on every one of the finding's flows, and in that case
        # the prompt itself instructs the model to call the pair uncertain.
        # Reading the row's margin alone scored the model as inverting a
        # field when it was following an instruction -- the check was
        # comparing against the wrong scope.
        conf = decision.get("confidence")
        runner_conf = decision.get("runner_up_confidence")
        if (conf is not None and runner_conf is not None
                and not decision.get("group_ambiguous")):
            margin = float(conf) - float(runner_conf)
            if margin >= 0.15 and _UNDECIDED.search(low):
                findings.append({
                    "check": "decision",
                    "severity": "high",
                    "detail": f"calls the decision uncertain or close, but "
                              f"the chosen class leads the runner-up by "
                              f"{margin:.4f}. Nothing in the input says the "
                              f"model was undecided.",
                })

    in_text = _mechanisms_in(text)
    in_input = _mechanisms_in(prompt)

    # Nowhere in the input: invention, and withheld like an invented figure.
    invented_mech = sorted(in_text - in_input)
    if invented_mech:
        findings.append({
            "check": "mechanism",
            "severity": "high",
            "detail": f"names {', '.join(invented_mech)}, which "
                      f"{'is' if len(invented_mech) == 1 else 'are'} not in "
                      f"the evidence supplied. A flow record does not "
                      f"establish an application protocol.",
        })

    # In the input, but only as an example inside a feature definition. The
    # SHAP panel is the one place this is always an over-reading: an
    # attribution is computed over counts, sizes and timings.
    overread = sorted(in_text & in_input) if strict_mechanism else []
    if overread:
        findings.append({
            "check": "mechanism",
            "severity": "medium",
            "detail": f"names {', '.join(overread)}. The word appears in the "
                      f"feature definitions supplied, not in an observation "
                      f"-- an attribution is computed over packet counts, "
                      f"sizes and timings, which do not establish a "
                      f"protocol. Read it as the model's assumption.",
        })

    stats = {
        "narrative_chars": len(text),
        "numbers_stated": len(_numbers(text)),
        "numbers_unsupported": len(invented),
        "mechanisms_unsupported": invented_mech,
        "mechanisms_overread": overread,
        "sources_cited": sorted(cited),
        "sources_supplied": sorted(sources_supplied or []),
        "findings": len(findings),
        "highest_severity": ("high" if any(f["severity"] == "high"
                                           for f in findings)
                             else "medium" if findings else "none"),
    }
    return findings, stats


# What each check means to a reader, rather than to the person who wrote it.
#
# The panel used to print the machinery: a fixed withholding paragraph, then
# the verdict line, then one row per finding tagged "[high] anchors:" with a
# count and a quoted fragment, then a provenance line carrying a token count
# and a prompt hash. Five overlapping statements of one fact, in the
# vocabulary of the checker rather than of the investigation -- and they
# could contradict each other on their face, because the verdict counts
# CLAIMS while the findings count steps and anchors.
#
# An investigator needs one sentence: what is missing, why, and whether the
# rest of the panel can be trusted. The counts, severities, check names and
# hashes stay on the panel for the saved case.
_PLAIN = {
    "anchors": "quoted wording that is not in the playbook it was given",
    "citation": "named a source document it was never shown",
    "figures": "stated a figure that is not in the capture",
    "reference": "cited a reference number that does not exist",
    "direction": "described evidence as pointing the opposite way to the "
                 "measurement",
    "mechanism": "named a protocol or behaviour it was not given",
    "units": "expressed a contribution as a percentage, which SHAP values "
             "are not",
    "magnitude": "judged a quantity as large or small, where the measured "
                 "comparison is printed below",
}

# What the reader can still rely on, per panel. Naming it is the point of the
# sentence: withholding prose is only tolerable if what remains is complete.
_REMAINS = {
    "recommendations": "The steps and sources below are read from the "
                       "playbook itself, so they are unaffected.",
    "shap_explanation": "The figures and directions below are measured from "
                        "the model, so they are unaffected.",
    "flow_summary": "The counts below are computed from the predictions, so "
                    "they are unaffected.",
}


def plain_reason(findings, panel_name=None, withheld=False):
    """One human sentence for what the checks found, or None when clean.

    Returns None if there is nothing to say, so the caller can print nothing
    at all -- silence is the clean state, and a line saying "no problems" is
    a line the reader has to process for no benefit.
    """
    findings = findings or []
    if not findings:
        return None

    high = [f for f in findings if f.get("severity") == "high"]
    chosen = high or findings

    # Two reasons at most. A third adds length without changing what the
    # reader does next, which is to read the evidence rather than the prose.
    reasons, seen = [], set()
    for f in chosen:
        phrase = _PLAIN.get(f.get("check"))
        if phrase and phrase not in seen:
            seen.add(phrase)
            reasons.append(phrase)
        if len(reasons) == 2:
            break
    if not reasons:
        return None

    why = reasons[0] if len(reasons) == 1 else " and ".join(reasons)
    remains = _REMAINS.get(panel_name, "The evidence below is unaffected.")

    if withheld or high:
        return ("The local model's summary is not shown, because it " + why
                + ". " + remains)
    return "One phrase was removed from the summary: the model " + why + "."


def summary_line(stats, findings):
    """One line for the panel header, so the state is visible without digging."""
    if not findings:
        n = stats["numbers_stated"]
        return (f"Checked: {n} figure{'s' if n != 1 else ''} traced to the "
                f"input, no unsupported claims.")

    high = [f for f in findings if f["severity"] == "high"]
    if high:
        return (f"UNVERIFIED: {len(high)} claim"
                f"{'s' if len(high) != 1 else ''} could not be traced to the "
                f"model's input. Read the figures below, not the prose.")
    # "presentational" is right for a units slip and wrong for a protocol
    # the model assumed, so the word follows the finding rather than the
    # severity.
    kind = ("unsupported assumption"
            if any(f["check"] == "mechanism" for f in findings)
            else "presentational issue")
    return (f"{len(findings)} {kind}"
            f"{'s' if len(findings) != 1 else ''} in the wording; the figures "
            f"below are unaffected.")
