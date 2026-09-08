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

# Any number with three or more significant digits, which is where an
# invented figure shows up. Small integers ("two paragraphs", "step 3") are
# ignored deliberately -- flagging them is noise.
_NUMBER = re.compile(r"\d[\d,]{2,}(?:\.\d+)?")


def _numbers(text):
    out = set()
    for m in _NUMBER.finditer(text or ""):
        raw = m.group(0).replace(",", "")
        try:
            out.add(float(raw))
        except ValueError:
            pass
    return out


def check(narrative, prompt, sources_supplied):
    """
    Compare a narration against the input that produced it.

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
    invented = sorted(
        n for n in _numbers(text)
        if n not in in_prompt
        and not any(abs(n - p) < 0.51 for p in in_prompt)   # rounding
        and n >= 100                                        # ignore small ints
    )
    if invented:
        findings.append({
            "check": "figures",
            "severity": "high",
            "detail": f"states {', '.join(f'{n:,.0f}' for n in invented[:5])}"
                      f"{'...' if len(invented) > 5 else ''}, which "
                      f"{'does' if len(invented) == 1 else 'do'} not appear "
                      f"in what the model was given.",
        })

    stats = {
        "narrative_chars": len(text),
        "numbers_stated": len(_numbers(text)),
        "numbers_unsupported": len(invented),
        "sources_cited": sorted(cited),
        "sources_supplied": sorted(sources_supplied or []),
        "findings": len(findings),
        "highest_severity": ("high" if any(f["severity"] == "high"
                                           for f in findings)
                             else "medium" if findings else "none"),
    }
    return findings, stats


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
    return (f"{len(findings)} presentational issue"
            f"{'s' if len(findings) != 1 else ''} in the wording; the figures "
            f"below are unaffected.")
