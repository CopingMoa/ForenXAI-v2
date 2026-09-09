"""
source_guard.py
===============

Checks, at the moment a document is about to be used, that the passages it
quotes are still in the PDFs they name.

WHY AT RUNTIME AND NOT ONLY AT BUILD TIME
`fetch_knowledge.py --verify` already proves every quote against its source,
and that is the right gate before shipping. It is not a gate an investigator
can rely on: the knowledge files and the _sources directory are ordinary
files on an ordinary disk. A source can be replaced -- it happened twice in
this project's own history, once when the USENIX proceedings PDF was
swapped for the Communications of the ACM version of the same work, which
kept only two of eight quoted passages. Nothing in the running application
would have noticed.

So the guard runs again, against the file on disk, before the text reaches
either the panel or the language model.

WHY IT IS AFFORDABLE
The expensive part is turning a PDF into text -- 3.7M characters across the
registered corpus, seconds per run. It is done once and cached, keyed by the
SHA-256 of the file it came from, so:

  * the cache is content-addressed: replace the PDF and the key changes,
    the old cache is ignored, and the quotes are re-checked against the new
    file. A stale cache cannot mask a swapped source.
  * verification itself is substring containment over a normalised string,
    which CPython does with the two-way algorithm in O(n + m). Warm, a
    whole document costs well under a millisecond.

WHAT IT DOES ON FAILURE -- two tiers, and the line between them matters

  DRIFT (>= REPAIR_FLOOR alike to a passage that IS in the source)
      repair_document() realigns the quote to the source's own words,
      copied out of the source and never generated, with the source's
      capitalisation restored. A repaired quote is traceable by
      construction: it is the source's text. This makes the citation true
      again rather than papering over it.

  FABRICATION (below the floor, or nothing close in the source at all)
      refused. At that point the citation is wrong, not the wording, and
      only the author can say what was meant. The document is quarantined
      -- withheld from the panel and from the model, and named on screen
      with the failing passage.

Repair is never silent: a .bak is kept, the change is reported, and the
document is re-verified afterwards.
"""
import os
import re
import hashlib

import fetch_knowledge as fk

CACHE = os.path.join(fk.SOURCE_DIR, ".cache")

# Per-process memo. A capture is analysed many times in one session and the
# same playbooks come back each time.
_TEXT = {}
_RAW = {}
_RESULT = {}


# Keys answered from the extracted-text cache because the source document
# itself was not shipped. Read by verify_sections() so a panel built from a
# --no-sources copy can say which of the two it checked against.
FROM_CACHE = set()


def _cached_only(key, suffix):
    """The cached extraction for a key whose source document is absent.

    A --no-sources build ships knowledge/_sources/.cache -- 7.2 MB of
    extracted text -- and leaves the 98 MB of PDFs behind. Without this the
    absent PDF made normalised_source() return None, every quote in every
    retrieved document failed to verify, and the panels rendered with the
    check switched off in the one build most likely to be handed to someone
    else.

    The cache filename carries the hash of the PDF it was extracted from, so
    the recipient still knows WHICH document the text came from; what they
    cannot do is re-derive that text from the document themselves. That is a
    real step down from the full build and it is recorded rather than
    glossed: the key goes into FROM_CACHE, and the panel reports the weaker
    provenance instead of implying the stronger one.

    Exactly one cache file must match. Two would mean two extractions of
    different documents under one key, and choosing between them silently is
    how the wrong text ends up backing a quote.
    """
    if not os.path.isdir(CACHE):
        return None
    stamps = [f for f in os.listdir(CACHE)
              if f.startswith(key + ".") and f.endswith(suffix)]
    if len(stamps) != 1:
        return None
    with open(os.path.join(CACHE, stamps[0]), encoding="utf-8") as fh:
        text = fh.read()
    FROM_CACHE.add(key)
    return text


def _digest(path, n=16):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()[:n]


def normalised_source(key):
    """The source's text, folded for comparison, cached against its hash.

    Returns None when the source is not on disk at all -- a different
    failure from a quote that does not match, and reported differently.
    """
    if key in _TEXT:
        return _TEXT[key]

    meta = fk.SOURCES.get(key)
    if not meta:
        return None
    ext = {"pdf": ".pdf", "text": ".txt", "html": ".html"}[meta["kind"]]
    path = os.path.join(fk.SOURCE_DIR, key + ext)
    if not os.path.isfile(path):
        cached = _cached_only(key, ".norm")
        _TEXT[key] = cached
        return cached

    # Content-addressed: the hash is in the filename, so a replaced source
    # cannot be answered from the cache written for the old one.
    stamp = os.path.join(CACHE, f"{key}.{_digest(path)}.norm")
    if os.path.isfile(stamp):
        text = open(stamp, encoding="utf-8").read()
    else:
        text = fk._norm(fk._text_of(key))
        os.makedirs(CACHE, exist_ok=True)
        # Old caches for this key are now unreachable; drop them so the
        # directory does not grow one file per revision of every source.
        for old in os.listdir(CACHE):
            if old.startswith(key + ".") and old.endswith(".norm"):
                os.remove(os.path.join(CACHE, old))
        with open(stamp, "w", encoding="utf-8") as fh:
            fh.write(text)

    _TEXT[key] = text
    return text


def raw_source(key):
    """The source's text as printed, cached against its hash.

    Same content-addressed scheme as the normalised copy. Without it a
    repair re-extracted the PDF to recover capitalisation and took 15
    seconds against 15 milliseconds -- the extraction, not the alignment,
    was the whole cost.
    """
    if key in _RAW:
        return _RAW[key]

    meta = fk.SOURCES.get(key)
    if not meta:
        return None
    ext = {"pdf": ".pdf", "text": ".txt", "html": ".html"}[meta["kind"]]
    path = os.path.join(fk.SOURCE_DIR, key + ext)
    if not os.path.isfile(path):
        cached = _cached_only(key, ".raw")
        _RAW[key] = cached
        return cached

    stamp = os.path.join(CACHE, f"{key}.{_digest(path)}.raw")
    if os.path.isfile(stamp):
        text = open(stamp, encoding="utf-8").read()
    else:
        text = fk._text_of(key) or ""
        os.makedirs(CACHE, exist_ok=True)
        for old in os.listdir(CACHE):
            if old.startswith(key + ".") and old.endswith(".raw"):
                os.remove(os.path.join(CACHE, old))
        with open(stamp, "w", encoding="utf-8") as fh:
            fh.write(text)

    _RAW[key] = text
    return text


def verify_document(rel_path):
    """Check one knowledge document's quotes against the sources it names.

    Returns {"ok": bool, "checked": int, "failures": [...]}. A document with
    no quote blocks is ok with checked == 0: hand-written prose is the
    author's and is not held to this.
    """
    full = os.path.join(fk.KNOWLEDGE, rel_path)
    if not os.path.isfile(full):
        return {"ok": False, "checked": 0,
                "failures": [{"source": None, "why": "document is missing",
                              "quote": ""}]}

    key = (rel_path, os.path.getmtime(full))
    if key in _RESULT:
        return _RESULT[key]

    body = open(full, encoding="utf-8", errors="replace").read()
    checked, failures = 0, []

    for section in re.split(r"\n(?=#{1,6} )", body):
        head = section.split("\n", 1)[0]
        m = re.match(r"#{1,6} From ([\w.\-]+)\s*$", head)
        if not m:
            continue
        src = m.group(1)
        text = normalised_source(src)
        if text is None:
            failures.append({"source": src, "quote": "",
                             "why": ("names a source that is not registered "
                                     "or not on disk")})
            continue
        for block in fk._quoted_blocks(section.partition("\n")[2]):
            if len(block) < 100:
                continue
            checked += 1
            if fk._norm(block) not in text:
                failures.append({
                    "source": src, "quote": block[:90],
                    # The whole block, for repair. `quote` stays short
                    # because it is what gets printed on screen.
                    "quote_full": block,
                    "why": "this passage is not in the document it names",
                })

    result = {"ok": not failures, "checked": checked, "failures": failures}
    _RESULT[key] = result
    return result


def _best_window(quote_norm, source_norm):
    """The passage in the source most like this quote, and how alike.

    Brute-force alignment over 3.7M characters is not affordable, and it is
    not needed: a quote that has DRIFTED still shares long runs with the
    passage it came from. So anchor first, align second.

      1. take the longest words in the quote as anchors -- long words are
         rare, so each one narrows 3.7M characters to a handful of offsets
      2. align only the windows around those offsets, with difflib
         (Ratcliff-Obershelp), which is O(window^2) on a few hundred
         characters rather than on the corpus

    Returns (ratio, text) with ratio 0.0 when no anchor matched at all.
    """
    import difflib

    words = sorted({w for w in re.findall(r"[a-z]{6,}", quote_norm)},
                   key=len, reverse=True)[:4]
    span = len(quote_norm)
    offsets = []
    for w in words:
        start = 0
        for _ in range(20):                    # cap the candidates per anchor
            i = source_norm.find(w, start)
            if i < 0:
                break
            offsets.append(i)
            start = i + 1
    if not offsets:
        return 0.0, ""

    best = (0.0, "")
    seen = set()
    for i in offsets:
        lo = max(0, i - span)
        key = lo // (span // 2 or 1)           # collapse overlapping windows
        if key in seen:
            continue
        seen.add(key)
        window = source_norm[lo:i + 2 * span]
        m = difflib.SequenceMatcher(None, quote_norm, window)
        # Longest common run tells us where the quote sits inside the window.
        a, b, size = m.find_longest_match(0, len(quote_norm), 0, len(window))
        if size < 20:
            continue
        # Snap to word boundaries. Slicing by offset alone cuts mid-word --
        # it produced "enial-of-service events may occur" once, which
        # verifies (it is a substring) and reads as damage.
        lo_c = max(0, b - a)
        hi_c = min(len(window), lo_c + span)
        while lo_c > 0 and window[lo_c - 1] not in " \t\n":
            lo_c -= 1
        while hi_c < len(window) and window[hi_c] not in " \t\n":
            hi_c += 1
        cand = window[lo_c:hi_c].strip()

        ratio = difflib.SequenceMatcher(None, quote_norm, cand).ratio()
        if ratio > best[0]:
            best = (ratio, cand)
    return best


def _as_printed(key, normalised_match):
    """The same passage with the source's own capitalisation restored.

    `_norm` lowercases, so a repair written from it reads "denial-of-service
    events may occur" where the document says "Denial-of-service". The
    quote would verify -- normalisation folds case on both sides -- and
    would still be wrong to put in a thesis.

    So the match is located again in the RAW text, allowing any whitespace
    between words and ignoring case. Returns None if it cannot be found,
    and the caller keeps the normalised form rather than failing the repair.
    """
    if not normalised_match:
        return None
    raw = raw_source(key)
    if not raw:
        return None
    words = normalised_match.split()
    if len(words) < 4:
        return None
    pattern = r"\s+".join(re.escape(w) for w in words)
    m = re.search(pattern, raw, re.I)
    return re.sub(r"\s+", " ", m.group(0)).strip() if m else None


# A quote below this is not drift, it is a different passage -- or one that
# was never in the source. Repairing that would be inventing provenance, so
# it is refused and the document stays quarantined.
REPAIR_FLOOR = 0.90


def repair_document(rel_path, apply=False, floor=REPAIR_FLOOR):
    """Realign a document's quotes to the source they name.

    The replacement text is COPIED FROM THE SOURCE, never generated, so a
    repaired quote is by construction traceable -- this makes the citation
    true again rather than papering over it. A quote that does not closely
    match anything in the source is refused, because at that point the
    citation is wrong and only the author can say what was meant.

    Returns a report; with apply=True the file is rewritten and a .bak kept.
    """
    result = verify_document(rel_path)
    if result["ok"]:
        return {"repaired": [], "refused": [], "applied": False,
                "note": "nothing to repair"}

    full = os.path.join(fk.KNOWLEDGE, rel_path)
    body = open(full, encoding="utf-8").read()
    repaired, refused = [], []

    for fail in result["failures"]:
        src, quote = fail["source"], fail.get("quote_full") or fail["quote"]
        text = normalised_source(src)
        if text is None or not quote:
            refused.append({**fail, "why_refused": "source unavailable"})
            continue

        ratio, match = _best_window(fk._norm(quote), text)
        match = _as_printed(src, match) or match
        if ratio < floor or not match:
            refused.append({**fail, "ratio": round(ratio, 3),
                            "why_refused": f"closest passage in {src} is only "
                                           f"{ratio:.0%} alike; this is not "
                                           f"drift, and repairing it would "
                                           f"invent provenance"})
            continue

        # Re-wrap the source's own words as a blockquote, in place.
        wrapped = "\n".join("> " + line for line in
                            __import__("textwrap").wrap(match.strip(), 72))
        old_block = re.search(
            r"(?:^> .*\n)+",
            body[body.find(quote[:40].split("\n")[0]) - 200:] or body, re.M)
        # Locate by the quote's own first line rather than by offset maths.
        first = quote.strip().split("\n")[0][:50]
        pat = re.compile(r"(?:^>.*\n)*^>[^\n]*"
                         + re.escape(first[:40]) + r"[^\n]*\n(?:^>.*\n)*",
                         re.M)
        m = pat.search(body)
        if not m:
            refused.append({**fail, "why_refused": "could not locate the "
                                                   "block in the document"})
            continue
        repaired.append({"source": src, "ratio": round(ratio, 3),
                         "was": quote[:80], "now": match[:80]})
        body = body[:m.start()] + wrapped + "\n" + body[m.end():]

    if apply and repaired:
        import shutil
        shutil.copy2(full, full + ".bak")
        open(full, "w", encoding="utf-8", newline="\n").write(body)
        _RESULT.clear()

    return {"repaired": repaired, "refused": refused,
            "applied": bool(apply and repaired),
            "proposed": body if repaired and not apply else None}


def verify_sections(sections):
    """Verify every retrieved document. Returns (verified, quarantined).

    `quarantined` entries carry the reason, so the panel can say which
    document was withheld and why rather than silently dropping it.
    """
    verified, quarantined = [], []
    for s in sections:
        src = s.get("source")
        if not src:
            verified.append(s)
            continue
        r = verify_document(src)
        if r["ok"]:
            # Say WHAT the quotes were checked against. A --no-sources build
            # ships the extracted-text cache rather than the PDFs, so the
            # check still runs but one link of the chain is missing: the
            # recipient cannot re-derive that text from the document. The
            # panel reports the weaker provenance instead of implying the
            # stronger one.
            verified.append({**s,
                             "quotes_verified": r["checked"],
                             "verified_against": (
                                 "cache" if FROM_CACHE else "source")})
        else:
            quarantined.append({**s, "verification": r})
    return verified, quarantined
