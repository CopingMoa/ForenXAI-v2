"""
fetch_knowledge.py
==================

Downloads the response-guidance sources, extracts the sections that apply to
each attack class, and checks what is on disk is still the document it claims
to be.

    python fetch_knowledge.py --download     fetch every source once
    python fetch_knowledge.py --extract      build draft .md per attack class
    python fetch_knowledge.py --verify       check provenance, hashes, age
    python fetch_knowledge.py --status       coverage table
    python fetch_knowledge.py --all          download, extract, verify

WHAT IS AUTOMATED AND WHAT IS NOT
Downloading, converting and locating candidate sections are mechanical, so
they are automated. Deciding which paragraphs actually answer "what do I do
about this class" is judgement, so every generated file is marked
REVIEW REQUIRED and `--verify` fails while that marker is present.

A draft nobody read is not a source. The marker is what stops one reaching
an investigator.

WHY DOWNLOAD RATHER THAN FETCH AT RUN TIME
A page can change between citing it and someone checking the citation. A
local copy with a recorded hash and retrieval date can be re-verified; a URL
cannot. That is the difference between a forensic tool and a research
assistant, and it is why `_sources/manifest.json` records a SHA-256 and a
date for every file.

FRESHNESS
`--verify` warns when a source is older than STALE_AFTER_DAYS. It cannot
know whether a publisher has issued a revision -- only that nobody has
checked for one recently. Re-run `--download` and compare hashes to find out.
"""

import os
import re
import sys
import json
import hashlib
import argparse
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

KNOWLEDGE = os.path.join(HERE, "knowledge")
SOURCE_DIR = os.path.join(KNOWLEDGE, "_sources")
MANIFEST = os.path.join(SOURCE_DIR, "manifest.json")

STALE_AFTER_DAYS = 180
REVIEW_MARKER = "REVIEW REQUIRED"


# ============================================================
# THE SOURCES
#
# Each was verified against the publisher's own page: title, authors, date
# and identifier are as the publisher states them. `citation` is the IEEE
# form that goes into the generated file's provenance header.
# ============================================================

SOURCES = {
    "NIST.SP.800-61r3": {
        "url": "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/"
               "NIST.SP.800-61r3.pdf",
        "kind": "pdf",
        "citation": 'A. Nelson, S. Rekhi, M. Souppaya and K. Scarfone, '
                    '"Incident response recommendations and considerations '
                    'for cybersecurity risk management," NIST SP 800-61r3, '
                    'Apr. 2025, doi: 10.6028/NIST.SP.800-61r3.',
        "landing": "https://csrc.nist.gov/pubs/sp/800/61/r3/final",
    },
    "NIST.SP.800-53r5": {
        "url": "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/"
               "NIST.SP.800-53r5.pdf",
        "kind": "pdf",
        "citation": 'Joint Task Force, "Security and privacy controls for '
                    'information systems and organizations," NIST '
                    'SP 800-53r5, rel. 5.2.0, Aug. 2025, doi: '
                    '10.6028/NIST.SP.800-53r5.',
        "landing": "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
    },
    "NIST.SP.800-52r2": {
        "url": "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/"
               "NIST.SP.800-52r2.pdf",
        "kind": "pdf",
        "citation": 'K. McKay and D. Cooper, "Guidelines for the selection, '
                    'configuration, and use of Transport Layer Security '
                    '(TLS) implementations," NIST SP 800-52r2, Aug. 2019, '
                    'doi: 10.6028/NIST.SP.800-52r2.',
        "landing": "https://csrc.nist.gov/pubs/sp/800/52/r2/final",
    },
    "NIST.CSWP.29": {
        "url": "https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf",
        "kind": "pdf",
        "citation": 'National Institute of Standards and Technology, "The '
                    'NIST Cybersecurity Framework (CSF) 2.0," NIST CSWP 29, '
                    'Feb. 2024, doi: 10.6028/NIST.CSWP.29.',
        "landing": "https://www.nist.gov/cyberframework",
    },
    "CISA.playbooks": {
        "url": "https://www.cisa.gov/sites/default/files/publications/"
               "Federal_Government_Cybersecurity_Incident_and_Vulnerability_"
               "Response_Playbooks_508C.pdf",
        "kind": "pdf",
        # Corrected against the PDF's own title page, which reads
        # "Publication: November 2021". The August 2024 date on the CISA
        # landing page is when that PAGE was updated, not when the document
        # was published -- citing it would have been wrong by three years.
        "citation": 'Cybersecurity and Infrastructure Security Agency, '
                    '"Cybersecurity incident & vulnerability response '
                    'playbooks," CISA, Washington, DC, USA, Nov. 2021.',
        "landing": "https://www.cisa.gov/resources-tools/resources/federal-"
                   "government-cybersecurity-incident-and-vulnerability-"
                   "response-playbooks",
    },
    "RFC9424": {
        "url": "https://www.rfc-editor.org/rfc/rfc9424.txt",
        "kind": "text",
        "citation": 'K. Paine, O. Whitehouse, J. Sellwood and A. Shaw, '
                    '"Indicators of compromise (IoCs) and their role in '
                    'attack defence," RFC 9424, Aug. 2023, doi: '
                    '10.17487/RFC9424.',
        "landing": "https://www.rfc-editor.org/rfc/rfc9424.html",
    },
    "RFC1858": {
        "url": "https://www.rfc-editor.org/rfc/rfc1858.txt",
        "kind": "text",
        "citation": 'G. Ziemba, D. Reed and P. Traina, "Security '
                    'considerations for IP fragment filtering," RFC 1858, '
                    'Oct. 1995, doi: 10.17487/RFC1858.',
        "landing": "https://www.rfc-editor.org/rfc/rfc1858.html",
    },
    "RFC3128": {
        "url": "https://www.rfc-editor.org/rfc/rfc3128.txt",
        "kind": "text",
        "citation": 'I. Miller, "Protection against a variant of the tiny '
                    'fragment attack," RFC 3128, Jun. 2001, doi: '
                    '10.17487/RFC3128.',
        "landing": "https://www.rfc-editor.org/rfc/rfc3128.html",
    },
    "OWASP.Top10.2025": {
        "url": "https://owasp.org/Top10/2025/",
        "kind": "html",
        "citation": 'Open Worldwide Application Security Project, "OWASP '
                    'Top 10:2025 — web application security risks," OWASP '
                    'Foundation, 2025.',
        "landing": "https://owasp.org/Top10/2025/",
    },
}


# ============================================================
# CLASS -> WHICH SOURCES, AND WHAT TO LOOK FOR IN THEM
#
# The keywords locate CANDIDATE paragraphs. They do not decide which ones
# belong in the file -- a person does that, which is what REVIEW REQUIRED
# enforces.
# ============================================================

TARGETS = {
    "denial_of_service.md": {
        "classes": ["DoS", "DDoS", "Slowloris"],
        "title": "Denial of service — response",
        "sources": ["NIST.SP.800-61r3", "NIST.SP.800-53r5"],
        "keywords": ["denial of service", "rate limit", "SC-5",
                     "availability", "flooding", "containment"],
    },
    "reconnaissance.md": {
        "classes": ["PortScan"],
        "title": "Scanning and reconnaissance — response",
        "sources": ["NIST.SP.800-61r3", "NIST.SP.800-53r5", "RFC9424"],
        "keywords": ["scanning", "reconnaissance", "SI-4", "port scan",
                     "detection and analysis", "monitoring"],
    },
    "exploitation.md": {
        "classes": ["Exploitation", "BufferOverflow"],
        "title": "Exploitation of a service — response",
        "sources": ["CISA.playbooks", "NIST.SP.800-61r3"],
        "keywords": ["vulnerability response", "exploit", "patch",
                     "remediation", "eradication", "SI-2"],
    },
    "web_application.md": {
        "classes": ["API", "WebBased"],
        "title": "Web application attack — response",
        "sources": ["OWASP.Top10.2025", "CISA.playbooks"],
        "keywords": ["injection", "how to prevent", "validation",
                     "access control", "broken"],
    },
    "credential_attack.md": {
        "classes": ["Bruteforce"],
        "title": "Credential attack — response",
        "sources": ["NIST.SP.800-53r5", "OWASP.Top10.2025",
                    "NIST.SP.800-61r3"],
        "keywords": ["AC-7", "unsuccessful logon", "authentication failure",
                     "brute force", "lockout", "identification and "
                     "authentication"],
    },
    "data_exfiltration.md": {
        "classes": ["Exfiltration"],
        "title": "Data exfiltration — response",
        "sources": ["NIST.SP.800-61r3", "RFC9424", "NIST.SP.800-53r5"],
        "keywords": ["exfiltration", "data loss", "AC-4", "information flow",
                     "indicator", "containment"],
    },
    "command_and_control.md": {
        "classes": ["C2Beaconing"],
        "title": "Command and control — response",
        "sources": ["NIST.SP.800-61r3", "RFC9424", "NIST.SP.800-53r5"],
        "keywords": ["command and control", "beacon", "indicator of "
                     "compromise", "SI-4", "outbound", "containment"],
    },
    "dns_abuse.md": {
        "classes": ["DNS"],
        "title": "DNS abuse — response",
        "sources": ["NIST.SP.800-53r5", "RFC9424", "NIST.SP.800-61r3"],
        "keywords": ["SC-20", "SC-21", "domain name", "DNS", "resolver",
                     "name resolution"],
    },
    "mitm.md": {
        "classes": ["MITM"],
        "title": "Adversary in the middle — response",
        "sources": ["NIST.SP.800-53r5", "NIST.SP.800-52r2",
                    "NIST.SP.800-61r3"],
        "keywords": ["SC-8", "SC-23", "transmission confidentiality",
                     "session authenticity", "interception"],
    },
    # These two are written by hand: no published playbook treats them as a
    # single procedure. Listed so --status counts them, and skipped by
    # --extract so a generated draft never overwrites the reasoned version.
    "benign.md": {
        "classes": ["Benign"], "title": "Benign traffic — no action",
        "sources": ["NIST.SP.800-61r3", "RFC9424"],
        "keywords": [], "hand_written": True,
    },
    "evasion.md": {
        "classes": ["Evasion"], "title": "Detection evasion — response",
        "sources": ["RFC1858", "RFC3128", "NIST.SP.800-53r5"],
        "keywords": [], "hand_written": True,
    },
    "crypto_weakness.md": {
        "classes": ["TLSSSL"], "title": "TLS/SSL weakness — response",
        "sources": ["NIST.SP.800-52r2", "NIST.SP.800-53r5",
                    "CISA.playbooks"],
        "keywords": [], "hand_written": True,
    },
}


# ============================================================
# DOWNLOAD
# ============================================================

def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _load_manifest():
    if os.path.isfile(MANIFEST):
        with open(MANIFEST, encoding="utf-8") as fh:
            return json.load(fh)
    return {}


def download(force=False):
    import requests

    os.makedirs(SOURCE_DIR, exist_ok=True)
    manifest = _load_manifest()
    changed = []

    for key, meta in SOURCES.items():
        ext = {"pdf": ".pdf", "text": ".txt", "html": ".html"}[meta["kind"]]
        path = os.path.join(SOURCE_DIR, key + ext)

        if os.path.isfile(path) and not force:
            print(f"  have    {key}")
            continue

        try:
            r = requests.get(meta["url"], timeout=120,
                             headers={"User-Agent": "ForenXAI/1.0"})
            r.raise_for_status()
        except Exception as e:
            print(f"  FAILED  {key}: {type(e).__name__}: {e}")
            continue

        digest = _sha(r.content)
        was = manifest.get(key, {}).get("sha256")

        with open(path, "wb") as fh:
            fh.write(r.content)

        # A changed hash means the publisher revised the document. That is
        # the signal to re-read the extracted sections, so it is reported
        # rather than logged quietly.
        if was and was != digest:
            changed.append(key)

        manifest[key] = {
            "url": meta["url"],
            "landing": meta["landing"],
            "citation": meta["citation"],
            "file": os.path.basename(path),
            "bytes": len(r.content),
            "sha256": digest,
            "retrieved": datetime.now().isoformat(timespec="seconds"),
        }
        print(f"  got     {key:<22}{len(r.content)/1e6:>6.2f} MB  "
              f"{digest[:12]}")

    os.makedirs(SOURCE_DIR, exist_ok=True)
    with open(MANIFEST, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)

    if changed:
        print("\n  CHANGED SINCE LAST DOWNLOAD -- re-read the extracted "
              "sections for:")
        for c in changed:
            print(f"    {c}")
    return manifest


# ============================================================
# TEXT EXTRACTION
# ============================================================

def _text_of(key):
    meta = SOURCES[key]
    ext = {"pdf": ".pdf", "text": ".txt", "html": ".html"}[meta["kind"]]
    path = os.path.join(SOURCE_DIR, key + ext)

    if not os.path.isfile(path):
        return None

    if meta["kind"] == "pdf":
        import pypdf
        r = pypdf.PdfReader(path)
        return "\n\n".join(p.extract_text() or "" for p in r.pages)

    raw = open(path, encoding="utf-8", errors="replace").read()

    if meta["kind"] == "html":
        raw = re.sub(r"(?is)<(script|style|nav|header|footer).*?</\1>", " ", raw)
        raw = re.sub(r"(?s)<[^>]+>", " ", raw)
        raw = re.sub(r"&[a-z]+;", " ", raw)

    return re.sub(r"[ \t]+", " ", raw)


def _blocks(text, window=6):
    """
    Split into overlapping windows of consecutive lines.

    Splitting on blank lines is wrong for these documents: a NIST control
    catalogue separates paragraphs with a SINGLE newline, so a blank-line
    split merges hundreds of pages into a handful of blocks that then fail
    every length filter. Extracting 581 usable paragraphs from a 500-page
    catalogue was the symptom.

    A sliding window over lines keeps the text around a match, which is what
    a reviewer needs: a control identifier means nothing without the
    sentence that follows it.
    """
    # Every line is kept, including page numbers and running heads.
    # Dropping them produced blocks that joined text which is NOT adjacent
    # in the source, so the quoted passage could not be found in the
    # document it named -- verify_extracts() caught four of those. A quote
    # has to be contiguous to be checkable, and checkable matters more than
    # tidy.
    lines = [re.sub(r"\s+", " ", ln).strip()
             for ln in (text or "").splitlines()]

    for i in range(0, len(lines), window // 2):     # 50% overlap
        block = " ".join(lines[i:i + window]).strip()
        if 150 <= len(block) <= 2000:
            yield block


def _candidates(key, keywords, limit=6):
    """Blocks mentioning a keyword, most matches first, de-duplicated."""
    text = _text_of(key)
    if not text:
        return []

    scored, seen = [], set()
    for b in _blocks(text):
        low = b.lower()
        hits = sum(1 for k in keywords if k.lower() in low)
        if not hits:
            continue
        # Overlapping windows repeat text; keep the first of each.
        fingerprint = low[:80]
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        scored.append((hits, len(b), b))

    scored.sort(key=lambda t: (-t[0], t[1]))
    return [b for _, _, b in scored[:limit]]


def extract(force=False):
    """Write a REVIEW REQUIRED draft for every class that has no file yet."""
    manifest = _load_manifest()
    out_dir = os.path.join(KNOWLEDGE, "incident_response")
    os.makedirs(out_dir, exist_ok=True)

    for name, spec in TARGETS.items():
        path = os.path.join(out_dir, name)

        if spec.get("hand_written"):
            state = "present" if os.path.isfile(path) else "MISSING"
            print(f"  skip    {name:<26}hand-written ({state})")
            continue

        if os.path.isfile(path) and not force:
            print(f"  have    {name}")
            continue

        blocks, cited = [], []
        for key in spec["sources"]:
            found = _candidates(key, spec["keywords"])
            if not found:
                continue
            cited.append(key)
            blocks.append(f"\n## From {key}\n")
            blocks += [f"\n{p}\n" for p in found]

        if not blocks:
            print(f"  NO TEXT {name:<26}sources not downloaded?")
            continue

        header = [
            f"# {spec['title']}",
            "",
            f"> **{REVIEW_MARKER}.** These paragraphs were selected by "
            f"keyword, not by judgement. Read them, keep what actually "
            f"prescribes an action, delete the rest, then remove this "
            f"marker. `--verify` fails while it is present.",
            ">",
            f"> Covers: {', '.join(spec['classes'])}",
            ">",
        ]
        for key in cited:
            m = manifest.get(key, {})
            header.append(f"> Source: {SOURCES[key]['citation']}")
            if m.get("sha256"):
                header.append(f">   retrieved {m['retrieved'][:10]}, "
                              f"sha256 {m['sha256'][:16]}")
        header += [">", "> Keep this file under about 1,500 words: the "
                        "model's context is 8,192 tokens.", ""]

        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(header) + "\n" + "".join(blocks))

        words = len("".join(blocks).split())
        print(f"  draft   {name:<26}{len(cited)} source(s), ~{words} words")


# ============================================================
# CITATION AND EXTRACT VERIFICATION
#
# Two mechanical checks, both against the downloaded file rather than
# against a web page:
#
#   citations   the title and identifier this project claims must appear in
#               the document's own text. A landing page can say one thing
#               and the PDF another -- that is exactly how the CISA playbook
#               came to be cited as August 2024 when its title page reads
#               November 2021.
#
#   extracts    every passage quoted into a knowledge file must appear
#               verbatim in the source it names. This is what makes
#               "no hallucination" a checked property rather than a claim:
#               a sentence that is not in the document did not come from it.
# ============================================================

# Distinctive strings from each document's own front matter.
CITATION_CLAIMS = {
    "NIST.SP.800-61r3": ["Incident Response Recommendations", "800-61r3"],
    "NIST.SP.800-53r5": ["Security and Privacy Controls", "800-53"],
    "NIST.SP.800-52r2": ["Transport Layer Security", "800-52"],
    "NIST.CSWP.29": ["Cybersecurity Framework", "CSWP"],
    "CISA.playbooks": ["Vulnerability Response Playbooks",
                       "Publication: November 2021"],
    # RFCs write the number as "Request for Comments: N", never "RFC N".
    "RFC9424": ["Indicators of Compromise", "Request for Comments: 9424"],
    "RFC1858": ["Security Considerations for IP Fragment Filtering",
                "Request for Comments: 1858"],
    "RFC3128": ["Protection Against a Variant of the Tiny Fragment Attack",
                "Request for Comments: 3128"],
    "OWASP.Top10.2025": ["Top 10"],
}


def _norm(text):
    return re.sub(r"\s+", " ", (text or "")).strip().lower()


def verify_citations():
    """Every claimed title and identifier must be in the document itself."""
    problems = []
    print(f"{'source':<22}{'claims found':<16}state")
    for key, terms in CITATION_CLAIMS.items():
        text = _text_of(key)
        if text is None:
            print(f"  {key:<20}{'-':<16}not downloaded")
            problems.append(f"{key} not downloaded")
            continue
        low = _norm(text)
        missing = [t for t in terms if _norm(t) not in low]
        state = "ok" if not missing else f"MISSING {missing}"
        print(f"  {key:<20}{len(terms) - len(missing)}/{len(terms):<14}{state}")
        if missing:
            problems.append(f"{key}: {missing} not found in the document")
    return problems


def verify_extracts():
    """
    Every quoted passage must appear verbatim in the source it names.

    Only blocks under a `## From <source>` heading are checked -- prose a
    person wrote around them is theirs, not a quote, and is not held to
    this.
    """
    out_dir = os.path.join(KNOWLEDGE, "incident_response")
    problems = []
    cache = {}

    print(f"{'file':<28}{'quoted':<9}{'traced':<9}state")
    for name in TARGETS:
        path = os.path.join(out_dir, name)
        if not os.path.isfile(path):
            continue

        body = open(path, encoding="utf-8", errors="replace").read()
        # Split into (source key, text) pairs on the generated headings.
        parts = re.split(r"\n## From ([\w.\-]+)\n", body)
        if len(parts) < 3:
            print(f"  {name:<26}{'-':<9}{'-':<9}hand-written, not checked")
            continue

        quoted = traced = 0
        for key, chunk in zip(parts[1::2], parts[2::2]):
            if key not in cache:
                cache[key] = _norm(_text_of(key))
            source_text = cache[key] or ""
            for block in [b.strip() for b in chunk.split("\n\n")]:
                if len(block) < 100:
                    continue
                quoted += 1
                if _norm(block) in source_text:
                    traced += 1
                else:
                    problems.append(
                        f"{name}: a passage attributed to {key} is not in "
                        f"that document -- '{block[:60]}...'")

        state = "ok" if quoted == traced else f"{quoted - traced} UNTRACED"
        print(f"  {name:<26}{quoted:<9}{traced:<9}{state}")

    return problems


# ============================================================
# VERIFY
# ============================================================

def verify():
    """Check every knowledge file is real, sourced, reviewed and current."""
    manifest = _load_manifest()
    out_dir = os.path.join(KNOWLEDGE, "incident_response")
    problems, warnings = [], []

    print(f"{'file':<28}{'words':>7}  state")
    for name, spec in TARGETS.items():
        path = os.path.join(out_dir, name)

        if not os.path.isfile(path):
            print(f"  {name:<26}{'-':>7}  MISSING "
                  f"({', '.join(spec['classes'])} uncovered)")
            problems.append(f"{name} is missing")
            continue

        body = open(path, encoding="utf-8", errors="replace").read()
        words = len(body.split())
        notes = []

        if REVIEW_MARKER in body:
            notes.append("UNREVIEWED draft")
            problems.append(f"{name} still carries {REVIEW_MARKER}")

        if "> Source:" not in body and "Sources:" not in body:
            notes.append("no provenance header")
            problems.append(f"{name} has no source line")

        if words > 1500:
            notes.append(f"long ({words} words)")
            warnings.append(f"{name} may truncate in context")

        if words < 60:
            notes.append("very short")
            warnings.append(f"{name} is probably a stub")

        if "PLACEHOLDER" in body:
            notes.append("PLACEHOLDER text")
            problems.append(f"{name} is still a placeholder")

        print(f"  {name:<26}{words:>7}  "
              + ("; ".join(notes) if notes else "ok"))

    # Source freshness. This cannot know about a revision -- only that
    # nobody has looked recently.
    print(f"\n{'source':<24}{'retrieved':<14}age")
    cutoff = datetime.now() - timedelta(days=STALE_AFTER_DAYS)
    for key in SOURCES:
        m = manifest.get(key)
        if not m:
            print(f"  {key:<22}{'never':<14}not downloaded")
            warnings.append(f"{key} not downloaded")
            continue
        got = datetime.fromisoformat(m["retrieved"])
        age = (datetime.now() - got).days
        flag = "  STALE - re-download and compare hashes" if got < cutoff else ""
        print(f"  {key:<22}{m['retrieved'][:10]:<14}{age} d{flag}")
        if got < cutoff:
            warnings.append(f"{key} last checked {age} days ago")

    print()
    print("CITATIONS -- claimed title and identifier vs the document itself")
    problems += verify_citations()

    print()
    print("EXTRACTS -- every quoted passage vs its source")
    problems += verify_extracts()

    print()
    if problems:
        print(f"{len(problems)} problem(s):")
        for p in problems:
            print(f"  - {p}")
    if warnings:
        print(f"{len(warnings)} warning(s):")
        for w in warnings:
            print(f"  - {w}")
    if not problems and not warnings:
        print("All knowledge files are sourced, reviewed and current.")

    return len(problems)


# ============================================================
# STATUS
# ============================================================

def status():
    out_dir = os.path.join(KNOWLEDGE, "incident_response")
    covered, uncovered = [], []

    print(f"{'class':<16}{'document':<28}state")
    for name, spec in TARGETS.items():
        ok = os.path.isfile(os.path.join(out_dir, name))
        unreviewed = ok and REVIEW_MARKER in open(
            os.path.join(out_dir, name), encoding="utf-8",
            errors="replace").read()
        state = ("UNREVIEWED draft" if unreviewed
                 else "ready" if ok else "missing")
        for c in spec["classes"]:
            (covered if ok and not unreviewed else uncovered).append(c)
            print(f"  {c:<14}{name:<28}{state}")

    total = len(covered) + len(uncovered)
    print(f"\n{len(covered)} of {total} attack classes have a reviewed "
          f"document.")
    if uncovered:
        print("Uncovered: " + ", ".join(sorted(set(uncovered))))
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--download", action="store_true")
    ap.add_argument("--extract", action="store_true")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--force", action="store_true",
                    help="overwrite files that already exist")
    args = ap.parse_args()

    if not any((args.download, args.extract, args.verify, args.status,
                args.all)):
        return status()

    if args.download or args.all:
        print("DOWNLOAD")
        download(force=args.force)
        print()
    if args.extract or args.all:
        print("EXTRACT")
        extract(force=args.force)
        print()
    if args.verify or args.all:
        print("VERIFY")
        return verify()
    if args.status:
        return status()
    return 0


if __name__ == "__main__":
    sys.exit(main())
