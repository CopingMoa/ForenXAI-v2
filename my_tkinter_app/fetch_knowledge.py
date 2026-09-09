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
    # PEER-REVIEWED, PUBLISHED ARTEFACTS ONLY.
    #
    # Two rules, both learned the hard way:
    #
    #   1. No preprints. arXiv and author-hosted copies are removed even
    #      when the underlying work IS peer-reviewed, because a citation
    #      should name the artefact that was actually checked, and quotes
    #      here are checked against the file on disk. Removed on this
    #      basis: Lundberg.shap (NeurIPS 2017), Lundberg.treeshap (Nature
    #      Machine Intelligence 2020) and SommerPaxson.closedworld (IEEE
    #      S&P 2010) -- every one a real paper, none of them the published
    #      PDF.
    #
    #      Chen.xgboost was removed on the same basis and has been
    #      RESTORED: the copy now in _sources carries the ACM block on
    #      page 1 ("Permission to make digital or hard copies...", KDD '16,
    #      ISBN 978-1-4503-4232-2, DOI 10.1145/2939672.2939785), so it is
    #      the published proceedings version and not an author copy.
    #
    #   3. Peer review is required of the LITERATURE. Arslan.mits, the
    #      Acadlore journal paper, was removed for failing that test; it
    #      had been the only citation behind eight quote blocks in
    #      knowledge/interpretability, and every one of them has been
    #      re-sourced or withdrawn rather than left standing.
    #
    #   2. Standards bodies count. NIST, CISA, IETF and OWASP publish
    #      through their own review processes and their PDFs ARE the
    #      authoritative artefact, so they stay.
    #
    # Before adding a source, open the PDF and look for publisher front
    # matter -- proceedings statement, ISBN, DOI on the page itself. The
    # USENIX paper has it; the Sommer and Paxson copy did not.
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
    # The 2025 index page. Kept for the citation, but note it is an INDEX:
    # its text layer is a list of category names with no prose, which is why
    # every draft that quoted it produced a list of headings and nothing
    # actionable. Quote the per-category pages below instead.
    "OWASP.Top10.2025": {
        "url": "https://owasp.org/Top10/2025/",
        "kind": "html",
        "citation": 'Open Worldwide Application Security Project, "OWASP '
                    'Top 10:2025 — web application security risks," OWASP '
                    'Foundation, 2025.',
        "landing": "https://owasp.org/Top10/2025/",
    },
    "OWASP.A01.2025": {
        "url": "https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/",
        "kind": "html",
        "citation": 'Open Worldwide Application Security Project, '
                    '"A01:2025 — Broken access control," in OWASP Top '
                    '10:2025, OWASP Foundation, 2025.',
        "landing": "https://owasp.org/Top10/2025/"
                   "A01_2025-Broken_Access_Control/",
    },
    "OWASP.A05.2025": {
        "url": "https://owasp.org/Top10/2025/A05_2025-Injection/",
        "kind": "html",
        "citation": 'Open Worldwide Application Security Project, '
                    '"A05:2025 — Injection," in OWASP Top 10:2025, OWASP '
                    'Foundation, 2025.',
        "landing": "https://owasp.org/Top10/2025/A05_2025-Injection/",
    },
    "OWASP.A07.2025": {
        "url": "https://owasp.org/Top10/2025/"
               "A07_2025-Authentication_Failures/",
        "kind": "html",
        "citation": 'Open Worldwide Application Security Project, '
                    '"A07:2025 — Authentication failures," in OWASP Top '
                    '10:2025, OWASP Foundation, 2025.',
        "landing": "https://owasp.org/Top10/2025/"
                   "A07_2025-Authentication_Failures/",
    },

    # --------------------------------------------------------------
    # MACHINE LEARNING AND INTERPRETABILITY
    # --------------------------------------------------------------
    #
    # Everything above answers "what is this attack and what do I do about
    # it". None of it says how to read a MODEL OUTPUT -- what a 0.55
    # confidence means, whether a SHAP value is a cause, why a class
    # scoring F1 0.67 needs different handling from one scoring 0.99, or
    # why accuracy measured on a held-out split does not carry to a
    # different network.
    #
    # All of those are on screen in the three panels, and until now the
    # answers were prose written directly in panels_service.py with no
    # source behind them. These are the sources for them.
    #
    # Citations are taken from each document's own title page, never from a
    # publisher's landing page -- the rule that caught the CISA date being
    # three years wrong.

    # Forensic procedure. The only source here that speaks to evidence
    # handling and order of volatility, which is what analyst/ needs.
    "NIST.SP.800-86": {
        "url": "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/"
               "nistspecialpublication800-86.pdf",
        "kind": "pdf",
        "citation": 'K. Kent, S. Chevalier, T. Grance and H. Dang, "Guide '
                    'to integrating forensic techniques into incident '
                    'response," NIST SP 800-86, Aug. 2006, doi: '
                    '10.6028/NIST.SP.800-86.',
        "landing": "https://csrc.nist.gov/pubs/sp/800/86/final",
    },


    # Peer-reviewed replacement for the two Lundberg preprints.
    #
    # The Lundberg work is not disputed -- "A unified approach" is NeurIPS
    # 2017 and the TreeSHAP paper appeared in Nature Machine Intelligence
    # 2020, both peer-reviewed. What was on disk was the arXiv PREPRINT of
    # each, which is not the reviewed artefact, and a citation should name
    # the thing that was actually checked. Rather than cite a version we do
    # not hold, the SHAP claims are now carried by a reviewed paper that
    # states them and that is about intrusion detection, which is this
    # tool's domain.

    "NIST.AI.100-1": {
        "url": "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf",
        "kind": "pdf",
        "citation": 'National Institute of Standards and Technology, '
                    '"Artificial Intelligence Risk Management Framework '
                    '(AI RMF 1.0)," NIST AI 100-1, Jan. 2023, doi: '
                    '10.6028/NIST.AI.100-1.',
        "landing": "https://www.nist.gov/itl/ai-risk-management-framework",
    },

    "Chen.xgboost": {
        "url": "https://dl.acm.org/doi/pdf/10.1145/2939672.2939785",
        "kind": "pdf",
        "citation": 'T. Chen and C. Guestrin, "XGBoost: A scalable tree '
                    'boosting system," in Proc. 22nd ACM SIGKDD Int. Conf. '
                    'Knowledge Discovery and Data Mining, San Francisco, CA, '
                    'USA, Aug. 2016, pp. 785-794, doi: '
                    '10.1145/2939672.2939785.',
        "landing": "https://dl.acm.org/doi/10.1145/2939672.2939785",
    },
    "Iyengar.aip": {
        "url": "https://link.springer.com/book/10.1007/978-3-031-89327-8",
        "kind": "pdf",
        "citation": 'S. S. Iyengar, S. Nabavirazavi, Y. Hariprasad, '
                    'Prasad HB and C. Krishna Mohan, Artificial Intelligence '
                    'in Practice: Theory and Application for Cyber Security '
                    'and Forensics. Cham, Switzerland: Springer Nature, 2025, '
                    'doi: 10.1007/978-3-031-89327-8.',
        "landing": "https://link.springer.com/book/10.1007/978-3-031-89327-8",
    },
    # The Communications of the ACM Research Highlights version, not the
    # USENIX Security proceedings paper. Same authors and the same ten
    # pitfalls, condensed to nine pages -- so it is a DIFFERENT artefact,
    # and quotes must trace to this one. Three passages the project used to
    # quote do not exist here; the claims they carried were withdrawn
    # rather than re-attributed.
    "Arp.cacm": {
        "url": "https://dl.acm.org/doi/pdf/10.1145/3643456",
        "kind": "pdf",
        "citation": 'D. Arp, E. Quiring, F. Pendlebury, A. Warnecke, '
                    'F. Pierazzi, C. Wressnegger, L. Cavallaro and K. Rieck, '
                    '"Pitfalls in machine learning for computer security," '
                    'Commun. ACM, vol. 67, no. 11, pp. 104-112, Nov. 2024, '
                    'doi: 10.1145/3643456.',
        "landing": "https://dl.acm.org/doi/10.1145/3643456",
    },



}


# ============================================================
# CLASS -> WHICH SOURCES, AND WHAT TO LOOK FOR IN THEM
#
# The keywords locate CANDIDATE paragraphs. They do not decide which ones
# belong in the file -- a person does that, which is what REVIEW REQUIRED
# enforces.
# ============================================================

# One file per class, named after the class. A document that covers three
# classes cannot say anything specific to any of them, and the interface
# quotes the whole file -- so a DoS finding was showing Slowloris guidance
# and vice versa. Sixteen classes, sixteen files.
#
# Where two classes genuinely share a response, the files say so and repeat
# the shared steps. Duplication in a playbook is cheaper than a reader
# working out which half applies to them.

TARGETS = {
    "benign.md": {
        "classes": ["Benign"], "title": "Benign traffic — no action",
        "sources": ["NIST.SP.800-61r3", "RFC9424"],
        "keywords": [], "hand_written": True,
    },
    "dos.md": {
        "classes": ["DoS"],
        "title": "Denial of service (single source) — response",
        "sources": ["NIST.SP.800-61r3", "NIST.SP.800-53r5"],
        "keywords": ["denial of service", "SC-5", "resource exhaustion",
                     "availability", "containment"],
    },
    "ddos.md": {
        "classes": ["DDoS"],
        "title": "Distributed denial of service — response",
        "sources": ["NIST.SP.800-61r3", "NIST.SP.800-53r5"],
        "keywords": ["denial of service", "SC-5", "bandwidth", "flooding",
                     "upstream", "capacity"],
    },
    "slowloris.md": {
        "classes": ["Slowloris"],
        "title": "Slow-rate connection exhaustion — response",
        "sources": ["NIST.SP.800-61r3", "NIST.SP.800-53r5"],
        "keywords": ["denial of service", "SC-5", "connection", "timeout",
                     "session", "resource exhaustion"],
    },
    "portscan.md": {
        "classes": ["PortScan"],
        "title": "Port scanning and reconnaissance — response",
        "sources": ["NIST.SP.800-61r3", "NIST.SP.800-53r5", "RFC9424"],
        "keywords": ["scanning", "reconnaissance", "SI-4", "port",
                     "detection and analysis", "monitoring"],
    },
    "exploitation.md": {
        "classes": ["Exploitation"],
        "title": "Exploitation of a public-facing service — response",
        "sources": ["CISA.playbooks", "NIST.SP.800-61r3"],
        "keywords": ["vulnerability response", "exploit", "patch",
                     "remediation", "public-facing", "SI-2"],
    },
    "bufferoverflow.md": {
        "classes": ["BufferOverflow"],
        "title": "Memory-corruption exploitation — response",
        "sources": ["CISA.playbooks", "NIST.SP.800-61r3",
                    "NIST.SP.800-53r5"],
        "keywords": ["vulnerability response", "patch", "memory",
                     "eradication", "SI-2", "SI-16"],
    },
    "api.md": {
        "classes": ["API"],
        "title": "API abuse — response",
        "sources": ["OWASP.Top10.2025", "CISA.playbooks"],
        "keywords": ["injection", "how to prevent", "validation",
                     "access control", "authorization"],
    },
    "webbased.md": {
        "classes": ["WebBased"],
        "title": "Web application attack — response",
        "sources": ["OWASP.Top10.2025", "CISA.playbooks"],
        "keywords": ["injection", "how to prevent", "cross-site",
                     "validation", "broken"],
    },
    "bruteforce.md": {
        "classes": ["Bruteforce"],
        "title": "Credential brute force — response",
        "sources": ["NIST.SP.800-53r5", "OWASP.Top10.2025",
                    "NIST.SP.800-61r3"],
        "keywords": ["AC-7", "unsuccessful logon", "authentication failure",
                     "lockout", "credential", "identification and "
                     "authentication"],
    },
    "exfiltration.md": {
        "classes": ["Exfiltration"],
        "title": "Data exfiltration — response",
        "sources": ["NIST.SP.800-61r3", "RFC9424", "NIST.SP.800-53r5"],
        "keywords": ["exfiltration", "data loss", "AC-4", "information flow",
                     "indicator", "containment"],
    },
    "c2beaconing.md": {
        "classes": ["C2Beaconing"],
        "title": "Command and control beaconing — response",
        "sources": ["NIST.SP.800-61r3", "RFC9424", "NIST.SP.800-53r5"],
        "keywords": ["command and control", "beacon", "indicator of "
                     "compromise", "SI-4", "outbound", "containment"],
    },
    "dns.md": {
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
    # Hand-written: no published playbook treats either as one procedure.
    "evasion.md": {
        "classes": ["Evasion"], "title": "Detection evasion — response",
        "sources": ["RFC1858", "RFC3128", "NIST.SP.800-53r5"],
        "keywords": [], "hand_written": True,
    },
    "tlsssl.md": {
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

        # A source supplied by hand rather than fetched still needs a
        # manifest entry, or --verify reports it as never downloaded and
        # nothing records the hash of what is actually on disk.
        if meta.get("local_only"):
            if not os.path.isfile(path):
                print(f"  MISSING {key}: expected at {path}")
                continue
            data = open(path, "rb").read()
            digest = _sha(data)
            if manifest.get(key, {}).get("sha256") != digest:
                manifest[key] = {
                    "url": meta["url"],
                    "landing": meta["landing"],
                    "citation": meta["citation"],
                    "file": os.path.basename(path),
                    "bytes": len(data),
                    "sha256": digest,
                    "retrieved": datetime.now().isoformat(
                        timespec="seconds"),
                    "supplied_locally": True,
                }
                print(f"  local   {key:<22}{len(data)/1e6:>6.2f} MB  "
                      f"{digest[:12]}")
            else:
                print(f"  have    {key}  (supplied locally)")
            continue

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
    "OWASP.A01.2025": ["Broken Access Control", "How to prevent"],
    "OWASP.A05.2025": ["Injection", "How to prevent"],
    "OWASP.A07.2025": ["Authentication Failures", "How to prevent"],

    # Machine learning sources. Claims deliberately avoid characters the
    # PDF text layer renders as ligatures or curly quotes -- "Unified"
    # comes out as "Uni<fi>ed" and "Don'ts" as "Don<rsquo>ts", so a claim
    # containing either would fail against a document that is in fact
    # correct. _norm() collapses whitespace but does not fold those.
    "NIST.SP.800-86": ["Guide to Integrating Forensic",
                       "800-86"],
    "NIST.AI.100-1": ["Artificial Intelligence Risk Management",
                      "NIST AI 100-1"],
    "Arp.cacm": ["Pitfalls in Machine Learning for Computer Security",
                 "10.1145/3643456"],

    # The ACM block on page 1 is what makes this the published artefact
    # rather than the author copy, so the ISBN is the claim to check.
    "Chen.xgboost": ["XGBoost: A Scalable Tree Boosting System",
                     "978-1-4503-4232-2"],
    "Iyengar.aip": ["Artificial Intelligence in Practice",
                    "978-3-031-89327-8"],
}


# Characters a PDF text layer emits that a person retyping the same
# sentence would not. Folding them lets a quote be written readably and
# still be checked against the document -- without this, quoting "traffic"
# from a paper whose text layer holds "traf<ffi>c" fails verification even
# though the quote is correct.
_TEXT_FOLD = {
    "ﬀ": "ff", "ﬁ": "fi", "ﬂ": "fl",
    "ﬃ": "ffi", "ﬄ": "ffl", "ﬅ": "st", "ﬆ": "st",
    "‘": "'", "’": "'", "‛": "'",
    "“": '"', "”": '"',
    "‐": "-", "‑": "-", "‒": "-", "–": "-",
    "—": "-", "−": "-",
    " ": " ", " ": " ", " ": " ", " ": " ",
    "​": "", "­": "",
}


def _norm(text):
    """
    Fold a passage to the form both sides of a quote check are compared in.

    Ligatures, curly quotes and the various dashes are folded because they
    are artefacts of how the PDF stores glyphs, not of what the document
    says. Whitespace collapses so a quote spanning a line break still
    matches. Case is dropped last.

    What is deliberately NOT folded: letters, digits, and word order. A
    passage that fails this check after folding really is not in the
    document, which is the whole point of running it.
    """
    text = text or ""

    for bad, good in _TEXT_FOLD.items():
        if bad in text:
            text = text.replace(bad, good)

    # Hyphenation across a line break is deliberately NOT repaired.
    #
    # Joining "detec-\ntion" back into "detection" is tempting and breaks
    # things: passages already quoted in the playbooks were extracted with
    # the newline collapsed to a space, so they read "cti- documentation".
    # Repairing the source to "ctidocumentation" then fails to match five
    # quotes that were correct all along. Collapsing whitespace and nothing
    # else keeps both sides in the same shape.
    #
    # The practical consequence for an author: choose a span that is not
    # broken across a line, or reproduce the break as the extraction shows
    # it. `python fetch_knowledge.py --verify` will say which.
    return re.sub(r"\s+", " ", text).strip().lower()


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


def _quoted_blocks(chunk):
    """
    The passages inside a `## From <source>` section that are claimed quotes.

    Two conventions, and the section says which it is using:

      * If it contains markdown blockquote lines, ONLY those are quotes.
        Everything else is the author's own commentary. This lets a
        hand-written document put a quote and the reason it matters in the
        same section without the commentary being reported as an
        untraceable quote.

      * Otherwise every paragraph is a quote. This is what the generated
        playbooks do, and they must keep verifying unchanged.

    The blockquote form is preferred for anything written by hand: it is
    visible in the rendered document, so a reader can see which words are
    the source's and which are ours.
    """
    lines = chunk.split("\n")

    if any(line.lstrip().startswith(">") for line in lines):
        blocks, current = [], []
        for line in lines:
            stripped = line.lstrip()
            if stripped.startswith(">"):
                current.append(stripped[1:].strip())
            elif current:
                blocks.append(" ".join(current).strip())
                current = []
        if current:
            blocks.append(" ".join(current).strip())
        return [b for b in blocks if b]

    return [b.strip() for b in chunk.split("\n\n") if b.strip()]


def _checkable_files():
    """
    Every knowledge file whose quotes are checked, as (label, full path).

    Covers the model-guidance documents as well as the per-class playbooks.
    Those documents make claims about confidence, reliability and SHAP that
    drive what the interface recommends, so they are held to exactly the
    same standard: a quote is either in the document it names or it is a
    problem.
    """
    files = []

    out_dir = os.path.join(KNOWLEDGE, "incident_response")
    for name in TARGETS:
        files.append((name, os.path.join(out_dir, name)))

    for folder in ("interpretability", "datasets", "analyst"):
        directory = os.path.join(KNOWLEDGE, folder)
        if not os.path.isdir(directory):
            continue
        for name in sorted(os.listdir(directory)):
            if name.endswith(".md"):
                files.append((f"{folder}/{name}",
                              os.path.join(directory, name)))

    return files


def verify_extracts():
    """
    Every quoted passage must appear verbatim in the source it names.

    Only blocks under a `## From <source>` heading are checked -- prose a
    person wrote around them is theirs, not a quote, and is not held to
    this.
    """
    problems = []
    cache = {}

    print(f"{'file':<28}{'quoted':<9}{'traced':<9}state")
    for name, path in _checkable_files():
        if not os.path.isfile(path):
            continue

        body = open(path, encoding="utf-8", errors="replace").read()
        # Split into (source key, text) pairs on the generated headings.
        # A quote section ends at the NEXT HEADING OF ANY LEVEL, not at the
        # next "## From". Splitting only on "## From" swallows whatever the
        # author wrote after the quote and then reports their own prose as
        # an untraceable quote -- which makes the check noisy enough to
        # ignore, and a check people ignore is worse than none.
        sections = re.split(r"\n(?=#{1,6} )", body)

        quote_sections = [
            s for s in sections
            if re.match(r"#{1,6} From ([\w.\-]+)\s*$", s.split("\n", 1)[0])
        ]

        if not quote_sections:
            print(f"  {name:<26}{'-':<9}{'-':<9}hand-written, not checked")
            continue

        quoted = traced = 0
        for section in quote_sections:
            heading, _, chunk = section.partition("\n")
            key = re.match(r"#{1,6} From ([\w.\-]+)\s*$", heading).group(1)

            if key not in cache:
                cache[key] = _norm(_text_of(key))
            source_text = cache[key] or ""

            if not source_text:
                problems.append(
                    f"{name}: quotes {key}, which is not downloaded")
                continue

            for block in _quoted_blocks(chunk):
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
