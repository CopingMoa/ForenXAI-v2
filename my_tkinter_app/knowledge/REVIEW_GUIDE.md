# Reviewing a draft playbook

Nine files carry `REVIEW REQUIRED`. This is how to clear one, and what to do
when the draft turns out to be wrong.

About **10 minutes per file**, and `--verify` tells you when you are done.

---

## Before you start

The sources are already downloaded and hash-checked. You do **not** need to
find or fetch anything:

```
knowledge/_sources/          the nine documents, as PDFs and text
knowledge/_sources/manifest.json   URL, SHA-256 and retrieval date for each
```

Two checks have already run and passed, so you are not re-doing them:

| Already verified | What it proved |
|---|---|
| **Citations** | Every claimed title and identifier appears in the document's own text — not on a web page |
| **Extracts** | All 116 quoted passages appear **verbatim** in the source they name |

So the text in each draft is genuinely from the document it says. What is
**not** established is whether those particular paragraphs answer *"what do
I do about this class"* — that is the judgement only you can make.

---

## Reviewing one file

**1. Open the draft and its source side by side.**

```
knowledge/incident_response/reconnaissance.md
knowledge/_sources/NIST.SP.800-61r3.pdf
```

**2. Read each block under a `## From <source>` heading.** Keep it only if it
tells an investigator to *do* something, or to *check* something.

| Keep | Delete |
|---|---|
| "Record the source addresses and the ports contacted" | `SC-7(27) UNCLASSIFIED... SC-7(28) CONNECTIONS TO...` (a control index) |
| "Confirm the source is not an authorised scanner before blocking" | "This publication is available free of charge from..." |
| "Apply rate limiting at the perimeter" | Page headers, footers, tables of contents |

The index noise is easy to spot: it is a run of identifiers with no verb.

**3. Add structure.** Group what survives under headings. Use the two
hand-written files as the pattern:

```
## 1. What this class means here
## 2. Detection and analysis
## 3. Containment
## 4. What would make this a false positive
## 5. Not covered by these sources
```

Section 5 matters most. It is where you say what the sources do **not**
answer, which is the difference between an honest playbook and one that
implies more coverage than it has.

**4. Delete the `REVIEW REQUIRED` line.** The whole block, from
`> **REVIEW REQUIRED.**` to the end of that paragraph. Keep every
`> Source:` line — those become the citations the interface shows.

**5. Check.**

```bash
python fetch_knowledge.py --verify
```

The file should disappear from the problem list. If a passage you kept is
now reported as untraced, you edited inside a quote — restore it or move it
out from under the `## From` heading.

---

## If a draft is wrong or thin

**The extracted text does not answer the question.** The keywords found
the wrong part of the document. Open the source, find the right section
yourself, and paste it in with the same `## From <source>` heading — the
verifier will confirm it is really from that document.

**The document has nothing useful for this class.** Say so in the file
rather than padding it:

```markdown
## Not covered by these sources
NIST SP 800-61r3 treats this at the level of incident handling generally
and prescribes no step specific to this class. Fill from your own runbook.
```

A short honest file beats a long vague one. `evasion.md` is ~500 words.

**You want a source that is not in the set.** Add it to `SOURCES` in
`fetch_knowledge.py` with its URL and IEEE citation, add a `CITATION_CLAIMS`
entry naming two distinctive strings from its front matter, then
`--download`. The citation check will confirm the document is what you say
it is.

---

## What "done" looks like

```bash
python fetch_knowledge.py --verify
```

```
0 problem(s)
All knowledge files are sourced, reviewed and current.
```

and

```bash
python fetch_knowledge.py --status
```

```
16 of 16 attack classes have a reviewed document.
```

---

## Order

Review in the order a capture is likely to need them:

| # | File | Classes | Why first |
|---|---|---|---|
| 1 | `denial_of_service.md` | DoS, DDoS, Slowloris | Three classes at once, and your weakest two |
| 2 | `exploitation.md` | Exploitation, BufferOverflow | Two classes |
| 3 | `web_application.md` | API, WebBased | Two classes |
| 4 | `reconnaissance.md` | PortScan | Common, and usually a precursor |
| 5 | `credential_attack.md` | Bruteforce | Common |
| 6–9 | exfiltration, C2, DNS, MITM | One each | Finish the set |

The first three clear seven of sixteen classes in about half an hour.
