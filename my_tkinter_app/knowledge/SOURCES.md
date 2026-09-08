# Sources for the recommendations panel

Credible, current, publicly available guidance the panel can quote. Every
entry below was checked against the publisher's own page rather than recalled
— the title, authors, date and identifier are as the publisher states them.

**How to use this file.** Download what applies to your environment into
`knowledge/incident_response/` or `knowledge/detection/`, split it by section,
and point `config/knowledge_map.py` at the section — not the whole document.
An 80-page publication in one file dilutes the answer and, at 8,192 tokens of
context, triggers truncation.

**Licensing.** US Government works (NIST, CISA) are public domain. IETF RFCs are freely redistributable under the IETF Trust
provisions. ENISA reports permit reuse with attribution. OWASP is
CC BY-SA 4.0. Check each before
redistributing with the application.

---

## Tier 1 — incident response procedure

These say what to *do*. This is what panel 3 should quote.

**[1]** A. Nelson, S. Rekhi, M. Souppaya, and K. Scarfone, "Incident response
recommendations and considerations for cybersecurity risk management: A
CSF 2.0 community profile," National Institute of Standards and Technology,
Gaithersburg, MD, USA, NIST SP 800-61r3, Apr. 2025, doi:
10.6028/NIST.SP.800-61r3.

> The current revision, and the one to start with. Replaces the
> preparation / detection / containment / eradication / recovery structure of
> Rev. 2 with a CSF 2.0 profile. Public domain.

**[2]** Cybersecurity and Infrastructure Security Agency, "Federal government
cybersecurity incident and vulnerability response playbooks," CISA,
Washington, DC, USA, Aug. 2024. [Online]. Available:
https://www.cisa.gov/resources-tools/resources/federal-government-cybersecurity-incident-and-vulnerability-response-playbooks

> Two operational playbooks with decision points and hand-offs. More
> prescriptive than NIST — closer to the ordered steps panel 3 wants.
> Public domain.

**[3]** National Institute of Standards and Technology, "The NIST
Cybersecurity Framework (CSF) 2.0," National Institute of Standards and
Technology, Gaithersburg, MD, USA, NIST CSWP 29, Feb. 2024, doi:
10.6028/NIST.CSWP.29.

> The Respond and Recover functions give the organisational framing that
> SP 800-61r3 profiles against, so the two are designed to be read
> together. Final, current, and the vocabulary a reader is most likely to
> already know. Public domain.

---

## Tier 2 — attack context and classification

These say what the attack *is*, and give shared vocabulary.

**[4]** *Withdrawn.* MITRE ATT&CK was mapped per class and has been
removed.

> ATT&CK describes adversary behaviour observed at the HOST -- process
> creation, credential access, file writes. This tool sees CICFlowMeter flow
> records, which carry none of it, so a technique ID here read as
> corroboration the evidence could not support. Coverage was also uneven in
> a way that was not random: three classes had no honest mapping, and three
> others all collapsed onto T1190. ATT&CK for ICS is a separate matrix and
> describes neither the enterprise nor the IoT behaviour TRUSTLab captures.
>
> Map ATT&CK where the evidence lives -- endpoint telemetry -- not from flow
> records.

**[5]** K. Paine, O. Whitehouse, J. Sellwood, and A. Shaw, "Indicators of
compromise (IoCs) and their role in attack defence," RFC 9424, Aug. 2023,
doi: 10.17487/RFC9424.

> Directly relevant to a flow-based detector: it sets out what an indicator
> can and cannot establish, and introduces the Pyramid of Pain. Useful for
> the "what would make this a false positive" section, and for stating
> honestly what flow-level evidence proves.

**[6]** European Union Agency for Cybersecurity, "ENISA threat landscape
2025," ENISA, Athens, Greece, v1.2, Oct. 2025, rev. Jan. 2026. [Online].
Available: https://www.enisa.europa.eu/publications/enisa-threat-landscape-2025

> 4,875 incidents analysed over July 2024 – June 2025. Use for prevalence
> and trend context — "how common is this class of attack" — not for
> response steps.

---

## Tier 3 — severity, and application-layer classes

**[7]** Forum of Incident Response and Security Teams, "Common Vulnerability
Scoring System version 4.0: Specification document," FIRST.Org, Cary, NC,
USA, Nov. 2023. [Online]. Available: https://www.first.org/cvss/v4-0/

> Only needed if the interface ever assigns a severity. It currently does
> not, deliberately: the panel reports what the documentation prescribes
> and does not invent a rating. If you add one, use CVSS rather than an
> ad-hoc scale, and say which version.

**[8]** Open Worldwide Application Security Project, "OWASP top 10:2025 —
web application security risks," OWASP Foundation, Wakefield, MA, USA, 2025.
[Online]. Available: https://owasp.org/Top10/2025/

> The right reference for the API, WebBased and Exploitation classes.
> CC BY-SA 4.0.

---

## Tier 4 — prescriptive controls

**[9]** Joint Task Force, "Security and privacy controls for information
systems and organizations," National Institute of Standards and Technology,
Gaithersburg, MD, USA, NIST SP 800-53r5, Sep. 2020, rel. 5.2.0, Aug. 2025,
doi: 10.6028/NIST.SP.800-53r5.

> Individual controls a recommendation can name: SI-4 System Monitoring,
> SC-7 Boundary Protection, SC-5 Denial-of-Service Protection, AC-7
> Unsuccessful Logon Attempts. More specific than a framework and more
> quotable than a playbook — a control identifier is exactly the kind of
> citation an investigator can act on and an auditor can check. Final and
> maintained: release 5.2.0, August 2025. Public domain.

---

## Where each maps

| Class | Suggested source | Section to extract |
|---|---|---|
| DoS · DDoS · Slowloris | [1], [2] | containment, rate limiting, service protection |
| PortScan | [1], [5] | detection and analysis; what a scan indicates |
| Bruteforce | [1], [8] | credential attack response; A07 |
| API · WebBased | [8], [2] | the matching Top 10 risk |
| Exploitation · BufferOverflow | [1], [2] | vulnerability response playbook |
| C2Beaconing · Exfiltration | [1], [5] | containment; indicator handling |
| MITM | [1], [3] | network compromise response |
| DNS | [1], [5] | protocol abuse |
| Evasion · TLSSSL | — | no clean public playbook; write your own |

---

## What is deliberately absent

**Vendor documentation.** Product guides are accurate about their own
product and not portable. If your environment has one, put it in
`knowledge/` yourself — it will be more useful than anything above, because
it names your escalation path.

**Academic surveys.** They describe the field rather than prescribe an
action, so a panel quoting one produces prose an investigator cannot act on.
The exception is [5], which is procedural.

**Anything paywalled.** A source the reader cannot open is a source they
cannot check.

---

## Two things worth saying in the write-up

The most valuable file in `knowledge/` will not be on this list. It is your
own organisation's runbook: generic advice is what a model already
approximates, whereas your escalation contacts, approved blocking windows and
change process are what an investigator actually needs and cannot get
anywhere else.

And every source here describes response to a *confirmed* incident. None of
them addresses acting on a machine-learning classification whose reliability
varies by class — that gap is why the panel states the per-class F1 and the
Slowloris/DoS ambiguity beside the guidance, rather than presenting the
classification as settled fact.

---

# Machine learning and interpretability sources

Added so the panel can answer questions about the **model's output** —
confidence, per-class reliability, class ambiguity, SHAP attributions,
extraction validity — on the same footing as questions about the attack.
Before this, those answers were prose written in `panels_service.py` with no
source behind them, while every attack claim on the same screen carried an
IEEE citation.

All five are freely downloadable and are fetched by
`python fetch_knowledge.py --download`. Each citation below was taken from
the document's **own title page**, not from a publisher's landing page.

| # | Source | Used for | Verify by |
|---|---|---|---|
| 1 | D. Arp et al., "Dos and don'ts of machine learning in computer security," in Proc. 31st USENIX Security Symp., Boston, MA, USA, Aug. 2022, pp. 3971-3988. | Base rate fallacy (P8), inappropriate performance measures (P7), spurious correlations (P4), sampling bias | Open access at usenix.org/conference/usenixsecurity22/presentation/arp. Check §3 pitfall descriptions |
| 2 | R. Sommer and V. Paxson, "Outside the closed world: On using machine learning for network intrusion detection," in Proc. IEEE Symp. Security and Privacy, Oakland, CA, USA, May 2010, pp. 305-316, doi: 10.1109/SP.2010.25. | High cost of errors, semantic gap, variability of benign traffic | PDF at icir.org/robin/papers/oakland10-ml.pdf; record at ieeexplore.ieee.org/document/5504793 |
| 5 | National Institute of Standards and Technology, "Artificial Intelligence Risk Management Framework (AI RMF 1.0)," NIST AI 100-1, Jan. 2023, doi: 10.6028/NIST.AI.100-1. | Explainability vs interpretability | nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf, §3.5 |


## Which document answers which question

| Document | Retrieved when |
|---|---|
| `interpretability/shap_reading.md` | Always — every finding has attributions |
| `interpretability/caveats.md` | Always — the limits to quote alongside them |
| `datasets/scope.md` | Always — where the model has been shown to work |
| `interpretability/reliability.md` | The class has a weak measured F1 |
| `interpretability/confidence.md` | Flows below 0.60 confidence, **or** a small attack share of a large capture |
| `interpretability/class_ambiguity.md` | The runner-up class dominates the finding |
| `datasets/extraction_validity.md` | The fallback extractor ran, or the flow-timeout warning fired |
| `interpretability/glossary.md` | Reference — every ML term the panels display |

The conditions live in `MODEL_GUIDANCE` in `services/panels_service.py`.

## Reviewing these five

Same procedure as the incident-response playbooks, with one difference:
every quoted passage in these documents is inside a markdown blockquote
(`>`) under a `## From <source>` heading, so the source's words and the
author's are visually distinct. `python fetch_knowledge.py --verify` checks
only the blockquoted lines against the document, and reports 0 problems for
all five today.

What `--verify` does **not** check is whether the numeric claims about this
project's own model are right — 0.9337 accuracy, 0.9287 macro F1, DoS F1
0.6703, Slowloris F1 0.7593, 0.9044 importance correlation, 1.8e-05
additivity error. Those come from the pipeline's own artifacts, and each
document says so explicitly rather than implying the cited works support
them.

---

# Added for the class playbooks and the model description

| # | Source | Used for | Verify by |
|---|---|---|---|
| 9 | K. Kent, S. Chevalier, T. Grance and H. Dang, "Guide to integrating forensic techniques into incident response," NIST SP 800-86, Aug. 2006, doi: 10.6028/NIST.SP.800-86. | Data acquisition procedure, quoted in the classes where containment destroys evidence — Exploitation, BufferOverflow, Exfiltration | nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-86.pdf, §4 |
| 10 | T. Chen and C. Guestrin, "XGBoost: A scalable tree boosting system," in Proc. 22nd ACM SIGKDD Int. Conf. Knowledge Discovery and Data Mining, San Francisco, CA, USA, Aug. 2016, pp. 785-794, doi: 10.1145/2939672.2939785. | The model itself, so "gradient-boosted trees" is not left unsourced | arXiv:1603.02754 |
| 11 | OWASP, "A01:2025 — Broken access control," in OWASP Top 10:2025. | API, WebBased — access control and rate limiting | owasp.org/Top10/2025/A01_2025-Broken_Access_Control/ |
| 12 | OWASP, "A05:2025 — Injection," in OWASP Top 10:2025. | WebBased, Exploitation — parameterised queries | owasp.org/Top10/2025/A05_2025-Injection/ |
| 13 | OWASP, "A07:2025 — Authentication failures," in OWASP Top 10:2025. | Bruteforce — failed-login handling, MFA | owasp.org/Top10/2025/A07_2025-Authentication_Failures/ |

**Why the per-category OWASP pages and not the index.** `OWASP.Top10.2025`
points at the 2025 index. Its text layer is a list of category names with no
prose, so every draft that quoted it produced headings and nothing
actionable. The per-category pages carry the real "How to prevent" guidance.

**Files in `_sources/` that are NOT registered cannot be quoted.** Several
PDFs sit there unregistered — the RMF FAQ set, FIPS 200, SP 800-18r2, the
Privacy Framework, and a Springer volume. Nothing cites them, and nothing
may until they are added to `SOURCES` in `fetch_knowledge.py` with a
citation checked against their own title page. An unregistered file is a
file `--verify` cannot check.


---

# Withdrawn: the two SHAP preprints

`Lundberg.shap` and `Lundberg.treeshap` were removed and their PDFs
deleted. `Arslan.mits` replaces them.

**The underlying work is not in question.** "A unified approach to
interpreting model predictions" is NeurIPS 2017 and the TreeSHAP paper
appeared in Nature Machine Intelligence in 2020 — both peer-reviewed, both
the canonical references for SHAP. What sat in `_sources/` was the **arXiv
preprint** of each, which is not the reviewed artefact. A citation should
name the thing that was actually checked, and this project checks quotes
against the file on disk.

Rather than cite a version we do not hold, the SHAP claims are now carried
by a reviewed paper that states them and that is about intrusion detection:

**[14]** R. Arslan, T. Ozseven, M. M. Aydin and Y. Celik, "Cybersecurity in
intelligent transportation systems: A comparative study on AI-based anomaly
detection and threat analysis," *Mechatronics and Intelligent Transportation
Systems*, vol. 5, no. 1, pp. 11-30, 2026, doi: 10.56578/mits050102.

> Received 15 Dec 2025, revised 16 Feb 2026, accepted 27 Feb 2026. CC BY 4.0.
> Supplied locally rather than fetched, so its manifest entry is marked
> `supplied_locally` and records the SHA-256 of the file on disk.
>
> Used in `interpretability/shap_reading.md`, `glossary.md` and
> `caveats.md` for what SHAP and TreeSHAP compute, and for the polynomial
> -time property that makes explaining thousands of flows practical.

**What this costs.** Arslan et al. describe and apply SHAP; they do not
derive it. For the derivation, the NeurIPS and Nature Machine Intelligence
papers remain the references to read — they are simply no longer quoted
here, because the reviewed versions are not the files this repository
holds.
