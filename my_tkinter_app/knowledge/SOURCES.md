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
provisions. ENISA reports permit reuse with attribution. MITRE ATT&CK is free
with the attribution notice below. OWASP is CC BY-SA 4.0. Check each before
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

**[4]** MITRE Corporation, "MITRE ATT&CK: Enterprise matrix," The MITRE
Corporation, McLean, VA, USA, 2026. [Online]. Available:
https://attack.mitre.org/

> Required attribution: "© 2026 The MITRE Corporation. This work is
> reproduced and distributed with the permission of The MITRE Corporation."
> Already used in `KNOWLEDGE_MAP`; ten of sixteen classes map cleanly and
> three deliberately do not.

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

> The right reference for the API, WebBased and Exploitation classes, which
> ATT&CK covers only coarsely as T1190. CC BY-SA 4.0.

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
