# What the analyst does with a finding

> Source: Alex Nelson, Sanjay Rekhi, Murugiah Souppaya, and Karen Scarfone. 2025. Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile. NIST Special Publication 800-61r3. National Institute of Standards and Technology, Gaithersburg, MD, USA. https://doi.org/10.6028/NIST.SP.800-61r3
> Source: Cybersecurity and Infrastructure Security Agency. 2021. Cybersecurity Incident and Vulnerability Response Playbooks: Operational Procedures for Planning and Conducting Cybersecurity Incident and Vulnerability Response Activities in FCEB Information Systems. CISA, Washington, DC, USA.
>
> Retrieved: 2026-09-08

The per-class playbooks say what to do about **one attack type**. This says
what to do about **a finding**, in order, before you get there.

## 1. Order of work

Do these in order. Steps 1-2 are cheap and stop you acting on a result that
was never valid.

| # | Step | Where | Stop if |
|---|---|---|---|
| 1 | Check the flows are comparable | Flow Summary: engine, timeout warning, coerced cells | Timeout warning is on — re-extract first |
| 2 | Check the class is reliable enough | Finding: F1, confidence, runner-up | Weak F1 and low confidence — treat as a lead |
| 3 | Read the attributions | SHAP panel | The top feature is an extraction artefact |
| 4 | Corroborate in the capture | Wireshark, the raw PCAP | Nothing in the packets matches the class |
| 5 | Apply the class playbook | Recommendations panel | — |
| 6 | Preserve and record | Below | — |

Steps 1-3 are the part this tool can answer. Step 4 it cannot: it sees flow
records, not packets.

## 2. Mitigation, by how reversible it is

Containment steps differ in cost. Take the reversible ones first — a wrong
block on a production service is its own incident.

**Reversible, take immediately.** Increase logging on the hosts named in the
finding. Rate-limit the source. Alert the service owner.

**Reversible with notice.** Block the source address at the perimeter. Close
the specific port to that source. Move the host to a restricted VLAN.

**Not reversible, needs authority.** Take the host off the network.
Terminate sessions. Rebuild. These destroy volatile evidence — image first.

CISA lists the containment actions themselves:

## From CISA.playbooks

> capturing forensic images to preserve evidence for legal use (if
> applicable) and further investigation of the incident.

The order above is ours. CISA lists the actions; it does not rank them by
reversibility.

## 3. Preserve before you contain

## From CISA.playbooks

> collect and preserve data for incident verification, categorization,
> prioritization, mitigation, reporting, and attribution. When necessary
> and possible, such information should be preserved and safeguarded as
> best evidence for use in any potential law enforcement investigation.

For a finding from this tool, the evidence set is:

- The original PCAP and its SHA-256 (the case records both)
- The flow CSV and `flow_extraction.json` — which engine, which timeout
- The prediction output and its SHA-256
- The SHAP output for the flows you relied on

All four are written to the case directory. Keep them together; the flow CSV
alone is not interpretable without the engine record.

## 4. Chain of custody is a judgement call

## From NIST.SP.800-61r3

> Many incident responses involve the collection of incident data and
> metadata. Formal evidence gathering and handling using chain-of-custody
> procedures might not be performed for every incident that occurs

Not every finding warrants formal handling. Decide early, because you cannot
retrofit it: once the capture has been copied around without a record, the
chain is gone.

Apply formal handling when prosecution, dismissal, regulatory notification,
or an insurance claim is plausible. Otherwise record the hashes and move on.

## 5. What to write down

For each finding you report:

- Class, flow count, share of the capture
- Mean confidence, and the count below 0.60
- The class's measured F1, stated as a limit
- The runner-up class where ambiguity was flagged
- Which extraction engine produced the flows
- What you corroborated in the packets, and what you did not

The last line matters most. A finding this tool produced is a
classification, not a conclusion, until step 4 is done.

## 6. What not to claim

**"No X was found" is not "no X occurred."** Low recall on a class makes its
absence uninformative — see [[reliability]].

**A confident classification is not a corroborated one.** See
[[confidence]].

**An attribution is not a cause.** See [[shap-reading]].

## 7. Not covered by these sources

Neither source gives a threshold for escalation, a retention period, or the
confidence at which a finding becomes reportable. Both are site policy. The
reversibility ranking in §2 is this project's own ordering, not a scheme
either document endorses.

Related: [[confidence]], [[reliability]], [[extraction-validity]], [[scope]]
