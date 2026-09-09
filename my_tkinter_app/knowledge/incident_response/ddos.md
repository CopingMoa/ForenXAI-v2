# Distributed denial of service — response

> Source: Alex Nelson, Sanjay Rekhi, Murugiah Souppaya, and Karen Scarfone. 2025. Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile. NIST Special Publication 800-61r3. National Institute of Standards and Technology, Gaithersburg, MD, USA. https://doi.org/10.6028/NIST.SP.800-61r3
> Source: Joint Task Force. 2025. Security and Privacy Controls for Information Systems and Organizations. NIST Special Publication 800-53, Revision 5, Release 5.2.0. National Institute of Standards and Technology, Gaithersburg, MD, USA. https://doi.org/10.6028/NIST.SP.800-53r5, Control SC-5.
> Source: Cybersecurity and Infrastructure Security Agency. 2021. Cybersecurity Incident and Vulnerability Response Playbooks: Operational Procedures for Planning and Conducting Cybersecurity Incident and Vulnerability Response Activities in FCEB Information Systems. CISA, Washington, DC, USA.
>
> Retrieved: 2026-09-08

## 1. What this class means here

Many sources exhausting one target. The defining feature in the flow record
is source diversity: a large number of distinct addresses converging on one
destination in a short window.

## 2. Detection and analysis

Record the source address distribution, the target service and port, the
aggregate rate, and the capture window. **The source count is the finding.**
A handful of addresses is a flood; thousands is a distributed one, and the
response differs.

## From NIST.SP.800-53r5

> Denial-of-service events may occur due to a variety of internal and
> external causes, such as an attack by an adversary or a lack of planning
> to support organizational needs with respect to capacity and bandwidth.
> Such attacks can occur across a wide range of network protocols (e.g.,
> IPv4, IPv6).

Confirm the service actually degraded. A capture full of inbound traffic is
not an incident if the service served it.

Check whether sources are spoofed. Reflection and amplification produce
apparent sources that were never involved, and blocking them accomplishes
nothing.

## 3. Containment

**Host-level blocking does not work here.** By the time traffic reaches your
firewall it has already consumed the link. Filtering must happen upstream.

**Contact the upstream provider or scrubbing service first.** This is the
step that changes the outcome, and it takes the longest to arrange.

**Then rate-limit and filter locally** to protect what capacity remains.

**Preserve the source list before filtering.** It is the evidence, and once
the flood stops it is not recoverable.

## From CISA.playbooks

> Isolate threat actor activity and prevent additional damage from the
> activity or pivoting into other systems. Key containment activities
> include:

## 4. What would make this a false positive

A traffic spike from a legitimate event — a product launch, a news mention,
a misbehaving CDN — has many sources and degrades service. The tell is
whether requests are well-formed and whether sources have prior history.

A distributed load test, or a scanner run by your own team, produces the
same shape.

## 5. Not covered by these sources

Neither prescribes when to engage an upstream provider, nor how to
distinguish a flood from legitimate demand at flow level. Neither addresses
spoofed-source attribution.
