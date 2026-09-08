# Distributed denial of service — response

> Source: A. Nelson, S. Rekhi, M. Souppaya and K. Scarfone, "Incident response recommendations and considerations for cybersecurity risk management," NIST SP 800-61r3, Apr. 2025, doi: 10.6028/NIST.SP.800-61r3.
> Source: Joint Task Force, "Security and privacy controls for information systems and organizations," NIST SP 800-53r5, control SC-5, rel. 5.2.0, Aug. 2025, doi: 10.6028/NIST.SP.800-53r5.
> Source: Cybersecurity and Infrastructure Security Agency, "Cybersecurity incident & vulnerability response playbooks," CISA, Washington, DC, USA, Nov. 2021.
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
