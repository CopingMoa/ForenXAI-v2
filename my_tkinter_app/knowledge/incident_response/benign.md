# Benign traffic — no action, and why that still needs saying

> Written for this project rather than extracted: no incident-response
> guide has a chapter on doing nothing. The two claims that need a source
> are the false-negative risk and the retention obligation, and both are
> cited below.
>
> Source: A. Nelson, S. Rekhi, M. Souppaya and K. Scarfone, "Incident response recommendations and considerations for cybersecurity risk management," NIST SP 800-61r3, Apr. 2025, doi: 10.6028/NIST.SP.800-61r3.
> Source: K. Paine, O. Whitehouse, J. Sellwood and A. Shaw, "Indicators of compromise (IoCs) and their role in attack defence," RFC 9424, Aug. 2023, doi: 10.17487/RFC9424.
>
> Retrieved: 2026-09-08

## 1. What a Benign classification means

The model examined the flow's 74 statistical features and found them closer
to the Benign class than to any of the fifteen attack classes. That is all
it means.

It does **not** mean the flow was inspected and cleared. Nothing looked at
the payload, the destination's reputation, or what happened on the endpoint
afterwards.

## 2. No action is required for the flow itself

There is no containment step for traffic classified as normal. The
recommendation is to take none.

## 3. What still deserves a look

**Low-confidence Benign.** A flow classified Benign at 0.55 is not a
confident finding. The flow summary counts these; they are the flows most
worth a second opinion, in either direction.

**Benign as a runner-up on an attack finding.** Where the model nearly said
Benign for a class it flagged, the attack classification is weaker than its
headline confidence suggests.

**The classes this model handles badly.** DoS scores F1 0.6703 and
Slowloris 0.7593 on held-out data. Traffic of those types is more likely
than average to be misfiled as Benign, so absence of a DoS finding is not
evidence there was none.

## 4. The limit that matters

RFC 9424 sets out what an indicator can and cannot establish. A flow-level
classifier produces indicators, and the same limits apply: an indicator not
matching establishes that this indicator did not match, not that the
activity was absent.

Slow-and-low activity is designed to look ordinary at flow level. Benign is
the expected classification for a well-executed one.

## 5. Retention

SP 800-61r3 treats evidence handling as part of incident response.
Benign-classified flows are part of the same capture as the attack findings
and belong to the same evidence item; they are not spare data to discard.
Retain the whole capture under whatever policy covers the case, not only
the flows that were flagged.

## 6. Not covered by these sources

Neither source says how long to keep a capture, or when a low-confidence
Benign warrants manual review. Both are site policy, and belong in your own
runbook.
