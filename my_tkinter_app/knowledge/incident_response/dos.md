# Denial of service, single source — response

> Source: A. Nelson, S. Rekhi, M. Souppaya and K. Scarfone, "Incident response recommendations and considerations for cybersecurity risk management," NIST SP 800-61r3, Apr. 2025, doi: 10.6028/NIST.SP.800-61r3.
> Source: Joint Task Force, "Security and privacy controls for information systems and organizations," NIST SP 800-53r5, control SC-5, rel. 5.2.0, Aug. 2025, doi: 10.6028/NIST.SP.800-53r5.
> Source: Cybersecurity and Infrastructure Security Agency, "Cybersecurity incident & vulnerability response playbooks," CISA, Washington, DC, USA, Nov. 2021.
>
> Retrieved: 2026-09-08

## 1. What this class means here

One source exhausting a service: connection floods, request floods, or
resource consumption from a single address. Distinguished from DDoS by
source count, not by technique.

**This is one of the two weakest classes in the model** (F1 0.6703). It is
confused with Slowloris, which is the same goal by a different mechanism.
Confirm before reporting, and see the reliability guidance in the panel.

## 2. Detection and analysis

Record the source address, the target service and port, the request rate,
and the capture window.

SP 800-53r5 SC-5 places this among events with several possible causes, not
all hostile:

## From NIST.SP.800-53r5

> Denial-of-service events may occur due to a variety of internal and
> external causes, such as an attack by an adversary or a lack of planning
> to support organizational needs with respect to capacity and bandwidth.

That distinction is the whole analysis. Before treating this as an attack,
establish that the service actually degraded, and that capacity was not
simply exceeded by legitimate demand.

From the target host: request rate over time, error rates, CPU and memory,
and worker or connection-pool saturation.

## 3. Containment

Reversible first. A single source is often a misconfigured client.

**Rate-limit the source** at the perimeter. This is reversible and does not
break the client if it turns out to be legitimate.

**Then filter.** SC-5 requires the effects of such events be limited or
prevented, with the specific controls chosen by the organisation. A drop
rule for the source belongs here, not before rate limiting.

CISA describes the wider containment step:

## From CISA.playbooks

> Isolate threat actor activity and prevent additional damage from the
> activity or pivoting into other systems. Key containment activities
> include:

Isolation is disproportionate for a single-source flood unless the source is
internal, in which case the source host is the incident.

## 4. What would make this a false positive

A backup job, a monitoring poller, a load test, or a retry storm from a
broken client all produce sustained single-source load. Check whether the
source is a known internal system and whether the timing matches a schedule.

Capacity exhaustion without an attacker is the case SC-5 names explicitly.
If the service degraded under ordinary demand, this is a capacity finding.

## 5. Not covered by these sources

None states a request rate above which traffic is an attack, or how long a
degradation must last to be an incident. Both are site policy.
