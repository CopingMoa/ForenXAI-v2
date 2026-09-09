# Command and control beaconing — response

> Source: K. Paine, O. Whitehouse, J. Sellwood, and A. Shaw. 2023. Indicators of Compromise (IoCs) and Their Role in Attack Defence. RFC 9424. Internet Engineering Task Force. https://doi.org/10.17487/RFC9424
> Source: Joint Task Force. 2025. Security and Privacy Controls for Information Systems and Organizations. NIST Special Publication 800-53, Revision 5, Release 5.2.0. National Institute of Standards and Technology, Gaithersburg, MD, USA. https://doi.org/10.6028/NIST.SP.800-53r5, Control SI-4.
> Source: Cybersecurity and Infrastructure Security Agency. 2021. Cybersecurity Incident and Vulnerability Response Playbooks: Operational Procedures for Planning and Conducting Cybersecurity Incident and Vulnerability Response Activities in FCEB Information Systems. CISA, Washington, DC, USA.
>
> Retrieved: 2026-09-08

## 1. What this class means here

An internal host contacting an external destination at regular intervals —
implant checking in for instructions. Low volume, high regularity, sustained
across the capture.

**A beacon means a host is already compromised.** Unlike every other class
here, this is not an attempt: the delivery already happened, and this is the
consequence.

## 2. Detection and analysis

**Do not block it yet.** Blocking tells the operator they were seen, and you
lose the ability to scope the intrusion.

Record the internal host, the external destination, the interval between
flows, the jitter, and the bytes per flow.

- **Interval regularity** is the signal. A fixed period, or a period with
  small consistent jitter, across the whole capture.
- **The destination.** Check against threat intelligence and passive DNS.
  What resolved it, and when.
- **How long has it run?** Search historical logs for the same destination.
  The first contact bounds the intrusion.
- **Which other hosts contact it?** This is how you find the rest.

## From NIST.SP.800-53r5

> a. Monitor the system to detect: 1. Attacks and indicators of potential
> attacks in accordance with the following monitoring objectives:
> [Assignment: organization-defined monitoring objectives]; and 2.
> Unauthorized local, network, and remote connections;

RFC 9424 is the reference for using the destination as an indicator, and for
its limits: a host that does not match this indicator is not thereby clean.

## 3. Containment

**Scope before you contain.** Find every host talking to the destination.
Containing one while others continue achieves nothing.

**Then contain all of them at once:**

## From CISA.playbooks

> Isolate threat actor activity and prevent additional damage from the
> activity or pivoting into other systems. Key containment activities
> include:

**Preserve memory before isolating.** The implant is usually resident and
often not on disk.

**Rebuild the hosts.** A confirmed implant is not something to clean.

## 4. What would make this a false positive

Regular outbound polling is what most legitimate software does. Update
checkers, telemetry agents, monitoring clients, license checks, NTP,
certificate revocation, cloud agents — all beacon on a fixed interval.

The tell is the destination, not the pattern. A regular interval to a vendor
endpoint is software working; a regular interval to an unrecognised host is
the finding.

## 5. Not covered by these sources

None defines a beaconing interval or jitter threshold. Neither states when
to move from monitoring to containment. Nothing here identifies the malware
family — that requires the host.
