# Port scanning and reconnaissance — response

> Source: A. Nelson, S. Rekhi, M. Souppaya and K. Scarfone, "Incident response recommendations and considerations for cybersecurity risk management," NIST SP 800-61r3, Apr. 2025, doi: 10.6028/NIST.SP.800-61r3.
> Source: Joint Task Force, "Security and privacy controls for information systems and organizations," NIST SP 800-53r5, control SI-4, rel. 5.2.0, Aug. 2025, doi: 10.6028/NIST.SP.800-53r5.
> Source: K. Paine, O. Whitehouse, J. Sellwood and A. Shaw, "Indicators of compromise (IoCs) and their role in attack defence," RFC 9424, Aug. 2023, doi: 10.17487/RFC9424.
>
> Retrieved: 2026-09-08

## 1. What this class means here

One source contacting many ports or many hosts in a short window, mapping
what is reachable and what responds.

**Reconnaissance, not compromise.** A scan on its own establishes that
somebody looked. The finding that matters is what the same source did
afterwards.

## 2. Detection and analysis

Record the source address, the ports contacted, the order, and which ones
**responded**. The responses are the part that matters: they tell you what
the scanner learned.

Then, and this is the step that is usually skipped:

**Search the rest of the capture for the same source after the scan.** A
scan followed by a connection to one of the open ports is a different
incident from a scan alone.

SP 800-53r5 SI-4 covers this monitoring obligation:

## From NIST.SP.800-53r5

> a. Monitor the system to detect: 1. Attacks and indicators of potential
> attacks in accordance with the following monitoring objectives:
> [Assignment: organization-defined monitoring objectives]; and 2.
> Unauthorized local, network, and remote connections;

Record the source as an indicator, but note what RFC 9424 says a
non-matching indicator does and does not prove — absence of a later match is
not absence of activity.

## 3. Containment

**Confirm it is not an authorised scanner first.** Vulnerability scanners,
asset inventory tools and monitoring systems all port-scan by design, on a
schedule, from a known internal address. Blocking one breaks your own
security tooling.

Once confirmed hostile:

**Block the source at the perimeter** — reversible, and appropriate here
because a scanner has no legitimate traffic to lose.

**Close what should not have answered.** The scan's value to the attacker is
the list of open ports. Reducing that list is the durable fix; blocking one
address is not.

**Raise logging on the hosts that responded.** If the scan was preparation,
the next step targets those.

## 4. What would make this a false positive

An authorised vulnerability scan is the common case, and looks identical.
So does asset discovery, a monitoring system health-checking services, and a
misconfigured client retrying across ports.

A NAT gateway or proxy can also make many hosts appear as one source
contacting many ports.

## 5. Not covered by these sources

Neither states how many ports in what interval constitutes a scan, nor when
reconnaissance should be escalated. Both are site policy. Neither addresses
attribution behind NAT.
