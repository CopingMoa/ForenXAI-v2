# Detection evasion — response

> Assembled from the sources below rather than extracted from a single
> playbook: no published incident-response guide treats network-level IDS
> evasion as one procedure. Every claim traces to a cited section; where the
> sources do not cover something, this file says so.
>
> Source: G. Ziemba, D. Reed, and P. Traina. 1995. Security Considerations for IP Fragment Filtering. RFC 1858. Internet Engineering Task Force, Sections 3-4. https://doi.org/10.17487/RFC1858
> Source: I. Miller. 2001. Protection Against a Variant of the Tiny Fragment Attack. RFC 3128. Internet Engineering Task Force. https://doi.org/10.17487/RFC3128
> Source: Joint Task Force. 2025. Security and Privacy Controls for Information Systems and Organizations. NIST Special Publication 800-53, Revision 5, Release 5.2.0. National Institute of Standards and Technology, Gaithersburg, MD, USA. https://doi.org/10.6028/NIST.SP.800-53r5, Controls SI-4 and SC-7.
>
> Retrieved: 2026-09-08

## 1. What this class means here

TRUSTLab's Evasion class covers techniques that hide traffic from a
detector rather than attack a host directly: overlapping IP fragmentation
and TTL manipulation. The traffic is a delivery mechanism, so the finding
says an attempt was made to bypass inspection — not what the attacker was
delivering.

## 2. Detection and analysis

Record the source and destination addresses, and whether the flows are
fragmented.

RFC 1858 §3 describes the tiny-fragment attack:

## From RFC1858

> With many IP implementations it is possible to impose an unusually small
> fragment size on outgoing packets. If the fragment size is made small
> enough to force some of a TCP packet's TCP header fields into the second
> fragment, filter rules that specify patterns for those fields will not
> match.

A filter examining only the first fragment never sees the flags it is
filtering on.

RFC 1858 §4 describes the overlapping-fragment attack:

## From RFC1858

> an attacker could construct a series of packets in which the lowest
> (zero-offset) fragment would contain innocuous data (and thereby be
> passed by administrative packet filters), and in which some subsequent
> packet having a non- zero offset would overlap TCP header information
> (destination port, for instance) and cause it to be modified.

RFC 3128 then shows that RFC 1858's own Indirect Method — rejecting
fragments at offset 1 — does not catch every variant:

## From RFC3128

> The Indirect Method attempts to solve both Tiny Fragment and Overlapping
> Fragment attacks, solely by rejecting packets with FO=1. However none of
> the above fragments have FO=1, so none are rejected.

The consequence for this pipeline: if evasion succeeded, what the flow
record describes is not what the endpoint received. A classification of any
other flow in the same capture is correspondingly less reliable.

## 3. Containment

**Enforce a minimum fragment offset** on the filtering device, so the
transport header can never arrive inside a non-zero-offset fragment. RFC 1858
§4.2 puts that minimum at sixteen octets for TCP.

**Reassemble fragments at the perimeter device** before inspection, rather
than at the endpoint. SP 800-53r5 SC-7 places control of communications at
the external managed interface.

**Verify the reassembly configuration** before treating any downstream
classification as sound. A detector that inspects fragments independently is
the condition these attacks exploit.

The sourced basis for each of the three follows.

Discarding TCP fragments at offset 1 is RFC 1858's Indirect Method, and
RFC 3128 above shows it is not sufficient on its own. The remedy RFC 1858
§4.2 gives for the overlapping attack is a minimum offset, not a single
rejected value:

## From RFC1858

> If the router's filtering module enforces a minimum fragment offset for
> fragments that have non-zero offsets, it can prevent overlaps in filter
> parameter regions of the transport headers.

For TCP the RFC puts that minimum at sixteen octets, so the flags field can
never arrive in a non-zero-offset fragment.

SP 800-53r5 SC-7 (Boundary Protection) places this at the perimeter:

## From NIST.SP.800-53r5

> Monitor and control communications at the external managed interfaces to
> the system and at key internal managed interfaces within the system;

Fragment reassembly policy belongs at that boundary, so the perimeter
device — not the endpoint — should reassemble before inspection.

SP 800-53r5 SI-4 (System Monitoring) requires detection of attack
indicators:

## From NIST.SP.800-53r5

> Monitor the system to detect: 1. Attacks and indicators of potential
> attacks in accordance with the following monitoring objectives:
> [Assignment: organization-defined monitoring objectives]; and 2.
> Unauthorized local, network, and remote connections;

A detector that inspects fragments independently is the condition these
attacks exploit, so verify the reassembly configuration before treating any
downstream classification as sound.

## 4. What would make this a false positive

Fragmentation is normal on paths with a smaller MTU than the sender assumed,
so fragmented traffic alone is not evasion. Tunnelled traffic, VPN
endpoints, and some IPv6 transitions fragment routinely.

Low TTL values occur naturally when the capture point is many hops from the
source.

Confirm the fragments actually overlap, or that TTLs vary within a single
flow, before treating this as deliberate.

## 5. Not covered by these sources

Neither RFC prescribes escalation, evidence handling, or notification for a
detected evasion attempt. Neither addresses TTL manipulation, which TRUSTLab
includes in this class — RFC 1858 and RFC 3128 concern fragmentation only.
Fill both gaps from your own runbook.
