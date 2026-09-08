# Detection evasion — response

> Assembled from the sources below rather than extracted from a single
> playbook: no published incident-response guide treats network-level IDS
> evasion as one procedure. Every claim traces to a cited section; where the
> sources do not cover something, this file says so.
>
> Sources:
>   G. Ziemba, D. Reed and P. Traina, "Security considerations for IP
>   fragment filtering," RFC 1858, §3–§4, Oct. 1995.
>   I. Miller, "Protection against a variant of the tiny fragment attack,"
>   RFC 3128, Jun. 2001.
>   Joint Task Force, NIST SP 800-53r5, controls SI-4 and SC-7, rel. 5.2.0,
>   Aug. 2025.
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

RFC 1858 §3 describes the tiny-fragment attack: a first fragment made small
enough that the TCP header is split across fragments, so a filter examining
only the first fragment never sees the flags it is filtering on.

RFC 1858 §4 describes the overlapping-fragment attack: the zero-offset
fragment carries innocuous data and passes the filter, while a later
fragment with a non-zero offset overlaps and rewrites the TCP header after
inspection. RFC 3128 extends this to a variant RFC 1858's original
recommendation did not catch.

The consequence for this pipeline: if evasion succeeded, what the flow
record describes is not what the endpoint received. A classification of any
other flow in the same capture is correspondingly less reliable.

## 3. Containment

RFC 1858 §3 prescribes discarding TCP fragments where the fragment offset
equals 1, which blocks the overlapping variant directly.

SP 800-53r5 SC-7 (Boundary Protection) requires that traffic be monitored
and controlled at managed interfaces. Fragment reassembly policy belongs at
that boundary, so the perimeter device — not the endpoint — should
reassemble before inspection.

SP 800-53r5 SI-4 (System Monitoring) requires detection of attack
indicators. A detector that inspects fragments independently is the
condition these attacks exploit, so verify the reassembly configuration
before treating any downstream classification as sound.

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
