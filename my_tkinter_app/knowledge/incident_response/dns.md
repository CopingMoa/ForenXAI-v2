# DNS abuse and tunnelling — response

> Source: Joint Task Force, "Security and privacy controls for information systems and organizations," NIST SP 800-53r5, control SC-20, rel. 5.2.0, Aug. 2025, doi: 10.6028/NIST.SP.800-53r5.
> Source: K. Paine, O. Whitehouse, J. Sellwood and A. Shaw, "Indicators of compromise (IoCs) and their role in attack defence," RFC 9424, Aug. 2023, doi: 10.17487/RFC9424.
> Source: Cybersecurity and Infrastructure Security Agency, "Cybersecurity incident & vulnerability response playbooks," CISA, Washington, DC, USA, Nov. 2021.
>
> Retrieved: 2026-09-08

## 1. What this class means here

DNS used as something other than name resolution: tunnelling data inside
queries and responses, or resolving attacker-controlled domains as part of
command and control.

DNS is allowed outbound almost everywhere, which is exactly why it is used
this way. **Blocking DNS outright breaks the network**, so containment here
is different from every other class.

## 2. Detection and analysis

Record the internal source, the resolver used, the query names, record types
and response sizes.

The tunnelling signals:

- **Query volume** far above normal for that host.
- **Name length and entropy.** Encoded data appears as long, random-looking
  labels under one parent domain.
- **Record types.** Disproportionate TXT, NULL or CNAME volume.
- **One parent domain** receiving nearly all queries. That domain is the
  finding.
- **Response sizes** consistently near the maximum.

Check the parent domain as an indicator; RFC 9424 covers what a match does
and does not establish.

SP 800-53r5 SC-20 concerns the integrity of resolution itself:

## From NIST.SP.800-53r5

> a. Provide additional data origin authentication and integrity
> verification artifacts along with the authoritative name resolution data
> the system returns in response to external name/address resolution
> queries; and

## 3. Containment

**Do not block port 53.** Point the host at a controlled resolver instead —
reversible, keeps the network working, and gives you a full query log.

**Sinkhole the specific domain**, not the protocol.

**Block direct outbound DNS** so hosts must use the internal resolver. This
is the durable fix: tunnelling depends on reaching an external resolver.

**Then treat the source host as compromised.** DNS tunnelling is a symptom;
something on that host is doing it.

## From CISA.playbooks

> Isolate threat actor activity and prevent additional damage from the
> activity or pivoting into other systems. Key containment activities
> include:

## 4. What would make this a false positive

Some security and CDN products legitimately encode data in DNS. Anti-virus
reputation lookups, some cloud agents and certain content-delivery
mechanisms produce high-volume queries with long encoded labels under one
parent domain — the exact signature.

A misconfigured resolver, or a host that lost its cache, produces query
floods too.

Check the parent domain against the vendor's documentation before acting.

## 5. Not covered by these sources

Neither defines a query rate or name length that indicates tunnelling.
SC-20 is about DNSSEC and authoritative resolution, not tunnelling
detection. Neither states when DNS abuse warrants escalation.
