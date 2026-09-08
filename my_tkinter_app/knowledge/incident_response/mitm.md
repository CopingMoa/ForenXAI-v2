# Machine-in-the-middle — response

> Source: K. McKay and D. Cooper, "Guidelines for the selection, configuration, and use of Transport Layer Security (TLS) implementations," NIST SP 800-52r2, Aug. 2019, doi: 10.6028/NIST.SP.800-52r2.
> Source: Joint Task Force, "Security and privacy controls for information systems and organizations," NIST SP 800-53r5, control SC-8, rel. 5.2.0, Aug. 2025, doi: 10.6028/NIST.SP.800-53r5.
> Source: Cybersecurity and Infrastructure Security Agency, "Cybersecurity incident & vulnerability response playbooks," CISA, Washington, DC, USA, Nov. 2021.
>
> Retrieved: 2026-09-08

## 1. What this class means here

An attacker positioned between two parties, able to read and potentially
alter traffic: ARP spoofing, rogue gateway, DNS redirection, or TLS
interception with a substituted certificate.

**The scope is the segment, not the host.** If this is real, everything
observed on that segment during the window may have been read or modified —
including traffic belonging to other findings in the same capture.

## 2. Detection and analysis

Record the addresses involved, the segment, and the capture window.

- **ARP tables.** Two MAC addresses claiming one IP, or the gateway's IP
  mapped to an unexpected MAC, is the classic signature.
- **Gateway MAC over time.** A change mid-capture is the event.
- **Certificate chains presented.** A certificate not signed by the expected
  authority means interception.
- **TLS version and cipher downgrade.** Forcing a weaker negotiation is how
  interception is made possible.

SP 800-52r2 states the version floor a downgrade would be pushing below:

## From NIST.SP.800-52r2

> These servers shall not allow the use of SSL 2.0 or SSL 3.0. Agencies
> shall support TLS 1.3 by January 1, 2024. After this date, servers shall
> support TLS 1.3 for both government-only and citizen or business-facing
> applications.

SP 800-53r5 SC-8 is the control this defeats:

## From NIST.SP.800-53r5

> Protecting the confidentiality and integrity of transmitted information
> applies to internal and external networks as well as any system
> components that can transmit information, including servers,

## 3. Containment

**Identify the attacking host from the ARP evidence first.** Everything else
depends on knowing which port it is on.

**Disable the switch port**, rather than blocking at the perimeter. The
attacker is on the local segment; a perimeter rule does not reach it.

**Then, for the segment:**

## From CISA.playbooks

> Isolate threat actor activity and prevent additional damage from the
> activity or pivoting into other systems. Key containment activities
> include:

**Rotate credentials that crossed the segment during the window.** Anything
transmitted may have been captured, including inside intercepted TLS.

**Enable dynamic ARP inspection and DHCP snooping** on the switch. This is
the durable fix.

## 4. What would make this a false positive

**Corporate TLS inspection.** A sanctioned proxy substitutes certificates by
design and looks exactly like interception. Check whether the certificate
authority is your own before escalating.

**HA failover.** A gateway pair moving a virtual IP between them changes the
MAC legitimately.

**Load balancers, NAT and captive portals** all rewrite traffic.

Confirm the substituting device is not one of yours before treating this as
an intrusion.

## 5. Not covered by these sources

Neither addresses ARP spoofing detection or switch configuration. SP 800-52r2
covers TLS configuration, not interception response. Neither states what
must be rotated after a confirmed interception.
