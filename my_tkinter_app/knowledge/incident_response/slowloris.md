# Slowloris, slow-rate resource exhaustion — response

> Source: A. Nelson, S. Rekhi, M. Souppaya and K. Scarfone, "Incident response recommendations and considerations for cybersecurity risk management," NIST SP 800-61r3, Apr. 2025, doi: 10.6028/NIST.SP.800-61r3.
> Source: Joint Task Force, "Security and privacy controls for information systems and organizations," NIST SP 800-53r5, control SC-5, rel. 5.2.0, Aug. 2025, doi: 10.6028/NIST.SP.800-53r5.
>
> Retrieved: 2026-09-08

## 1. What this class means here

Holding many connections open with minimal data, exhausting a server's
connection or worker pool rather than its bandwidth. Low volume by design,
which is why it does not look like a flood.

**This class scores F1 0.7593 and is confused with DoS**, which is the same
objective by a different mechanism. When both appear, report the pair —
"slow-rate resource exhaustion consistent with Slowloris or DoS" — not one
name.

## 2. Detection and analysis

The signal is in the shape, not the volume:

- **Concurrent connection count** on the target, against its normal level.
- **Per-connection duration** — long-lived connections carrying almost no
  data.
- **Bytes per connection** — very low, sustained.
- **Worker or thread pool state** on the server. Exhaustion here, with the
  link nearly idle, is the confirmation.

## From NIST.SP.800-53r5

> Denial-of-service events may occur due to a variety of internal and
> external causes, such as an attack by an adversary or a lack of planning
> to support organizational needs with respect to capacity and bandwidth.

Low bandwidth use is what makes this hard to see. A capacity graph looks
healthy while the service is unavailable.

## 3. Containment

All three steps here are reversible and none blocks a legitimate user.

**Set a connection timeout** on the server, and a header-completion timeout.
The attack depends on the server waiting indefinitely.

**Limit concurrent connections per source address.**

**Put a reverse proxy in front** that buffers complete requests before
passing them upstream. This removes the mechanism entirely.

Blocking source addresses is the least effective option: the technique needs
few connections per source, so an attacker can spread across many.

## 4. What would make this a false positive

Long-polling, server-sent events and WebSocket clients all hold connections
open with little traffic, and are indistinguishable at flow level. Mobile
clients on poor links produce slow, long, low-data connections too.

Check whether the connections belong to an application that legitimately
uses them before acting.

## 5. Not covered by these sources

Neither names Slowloris, nor states a timeout value. SC-5 leaves the choice
of controls to the organisation. Fill both from your own runbook.
