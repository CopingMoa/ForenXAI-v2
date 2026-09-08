# API abuse — response

> Source: Open Worldwide Application Security Project, "A01:2025 — Broken access control," in OWASP Top 10:2025, OWASP Foundation, 2025.
> Source: Open Worldwide Application Security Project, "A07:2025 — Authentication failures," in OWASP Top 10:2025, OWASP Foundation, 2025.
> Source: Joint Task Force, "Security and privacy controls for information systems and organizations," NIST SP 800-53r5, controls AC-4 and SI-4, rel. 5.2.0, Aug. 2025, doi: 10.6028/NIST.SP.800-53r5.
>
> Retrieved: 2026-09-08

## 1. What this class means here

TRUSTLab's API class is abuse of a machine-facing HTTP endpoint: enumerating
object identifiers, replaying calls, exhausting a rate limit, or reaching a
method the caller should not be able to reach.

The flow record shows the shape of the traffic — request volume, timing,
directionality — not the request contents. **The classification says traffic
to an API looked abusive. It does not say what was called or whether it
succeeded.** Everything below assumes you will read the requests.

## 2. Detection and analysis

Record the source address, the destination service and port, the request
rate and the capture window.

Then, from the web or gateway logs for that window:

- **The paths hit.** Sequential object identifiers (`/orders/1001`,
  `/orders/1002`, …) are enumeration. Repeated calls to one path are replay
  or a stuck client.
- **The response codes.** A run of 401/403 is a caller being refused, which
  is the control working. A run of **200s** on the same pattern is the
  finding — the caller was not refused.
- **Which credential.** One API key or token across an abnormal number of
  calls narrows the scope from an address to an account.

The distinction that decides severity is authorisation:

## From OWASP.A01.2025

> Access control is only effective when implemented in trusted server-side
> code or serverless APIs, where the attacker cannot modify the access
> control check or metadata. Except for public resources, deny by default.

If the endpoint enforces authorisation server-side and returned 403, you
have an attempt. If it returned data, you have a disclosure — and the flow
record cannot tell you which.

## 3. Containment

Take the reversible steps first. An API client is usually a real integration
and blocking it breaks a service that was working.

**Rate-limit the source.** OWASP names this directly for this case:

 ##From OWASP.A01.2025

> Log access control failures, alert admins when appropriate (e.g., repeated
> failures). Implement rate limits on API and controller access to minimize
> the harm from automated attack tooling.

**Revoke the credential, not the address.** If the calls carry one key or
token, revoking it stops the abuse and leaves every other client working. A
perimeter block on the address also stops legitimate traffic from that host.

**Then the boundary.** SP 800-53r5 AC-4 (Information Flow Enforcement)
governs what may cross between systems, and SI-4 (System Monitoring)
requires detection of attack indicators. Keep the raised logging after the
block — the next attempt will come from a different address.

## 4. If the calls carried credentials

## From OWASP.A07.2025

> Where possible, implement and enforce use of multi-factor authentication
> to prevent automated credential stuffing, brute force, and stolen
> credential reuse attacks.

MFA does not apply to a machine-to-machine key. What does: rotate the key,
scope the replacement to only the methods that client needs, and check
whether the same key was used from any other address in the window.

## 5. What would make this a false positive

**A legitimate batch job.** Nightly synchronisation, a data export, a
monitoring poller — all produce high-rate, regular, single-source API
traffic. Check whether the source is a known internal system and whether the
timing matches a schedule.

**A retry storm.** A broken client retrying a failing call looks like replay
abuse. The tell is the response code: a client hammering a 500 is a bug, not
an attack.

**A newly deployed integration.** Traffic with no history looks anomalous
because it has no baseline, not because it is hostile.

## 6. Not covered by these sources

Neither OWASP category prescribes an incident-response procedure — they are
prevention guidance written for developers. Neither states a request rate
above which traffic is abusive; that depends on the endpoint and belongs in
your own runbook.

Nothing here establishes whether data actually left. That needs the response
bodies or the application's own audit log, and this tool sees neither.
