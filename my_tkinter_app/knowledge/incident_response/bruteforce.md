# Credential brute force — response

> Source: Open Worldwide Application Security Project, "A07:2025 — Authentication failures," in OWASP Top 10:2025, OWASP Foundation, 2025.
> Source: Joint Task Force, "Security and privacy controls for information systems and organizations," NIST SP 800-53r5, control AC-7, rel. 5.2.0, Aug. 2025, doi: 10.6028/NIST.SP.800-53r5.
> Source: Cybersecurity and Infrastructure Security Agency, "Cybersecurity incident & vulnerability response playbooks," CISA, Washington, DC, USA, Nov. 2021.
>
> Retrieved: 2026-09-08

## 1. What this class means here

Repeated authentication attempts against a service — password guessing,
credential stuffing, or spraying one password across many accounts.

**The flow record shows the attempts, not the outcome.** Whether any
succeeded is the only question that matters here, and it is answered from
the authentication log, not from this tool.

## 2. Detection and analysis

Record the source address, the target service and port, the attempt rate and
the capture window. Then, from the authentication log for that window:

- **Did any attempt succeed?** A success after a run of failures converts
  this from an attempt into an intrusion, and everything downstream changes.
- **How many accounts?** Many attempts against one account is guessing; one
  or two attempts against many accounts is spraying, and spraying evades
  per-account lockout by design.
- **What happened after a success?** The session that followed is the
  incident.

## From OWASP.A07.2025

> Limit or increasingly delay failed login attempts but be careful not to
> create a denial of service scenario. Log all failures and alert
> administrators when credential stuffing, brute force, or other attacks are
> detected or suspected.

The warning in that sentence is not decoration. Aggressive lockout turns an
authentication attack into an availability outage, which is sometimes the
attacker's actual goal.

## 3. Containment

**If any attempt succeeded**, this is not a brute-force response any more.
Preserve the session, reset the credential, and treat the account as
compromised.

**If none succeeded**, take the reversible steps:

**Rate-limit the source**, and delay rather than block outright.

SP 800-53r5 AC-7 states the lockout control:

## From NIST.SP.800-53r5

> a. Enforce a limit of [Assignment: organization-defined number]
> consecutive invalid logon attempts by a user during a [Assignment:
> organization-defined time period]; and

The number and the period are yours to set. Setting them too tight is how
lockout becomes the outage OWASP warns about.

**Enable MFA on the targeted accounts.** It defeats stuffing and reuse
outright, and is the only step here that removes the technique rather than
slowing it.

## 4. What would make this a false positive

An expired credential in a scheduled job or a service account retries
forever and produces exactly this pattern. So does a user with a saved wrong
password on a mobile client, and a misconfigured SSO integration.

The tell is the account: automation hammers one account from one address on
a regular interval.

## 5. Not covered by these sources

Neither states an attempt rate that constitutes an attack, nor a lockout
threshold — AC-7 leaves both as organisational assignments. Neither
addresses attribution when attempts come through a proxy.
