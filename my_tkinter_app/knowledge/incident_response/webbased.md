# Web application attack — response

> Source: Open Worldwide Application Security Project. 2025. A05:2025 - Injection. In OWASP Top 10:2025. OWASP Foundation.
> Source: Open Worldwide Application Security Project. 2025. A01:2025 - Broken Access Control. In OWASP Top 10:2025. OWASP Foundation.
> Source: Cybersecurity and Infrastructure Security Agency. 2021. Cybersecurity Incident and Vulnerability Response Playbooks: Operational Procedures for Planning and Conducting Cybersecurity Incident and Vulnerability Response Activities in FCEB Information Systems. CISA, Washington, DC, USA.
>
> Retrieved: 2026-09-08

## 1. What this class means here

Attacks carried in HTTP requests to a web application: injection, traversal,
access-control bypass, or forced browsing to pages the caller should not
reach.

**The flow record shows request shape, not request content.** The
classification says the traffic looked like a web attack. What was actually
sent is in the web server log, and that is where this response begins.

## 2. Detection and analysis

Record the source address, target host and port, request volume and the
capture window. Then, from the web server or WAF log:

- **The request paths and parameters.** Injection and traversal are visible
  in the query string or body.
- **The response codes.** This is the finding: a 403 is the control working,
  a **200 on an attack pattern means the application served the request**.
- **Response size.** A large response to an injection attempt is data
  leaving.

## 3. Containment

Reversible first. Blocking an address is cheap; taking an application down
is not.

**Block the source** at the perimeter or WAF.

**Fix the input handling.** OWASP is unambiguous about what actually works:

## From OWASP.A05.2025

> The best means to prevent injection requires keeping data separate from
> commands and queries: The preferred option is to use a safe API, which
> avoids using the interpreter entirely, provides a parameterized interface,
> or migrates to Object Relational Mapping Tools (ORMs).

A WAF rule buys time. Parameterised queries remove the vulnerability.

**Check the authorisation model** if the requests reached data they should
not have:

## From OWASP.A01.2025

> Access control is only effective when implemented in trusted server-side
> code or serverless APIs, where the attacker cannot modify the access
> control check or metadata. Except for public resources, deny by default.

**If any attempt succeeded**, the application and its data are in scope:

## From CISA.playbooks

> Isolate threat actor activity and prevent additional damage from the
> activity or pivoting into other systems. Key containment activities
> include:

## 4. What would make this a false positive

**Scanners.** An authorised vulnerability scan produces thousands of
injection-shaped requests, all refused. Check whether the source is a known
scanner and whether every response was an error.

**Legitimate content.** A CMS or search box carrying SQL keywords in user
text looks like injection at flow level.

**Broken clients** producing malformed URLs.

The common thread: if every response was 4xx, you have attempts, not a
breach.

## 5. Not covered by these sources

The OWASP categories are prevention guidance for developers and prescribe no
incident-response procedure. Neither states when a web attack becomes a
reportable breach. Nothing here establishes what data was returned — that
needs the response bodies, which this tool does not see.
