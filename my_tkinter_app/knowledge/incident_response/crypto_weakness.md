# TLS/SSL weakness — response

> Assembled from the sources below rather than extracted from a single
> playbook: TRUSTLab's TLSSSL class groups several unrelated attacks
> (Heartbleed, POODLE, BEAST, certificate anomalies) that no one guide
> treats together. Every claim traces to a cited section; where the sources
> do not cover something, this file says so.
>
> Sources:
>   K. McKay and D. Cooper, "Guidelines for the selection, configuration,
>   and use of Transport Layer Security (TLS) implementations," NIST
>   SP 800-52r2, Aug. 2019, doi: 10.6028/NIST.SP.800-52r2.
>   Joint Task Force, NIST SP 800-53r5, controls SC-8, SC-13 and SC-23,
>   rel. 5.2.0, Aug. 2025.
>   Cybersecurity and Infrastructure Security Agency, "Vulnerability
>   response playbook," Aug. 2024.
>
> Retrieved: 2026-09-08

## 1. What this class means here

The class covers two different situations that a flow record cannot
separate:

  - **exploitation of a TLS implementation flaw** — Heartbleed reads memory
    from the server; POODLE and BEAST recover plaintext by manipulating the
    session
  - **a weak or anomalous configuration** — a deprecated protocol version,
    a weak cipher suite, or a certificate that fails validation

The first is an attack in progress. The second is an exposure that may
never have been exploited. Establish which before responding, because the
responses differ.

## 2. Detection and analysis

Record the destination service, the negotiated protocol version and cipher
suite, and the certificate presented.

SP 800-52r2 requires TLS 1.2 with FIPS-based cipher suites as a minimum for
government servers and clients, and support for TLS 1.3 from 1 January 2024.
A negotiated version below that is a finding in itself, independent of any
attack.

SP 800-52r2 also covers certificate requirements and the TLS extensions that
affect security, which is the reference for a certificate-anomaly finding.

## 3. Containment

**If a configuration weakness:** SP 800-53r5 SC-13 (Cryptographic
Protection) requires cryptography that meets applicable standards. Bring the
service to the SP 800-52r2 baseline — disable protocol versions and cipher
suites below it.

**If exploitation is suspected:** treat it as a vulnerability response, not
a configuration change. The CISA Vulnerability Response Playbook applies:
identify the affected software version, determine exposure, and patch.
Heartbleed in particular requires assuming key material was disclosed —
rotate certificates and private keys, not only patch.

SP 800-53r5 SC-8 (Transmission Confidentiality and Integrity) and SC-23
(Session Authenticity) are the controls a finding here should cite.

## 4. What would make this a false positive

A legacy internal service that is deliberately exempted from the baseline
will look identical to an unpatched one. Check the exemption register before
escalating.

Self-signed certificates on internal services fail validation by design and
are not evidence of an attack.

A flow record shows that a TLS session occurred; it does not show that an
exploit succeeded. Nothing in this class should be reported as confirmed
compromise on flow evidence alone.

## 5. Not covered by these sources

None of them says how to decide, from flow records, whether an observed TLS
session was an exploitation attempt or an ordinary connection to a weakly
configured service. That distinction requires the endpoint logs, and this
model cannot make it.

Escalation, key-rotation authority and change windows are site-specific.
Fill them from your own runbook.
