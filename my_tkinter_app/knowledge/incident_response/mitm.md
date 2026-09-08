# Adversary in the middle — response

> **REVIEW REQUIRED.** These paragraphs were selected by keyword, not by judgement. Read them, keep what actually prescribes an action, delete the rest, then remove this marker. `--verify` fails while it is present.
>
> Covers: MITM
>
> Source: Joint Task Force, "Security and privacy controls for information systems and organizations," NIST SP 800-53r5, rel. 5.2.0, Aug. 2025, doi: 10.6028/NIST.SP.800-53r5.
>   retrieved 2026-09-08, sha256 fc63bcd61715d018
> Source: K. McKay and D. Cooper, "Guidelines for the selection, configuration, and use of Transport Layer Security (TLS) implementations," NIST SP 800-52r2, Aug. 2019, doi: 10.6028/NIST.SP.800-52r2.
>   retrieved 2026-09-08, sha256 f9a4dbb9cc6ac677
>
> Keep this file under about 1,500 words: the model's context is 8,192 tokens.


## From NIST.SP.800-53r5

SC-9 Transmission Confidentiality W: Incorporated into SC-8. SC-10 Network Disconnect S SC-11 Trusted Path S √ SC-11(1) IRREFUTABLE COMMUNICATIONS PATH S √ SC-12 Cryptographic Key Establishment and Management O/S SC-12(1) AVAILABILITY O/S

(Recursive or Caching Resolver) SC-21(1) DATA ORIGIN AND INTEGRITY W: Incorporated into SC-21. SC-22 Architecture and Provisioning for Name/Address Resolution Service SC-23 Session Authenticity S SC-23(1) INVALIDATE SESSION IDENTIFIERS AT LOGOUT S

SC-8(3) CRYPTOGRAPHIC PROTECTION FOR MESSAGE EXTERNALS S SC-8(4) CONCEAL OR RANDOMIZE COMMUNICATIONS S SC-8(5) PROTECTED DISTRIBUTION SYSTEM S SC-9 Transmission Confidentiality W: Incorporated into SC-8. SC-10 Network Disconnect S SC-11 Trusted Path S √

SC-8 Transmission Confidentiality and Integrity S SC-8(1) CRYPTOGRAPHIC PROTECTION S SC-8(2) PRE- AND POST-TRANSMISSION HANDLING S SC-8(3) CRYPTOGRAPHIC PROTECTION FOR MESSAGE EXTERNALS S SC-8(4) CONCEAL OR RANDOMIZE COMMUNICATIONS S SC-8(5) PROTECTED DISTRIBUTION SYSTEM S

Related Controls: SC-2, SC-20, SC-21, SC-24. Control Enhancements: None. References: [SP 800-81-2]. SC-23 SESSION AUTHENTICITY Control: Protect the authenticity of communications sessions. Discussion: Protecting session authenticity addresses communications protection at the session

SC-7(27) UNCLASSIFIED NON-NATIONAL SECURITY SYSTEM CONNECTIONS O SC-7(28) CONNECTIONS TO PUBLIC NETWORKS O SC-7(29) SEPARATE SUBNETS TO ISOLATE FUNCTIONS S SC-8 Transmission Confidentiality and Integrity S SC-8(1) CRYPTOGRAPHIC PROTECTION S SC-8(2) PRE- AND POST-TRANSMISSION HANDLING S

## From NIST.SP.800-52r2

handshake as a renegotiation of the attacker’s negotiated session and thus believes that the initial data transmitted by the attacker is from the legitimate client. The session renegotiation extension is defined to prevent such a session splicing or session interception. The extension uses the concept of cryptographically binding the initial session negotiation and session renegotiation. Server implementations shall perform initial and subsequent renegotiations in accordance with RFC 5746 [59] and RFC 8446 [57].

In TLS versions 1.0 to 1.2, session renegotiation is vulnerable to an attack in which the attacker forms a TLS connection with the target server, injects content of its choice, and then splices in a new TLS connection from a legitimate client. The server treats the legitimate client’s initial TLS handshake as a renegotiation of the attacker’s negotiated session and thus believes that the initial data transmitted by the attacker is from the legitimate client. The session renegotiation extension is defined to prevent such a session splicing or session interception. The extension uses the
