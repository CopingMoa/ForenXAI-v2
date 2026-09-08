# DNS abuse — response

> **REVIEW REQUIRED.** These paragraphs were selected by keyword, not by judgement. Read them, keep what actually prescribes an action, delete the rest, then remove this marker. `--verify` fails while it is present.
>
> Covers: DNS
>
> Source: Joint Task Force, "Security and privacy controls for information systems and organizations," NIST SP 800-53r5, rel. 5.2.0, Aug. 2025, doi: 10.6028/NIST.SP.800-53r5.
>   retrieved 2026-09-08, sha256 fc63bcd61715d018
> Source: K. Paine, O. Whitehouse, J. Sellwood and A. Shaw, "Indicators of compromise (IoCs) and their role in attack defence," RFC 9424, Aug. 2023, doi: 10.17487/RFC9424.
>   retrieved 2026-09-08, sha256 c11e9ebbcf4c5df5
> Source: A. Nelson, S. Rekhi, M. Souppaya and K. Scarfone, "Incident response recommendations and considerations for cybersecurity risk management," NIST SP 800-61r3, Apr. 2025, doi: 10.6028/NIST.SP.800-61r3.
>   retrieved 2026-09-08, sha256 e5593d6bb85daece
>
> Keep this file under about 1,500 words: the model's context is 8,192 tokens.


## From NIST.SP.800-53r5

communications services. Examples of control plane traffic include Border Gateway Protocol (BGP) routing, Domain Name System (DNS), and management protocols. See [SP 800-189] for additional information on the use of the resource public key infrastructure (RPKI) to protect BGP routes and detect unauthorized BGP announcements. Related Controls: AC-3, SC-8, SC-20, SC-21, SC-22. (5) BOUNDARY PROTECTION | DENY BY DEFAULT — ALLOW BY EXCEPTION

response data. Related Controls: SC-20, SC-22. Control Enhancements: None. (1) SECURE NAME/ADDRESS RESOLUTION SERVICE (RECURSIVE OR CACHING RESOLVER) | DATA ORIGIN AND INTEGRITY [Withdrawn: Incorporated into SC-21.]

SC-20(1) CHILD SUBSPACES W: Incorporated into SC-20. SC-20(2) DATA ORIGIN AND INTEGRITY S SC-21 Secure Name/Address Resolution Service (Recursive or Caching Resolver) SC-21(1) DATA ORIGIN AND INTEGRITY W: Incorporated into SC-21. SC-22 Architecture and Provisioning for

requests from clients external to organizations (i.e., on external networks, including the Internet). Organizations specify clients that can access authoritative DNS servers in certain roles (e.g., by address ranges and explicit lists). Related Controls: SC-2, SC-20, SC-21, SC-24. Control Enhancements: None. References: [SP 800-81-2].

clients use authenticated channels to recursive resolvers that perform such validations. Systems that use technologies other than the DNS to map between host and service names and network addresses provide some other means to enable clients to verify the authenticity and integrity of response data. Related Controls: SC-20, SC-22. Control Enhancements: None.

References: [FIPS 140-3], [FIPS 186-4], [SP 800-81-2]. SC-21 SECURE NAME/ADDRESS RESOLUTION SERVICE (RECURSIVE OR CACHING RESOLVER) Control: Request and perform data origin authentication and data integrity verification on the name/address resolution responses the system receives from authoritative sources. Discussion: Each client of name resolution services either performs this validation on its own or has authenticated channels to trusted validation providers. Systems that provide name and

## From RFC9424

* Fully Qualified Domain Names (FQDNs) in network traffic, DNS resolver caches, or logs * TLS Server Name Indication values in network traffic * Code-signing certificates in binaries * TLS certificate information (such as SHA256 hashes) in network traffic

When associated with malicious activity, the following are some examples of protocol-related IoCs: * IPv4 and IPv6 addresses in network traffic * Fully Qualified Domain Names (FQDNs) in network traffic, DNS resolver caches, or logs * TLS Server Name Indication values in network traffic

june-2018>. [PDNS] UK NCSC, "Protective Domain Name Service (PDNS)", August 2017, <https://www.ncsc.gov.uk/information/pdns>. [PoP] Bianco, D., "The Pyramid of Pain", March 2013, <https://detect-respond.blogspot.com/2013/03/the-pyramid- of-pain.html>.

automated manner. This could also be achieved within an enterprise by ensuring those control points with the widest aperture (for example, enterprise-wide DNS resolvers) are able to act automatically based on IoC feeds. 3.2.5. Detection Security controls with deployed IoCs monitor their relevant control

[Owari] UK NCSC, "Owari botnet own-goal takeover", 2018, <https:// webarchive.nationalarchives.gov.uk/ukgwa/20220301141030/ https://www.ncsc.gov.uk/report/weekly-threat-report-8th- june-2018>. [PDNS] UK NCSC, "Protective Domain Name Service (PDNS)", August 2017, <https://www.ncsc.gov.uk/information/pdns>.

adding support for the distribution and consumption of IoCs directly to their products, without each user having to do it, thus addressing the threat for the whole user base at once in a machine-scalable and automated manner. This could also be achieved within an enterprise by ensuring those control points with the widest aperture (for example, enterprise-wide DNS resolvers) are able to act automatically

## From NIST.SP.800-61r3

adverse events High R1: Monitoring should include wired and wireless networks, network communications and flows, network services (e.g., DNS and BGP), and the presence of unauthorized or rogue

communications and flows, network services (e.g., DNS and BGP), and the presence of unauthorized or rogue networks within facilities. DE.CM-02 The physical environment is monitored to find potentially
