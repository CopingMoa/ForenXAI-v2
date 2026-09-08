# Data exfiltration — response

> **REVIEW REQUIRED.** These paragraphs were selected by keyword, not by judgement. Read them, keep what actually prescribes an action, delete the rest, then remove this marker. `--verify` fails while it is present.
>
> Covers: Exfiltration
>
> Source: A. Nelson, S. Rekhi, M. Souppaya and K. Scarfone, "Incident response recommendations and considerations for cybersecurity risk management," NIST SP 800-61r3, Apr. 2025, doi: 10.6028/NIST.SP.800-61r3.
>   retrieved 2026-09-08, sha256 e5593d6bb85daece
> Source: K. Paine, O. Whitehouse, J. Sellwood and A. Shaw, "Indicators of compromise (IoCs) and their role in attack defence," RFC 9424, Aug. 2023, doi: 10.17487/RFC9424.
>   retrieved 2026-09-08, sha256 c11e9ebbcf4c5df5
> Source: Joint Task Force, "Security and privacy controls for information systems and organizations," NIST SP 800-53r5, rel. 5.2.0, Aug. 2025, doi: 10.6028/NIST.SP.800-53r5.
>   retrieved 2026-09-08, sha256 fc63bcd61715d018
>
> Keep this file under about 1,500 words: the model's context is 8,192 tokens.


## From NIST.SP.800-61r3

Identify (Improvement Category) Containment, Eradication & Recovery Respond Recover Identify (Improvement Category) Post-Incident Activity Identify (Improvement Category)

are restored, and normal operating status is confirmed High R1: Check restored assets for indicators of compromise, and remediate the root causes of the incident before production use.

and indicators of compromise. R2: Rapidly acquire and analyze vulnerability disclosures for the organization’s technologies from suppliers, vendors, and third-party security advisories.

CSF Element CSF Element Description Priority Recommendations, Considerations, Notes DE.AE (Adverse Event Analysis) Anomalies, indicators of compromise, and other potentially adverse events are

restoration. RC.RP-05 The integrity of restored assets is verified, systems and services are restored, and normal operating status is confirmed High R1: Check restored assets for indicators of

RC.RP-03 The integrity of backups and other restoration assets is verified before using them for restoration High R1: Check restoration assets for indicators of compromise, file corruption, and other

## From RFC9424

ISSN: 2070-1721 Binary Firefly J. Sellwood A. Shaw UK National Cyber Security Centre August 2023 Indicators of Compromise (IoCs) and Their Role in Attack Defence

[Timestomp] MITRE, "Indicator Removal: Timestomp", January 2020, <https://attack.mitre.org/techniques/T1099/>. [TLP] FIRST, "Traffic Light Protocol (TLP)", <https://www.first.org/tlp/>. Acknowledgements

[TAXII] OASIS Cyber Threat Intelligence (CTI), "Introduction to TAXII", <https://oasis-open.github.io/cti- documentation/taxii/intro.html>. [Timestomp] MITRE, "Indicator Removal: Timestomp", January 2020, <https://attack.mitre.org/techniques/T1099/>.

UK National Cyber Security Centre August 2023 Indicators of Compromise (IoCs) and Their Role in Attack Defence Abstract Cyber defenders frequently rely on Indicators of Compromise (IoCs) to identify, trace, and block malicious activity in networks or on

of the possible indicator values and theoretical completeness of a list of all possible indicator values. 5.2. Precision 5.2.1. Specificity Alongside pain and fragility, the PoP's levels can also be considered in terms of how precise the defence can be, with the false positive

which may cause performance degradation, particularly during detection. In some cases, such sources of indicators can lead to a pragmatic decision being made between obtaining reasonable coverage of the possible indicator values and theoretical completeness of a list of all possible indicator values. 5.2. Precision

## From NIST.SP.800-53r5

(XML) gateways. The devices verify adherence to protocol formats and specifications at the application layer and identify vulnerabilities that cannot be detected by devices that operate at the network or transport layers. The prevention of exfiltration is similar to data loss prevention or data leakage prevention and is closely associated with cross-domain solutions and system guards that enforce information flow requirements. Related Controls: AC-2, CA-8, SI-3.

AC-4(3) DYNAMIC INFORMATION FLOW CONTROL S AC-4(4) FLOW CONTROL OF ENCRYPTED INFORMATION S AC-4(5) EMBEDDED DATA TYPES S AC-4(6) METADATA S AC-4(7) ONE-WAY FLOW MECHANISMS S AC-4(8) SECURITY AND PRIVACY POLICY FILTERS S

AC-4(20) APPROVED SOLUTIONS O AC-4(21) PHYSICAL OR LOGICAL SEPARATION OF INFORMATION FLOWS O/S AC-4(22) ACCESS ONLY S AC-4(23) MODIFY NON-RELEASABLE INFORMATION O/S AC-4(24) INTERNAL NORMALIZED FORMAT S AC-4(25) DATA SANITIZATION S

AC-4 Information Flow Enforcement S AC-4(1) OBJECT SECURITY AND PRIVACY ATTRIBUTES S AC-4(2) PROCESSING DOMAINS S AC-4(3) DYNAMIC INFORMATION FLOW CONTROL S AC-4(4) FLOW CONTROL OF ENCRYPTED INFORMATION S AC-4(5) EMBEDDED DATA TYPES S

AC-3(13) ATTRIBUTE-BASED ACCESS CONTROL S AC-3(14) INDIVIDUAL ACCESS S AC-3(15) DISCRETIONARY AND MANDATORY ACCESS CONTROL S AC-4 Information Flow Enforcement S AC-4(1) OBJECT SECURITY AND PRIVACY ATTRIBUTES S AC-4(2) PROCESSING DOMAINS S

AC-4(17) DOMAIN AUTHENTICATION S AC-4(18) SECURITY ATTRIBUTE BINDING W: Incorporated into AC-16. AC-4(19) VALIDATION OF METADATA S AC-4(20) APPROVED SOLUTIONS O AC-4(21) PHYSICAL OR LOGICAL SEPARATION OF INFORMATION FLOWS O/S AC-4(22) ACCESS ONLY S
