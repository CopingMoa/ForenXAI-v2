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

RS.MI (Incident Mitigation) Activities are performed to prevent expansion of an event and mitigate its effects High N1: Manually selecting containment and

Assets are monitored to find anomalies, indicators of compromise, and other potentially adverse events High R1: Continuous monitoring for unauthorized activity, deviations from

other indicators, such as an unavailable service. Other incident response teams may also report incidents to the organization. RS.MA-03 Incidents are categorized and prioritized

other restoration assets is verified before using them for restoration High R1: Check restoration assets for indicators of compromise, file corruption, and other integrity issues before use.

data leaks, exfiltration, and other adverse events. R2: Monitor authentication attempts to identify attacks against credentials and unauthorized credential use. R3: Monitor software and hardware

operating status is confirmed High R1: Check restored assets for indicators of compromise, and remediate the root causes of the incident before production use. R2: Verify the correctness and adequacy of

## From RFC9424

[Timestomp] MITRE, "Indicator Removal: Timestomp", January 2020, <https://attack.mitre.org/techniques/T1099/>.  [TLP] FIRST, "Traffic Light Protocol (TLP)", <https://www.first.org/tlp/>.

TAXII", <https://oasis-open.github.io/cti- documentation/taxii/intro.html>.  [Timestomp] MITRE, "Indicator Removal: Timestomp", January 2020, <https://attack.mitre.org/techniques/T1099/>.

encoded in the DNS response [LAZARUS].  5.1.3. Completeness  In many cases, the list of indicators resulting from an activity or discovered in a malware sample is relatively short and so only adds

Indicators of Compromise (IoCs) and Their Role in Attack Defence  Abstract  Cyber defenders frequently rely on Indicators of Compromise (IoCs) to identify, trace, and block malicious activity in networks or on

detection. In some cases, such sources of indicators can lead to a pragmatic decision being made between obtaining reasonable coverage of the possible indicator values and theoretical completeness of a list of all possible indicator values.  5.2. Precision

IoCs extrapolated from knowledge of past events (such as from identifying attacker infrastructure by monitoring domain name registration patterns).  Crucially, for an IoC to be discovered, the indicator must be extractable from the Internet protocol, tool, or technology it is

## From NIST.SP.800-53r5

(XML) gateways. The devices verify adherence to protocol formats and specifications at the application layer and identify vulnerabilities that cannot be detected by devices that operate at the network or transport layers. The prevention of exfiltration is similar to data loss prevention or data leakage prevention and is closely associated with cross-domain solutions and system guards that enforce information flow requirements. Related Controls: AC-2, CA-8, SI-3.

AC-4(1) OBJECT SECURITY AND PRIVACY ATTRIBUTES S AC-4(2) PROCESSING DOMAINS S AC-4(3) DYNAMIC INFORMATION FLOW CONTROL S AC-4(4) FLOW CONTROL OF ENCRYPTED INFORMATION S AC-4(5) EMBEDDED DATA TYPES S AC-4(6) METADATA S

AC-4(21) PHYSICAL OR LOGICAL SEPARATION OF INFORMATION FLOWS O/S AC-4(22) ACCESS ONLY S AC-4(23) MODIFY NON-RELEASABLE INFORMATION O/S AC-4(24) INTERNAL NORMALIZED FORMAT S AC-4(25) DATA SANITIZATION S AC-4(26) AUDIT FILTERING ACTIONS O/S

AC-3(14) INDIVIDUAL ACCESS S AC-3(15) DISCRETIONARY AND MANDATORY ACCESS CONTROL S AC-4 Information Flow Enforcement S AC-4(1) OBJECT SECURITY AND PRIVACY ATTRIBUTES S AC-4(2) PROCESSING DOMAINS S AC-4(3) DYNAMIC INFORMATION FLOW CONTROL S

harm the services or systems on the destination network. Related Controls: SI-3. (16) INFORMATION FLOW ENFORCEMENT | INFORMATION TRANSFERS ON INTERCONNECTED SYSTEMS [Withdrawn: Incorporated into AC-4.] (17) INFORMATION FLOW ENFORCEMENT | DOMAIN AUTHENTICATION

AC-4(18) SECURITY ATTRIBUTE BINDING W: Incorporated into AC-16. AC-4(19) VALIDATION OF METADATA S AC-4(20) APPROVED SOLUTIONS O AC-4(21) PHYSICAL OR LOGICAL SEPARATION OF INFORMATION FLOWS O/S AC-4(22) ACCESS ONLY S AC-4(23) MODIFY NON-RELEASABLE INFORMATION O/S
