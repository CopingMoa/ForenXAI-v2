# Scanning and reconnaissance — response

> **REVIEW REQUIRED.** These paragraphs were selected by keyword, not by judgement. Read them, keep what actually prescribes an action, delete the rest, then remove this marker. `--verify` fails while it is present.
>
> Covers: PortScan
>
> Source: A. Nelson, S. Rekhi, M. Souppaya and K. Scarfone, "Incident response recommendations and considerations for cybersecurity risk management," NIST SP 800-61r3, Apr. 2025, doi: 10.6028/NIST.SP.800-61r3.
>   retrieved 2026-09-08, sha256 e5593d6bb85daece
> Source: Joint Task Force, "Security and privacy controls for information systems and organizations," NIST SP 800-53r5, rel. 5.2.0, Aug. 2025, doi: 10.6028/NIST.SP.800-53r5.
>   retrieved 2026-09-08, sha256 fc63bcd61715d018
> Source: K. Paine, O. Whitehouse, J. Sellwood and A. Shaw, "Indicators of compromise (IoCs) and their role in attack defence," RFC 9424, Aug. 2023, doi: 10.17487/RFC9424.
>   retrieved 2026-09-08, sha256 c11e9ebbcf4c5df5
>
> Keep this file under about 1,500 words: the model's context is 8,192 tokens.


## From NIST.SP.800-61r3

controls. DE.CM-03 Personnel activity and technology usage are monitored to find potentially adverse events High R1: Monitoring personnel activity and

of the incident’s magnitude, thus allowing the incident to continue indefinitely on other targets without the organization’s knowledge or monitoring. RS.CO (Incident Response

Assets are monitored to find anomalies, indicators of compromise, and other potentially adverse events High R1: Continuous monitoring for unauthorized activity, deviations from

commensurate with risk Medium N1: See the notes for PR. PR.PS-04 Log records are generated and made available for continuous monitoring Medium N1: Logs are particularly important for

to find potentially adverse events High R1: Monitoring personnel activity and technology usage should include anomalous user activity or unusual patterns of activity, authentication and

DE.CM-01 Networks and network services are monitored to find potentially adverse events High R1: Monitoring should include wired and wireless networks, network communications and flows, network

## From NIST.SP.800-53r5

Related Controls: CA-2, CA-7, CA-8, CM-2, CM-4, CM-6, CM-8, RA-2, RA-3, SA-11, SA-15, SC-38, SI-2, SI-3, SI-4, SI-7, SR-11. Control Enhancements: (1) VULNERABILITY MONITORING AND SCANNING | UPDATE TOOL CAPABILITY [Withdrawn: Incorporated into RA-5.] (2) VULNERABILITY MONITORING AND SCANNING | UPDATE VULNERABILITIES TO BE SCANNED

engineering techniques or by monitoring the behavior of executing code. Related Controls: None. References: [SP 800-83], [SP 800-125B], [SP 800-177]. SI-4 SYSTEM MONITORING Control:

include scanning external websites, monitoring social media, and training staff to recognize the unauthorized use of organizational information. Related Controls: None. References: None. AU-14 SESSION AUDIT Control:

Related Controls: None. References: [OMB A-130], [SP 800-30], [SP 800-39], [SP 800-161], [IR 8023], [IR 8062], [IR 8272]. RA-4 RISK ASSESSMENT UPDATE [Withdrawn: Incorporated into RA-3.] RA-5 VULNERABILITY MONITORING AND SCANNING Control:

CHAPTER THREE PAGE 185 This publication is available free of charge from: https://doi.org/10.6028/NIST.SP.800-53r5  systems and system monitoring capabilities to provide integrated threat coverage for the organization. Related Controls: SI-4.

SI-4 SYSTEM MONITORING Control:  NIST SP 800-53, REV. 5 SECURITY AND PRIVACY CONTROLS FOR INFORMATION SYSTEMS AND ORGANIZATIONS _________________________________________________________________________________________________ CHAPTER THREE PAGE 337

## From RFC9424

Kill chain: A model for conceptually breaking down a cyber intrusion into stages of the attack from reconnaissance through to actioning the attacker's objectives. This model allows defenders to think about, discuss, plan for, and implement controls to defend against

through blocking, monitoring, and responding to adversarial activity at the network, endpoint, or application levels.  Command and control (C2) server: An attacker-controlled server used to communicate with, send commands to, and receive data from compromised machines.

consuming.  A third important consideration when performing manual processing is the longer phase monitoring and adjustment necessary to effectively age out IoCs as they become irrelevant or, more crucially, inaccurate. Manual implementations must often simply include or

IoCs extrapolated from knowledge of past events (such as from identifying attacker infrastructure by monitoring domain name registration patterns).  Crucially, for an IoC to be discovered, the indicator must be extractable from the Internet protocol, tool, or technology it is

3.2.1. Discovery  IoCs are discovered initially through manual investigation or automated analysis. They can be discovered in a range of sources, including at endpoints and in the network (on the wire). They must either be extracted from logs monitoring protocol packet captures,

stages of the attack from reconnaissance through to actioning the attacker's objectives. This model allows defenders to think about, discuss, plan for, and implement controls to defend against discrete phases of an attacker's activity [KillChain].  Tactics, Techniques, and Procedures (TTPs):
