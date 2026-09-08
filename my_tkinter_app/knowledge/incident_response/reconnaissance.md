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

replaced, and removed commensurate with risk Medium N1: See the notes for PR. PR.PS-04 Log records are generated and made available for continuous monitoring

the monitoring and analysis activities performed to find and characterize potentially adverse events and, in turn, find cybersecurity incidents. DE.CM (Continuous

technology usage are monitored to find potentially adverse events High R1: Monitoring personnel activity and technology usage should include anomalous user activity or unusual

monitoring operations and usage to detect adverse cybersecurity events, and identifying “shadow IT” usage. ID.AM-03 Representations of the organization’s authorized network communication and

adverse events High R1: Monitoring should include wired and wireless networks, network communications and flows, network services (e.g., DNS and BGP), and the presence of unauthorized or rogue

DE.CM-06 External service provider activities and services are monitored to find potentially adverse events High R1: Monitoring external service provider activities and services should include

## From NIST.SP.800-53r5

Related Controls: CA-2, CA-7, CA-8, CM-2, CM-4, CM-6, CM-8, RA-2, RA-3, SA-11, SA-15, SC-38, SI-2, SI-3, SI-4, SI-7, SR-11. Control Enhancements: (1) VULNERABILITY MONITORING AND SCANNING | UPDATE TOOL CAPABILITY [Withdrawn: Incorporated into RA-5.] (2) VULNERABILITY MONITORING AND SCANNING | UPDATE VULNERABILITIES TO BE SCANNED

preventing such extraneous content from being displayed, and then alerting monitoring tools that anomalous behavior has been discovered. Related Controls: SI-3, SI-4, SI-11. Control Enhancements: None. References: None. SI-16 MEMORY PROTECTION

SI-4(16) CORRELATE MONITORING INFORMATION O/S √ SI-4(17) INTEGRATED SITUATIONAL AWARENESS O √ SI-4(18) ANALYZE TRAFFIC AND COVERT EXFILTRATION O/S √ SI-4(19) RISK FOR INDIVIDUALS O √ SI-4(20) PRIVILEGED USERS S √ SI-4(21) PROBATIONARY PERIODS O √

SI-3(6) TESTING AND VERIFICATION O SI-3(7) NONSIGNATURE-BASED DETECTION W: Incorporated into SI-3. SI-3(8) DETECT UNAUTHORIZED COMMANDS S SI-3(9) AUTHENTICATE REMOTE COMMANDS W: Moved to AC-17(10). SI-3(10) MALICIOUS CODE ANALYSIS O SI-4 System Monitoring O/S √

future threats. Organizations can conduct malicious code analyses by employing reverse engineering techniques or by monitoring the behavior of executing code. Related Controls: None. References: [SP 800-83], [SP 800-125B], [SP 800-177]. SI-4 SYSTEM MONITORING Control:

AC-18 Wireless Access O AC-18(1) AUTHENTICATION AND ENCRYPTION S AC-18(2) MONITORING UNAUTHORIZED CONNECTIONS W: Incorporated into SI-4. AC-18(3) DISABLE WIRELESS NETWORKING O/S AC-18(4) RESTRICT CONFIGURATIONS BY USERS O AC-18(5) ANTENNAS AND TRANSMISSION POWER LEVELS O

## From RFC9424

2. Terminology Attack defence: The activity of providing cyber security to an environment through the prevention of, detection of, and response to attempted and successful cyber intrusions. A successful defence can be achieved through blocking, monitoring, and responding to adversarial

Kill chain: A model for conceptually breaking down a cyber intrusion into stages of the attack from reconnaissance through to actioning the attacker's objectives. This model allows defenders to think about, discuss, plan for, and implement controls to defend against discrete phases of an attacker's activity [KillChain].

destination for C2 traffic rather than relying on a pre-assigned list of static IP addresses or domains that can be blocked more easily when extracted from, or otherwise linked to, the malware. Kill chain: A model for conceptually breaking down a cyber intrusion into stages of the attack from reconnaissance through to actioning the

consuming. A third important consideration when performing manual processing is the longer phase monitoring and adjustment necessary to effectively age out IoCs as they become irrelevant or, more crucially, inaccurate. Manual implementations must often simply include or exclude an IoC, as anything more granular is time-consuming and

the prevention of, detection of, and response to attempted and successful cyber intrusions. A successful defence can be achieved through blocking, monitoring, and responding to adversarial activity at the network, endpoint, or application levels. Command and control (C2) server: An attacker-controlled server used to communicate with, send

investigation. IoCs are deployed to firewalls and other security control points by adding them to the list of indicators that the control point is searching for in the traffic that it is monitoring. When associated with malicious activity, the following are some examples of protocol-related IoCs: * IPv4 and IPv6 addresses in network traffic
