# Command and control — response

> **REVIEW REQUIRED.** These paragraphs were selected by keyword, not by judgement. Read them, keep what actually prescribes an action, delete the rest, then remove this marker. `--verify` fails while it is present.
>
> Covers: C2Beaconing
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

overwhelming the organization’s resources. Most incidents require some form of containment. C1: Consider configuring cybersecurity technologies (e.g., antivirus software) and the cybersecurity features of other

prevent expansion of an event and mitigate its effects High N1: Manually selecting containment and eradication actions may be easier and faster if the organization has criteria and procedures in place. Criteria could take the

some of the risk evaluation factors in RS.MA. Another factor to consider is the duration of the containment measure (e.g., an emergency workaround that must be removed within hours, a temporary workaround to be removed within two

Containment, Eradication & Recovery Respond Recover Identify (Improvement Category) Post-Incident Activity Identify (Improvement Category) Organizations should use the incident response life cycle framework or model that suits them

C1: Consider configuring cybersecurity technologies (e.g., antivirus software) and the cybersecurity features of other technologies (e.g., operating systems, network infrastructure devices) to automatically perform some containment

## From RFC9424

the servers to be identified, their beacon configurations to be downloaded, and the associated infrastructure addresses to be extracted as IoCs.  The resulting mass IoCs for Cobalt Strike are:

these IoCs may be used by cyber defenders.  4.2.1. Cobalt Strike  Cobalt Strike [COBALT] is a commercial attack framework used for penetration testing that consists of an implant framework (beacon), a

4.2.1.1. Overall TTP  A beacon configuration describes how the implant should operate and communicate with its C2 server. This configuration also provides ancillary information such as the Cobalt Strike user licence

A beacon configuration describes how the implant should operate and communicate with its C2 server. This configuration also provides ancillary information such as the Cobalt Strike user licence watermark.  4.2.1.2. IoCs

Command and control (C2) server: An attacker-controlled server used to communicate with, send commands to, and receive data from compromised machines. Communication between a C2 server and compromised hosts is called "command and control traffic".

Communication between a C2 server and compromised hosts is called "command and control traffic".  Domain Generation Algorithm (DGA): The algorithm used in malware strains to periodically generate domain names (via algorithm). Malware may use DGAs to compute a

## From NIST.SP.800-53r5

SI-4 System Monitoring O/S √ SI-4(1) SYSTEM-WIDE INTRUSION DETECTION SYSTEM O/S √ SI-4(2) AUTOMATED TOOLS AND MECHANISMS FOR REAL-TIME ANALYSIS S √ SI-4(3) AUTOMATED TOOL AND MECHANISM INTEGRATION S √ SI-4(4) INBOUND AND OUTBOUND COMMUNICATIONS TRAFFIC S √ SI-4(5) SYSTEM-GENERATED ALERTS S √

3, SI-4, SI-5, SI-7, and SI-10. SC-15 Collaborative Computing Devices and Applications S SC-15(1) PHYSICAL OR LOGICAL DISCONNECT S SC-15(2) BLOCKING INBOUND AND OUTBOUND COMMUNICATIONS TRAFFIC W: Incorporated into SC-7. SC-15(3) DISABLING AND REMOVAL IN SECURE WORK AREAS O SC-15(4) EXPLICITLY INDICATE CURRENT PARTICIPANTS S

SI-4(3) AUTOMATED TOOL AND MECHANISM INTEGRATION S √ SI-4(4) INBOUND AND OUTBOUND COMMUNICATIONS TRAFFIC S √ SI-4(5) SYSTEM-GENERATED ALERTS S √ SI-4(6) RESTRICT NON-PRIVILEGED USERS W: Incorporated into AC-6(10). SI-4(7) AUTOMATED RESPONSE TO SUSPICIOUS EVENTS S √ SI-4(8) PROTECTION OF MONITORING INFORMATION W: Incorporated into SI-4.

exfiltration of information. Techniques used to prevent the exfiltration of information from systems may be implemented at internal endpoints, external boundaries, and across managed interfaces and include adherence to protocol formats, monitoring for beaconing activity from systems, disconnecting external network interfaces except when explicitly needed, employing traffic profile analysis to detect deviations from the volume and types of traffic expected, call backs to command and control centers, conducting penetration testing,

BY ASSURANCE SI-4(22) UNAUTHORIZED NETWORK SERVICES S √ SI-4(23) HOST-BASED DEVICES O √ SI-4(24) INDICATORS OF COMPROMISE S √ SI-4(25) OPTIMIZE NETWORK TRAFFIC ANALYSIS S √

engineering techniques or by monitoring the behavior of executing code. Related Controls: None. References: [SP 800-83], [SP 800-125B], [SP 800-177]. SI-4 SYSTEM MONITORING Control:
