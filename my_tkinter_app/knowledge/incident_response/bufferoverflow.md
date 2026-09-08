# Memory-corruption exploitation — response

> **REVIEW REQUIRED.** These paragraphs were selected by keyword, not by judgement. Read them, keep what actually prescribes an action, delete the rest, then remove this marker. `--verify` fails while it is present.
>
> Covers: BufferOverflow
>
> Source: Cybersecurity and Infrastructure Security Agency, "Cybersecurity incident & vulnerability response playbooks," CISA, Washington, DC, USA, Nov. 2021.
>   retrieved 2026-09-08, sha256 2277247542d844d2
> Source: A. Nelson, S. Rekhi, M. Souppaya and K. Scarfone, "Incident response recommendations and considerations for cybersecurity risk management," NIST SP 800-61r3, Apr. 2025, doi: 10.6028/NIST.SP.800-61r3.
>   retrieved 2026-09-08, sha256 e5593d6bb85daece
> Source: Joint Task Force, "Security and privacy controls for information systems and organizations," NIST SP 800-53r5, rel. 5.2.0, Aug. 2025, doi: 10.6028/NIST.SP.800-53r5.
>   retrieved 2026-09-08, sha256 fc63bcd61715d018
>
> Keep this file under about 1,500 words: the model's context is 8,192 tokens.


## From CISA.playbooks

vulnerability, initiate the Vulnerability Response Playbook below to address the vulnerability during eradication activities. Eradication Activities • Remediating all infected IT environments (e.g., cloud, OT, hybrid, host, and network

stringent enough. Therefore, eradication plans should be well formulated and coordinated before execution. If the adversary exploited a specific vulnerability, initiate the Vulnerability Response Playbook below to address the vulnerability during eradication activities.

Reporting and Notification Sharing information about how vulnerabilities are being exploited by adversaries can help defenders across the federal government understand which vulnerabilities are most critical to patch. CISA, in partnership with other federal agencies, is responsible for the overall security posture of the FCEB. As such, CISA needs to maintain awareness of the status of vulnerability response for actively exploited

most critical to patch. CISA, in partnership with other federal agencies, is responsible for the overall security posture of the FCEB. As such, CISA needs to maintain awareness of the status of vulnerability response for actively exploited vulnerabilities. This awareness enables CISA to help other agencies understand the impact of vulnerabilities and to narrow the time between disclosure and vulnerability exploitation. Agencies must report to CISA in accordance with Federal Incident Notification Guidelines, Binding Operational

Eradication & Recovery.................................................................................................................... 15 Post-Incident Activities ..................................................................................................................... 16 Coordination..................................................................................................................................... 17 Vulnerability Response Playbook......................................................................................................... 21 Preparation....................................................................................................................................... 21 Vulnerability Response Process....................................................................................................... 22

scratch. • Rebuilding hardware (required when the incident involves rootkits). • Replacing compromised files with clean versions. • Installing patches.

## From NIST.SP.800-61r3

select and perform eradication actions instead of or in addition to automated eradication measures. RC (Recover) Assets and operations affected by a cybersecurity incident are restored

an emergency workaround that must be removed within hours, a temporary workaround to be removed within two weeks, or a permanent solution). The eradication measure’s duration could be similarly evaluated.

R5: Monitor endpoints for cyber health issues (e.g., missing patches, malware infections, or unauthorized software), and redirect endpoints with issues to a remediation environment before access is authorized.

C1: Consider configuring cybersecurity technologies and the cybersecurity features of other technologies (e.g., operating systems, network infrastructure devices) to automatically perform some eradication actions.

including cybersecurity protection mechanisms, for signs of tampering, failure, or compromise. R5: Monitor endpoints for cyber health issues (e.g., missing patches, malware infections, or unauthorized software), and

weeks, or a permanent solution). The eradication measure’s duration could be similarly evaluated. R1: In some instances, organizations redirect an attacker to a sandbox so that they can monitor the attacker’s activity,

## From NIST.SP.800-53r5

SI-2(2) AUTOMATED FLAW REMEDIATION STATUS O SI-2(3) TIME TO REMEDIATE FLAWS AND BENCHMARKS FOR CORRECTIVE ACTIONS O SI-2(4) AUTOMATED PATCH MANAGEMENT TOOLS O/S SI-2(5) AUTOMATIC SOFTWARE AND FIRMWARE UPDATES O/S

SI-14 Non-Persistence O √ SI-14(1) REFRESH FROM TRUSTED SOURCES O √ SI-14(2) NON-PERSISTENT INFORMATION O √ SI-14(3) NON-PERSISTENT CONNECTIVITY O √ SI-15 Information Output Filtering S √ SI-16 Memory Protection S √

SI-14(3) NON-PERSISTENT CONNECTIVITY O √ SI-15 Information Output Filtering S √ SI-16 Memory Protection S √ SI-17 Fail-Safe Procedures S √ SI-18 Personally Identifiable Information Quality Operations O/S SI-18(1) AUTOMATION SUPPORT O/S

O SI-2(4) AUTOMATED PATCH MANAGEMENT TOOLS O/S SI-2(5) AUTOMATIC SOFTWARE AND FIRMWARE UPDATES O/S SI-2(6) REMOVAL OF PREVIOUS VERSIONS OF SOFTWARE AND FIRMWARE O/S SI-3 Malicious Code Protection O/S SI-3(1) CENTRAL MANAGEMENT W: Incorporated into PL-9.

Related Controls: SI-3, SI-4, SI-11. Control Enhancements: None. References: None. SI-16 MEMORY PROTECTION Control: Implement the following controls to protect the system memory from unauthorized code execution: [Assignment: organization-defined controls].

SI-16 MEMORY PROTECTION Control: Implement the following controls to protect the system memory from unauthorized code execution: [Assignment: organization-defined controls]. Discussion: Some adversaries launch attacks with the intent of executing code in non-executable regions of memory or in memory locations that are prohibited. Controls employed to protect memory include data execution prevention and address space layout randomization. Data
