# Slow-rate connection exhaustion — response

> **REVIEW REQUIRED.** These paragraphs were selected by keyword, not by judgement. Read them, keep what actually prescribes an action, delete the rest, then remove this marker. `--verify` fails while it is present.
>
> Covers: Slowloris
>
> Source: A. Nelson, S. Rekhi, M. Souppaya and K. Scarfone, "Incident response recommendations and considerations for cybersecurity risk management," NIST SP 800-61r3, Apr. 2025, doi: 10.6028/NIST.SP.800-61r3.
>   retrieved 2026-09-08, sha256 e5593d6bb85daece
> Source: Joint Task Force, "Security and privacy controls for information systems and organizations," NIST SP 800-53r5, rel. 5.2.0, Aug. 2025, doi: 10.6028/NIST.SP.800-53r5.
>   retrieved 2026-09-08, sha256 fc63bcd61715d018
>
> Keep this file under about 1,500 words: the model's context is 8,192 tokens.


## From NIST.SP.800-61r3

ransomware, account takeover, denial of service).  NIST SP 800-61r3 Incident Response Recommendations and April 2025 Considerations for Cyber Risk Management

High R1: Perform a more detailed review of incidents to help categorize them by incident type (e.g., data breach, ransomware, account takeover, denial of service).

provenance are preserved High N1: Facts discovered and actions taken during incident response tasks can be recorded by many means, including a paper logbook, audio/video recordings, or automatic session monitoring and logging,

recorded by many means, including a paper logbook, audio/video recordings, or automatic session monitoring and logging, as permitted by the organization’s incident response plan and policy. R1: Safeguard the confidentiality and

an information system; or constitutes a violation or imminent threat of violation of law, security policies, security procedures, or acceptable use policies. [FISMA2014] Examples of incidents include an attacker: • Employing a botnet to send high volumes of connection requests to an internet-facing service, making it unavailable to legitimate service users

Examples of incidents include an attacker: • Employing a botnet to send high volumes of connection requests to an internet-facing service, making it unavailable to legitimate service users • Obtaining administrative credentials at a software-as-a-service provider, which puts sensitive tenant data entrusted to that provider at risk • Intruding upon an organization’s business network to steal credentials and use them to

## From NIST.SP.800-53r5

AC-11 Device Lock S AC-11(1) PATTERN-HIDING DISPLAYS S AC-12 Session Termination S AC-12(1) USER-INITIATED LOGOUTS O/S AC-12(2) TERMINATION MESSAGE S AC-12(3) TIMEOUT WARNING MESSAGE S

ensures that connections established during nonlocal maintenance and diagnostic sessions have been terminated and are no longer available for use. Related Controls: AC-12. References: [FIPS 140-3], [FIPS 197], [FIPS 201-2], [SP 800-63-3], [SP 800-88]. MA-5 MAINTENANCE PERSONNEL Control:

800-177], [IR 8023]. SC-9 TRANSMISSION CONFIDENTIALITY [Withdrawn: Incorporated into SC-8.] SC-10 NETWORK DISCONNECT Control: Terminate the network connection associated with a communications session at the end of the session or after [Assignment: organization-defined time period] of inactivity.

(FTP) sessions, systems typically send logout messages as final messages prior to terminating sessions. Related Controls: None. (3) SESSION TERMINATION | TIMEOUT WARNING MESSAGE Display an explicit message to users indicating that the session will end in [Assignment: organization-defined time until end of session].

of mission or business capabilities. Related Controls: SC-8, SC-12, SC-13. (7) NONLOCAL MAINTENANCE | DISCONNECT VERIFICATION Verify session and network connection termination after the completion of nonlocal maintenance and diagnostic sessions. Discussion: Verifying the termination of a connection once maintenance is completed

at the application level if multiple application sessions are using a single operating system-level network connection. Periods of inactivity may be established by organizations and include time periods by type of network access or for specific network accesses. Related Controls: AC-17, SC-23. Control Enhancements: None. References: None.
