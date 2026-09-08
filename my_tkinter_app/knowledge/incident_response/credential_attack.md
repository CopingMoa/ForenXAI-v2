# Credential attack — response

> **REVIEW REQUIRED.** These paragraphs were selected by keyword, not by judgement. Read them, keep what actually prescribes an action, delete the rest, then remove this marker. `--verify` fails while it is present.
>
> Covers: Bruteforce
>
> Source: Joint Task Force, "Security and privacy controls for information systems and organizations," NIST SP 800-53r5, rel. 5.2.0, Aug. 2025, doi: 10.6028/NIST.SP.800-53r5.
>   retrieved 2026-09-08, sha256 fc63bcd61715d018
> Source: Open Worldwide Application Security Project, "OWASP Top 10:2025 — web application security risks," OWASP Foundation, 2025.
>   retrieved 2026-09-08, sha256 37db8253029a5a6a
>
> Keep this file under about 1,500 words: the model's context is 8,192 tokens.


## From NIST.SP.800-53r5

address. If automatic system lockout or execution of a delay algorithm is not implemented in support of the availability objective, organizations consider a combination of other actions to help prevent brute force attacks. In addition to the above, organizations can prompt users to respond to a secret question before the number of allowed unsuccessful logon attempts is exceeded. Automatically unlocking an account after a specified period of time is generally not permitted. However, exceptions may be required based on operational mission or need.

AC-6(7) REVIEW OF USER PRIVILEGES O AC-6(8) PRIVILEGE LEVELS FOR CODE EXECUTION S AC-6(9) LOG USE OF PRIVILEGED FUNCTIONS S AC-6(10) PROHIBIT NON-PRIVILEGED USERS FROM EXECUTING PRIVILEGED FUNCTIONS AC-7 Unsuccessful Logon Attempts S

AC-6(10) PROHIBIT NON-PRIVILEGED USERS FROM EXECUTING PRIVILEGED FUNCTIONS AC-7 Unsuccessful Logon Attempts S AC-7(1) AUTOMATIC ACCOUNT LOCK W: Incorporated into AC-7. AC-7(2) PURGE OR WIPE MOBILE DEVICE S AC-7(3) BIOMETRIC ATTEMPT LIMITING O

the user’s last access. Related Controls: AC-7, PL-4. Control Enhancements: (1) PREVIOUS LOGON NOTIFICATION | UNSUCCESSFUL LOGONS Notify the user, upon successful logon, of the number of unsuccessful logon attempts since the last successful logon.

Related Controls: None. References: None. AC-7 UNSUCCESSFUL LOGON ATTEMPTS Control: a. Enforce a limit of [Assignment: organization-defined number] consecutive invalid logon attempts by a user during a [Assignment: organization-defined time period]; and

Related Controls: AC-2, AC-9, AU-2, AU-6, IA-5. Control Enhancements: (1) UNSUCCESSFUL LOGON ATTEMPTS | AUTOMATIC ACCOUNT LOCK [Withdrawn: Incorporated into AC-7.] (2) UNSUCCESSFUL LOGON ATTEMPTS | PURGE OR WIPE MOBILE DEVICE Purge or wipe information from [Assignment: organization-defined mobile devices] based

## From OWASP.Top10.2025

A02:2025 - Security Misconfiguration A03:2025 - Software Supply Chain Failures A04:2025 - Cryptographic Failures A05:2025 - Injection A06:2025 - Insecure Design A07:2025 - Authentication Failures

A05:2025 - Injection A06:2025 - Insecure Design A07:2025 - Authentication Failures A08:2025 - Software or Data Integrity Failures A09:2025 - Security Logging and Alerting Failures A10:2025 - Mishandling of Exceptional Conditions
