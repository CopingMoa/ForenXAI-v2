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

Internet Protocol (IP) addresses, requiring a CAPTCHA to prevent automated attacks, or applying user profiles such as location, time of day, IP address, device, or Media Access Control (MAC) address. If automatic system lockout or execution of a delay algorithm is not implemented in support of the availability objective, organizations consider a combination of other actions to help prevent brute force attacks. In addition to the above, organizations can prompt users to respond to a secret question before the number of allowed unsuccessful logon attempts is

FUNCTIONS S AC-7 Unsuccessful Logon Attempts S AC-7(1) AUTOMATIC ACCOUNT LOCK W: Incorporated into AC-7. AC-7(2) PURGE OR WIPE MOBILE DEVICE S AC-7(3) BIOMETRIC ATTEMPT LIMITING O

AC-6(8) PRIVILEGE LEVELS FOR CODE EXECUTION S AC-6(9) LOG USE OF PRIVILEGED FUNCTIONS S AC-6(10) PROHIBIT NON-PRIVILEGED USERS FROM EXECUTING PRIVILEGED FUNCTIONS S AC-7 Unsuccessful Logon Attempts S

prevention mechanisms or malicious code protection mechanisms. Preventing non- privileged users from executing privileged functions is enforced by AC-3. Related Controls: None. References: None. AC-7 UNSUCCESSFUL LOGON ATTEMPTS Control:

AC-7(4) USE OF ALTERNATE AUTHENTICATION FACTOR O/S AC-8 System Use Notification O/S AC-9 Previous Logon Notification S AC-9(1) UNSUCCESSFUL LOGONS S  NIST SP 800-53, REV. 5 SECURITY AND PRIVACY CONTROLS FOR INFORMATION SYSTEMS AND ORGANIZATIONS

the user’s last access. Related Controls: AC-7, PL-4. Control Enhancements: (1) PREVIOUS LOGON NOTIFICATION | UNSUCCESSFUL LOGONS Notify the user, upon successful logon, of the number of unsuccessful logon attempts since the last successful logon.

## From OWASP.Top10.2025

A03:2025 - Software Supply Chain Failures A04:2025 - Cryptographic Failures A05:2025 - Injection A06:2025 - Insecure Design A07:2025 - Authentication Failures A08:2025 - Software or Data Integrity Failures

A06:2025 - Insecure Design A07:2025 - Authentication Failures A08:2025 - Software or Data Integrity Failures A09:2025 - Security Logging and Alerting Failures A10:2025 - Mishandling of Exceptional Conditions
