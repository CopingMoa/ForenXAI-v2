# Buffer overflow against a listening service — response

> Source: Joint Task Force, "Security and privacy controls for information systems and organizations," NIST SP 800-53r5, control SI-2, rel. 5.2.0, Aug. 2025, doi: 10.6028/NIST.SP.800-53r5.
> Source: K. Kent, S. Chevalier, T. Grance and H. Dang, "Guide to integrating forensic techniques into incident response," NIST SP 800-86, Aug. 2006, doi: 10.6028/NIST.SP.800-86.
> Source: Cybersecurity and Infrastructure Security Agency, "Cybersecurity incident & vulnerability response playbooks," CISA, Washington, DC, USA, Nov. 2021.
>
> Retrieved: 2026-09-08

## 1. What this class means here

Oversized or malformed input to a listening network service, intended to
corrupt memory and run attacker-supplied code.

TRUSTLab's BufferOverflow is against a **network service**, not a client
application. It overlaps with Exploitation, and the model confuses the two;
where both appear, report the pair.

**Treat as attempted code execution.** This is the highest-urgency class in
the set.

## 2. Detection and analysis

Record the source, the target host, service and port, and the capture
window. The flow-level signal is unusual packet sizes to a service that
normally receives small, regular requests.

The confirmation is on the host, not in the capture:

- **Did the service crash, restart, or log a fault?** A restart at the
  timestamp is the strongest corroboration available.
- **Packet payloads** — long runs of repeated bytes, NOP-like padding, or
  input far exceeding the protocol's normal field lengths.
- **New processes, listeners or child processes** spawned by the service
  account after the window.

## 3. Containment

**Capture memory before anything else.** Isolating or rebooting the host
destroys the only place a live exploit is visible.

## From NIST.SP.800-86

> Data acquisition should be performed using a three-step process:
> developing a plan to acquire the data, acquiring the data, and verifying
> the integrity of the acquired data.

Then:

## From CISA.playbooks

> Isolate threat actor activity and prevent additional damage from the
> activity or pivoting into other systems. Key containment activities
> include:

**Patch, do not just block.** The address is disposable; the flaw is not:

## From NIST.SP.800-53r5

> a. Identify, report, and correct system flaws; b. Test software and
> firmware updates related to flaw remediation for effectiveness and
> potential side effects before installation;

**Rebuild rather than clean** if code execution is confirmed. A service
compromised at memory level cannot be reliably repaired in place.

## 4. What would make this a false positive

Legitimate large transfers to a service that usually receives small requests
— a file upload, a bulk API call, a database import — look identical at flow
level.

Protocol negotiation with unusual field lengths, and traffic from a broken
client sending malformed frames, both produce the same shape.

Without a crash, a log entry or a host artefact, this is an anomaly, not a
finding.

## 5. Not covered by these sources

None describes overflow techniques or how to recognise a specific exploit in
a payload. SI-2 states no patch window. Nothing here establishes whether
code actually executed — only host examination can.
