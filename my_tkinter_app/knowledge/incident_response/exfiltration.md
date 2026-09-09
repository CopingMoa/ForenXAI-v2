# Data exfiltration — response

> Source: Joint Task Force. 2025. Security and Privacy Controls for Information Systems and Organizations. NIST Special Publication 800-53, Revision 5, Release 5.2.0. National Institute of Standards and Technology, Gaithersburg, MD, USA. https://doi.org/10.6028/NIST.SP.800-53r5, Control SC-7.
> Source: Karen Kent, Suzanne Chevalier, Tim Grance, and Hung Dang. 2006. Guide to Integrating Forensic Techniques into Incident Response. NIST Special Publication 800-86. National Institute of Standards and Technology, Gaithersburg, MD, USA. https://doi.org/10.6028/NIST.SP.800-86
> Source: K. Paine, O. Whitehouse, J. Sellwood, and A. Shaw. 2023. Indicators of Compromise (IoCs) and Their Role in Attack Defence. RFC 9424. Internet Engineering Task Force. https://doi.org/10.17487/RFC9424
>
> Retrieved: 2026-09-08

## 1. What this class means here

Data leaving the network to a destination it should not reach: large or
sustained outbound transfers from an internal host, often to a destination
with no prior history.

**This is the class where preservation matters most and where containment
destroys evidence.** Isolating the source host first is the instinct and it
is usually wrong.

## 2. Detection and analysis

Record the internal source host, the external destination, the outbound byte
volume, the timing and the capture window.

Three questions decide severity:

- **How much left, and over what period?** Compare against that host's
  normal outbound volume, not against the network's.
- **Where did it go?** A destination the host has never contacted, or one
  that resolves to hosting infrastructure, is the finding. Check it as an
  indicator; RFC 9424 is the reference for how far an indicator match takes
  you.
- **What does that host have access to?** This bounds what could have left,
  which is the question the report has to answer.

**The flow record shows volume and destination, never content.** What
actually left is established from the host or from a proxy that logged it.

## 3. Containment

**Preserve first.** Session state, memory and open file handles on the
source host are the record of what was being read.

## From NIST.SP.800-86

> Data acquisition should be performed using a three-step process:
> developing a plan to acquire the data, acquiring the data, and verifying
> the integrity of the acquired data.

**Then block at the boundary**, not on the host — a boundary block is
reversible and does not alert the operator on the host:

## From NIST.SP.800-53r5

> a. Monitor and control communications at the external managed interfaces
> to the system and at key internal managed interfaces within the system;

**Then isolate the host**, once imaged.

**Rotate anything the host held.** Credentials, keys and tokens on that host
must be assumed disclosed.

## 4. What would make this a false positive

Backup to cloud storage, a large software update pushed outward, log
shipping to a SaaS collector, a video call, or a scheduled database export
all produce sustained high-volume outbound traffic to an external
destination.

The tell is the destination and the schedule. A known endpoint on a regular
interval is operations; an unrecognised endpoint once is the finding.

## 5. Not covered by these sources

None states a volume threshold above which outbound traffic is exfiltration,
nor a notification obligation. Neither establishes what data left — that
requires host or proxy evidence this tool does not see.
