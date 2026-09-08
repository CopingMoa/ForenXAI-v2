# Benign traffic — validation and event analysis

> Source: A. Nelson, S. Rekhi, M. Souppaya and K. Scarfone, "Incident response recommendations and considerations for cybersecurity risk management," NIST SP 800-61r3, Apr. 2025, doi: 10.6028/NIST.SP.800-61r3.
> Source: K. Paine, O. Whitehouse, J. Sellwood and A. Shaw, "Indicators of compromise (IoCs) and their role in attack defence," RFC 9424, Aug. 2023, doi: 10.17487/RFC9424.
>
> Retrieved: 2026-09-08

## 1. What "benign" means in this framework

SP 800-61r3 has no standalone glossary entry for *benign*; it establishes
the meaning through continuous monitoring and anomaly detection.

**An event is any observable occurrence** involving computing assets,
including networks and cloud environments. When continuous monitoring flags
an anomaly, the occurrence may have either a benign or a malicious
foundation.

**Attackers make malicious traffic resemble normal operations.**
Organisations are advised to use cyber threat information alongside
continuous monitoring to identify activity that might otherwise have been
incorrectly considered benign.

**An observation is not a conclusion.** Because an event is merely an
observable occurrence, additional analysis is required to determine whether
an adverse cybersecurity event is actually an incident.

## 2. Verification and log analysis

Separating truly benign anomalies from incidents requires specific
procedures.

**Tune continuously.** Automated monitoring technologies must be tuned to
reduce false positives and false negatives to acceptable levels.

**Correlate across sources.** Event correlation technologies — SIEM, SOAR —
gather related data captured across multiple sources. Current cyber threat
intelligence must be integrated into log analysis tools to improve
detection accuracy and characterise threat actors and indicators of
compromise.

**Filter with context.** Analysts apply defined incident criteria to the
known and assumed characteristics of the activity, taking known false
positives into account before declaring an incident.

**Review manually.** Automation cannot catch everything or monitor every
technology, so security personnel must regularly conduct manual reviews of
log events.

## 3. How this tool maps to those steps

**Continuous monitoring and feature extraction.** CICFlowMeter v4 converts
a capture into per-flow records, which is the monitoring and event-analysis
step above.

**Automated anomaly detection.** A sixteen-class XGBoost model processes
those flow features, filtering a large event set down to a subset suitable
for analysis.

**Contextual analysis.** Each finding carries its class, the model's
measured reliability for that class, and any ambiguity with another class —
which is the contextual information SP 800-61r3 asks be applied to observed
activity.

**Enabling manual review.** SHAP attributions translate the model's
statistical features into evidence an analyst can read, which is what makes
the required manual review of low-confidence flows practical rather than
nominal.

## 4. No action is required for a benign flow

There is no containment step for traffic classified as normal. The
recommendation is to take none.

## 5. What still deserves a second look

**Low-confidence benign.** A flow classified benign at 0.55 is not a
confident finding. The flow summary counts these.

**Benign as the runner-up on an attack finding.** Where the model nearly
said benign for a class it flagged, that classification is weaker than its
headline confidence suggests.

**The classes this model handles badly.** DoS scores F1 0.6703 and
Slowloris 0.7593 on held-out data. Traffic of those types is more likely
than average to be misfiled as benign, so the absence of a DoS finding is
not evidence there was none.

**The limit RFC 9424 states.** An indicator that does not match establishes
that this indicator did not match — not that the activity was absent.
Slow-and-low activity is designed to look ordinary at flow level, and
benign is the expected classification for a well-executed one.

## 6. Retention

SP 800-61r3 treats evidence handling as part of incident response.
Benign-classified flows belong to the same evidence item as the attack
findings in that capture, and are retained with them rather than discarded
as spare data.

## 7. Not covered by these sources

Neither source says how long to retain a capture, or the confidence
threshold below which a benign classification warrants manual review. Both
are site policy and belong in your own runbook.

Neither addresses how to establish, from flow records alone, that a benign
classification is correct. That would require endpoint evidence, which this
tool does not see.
