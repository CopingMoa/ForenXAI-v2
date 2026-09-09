# When the features themselves are not comparable

> Source: Daniel Arp, Erwin Quiring, Feargus Pendlebury, Alexander Warnecke, Fabio Pierazzi, Christian Wressnegger, Lorenzo Cavallaro, and Konrad Rieck. 2024. Pitfalls in Machine Learning for Computer Security. Commun. ACM 67, 11 (Nov. 2024), 104-112. https://doi.org/10.1145/3643456
>
> Retrieved: 2026-09-08

## 1. The step before the model

A PCAP is not what the model sees. A flow extractor turns packets into
per-flow records, and every decision it makes — where one flow ends and the
next begins, what counts as idle, how a subflow is split — changes the
feature values the model is then asked to classify.

If those decisions differ from the ones used to build the training set, the
model receives numbers that mean something different from what it learned,
and it will still return a confident answer. Nothing errors.

## 2. Two things this tool records, and why

**Which engine ran.** CICFlowMeter v4 is the reference implementation the
training data was built with. When it is unavailable this tool falls back
to a pure-Python extractor. Both use a 120-second flow timeout, but their
activity, bulk and subflow boundaries differ. The engine is written to
`flow_extraction.json` beside the flow CSV and shown in the Flow Summary
panel, so a feature value can always be traced to the code that computed
it.

**Whether the timeout truncated flows.** If the longest flow in a capture
is almost exactly the timeout, flows were cut by the extractor rather than
by the traffic. Every timing feature — durations, inter-arrival statistics,
idle and active periods — is then measuring the extractor, not the network.
The Flow Summary panel warns when it sees this.

## 3. Why this is a correctness problem, not a tidiness one

## From Arp.cacm

> Spurious correlations result from artifacts that correlate with the task
> to solve but are not actually re - lated to it, leading to false
> associations.

An extraction artefact is exactly such an artefact. If the training capture
and the evidence capture were extracted with different settings, a feature
can separate the classes for reasons that have nothing to do with the
traffic.

The related failure they describe is sampling bias, where the correlations
come from differences between the data the model was fitted on and the data
it is actually used on. A capture extracted differently from the training
set is exactly that difference.

## 4. What to check before trusting a finding

| Check | Where | If it fails |
|---|---|---|
| Which engine produced the flows | Flow Summary panel, `flow_extraction.json` | Note it in the report; prefer re-extracting with CICFlowMeter v4 for anything contested |
| Flow-timeout warning | Flow Summary panel | Every timing feature is suspect. Re-extract with a timeout matching the training data before relying on the result |
| Coerced cells at intake | Flow Summary panel | Non-numeric values became zeros. A high share means the CSV is not what it claims |
| Capture window vs sum of flow durations | Flow Summary panel | These differ legitimately (flows overlap). A capture window far shorter than expected suggests a truncated capture |

## 5. The one that cannot be checked from inside

A truncated or filtered capture looks entirely normal at flow level. If
packets were dropped at the capture point, or a BPF filter was applied
before recording, the flow table is internally consistent and describes
traffic that is not what crossed the wire. Only the capture's own metadata
and chain of custody can settle that, and this tool does not see them.

## 6. Not covered by this source

Arp et al. address machine-learning methodology, not packet capture. They
say nothing about flow-extractor configuration, capture integrity, or
evidence handling. The engine and timeout guidance above is this project's
own, derived from how its training data was built.

Related: [[scope]], [[confidence]], [[shap-reading]]
