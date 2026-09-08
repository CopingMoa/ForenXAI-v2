# When two classes are indistinguishable

> Source: D. Arp et al., "Dos and don'ts of machine learning in computer security," in Proc. 31st USENIX Security Symp., Boston, MA, USA, Aug. 2022, pp. 3971-3988.
> Source: R. Sommer and V. Paxson, "Outside the closed world: On using machine learning for network intrusion detection," in Proc. IEEE Symp. Security and Privacy, Oakland, CA, USA, May 2010, pp. 305-316, doi: 10.1109/SP.2010.25.
>
> Retrieved: 2026-09-08

## 1. What the Ambiguity block means

The recommendations panel shows an Ambiguity block when the model's
**runner-up** class dominates the group — when, across the flows in this
finding, the second-choice class is consistently the same one and holds a
large share of the remaining probability.

That is not the model being unsure in a general way. It is a specific
statement: *these two classes look alike in this feature space*, and the
one on the label won by a margin that may not survive contact with a
different capture.

When it fires, the panel retrieves **both** playbooks. That is deliberate.
Presenting only the winner's playbook would imply a distinction the model
did not actually make.

## 2. The pair this model cannot separate

**DoS and Slowloris.** Both are resource-exhaustion attacks that hold
connections open rather than flooding. In the 74 flow features they produce
similar duration, packet-count and inter-arrival profiles. They are the two
weakest classes in the model (F1 0.6703 and 0.7593) and they are weak
largely *because of each other*.

If a finding is one of these, the defensible statement is "slow-rate
resource exhaustion consistent with DoS or Slowloris", not a choice between
them.

## 3. Why this is a feature-set limit, not a training failure

## From USENIX.dosdonts

> Spurious correlations result from artifacts that correlate with the task
> to solve but are not actually related to it, leading to false
> associations.

The mirror of that problem is this one: where two classes share their
genuine signal, no artefact is available to separate them, and a model that
appears to separate them cleanly on a test split is more suspicious than
one that does not. Confusion between genuinely similar classes is the
model behaving correctly about a real limit.

## 4. The deeper reason to expect this in network data

## From SommerPaxson.closedworld

> a semantic gap between detection results and their operational
> interpretation; (iv) the enormous variability of benign traffic, making
> it difficult to find stable notions of normality; (v) significant
> challenges with performing sound evaluation; and (vi) the need to
> operate in an adversarial setting.

The semantic gap is the point here. The model separates *statistical
patterns in flow records*. The class names are labels a human attached to
those patterns. Where two attack techniques produce one pattern, the label
is a human distinction the data does not carry.

## 5. What to do

| Situation | Action |
|---|---|
| Ambiguity block shown | Read both playbooks. Take the containment steps they agree on first — they are safe under either reading |
| The two playbooks conflict | The distinction matters to your case; resolve it from the capture, not the model |
| No ambiguity block, but runner-up close on individual flows | Check per-flow confidence in the SHAP panel; the aggregate can hide a split group |
| Reporting | Name both classes and the runner-up share. A single class name overstates what was determined |

## 6. Not covered by these sources

Neither source gives a threshold for when a runner-up share makes two
classes "ambiguous" — the margin used by this tool is its own convention.
Neither addresses how to word a forensic finding covering two candidate
classes. Both are yours to set.

Related: [[reliability]], [[confidence]], [[shap-reading]]
