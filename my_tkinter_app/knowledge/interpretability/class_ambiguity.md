# When two classes are indistinguishable

> Source: Daniel Arp, Erwin Quiring, Feargus Pendlebury, Alexander Warnecke, Fabio Pierazzi, Christian Wressnegger, Lorenzo Cavallaro, and Konrad Rieck. 2024. Pitfalls in Machine Learning for Computer Security. Commun. ACM 67, 11 (Nov. 2024), 104-112. https://doi.org/10.1145/3643456
> Source: S. S. Iyengar, S. Nabavirazavi, Y. Hariprasad, Prasad HB, and C. Krishna Mohan. 2025. Artificial Intelligence in Practice: Theory and Application for Cyber Security and Forensics. Springer Nature, Cham, Switzerland. https://doi.org/10.1007/978-3-031-89327-8
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

## From Arp.cacm

> Spurious correlations result from artifacts that correlate with the task
> to solve but are not actually re - lated to it, leading to false
> associations.

The mirror of that problem is this one: where two classes share their
genuine signal, no artefact is available to separate them, and a model that
appears to separate them cleanly on a test split is more suspicious than
one that does not. Confusion between genuinely similar classes is the
model behaving correctly about a real limit.

## 4. The deeper reason to expect this in network data

The model separates *statistical patterns in flow records*. The class names
are labels a human attached to those patterns. Where two attack techniques
produce one pattern, the label is a distinction the data does not carry.

Rarity plausibly makes it worse, and that claim is **not** sourced here: it
is this project's reading of its own per-class F1 figures, and no document
in `knowledge/_sources` states it. Treat it as a hypothesis about this
model, not a finding.

What the sources do support is why an ambiguous pair is reported rather
than resolved. An explanation exists so a person can find the model's
error, not so the model can settle the question:

## From Iyengar.aip

> By grasping the AI's decisions, forensic experts can pinpoint where the
> AI might be going wrong. They can identify potential errors in the
> reasoning and fix them before they cause a wrongful conviction.

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
classes. Neither states that a rare class is separated worse than a common
one, which is why §4 above marks that as unsourced. All three are yours to
set.

Related: [[reliability]], [[confidence]], [[shap-reading]]
