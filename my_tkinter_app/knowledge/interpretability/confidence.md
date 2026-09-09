# Reading the confidence number

> Source: D. Arp, E. Quiring, F. Pendlebury, A. Warnecke, F. Pierazzi, C. Wressnegger, L. Cavallaro and K. Rieck, "Pitfalls in machine learning for computer security," Commun. ACM, vol. 67, no. 11, pp. 104-112, Nov. 2024, doi: 10.1145/3643456.
> Source: S. S. Iyengar, S. Nabavirazavi, Y. Hariprasad, Prasad HB and C. Krishna Mohan, Artificial Intelligence in Practice: Theory and Application for Cyber Security and Forensics. Cham, Switzerland: Springer Nature, 2025, doi: 10.1007/978-3-031-89327-8.
>
> Retrieved: 2026-09-08

## 1. What the number on screen actually is

Every finding carries a confidence, and every SHAP panel carries one too.
It is the largest value of `predict_proba` across the sixteen classes — the
model's own score for the class it chose, after the softmax over its raw
outputs.

Three things it is **not**:

**It is a calibrated probability ON TRUSTLAB, and this project has now
measured that.** Calibration asks whether flows scored 0.90 really are right
about 90% of the time. Measured across all 280,000 held-out TRUSTLab flows:

| Confidence | Flows | Mean confidence | Actual accuracy |
|---|---|---|---|
| below 0.60 | 19,193 | 0.5252 | 0.5111 |
| 0.60-0.70 | 13,589 | 0.6503 | 0.6328 |
| 0.70-0.80 | 11,138 | 0.7453 | 0.7223 |
| 0.80-0.90 | 2,957 | 0.8463 | 0.8008 |
| 0.90-0.95 | 4,520 | 0.9371 | 0.9312 |
| 0.95-0.99 | 3,962 | 0.9750 | 0.9677 |
| 0.99-1.00 | 224,641 | 0.9997 | 0.9997 |

Expected Calibration Error is **0.0034**, and no bin is out by more than
0.046. The number therefore does convert to a chance of being right --
*inside the environment it was measured in*. These are this project's own
measurements, not a claim from either source.

**The 0.60 threshold is measured, not chosen.** Below it, accuracy is 0.5111
across 19,193 flows -- barely better than a coin flip between the two most
likely classes. At or above it, accuracy is 0.9648. That is the empirical
justification for surfacing those flows for review.

**It is still not a probability anywhere else.** Calibration was measured on
a held-out split of the same capture environment the model was trained in.
Nothing here establishes that it holds on another network -- see [[scope]],
where the same model scored a mean ROC-AUC of 0.4665 across two other
datasets.

**It is not evidence about classes the model does not have.** The softmax
sums to 1.0 across the sixteen trained classes. Traffic belonging to none
of them still produces a confident answer, because the model has no way to
say "not in my vocabulary".

**It is not a measure of how much the model saw.** A single-packet flow and
a ten-minute session both get a score. Confidence says nothing about how
much evidence the flow contained.

## 2. Why a low-confidence flow matters more here than elsewhere

A false positive spends analyst time on traffic that turns out to be
ordinary; a false negative misses an intrusion. Neither is cheap, and the
explanation is what lets an analyst separate the two:

## From Iyengar.aip

> In cyber forensics, XAI algorithms play a crucial role in explaining the
> processes of data recovery and threat detection.

## From Iyengar.aip

> By grasping the AI's decisions, forensic experts can pinpoint where the
> AI might be going wrong. They can identify potential errors in the
> reasoning and fix them before they cause a wrongful conviction.

A low-confidence flow is where that pinpointing is actually needed, which
is why the Flow Summary panel counts flows below 0.60 separately rather
than folding them into an average. The average hides them; the count does
not.

## 3. The trap that catches most readers: base rates

A capture is mostly normal traffic. That imbalance changes what a
false-positive rate means, and the effect is much larger than intuition
suggests. Arp et al. list this as pitfall P8, the base rate fallacy:

## From Arp.cacm

> Class imbalance can easily lead to a misin - terpretation of performance
> if the base rate of the negative class is not considered. If this class
> is predominant, even a very low false-positive rate can result in
> surprisingly high numbers of false positives.

Applied here: a capture that is 95% benign, scored by a model with a 1%
false-positive rate on benign flows, produces roughly one spurious attack
finding for every twenty real ones — before any question of whether the
class is right. **A small attack count in a large capture is the case where
this matters most**, and it is exactly the case that looks most alarming on
screen.

## 4. What to do with a specific number

| What you see | What it means | What to do |
|---|---|---|
| High confidence, class with strong F1 | The model is doing what it was measured doing | Proceed to the class playbook |
| Below 0.60 | Below the panel's review threshold | Open the flow, read the SHAP attributions, confirm against the raw capture before reporting it |
| High confidence, few flows, large capture | Base rate applies | Treat as a lead, not a finding; corroborate from another source |
| High confidence, class with weak F1 | Confidence and reliability disagree | Reliability wins — see [[reliability]] |
| Runner-up close behind | The pair may be indistinguishable to this model | See [[class-ambiguity]] |

## 5. The threshold is ours, not the sources'

Neither source names 0.60, or any other cut-off. The threshold in this tool
is a display convention for deciding which flows to surface for review, and
it is not derived from either document. Set it from your own error budget:
how many flows can actually be reviewed by hand, against what a missed
detection costs you.

## 6. Not covered by these sources

Neither source gives a procedure for calibrating a multiclass network
classifier, nor a defensible confidence threshold for forensic reporting.
Neither addresses what confidence means for a class the model was never
trained on. Those remain open, and the honest position is to treat
confidence as a ranking, not a probability.

Related: [[reliability]], [[shap-reading]], [[class-ambiguity]], [[scope]]
