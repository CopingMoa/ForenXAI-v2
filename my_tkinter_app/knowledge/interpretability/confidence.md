# Reading the confidence number

> Source: D. Arp et al., "Dos and don'ts of machine learning in computer security," in Proc. 31st USENIX Security Symp., Boston, MA, USA, Aug. 2022, pp. 3971-3988.
> Source: R. Arslan, T. Ozseven, M. M. Aydin and Y. Celik, "Cybersecurity in intelligent transportation systems: A comparative study on AI-based anomaly detection and threat analysis," Mechatronics and Intelligent Transportation Systems, vol. 5, no. 1, pp. 11-30, 2026, doi: 10.56578/mits050102.
>
> Retrieved: 2026-09-08

## 1. What the number on screen actually is

Every finding carries a confidence, and every SHAP panel carries one too.
It is the largest value of `predict_proba` across the sixteen classes — the
model's own score for the class it chose, after the softmax over its raw
outputs.

Three things it is **not**:

**It is not a probability that the finding is correct.** It is the model's
score, not a measured frequency. Nothing in this pipeline has checked that
flows scored 0.90 are right 90% of the time. That check is called
calibration and it has not been run on this model, so the number ranks
flows against each other but does not convert to a chance of being right.

**It is not evidence about classes the model does not have.** The softmax
sums to 1.0 across the sixteen trained classes. Traffic belonging to none
of them still produces a confident answer, because the model has no way to
say "not in my vocabulary".

**It is not a measure of how much the model saw.** A single-packet flow and
a ten-minute session both get a score. Confidence says nothing about how
much evidence the flow contained.

## 2. Why a low-confidence flow matters more here than elsewhere

A false positive spends analyst time on traffic that turns out to be
ordinary; a false negative misses an intrusion. Neither is cheap, and
Arslan et al. put reducing the first among the reasons explanation matters
operationally:

## From Arslan.mits

> In security-centric operations (in SOCs), the explainability of machine
> learning models is an important requirement in terms of prioritizing
> generated alarms more accurately and quickly (alarm triage),
> investigating possible proactive attacks (threat hunting), and meeting
> legal/regulatory requirements [33-35].

That asymmetry is why the Flow Summary panel counts flows below 0.60
separately rather than folding them into an average. The average hides
them; the count does not.

## 3. The trap that catches most readers: base rates

A capture is mostly normal traffic. That imbalance changes what a
false-positive rate means, and the effect is much larger than intuition
suggests. Arp et al. list this as pitfall P8, the base rate fallacy: when
the negative class predominates, even a very low false-positive rate
produces a surprising number of false positives. They work the arithmetic
through:

## From USENIX.dosdonts

> consider the example in Figure 2 where 99 % true positives are possible
> at 1 % false positives. Yet, if we consider the class ratio of 1:100,
> this actually corresponds to 100 false positives for every 99 true
> positives.

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
