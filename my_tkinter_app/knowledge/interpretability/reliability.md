# Per-class reliability: why one number for the model is not enough

> Source: D. Arp et al., "Dos and don'ts of machine learning in computer security," in Proc. 31st USENIX Security Symp., Boston, MA, USA, Aug. 2022, pp. 3971-3988.
> Source: R. Arslan, T. Ozseven, M. M. Aydin and Y. Celik, "Cybersecurity in intelligent transportation systems: A comparative study on AI-based anomaly detection and threat analysis," Mechatronics and Intelligent Transportation Systems, vol. 5, no. 1, pp. 11-30, 2026, doi: 10.56578/mits050102.
>
> Retrieved: 2026-09-08

## 1. The headline figure and what it conceals

This model scores **0.9337 accuracy** and **0.9287 macro F1** on 280,000
held-out TRUSTLab flows. Both are averages over sixteen classes, and an
average is exactly the wrong summary when the classes differ this much:

| Class | F1 | Read a finding as |
|---|---|---|
| DoS | 0.6703 | Weak — corroborate before reporting |
| Slowloris | 0.7593 | Weak — corroborate before reporting |
| Most other classes | above 0.94 | Consistent with the measured behaviour |

A DoS finding and a DDoS finding look identical on screen. They are not
equally reliable, and the difference is not small: roughly one in three DoS
decisions was wrong on data drawn from the same environment the model was
trained in.

## 2. Why the average is the wrong measure

Arp et al. name this pitfall P7, inappropriate performance measures: a
measure that does not account for the constraints of the application, such
as imbalanced data or the need to keep a low false-positive rate.

A macro average gives the weakest class the same weight as the strongest,
which flatters the model when most classes are easy. A weighted average is
worse for this purpose: it lets the largest classes hide the smallest. The
per-class figure is the only one that answers the question an investigator
is actually asking, which is "how much should I trust *this* finding".

## 3. Precision and recall are different questions

F1 combines two things that fail in opposite directions, and which one is
failing changes what you should do:

- **Low precision** — the class fires when it should not. Findings in it
  contain false alarms. The cost is wasted analyst time.
- **Low recall** — the class misses real instances. The absence of a
  finding proves nothing. The cost is a missed intrusion.

F1 alone cannot tell you which. When a weak class matters to your case,
look at the per-class precision and recall in the pipeline's own evaluation
output rather than at F1.

## 4. Why the weakest classes are weak here

DoS and Slowloris are both slow-rate resource-exhaustion attacks, and at
flow-record level they resemble each other and, in places, ordinary
long-lived sessions. This is a limit of the feature set, not a training
accident: the information needed to separate them is largely absent from
the 74 features. Retraining will not fix it; different features would.

## 5. The wider point about what a test-set score means

Accuracy is the measure most distorted by imbalance, and a single-figure
alternative exists:

## From Arslan.mits

> Matthews correlation coefficient (MCC) combines the four elements of the
> confusion matrix to yield a balanced score from -1 (complete
> misclassification) to 0 (random prediction) to +1 (perfect
> classification). Unlike accuracy, MCC is still informative even under
> extreme class distribution skew

This pipeline reports accuracy and macro F1, not MCC. That is a limitation
of the reporting, not a defence of it.

A score measured on a held-out split of the same capture is the most
favourable measurement available. It is an upper bound on what to expect
elsewhere, never an estimate — see [[scope]].

## 6. What to do

| Situation | Action |
|---|---|
| Finding in a weak class | Say so in the report, with the F1 figure. Corroborate from the capture before asserting it |
| No finding in a weak class | Do not report "no DoS activity". Report "no DoS activity was classified", which is a different claim |
| Finding in a strong class | Reliability is consistent with the measured behaviour; the remaining questions are confidence and scope |
| Weak class AND low confidence | Treat as a lead only |

## 7. Not covered by these sources

Neither source states an F1 below which a classifier should not be used
operationally, and neither addresses evidential weight in a forensic
report. The 0.94 boundary used above is this project's own reading of its
measured results, not a threshold either paper endorses.

Related: [[confidence]], [[class-ambiguity]], [[scope]], [[shap-reading]]
