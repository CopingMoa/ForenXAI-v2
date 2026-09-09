# Scope and claim boundary

> Source: D. Arp, E. Quiring, F. Pendlebury, A. Warnecke, F. Pierazzi, C. Wressnegger, L. Cavallaro and K. Rieck, "Pitfalls in machine learning for computer security," Commun. ACM, vol. 67, no. 11, pp. 104-112, Nov. 2024, doi: 10.1145/3643456.
>
> Retrieved: 2026-09-08
>
> The measured figures below (952,000 training flows, 280,000 test flows,
> 0.9337 accuracy, 0.9287 macro F1) are this project's own results, not
> claims from the cited work. Arp et al. is cited for the general point
> that a score measured inside one environment does not transfer to
> another -- see [[extraction-validity]] and [[reliability]].

## What this model was built from

Trained and validated entirely on TRUSTLab. 952,000 training flows, 280,000
held-out test flows, sixteen classes, random split. Test accuracy 0.9337,
macro F1 0.9287.

## Where it has been shown to work

TRUSTLab held-out data only -- the same capture environment it learned from.

## Where it has not

Everywhere else. This is measured, not cautious wording. The same project
trained fifteen binary detectors on CICIDS2018 and TII-SSRC-23 and tested
them on TRUSTLab: mean ROC-AUC 0.4665, with eleven of fifteen below 0.50 --
worse than a coin flip, despite scoring 0.95-0.99 on their own data.

The cause was diagnosed: flow features do not survive a change of capture
environment. Training flows were extracted with a 120-second timeout;
TRUSTLab flows run to 15,717 seconds. Twenty-one of the 74 features differ
by more than three standard deviations between the two.

That is the sampling-bias pitfall, measured rather than assumed:

## From Arp.cacm

> The collected data does not sufficiently represent the true data
> distribution of the underlying security problem.

and the reason a held-out score inside one environment is not a deployment
claim:

## From Arp.cacm

> A learning-based system is solely evaluated in a laboratory setting,
> without discussing its practical limitations.

The figures above are this project's answer to the second: the limitation
is stated rather than left implicit.

## What to say in an interface

> Trained and validated on TRUSTLab. Accuracy on other capture environments
> is not established.

## What deploying elsewhere would require

Labelled traffic from the target network, extracted with a documented and
matching flow-timeout configuration, and retraining. Not a configuration
change.

## Per-class reliability

Twelve of sixteen classes are at F1 0.94 or above. Four are not:

| Class | F1 | Note |
|---|---|---|
| DoS | 0.6703 | confused with Slowloris |
| Slowloris | 0.7593 | confused with DoS |
| Exploitation | 0.7860 | bleeds into BufferOverflow |
| BufferOverflow | 0.8021 | overlaps Exploitation |
