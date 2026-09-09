# How far a SHAP attribution can be pushed

> Source: D. Arp, E. Quiring, F. Pendlebury, A. Warnecke, F. Pierazzi, C. Wressnegger, L. Cavallaro and K. Rieck, "Pitfalls in machine learning for computer security," Commun. ACM, vol. 67, no. 11, pp. 104-112, Nov. 2024, doi: 10.1145/3643456.
> Source: T. Chen and C. Guestrin, "XGBoost: A scalable tree boosting system," in Proc. 22nd ACM SIGKDD Int. Conf. Knowledge Discovery and Data Mining, San Francisco, CA, USA, Aug. 2016, pp. 785-794, doi: 10.1145/2939672.2939785.
> Source: S. S. Iyengar, S. Nabavirazavi, Y. Hariprasad, Prasad HB and C. Krishna Mohan, Artificial Intelligence in Practice: Theory and Application for Cyber Security and Forensics. Cham, Switzerland: Springer Nature, 2025, doi: 10.1007/978-3-031-89327-8.
>
> Retrieved: 2026-09-08
>
> The per-model figures below (0.9044 importance correlation, 1.8e-05
> additivity error) are this project's own measurements. What TreeSHAP
> computes is a property of the library this pipeline calls, not a claim
> from any source below; the sources are cited for what the model is, and
> for what an explanation is for in a forensic setting.

Quote these limits alongside any explanation. They are what separates an
explanation from a claim.

## From Iyengar.aip

> Finally, we must ensure that any use of XAI in forensics complies with
> evidence admissibility standards.

For what a SHAP value is and how to read the panel, see [[shap-reading]].
This file is only the limits.

## What a SHAP value is

The contribution one feature made to this prediction, relative to the
model's base value for that class.

**Contributions sum to the raw margin, in log-odds — not to the
prediction.** Stating it loosely ("they sum to the prediction") invites
adding a SHAP value to a probability, and the two are in different units.
On this model the attributions plus the base value reconstruct the margin
to within 1.8e-05; they do not sum to anything readable as a percentage.

There is a margin for the attributions to add up to because the model is a
sum of regression trees:

## From Chen.xgboost

> Unlike decision trees, each regression tree contains a continuous score
> on each of the leaf, we use wi to represent score on i-th leaf.

## From Chen.xgboost

> Figure 1: Tree Ensemble Model. The final predic- tion for a given example
> is the sum of predictions from each tree.

The algorithm is exact TreeSHAP with `feature_perturbation` set to
`tree_path_dependent`, not an approximation, and it uses no background
sample: the expected value comes from traversal counts stored in those
trees. That is a property of the implementation, not a claim from a cited
work. What is cited here is the model; what is measured here is the
consequence, an additivity error of 1.8e-05.

## What it is not

**Not causation.** "Flow Duration drove this prediction" means the model
weighted that feature heavily. It does not mean long duration causes the
attack, or that shortening it would prevent one.

**Not an absolute.** Attribution is measured against a baseline -- the mean
prediction -- not against zero. A feature with attribution near zero was not
necessarily irrelevant; it may simply have been near its typical value.

**Not stable under correlation.** Flow features are heavily inter-correlated
(packet length mean, max and std move together). Correlated features share
credit in ways that look arbitrary. A low attribution does not prove a
feature carries no information.

**Not proof the model learned the task.** A coherent attribution can point
at an artefact of the capture rather than at the attack:

## From Arp.cacm

> Artifacts unrelated to the security problem create shortcut pat- terns
> for separating classes. Consequently, the learning model adapts to these
> artifacts instead of solving the actual task.

Reading attributions is a recognised way to find that. The recommendation
to apply explanation techniques, and the caveat that those techniques have
limits of their own, appear in the authors' full USENIX Security 2022 paper
and NOT in the condensed CACM version cited here, so no quote is offered
for it.

**Not a defence of a wrong answer.** SHAP explains the model, not the world.
A confident, coherent explanation of a misclassification is still a
misclassification.

## Specific to this model

Values are computed on **scaled** features. The raw value shown in the
interface is for human reading only; the model reasons in the scaled space.

Slowloris and DoS have a per-feature importance correlation of **0.9044**
and share six of their top ten features. When either is predicted with the
other close behind, the attribution will look similar for both -- because it
genuinely is. Report the ambiguity, do not resolve it.

The model was trained and validated on TRUSTLab. An explanation of a flow
from a different capture environment is an explanation of what the model
did, not evidence the model was right.
