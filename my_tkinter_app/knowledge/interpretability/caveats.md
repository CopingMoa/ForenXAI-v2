# How far a SHAP attribution can be pushed

> Source: S. M. Lundberg et al., "Explainable AI for trees: From local explanations to global understanding," arXiv:1905.04610, May 2019. Published in revised form as Nature Machine Intelligence, vol. 2, no. 1, pp. 56-67, Jan. 2020, doi: 10.1038/s42256-019-0138-9.
> Source: D. Arp et al., "Dos and don'ts of machine learning in computer security," in Proc. 31st USENIX Security Symp., Boston, MA, USA, Aug. 2022, pp. 3971-3988.
>
> Retrieved: 2026-09-08
>
> The per-model figures below (0.9044 importance correlation, 1.8e-05
> additivity error) are this project's own measurements. The sourced
> claims about what TreeSHAP computes are in [[shap-reading]].

Quote these limits alongside any explanation. They are what separates an
explanation from a claim.

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

The algorithm is exact TreeSHAP with `feature_perturbation` set to
`tree_path_dependent` (Lundberg et al., 2019), not an approximation. It
uses no background sample: the expected value comes from traversal counts
stored in the trees.

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
