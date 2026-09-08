# Machine learning terms used in this interface

> Source: S. M. Lundberg and S.-I. Lee, "A unified approach to interpreting model predictions," in Advances in Neural Information Processing Systems 30, Long Beach, CA, USA, Dec. 2017, pp. 4765-4774.
> Source: S. M. Lundberg et al., "Explainable AI for trees: From local explanations to global understanding," arXiv:1905.04610, May 2019. Published in revised form as Nature Machine Intelligence, vol. 2, no. 1, pp. 56-67, Jan. 2020, doi: 10.1038/s42256-019-0138-9.
> Source: National Institute of Standards and Technology, "Artificial Intelligence Risk Management Framework (AI RMF 1.0)," NIST AI 100-1, Jan. 2023, doi: 10.6028/NIST.AI.100-1.
> Source: D. Arp et al., "Dos and don'ts of machine learning in computer security," in Proc. 31st USENIX Security Symp., Boston, MA, USA, Aug. 2022, pp. 3971-3988.
>
> Retrieved: 2026-09-08

Every term below appears somewhere in the three panels. This is what each
one means **in this tool**, not in general.

## Terms about the model's answer

**Class.** One of the sixteen labels the model can output: fifteen attack
types plus Benign. It cannot output anything else, so traffic unlike all
sixteen is still assigned one of them.

**Confidence.** The highest `predict_proba` score across the sixteen
classes. A ranking, not a measured probability of being correct — see
[[confidence]].

**Runner-up.** The class with the second-highest score. When it is
consistently the same class across a finding, the two may be
indistinguishable — see [[class-ambiguity]].

**Margin / raw score.** The model's output before the softmax turns it into
probabilities. SHAP values live here.

**Log-odds.** The units of the margin. Not a percentage, and not additive
with probabilities.

**Softmax.** The function converting sixteen margins into sixteen
probabilities summing to 1.0. It is non-linear, which is why a fixed change
in log-odds does not correspond to a fixed change in probability.

## Terms about how well it works

**Held-out test set.** 280,000 TRUSTLab flows the model never saw during
training. All reported scores come from these.

**Accuracy.** Share of flows classified correctly. 0.9337 here. Dominated
by the largest classes, so it says little about any specific finding.

**Precision.** Of the flows called class X, the share that really were X.
Low precision means false alarms.

**Recall.** Of the flows that really were X, the share the model found.
Low recall means misses, and makes "no finding" uninformative.

**F1.** The harmonic mean of precision and recall — one number that drops
if either drops, but which cannot tell you which one did.

**Macro F1.** F1 averaged over the sixteen classes with equal weight.
0.9287 here. Equal weighting is why it hides that DoS scores 0.6703 — see
[[reliability]].

**Class imbalance / base rate.** Most flows in a capture are benign. This
changes what a false-positive rate means in practice, usually for the
worse — see [[confidence]].

## Terms about the explanation

**SHAP value.** One feature's share of the distance between the model's
baseline output and its output for this flow, in log-odds.

**Base value.** The model's output before any feature is considered — the
starting point the attributions move away from. There is one per class.

**Additivity.** The property that base value plus all SHAP values equals
the model's margin. Checked at build time; error here is 1.8e-05.

## From Lundberg.shap

> We propose SHAP values as a unified measure of feature importance. These
> are the Shapley values of a conditional expectation function of the
> original model

**TreeSHAP.** The exact algorithm for Shapley values on tree ensembles,
used here in place of the sampling-based Kernel SHAP.

## From Lundberg.treeshap

> Efficiently and exactly computing the Shapley values guarantees that
> explanations will always be consistent and locally accurate.

**tree_path_dependent.** The setting that computes expectations by walking
the trees, using the traversal counts stored in them. It needs no
background sample and respects correlations present in the training data.

**Local vs global explanation.** *Local* explains one flow — what the SHAP
panel shows. *Global* summarises the whole model, as in the mean absolute
SHAP values in `shap_global.json`. A feature that matters globally may
matter not at all for the flow in front of you.

**Explainability vs interpretability.** NIST separates these:

## From NIST.AI.100-1

> whereas interpretability refers to the meaning of AI systems' output in
> the context of their designed functional purposes. Together,
> explainability and interpretability assist those operating or overseeing
> an AI system

SHAP gives explainability. Interpretability — what it means for this case —
is the analyst's work.

## Terms about the limits

**Generalisation.** Whether behaviour measured on the test set holds on new
data. Measured only within TRUSTLab here — see [[scope]].

**Spurious correlation.** A pattern the model learned that separates the
classes for reasons unrelated to the actual task.

## From USENIX.dosdonts

> Spurious correlations result from artifacts that correlate with the task
> to solve but are not actually related to it, leading to false
> associations.

**Sampling bias.** A difference between the data the model was fitted on
and the data it is being used on.

**Scaling / StandardScaler.** Each feature is centred and divided by its
standard deviation before the model sees it. The scaler travels with the
model; feature values in the panels are shown unscaled, as they came from
the extractor.

**Flow timeout.** How long the extractor waits before closing a flow. A
mismatch between the capture and the training data invalidates every timing
feature — see [[extraction-validity]].

## Not covered by these sources

None of these documents defines these terms for network forensics
specifically, and none states what weight any of these figures should carry
in a report. The numeric values quoted above (0.9337, 0.9287, 0.6703,
1.8e-05) are this project's own measurements, not claims from the cited
works.

Related: [[confidence]], [[reliability]], [[shap-reading]], [[class-ambiguity]], [[scope]], [[extraction-validity]]
