# Machine learning terms used in this interface

> Source: National Institute of Standards and Technology, "Artificial Intelligence Risk Management Framework (AI RMF 1.0)," NIST AI 100-1, Jan. 2023, doi: 10.6028/NIST.AI.100-1.
> Source: D. Arp, E. Quiring, F. Pendlebury, A. Warnecke, F. Pierazzi, C. Wressnegger, L. Cavallaro and K. Rieck, "Pitfalls in machine learning for computer security," Commun. ACM, vol. 67, no. 11, pp. 104-112, Nov. 2024, doi: 10.1145/3643456.
> Source: T. Chen and C. Guestrin, "XGBoost: A scalable tree boosting system," in Proc. 22nd ACM SIGKDD Int. Conf. Knowledge Discovery and Data Mining, San Francisco, CA, USA, Aug. 2016, pp. 785-794, doi: 10.1145/2939672.2939785.
> Source: S. S. Iyengar, S. Nabavirazavi, Y. Hariprasad, Prasad HB and C. Krishna Mohan, Artificial Intelligence in Practice: Theory and Application for Cyber Security and Forensics. Cham, Switzerland: Springer Nature, 2025, doi: 10.1007/978-3-031-89327-8.
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
probabilities. SHAP values live here. It is a sum of per-tree scores:

## From Chen.xgboost

> Unlike decision trees, each regression tree contains a continuous score
> on each of the leaf, we use wi to represent score on i-th leaf.

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

**TreeSHAP.** The exact algorithm for Shapley values on tree ensembles,
used here in place of the sampling-based Kernel SHAP. No document in
`knowledge/_sources` describes SHAP or TreeSHAP, so the definitions in this
section describe what the library computes and what this interface shows,
and carry no citation.

**tree_path_dependent.** The setting that computes expectations by walking
the trees, using the traversal counts stored in them. It needs no
background sample and respects correlations present in the training data.

**Local vs global explanation.** *Local* explains one flow — what the SHAP
panel shows. *Global* summarises the whole model, as in the mean absolute
SHAP values in `shap_global.json`. A feature that matters globally may
matter not at all for the flow in front of you.

**Explainability.** What a model can be made to say about its own output:

## From Iyengar.aip

> Explainable AI refers to models and systems that can provide humans with
> understandable explanations of their operations, decisions, or
> predictions.

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

## From Arp.cacm

> Spurious correlations result from artifacts that correlate with the task
> to solve but are not actually re - lated to it, leading to false
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
in a report. None of them describes SHAP, Shapley values or TreeSHAP at
all, which is why those entries are unsourced definitions of what this
interface shows. The numeric values quoted above (0.9337, 0.9287, 0.6703,
1.8e-05) are this project's own measurements, not claims from the cited
works.

Related: [[confidence]], [[reliability]], [[shap-reading]], [[class-ambiguity]], [[scope]], [[extraction-validity]]
