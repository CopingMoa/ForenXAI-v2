# Reading a SHAP attribution

> Source: S. M. Lundberg and S.-I. Lee, "A unified approach to interpreting model predictions," in Advances in Neural Information Processing Systems 30, Long Beach, CA, USA, Dec. 2017, pp. 4765-4774.
> Source: S. M. Lundberg et al., "Explainable AI for trees: From local explanations to global understanding," arXiv:1905.04610, May 2019. Published in revised form as Nature Machine Intelligence, vol. 2, no. 1, pp. 56-67, Jan. 2020, doi: 10.1038/s42256-019-0138-9.
> Source: National Institute of Standards and Technology, "Artificial Intelligence Risk Management Framework (AI RMF 1.0)," NIST AI 100-1, Jan. 2023, doi: 10.6028/NIST.AI.100-1.
> Source: D. Arp et al., "Dos and don'ts of machine learning in computer security," in Proc. 31st USENIX Security Symp., Boston, MA, USA, Aug. 2022, pp. 3971-3988.
>
> Retrieved: 2026-09-08

## 1. What the numbers in the SHAP panel are

Each row of the panel is one feature and one number. The number is that
feature's share of the distance between the model's baseline output and
its output for this particular flow.

## From Lundberg.shap

> We propose SHAP values as a unified measure of feature importance. These
> are the Shapley values of a conditional expectation function of the
> original model

The attributions add up. That is the defining property, and it is what
makes the panel checkable rather than decorative: the pipeline verifies
that the values sum to the model's margin plus the base value, and
additivity error on this model is 1.8e-05.

## 2. The units are log-odds, not probability

This is the single most misread thing in the panel.

A SHAP value of **+2.3** does not mean "230% more likely" or "adds 2.3 to
the probability". The values are in the model's raw margin space — log-odds
— and only become a probability after the softmax, which is not linear. A
contribution of +2.3 moves the margin by 2.3; what that does to the
probability depends entirely on where the margin already was.

Two consequences that matter when writing a report:

- **Do not add SHAP values to a probability.** They are in different units.
- **Do not compare a SHAP value to a percentage.** The panel states its
  units on screen for this reason, and the grounding checks flag any
  narration that renders a log-odds figure as a percentage.

## 3. How these particular values were computed

This tool uses TreeSHAP with `feature_perturbation="tree_path_dependent"`.

## From Lundberg.treeshap

> By default, TreeExplainer computes conditional expectations using tree
> traversal, but it also provides an option that enforces feature
> independence and supports explaining a model's loss function

Tree traversal is why no background sample is needed: the expected value
comes from the traversal counts already stored in the trees. It also means
the attributions respect the correlations present in the training data
rather than assuming features are independent.

The values are exact, not sampled:

## From Lundberg.treeshap

> Efficiently and exactly computing the Shapley values guarantees that
> explanations will always be consistent and locally accurate.

## 4. What an attribution does NOT establish

**It is not a cause.** A SHAP value says how the model's output changes as
that feature is introduced into a conditional expectation. It describes the
model, not the network. If the model learned an artefact, SHAP will
faithfully report the artefact as important.

## From USENIX.dosdonts

> Spurious correlations result from artifacts that correlate with the task
> to solve but are not actually related to it, leading to false
> associations.

**It is not the only explanation.** Correlated features share credit. If
`Fwd Header Length` and `Total Fwd Packet` move together, the split between
them is a property of the tree structure, not a ranking of real-world
importance.

**It is not evidence the classification is right.** SHAP explains the
answer the model gave, including when that answer is wrong. A confidently
wrong flow gets a confident, coherent-looking explanation.

## 5. What NIST asks you to distinguish

## From NIST.AI.100-1

> whereas interpretability refers to the meaning of AI systems' output in
> the context of their designed functional purposes. Together,
> explainability and interpretability assist those operating or overseeing
> an AI system

The SHAP panel supplies **explainability** — the mechanism. It does not
supply interpretability on its own. Turning "`Bwd Bulk Rate Avg` contributed
+2.56 log-odds toward API" into "this is an API attack against host X" is
the analyst's step, and it requires the capture, not the attribution.

## 6. Using the panel in practice

1. Read the units line first. Everything below it is log-odds.
2. Take the top three or four features, not the whole list — the tail is
   mostly noise around zero.
3. Look up each feature in the flow feature glossary; a feature you cannot
   define is one you cannot testify about.
4. Check the attribution against the raw flow. If SHAP says the decision
   turned on `Flow Duration` and the flow's duration is an artefact of the
   extractor's timeout, the explanation is real and the finding is not.
5. Only then read the class playbook.

## 7. Not covered by these sources

Neither SHAP paper addresses network forensics, evidential standards, or
what weight an attribution should carry in a report. NIST AI 100-1 is a
risk-management framework and prescribes no technique. None of the three
states a threshold above which an attribution is "important" — that
judgement is yours and it belongs in your own runbook.

Related: [[confidence]], [[reliability]], [[extraction-validity]], [[scope]]
