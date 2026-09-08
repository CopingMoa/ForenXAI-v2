# Reading a SHAP attribution

> Source: R. Arslan, T. Ozseven, M. M. Aydin and Y. Celik, "Cybersecurity in intelligent transportation systems: A comparative study on AI-based anomaly detection and threat analysis," Mechatronics and Intelligent Transportation Systems, vol. 5, no. 1, pp. 11-30, 2026, doi: 10.56578/mits050102.
> Source: National Institute of Standards and Technology, "Artificial Intelligence Risk Management Framework (AI RMF 1.0)," NIST AI 100-1, Jan. 2023, doi: 10.6028/NIST.AI.100-1.
> Source: D. Arp et al., "Dos and don'ts of machine learning in computer security," in Proc. 31st USENIX Security Symp., Boston, MA, USA, Aug. 2022, pp. 3971-3988.
>
> Retrieved: 2026-09-08

## 1. What the numbers in the SHAP panel are

Each row of the panel is one feature and one number: that feature's share of
the distance between the model's baseline output and its output for this
particular flow.

## From Arslan.mits

> Shapley additive explanations (SHAP) calculates feature contributions
> using Shapley values from game theory [31]. TreeSHAP provides optimized
> computational power for tree-based models and delivers more accurate
> values in polynomial time [32].

The attributions add up. That is the defining property and what makes the
panel checkable rather than decorative: the pipeline verifies that the
values sum to the model's margin plus the base value, and additivity error
on this model is 1.8e-05.

## 2. The units are log-odds, not probability

This is the single most misread thing in the panel.

A SHAP value of **+2.3** does not mean "230% more likely" or "adds 2.3 to
the probability". The values are in the model's raw margin space — log-odds
— and only become a probability after the softmax, which is not linear. A
contribution of +2.3 moves the margin by 2.3; what that does to the
probability depends entirely on where the margin already was.

Two consequences that matter when writing a report:

- **Do not add SHAP values to a probability.** Different units.
- **Do not compare a SHAP value to a percentage.** The panel states its
  units on screen for this reason, and the grounding checks flag any
  narration that renders a log-odds figure as a percentage.

## 3. How these particular values were computed

This tool uses TreeSHAP with `feature_perturbation="tree_path_dependent"`.
The expected value comes from traversal counts already stored in the trees,
which is why no background sample is needed, and why the attributions
respect correlations present in the training data rather than assuming the
features are independent.

The polynomial-time property quoted above is what makes this practical: the
panel explains thousands of flows in seconds, where the model-agnostic
alternative manages about three per second.

## 4. What an attribution does NOT establish

**It is not a cause.** A SHAP value describes how the model's output moves
as that feature is introduced. It describes the model, not the network. If
the model learned an artefact, SHAP will faithfully report the artefact as
important.

## From USENIX.dosdonts

> Spurious correlations result from artifacts that correlate with the task
> to solve but are not actually related to it, leading to false
> associations.

**It is not the only explanation.** Correlated features share credit. If
`Fwd Header Length` and `Total Fwd Packet` move together, the split between
them is a property of the tree structure, not a ranking of real-world
importance.

**It is not evidence the classification is right.** SHAP explains the answer
the model gave, including when that answer is wrong. A confidently wrong
flow gets a confident, coherent-looking explanation.

## 5. What NIST asks you to distinguish

## From NIST.AI.100-1

> whereas interpretability refers to the meaning of AI systems' output in
> the context of their designed functional purposes. Together,
> explainability and interpretability assist those operating or overseeing
> an AI system

The SHAP panel supplies **explainability** — the mechanism. It does not
supply interpretability on its own. Turning "`Bwd Bulk Rate Avg` contributed
+2.56 log-odds toward API" into "this is an API attack against host X" is
the analyst's step, and it needs the capture, not the attribution.

## 6. Using the panel in practice

1. Read the units line first. Everything below it is log-odds.
2. Take the top three or four features, not the whole list — the tail is
   mostly noise around zero.
3. Look up each feature in the flow feature glossary; a feature you cannot
   define is one you cannot testify about.
4. Check the attribution against the raw flow. If SHAP says the decision
   turned on `Flow Duration` and that duration is an artefact of the
   extractor's timeout, the explanation is real and the finding is not.
5. Only then read the class playbook.

## 7. Not covered by these sources

Arslan et al. apply SHAP to intrusion detection in a vehicular context; they
do not prescribe how much weight an attribution should carry in a forensic
report, and neither does NIST AI 100-1, which is a risk-management framework
rather than a technique. None of the three states a threshold above which an
attribution is "important". That judgement is yours and belongs in your own
runbook.

Related: [[confidence]], [[reliability]], [[extraction-validity]], [[scope]]
