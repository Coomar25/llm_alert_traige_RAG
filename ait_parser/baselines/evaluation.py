"""
Evaluation metrics harness.

This module is the SINGLE source of truth for how we compute
precision/recall/F1/FPR/latency. It is reused by:
    - the rule-based baseline (this stage)
    - the LLM-only baseline (future stage)
    - the LLM+RAG system (future stage)

Building it once and reusing it three times guarantees that the three
pipelines are compared on identical metric definitions — no drift, no
"different precision in different scripts" bugs.

All metrics are computed against ground-truth labels (is_attack) that
were applied in the labelling stage.
"""

from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Iterable, Dict, List


@dataclass
class ConfusionMatrix:
    """Standard 2x2 confusion matrix for binary classification."""
    tp: int = 0  # true positives:   predicted attack, was attack
    fp: int = 0  # false positives:  predicted attack, was benign
    tn: int = 0  # true negatives:   predicted benign, was benign
    fn: int = 0  # false negatives:  predicted benign, was attack

    def update(self, predicted_attack: bool, actual_attack: bool) -> None:
        """Add one prediction outcome to the matrix."""
        if predicted_attack and actual_attack:
            self.tp += 1
        elif predicted_attack and not actual_attack:
            self.fp += 1
        elif not predicted_attack and not actual_attack:
            self.tn += 1
        else:  # not predicted, was actual
            self.fn += 1

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def precision(self) -> float:
        """Of those predicted as attack, what fraction were actual attacks?"""
        denom = self.tp + self.fp
        return self.tp / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        """Of actual attacks, what fraction did we catch?"""
        denom = self.tp + self.fn
        return self.tp / denom if denom > 0 else 0.0

    @property
    def f1(self) -> float:
        """Harmonic mean of precision and recall."""
        p, r = self.precision, self.recall
        return (2 * p * r) / (p + r) if (p + r) > 0 else 0.0

    @property
    def false_positive_rate(self) -> float:
        """Of actual benigns, what fraction were flagged as attack?

        Crucial for SOC alert-fatigue analysis: low FPR = analysts trust the
        system, high FPR = they ignore it.
        """
        denom = self.fp + self.tn
        return self.fp / denom if denom > 0 else 0.0

    @property
    def accuracy(self) -> float:
        """Accuracy is misleading on imbalanced data; reported for completeness."""
        return (self.tp + self.tn) / self.total if self.total > 0 else 0.0

    def to_dict(self) -> dict:
        return {
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
            "total": self.total,
            "precision": round(self.precision, 6),
            "recall": round(self.recall, 6),
            "f1": round(self.f1, 6),
            "false_positive_rate": round(self.false_positive_rate, 6),
            "accuracy": round(self.accuracy, 6),
        }


@dataclass
class EvaluationResult:
    """Full evaluation output for one pipeline on one dataset (train OR test)."""
    pipeline_name: str
    split_name: str                                  # "train" or "test"
    overall: ConfusionMatrix = field(default_factory=ConfusionMatrix)
    by_scenario: Dict[str, ConfusionMatrix] = field(
        default_factory=lambda: defaultdict(ConfusionMatrix)
    )
    by_phase: Dict[str, ConfusionMatrix] = field(
        default_factory=lambda: defaultdict(ConfusionMatrix)
    )
    n_alerts: int = 0
    total_latency_ms: float = 0.0

    def record(self, predicted_attack: bool, actual_attack: bool,
               scenario: str, attack_phase: str | None,
               latency_ms: float = 0.0) -> None:
        """Record one prediction outcome.

        attack_phase is only used for actual attacks — it lets us compute
        per-phase recall. Benign alerts don't have a phase.
        """
        self.overall.update(predicted_attack, actual_attack)
        self.by_scenario[scenario].update(predicted_attack, actual_attack)
        if actual_attack and attack_phase:
            self.by_phase[attack_phase].update(predicted_attack, actual_attack)
        self.n_alerts += 1
        self.total_latency_ms += latency_ms

    @property
    def mean_latency_ms(self) -> float:
        return self.total_latency_ms / self.n_alerts if self.n_alerts > 0 else 0.0

    def to_dict(self) -> dict:
        return {
            "pipeline_name": self.pipeline_name,
            "split_name": self.split_name,
            "n_alerts": self.n_alerts,
            "mean_latency_ms": round(self.mean_latency_ms, 6),
            "total_latency_ms": round(self.total_latency_ms, 3),
            "overall": self.overall.to_dict(),
            "by_scenario": {s: cm.to_dict() for s, cm in self.by_scenario.items()},
            "by_phase": {p: cm.to_dict() for p, cm in self.by_phase.items()},
        }


def format_headline(result: EvaluationResult) -> str:
    """One-line headline string for the result. Useful for console output."""
    cm = result.overall
    return (
        f"[{result.pipeline_name}/{result.split_name}] "
        f"n={result.n_alerts:,} "
        f"precision={cm.precision:.4f} "
        f"recall={cm.recall:.4f} "
        f"F1={cm.f1:.4f} "
        f"FPR={cm.false_positive_rate:.4f} "
        f"mean_latency={result.mean_latency_ms:.3f}ms"
    )
