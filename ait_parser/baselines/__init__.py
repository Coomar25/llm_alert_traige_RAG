"""Rule-based baselines + evaluation harness for AIT-ADS alert triage."""

from .splits import TRAIN_SCENARIOS, TEST_SCENARIOS, ALL_SCENARIOS, split_of, validate_splits
from .evaluation import ConfusionMatrix, EvaluationResult, format_headline
from .rule_based import B1Config, B2Config, B2Predictor, predict_b1, KNOWN_BAD_GROUPS

__all__ = [
    "TRAIN_SCENARIOS", "TEST_SCENARIOS", "ALL_SCENARIOS", "split_of", "validate_splits",
    "ConfusionMatrix", "EvaluationResult", "format_headline",
    "B1Config", "B2Config", "B2Predictor", "predict_b1", "KNOWN_BAD_GROUPS",
]
