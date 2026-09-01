"""False-Positive classifier with scikit-learn training and heuristic fallback."""

from __future__ import annotations

import logging
from typing import Any

from inframetrix.ml.feature_extractor import FeatureExtractor
from inframetrix.models.finding import Finding

logger = logging.getLogger(__name__)


class FalsePositiveClassifier:
    """Predicts the probability that a finding is a false positive (0.0 - 1.0)."""

    def __init__(self) -> None:
        self._model: Any = None
        self._is_trained: bool = False

    @property
    def is_trained(self) -> bool:
        return self._is_trained

    def predict_fp_probability(self, finding: Finding) -> float:
        """Estimate false-positive probability (0.0 = definite TP, 1.0 = definite FP)."""
        if self._is_trained and self._model is not None:
            try:
                features = [FeatureExtractor.extract_features(finding)]
                # Model returns proba for class 0 (false_positive)
                probas = self._model.predict_proba(features)
                return round(float(probas[0][0]), 3)
            except Exception as exc:  # noqa: BLE001
                logger.debug(f"ML prediction fallback: {exc}")

        # Heuristic fallback
        return self._heuristic_fp_probability(finding)

    @staticmethod
    def _heuristic_fp_probability(finding: Finding) -> float:
        """Heuristic calculation when training samples are insufficient."""
        prob = 0.1  # base low FP probability

        # Test files have higher chance of mock secrets / dummy auth
        path = (finding.file_path or "").lower()
        if "test" in path or "mock" in path or "fixture" in path or "spec" in path:
            prob += 0.4

        # Low confidence findings
        if finding.confidence == "low":
            prob += 0.25
        elif finding.confidence == "high":
            prob -= 0.05

        # AI-slop / TODO comments often have lower criticality in development
        if finding.category == "ai-slop":
            prob += 0.15

        return round(min(max(prob, 0.0), 0.95), 2)

    def train(self, findings: list[Finding], labels: list[int]) -> bool:
        """Train a scikit-learn classifier on user-labeled findings."""
        if len(findings) < 10 or len(set(labels)) < 2:
            return False

        try:
            from sklearn.ensemble import HistGradientBoostingClassifier

            x = [FeatureExtractor.extract_features(f) for f in findings]
            y = labels

            clf = HistGradientBoostingClassifier(max_iter=50, random_state=42)
            clf.fit(x, y)

            self._model = clf
            self._is_trained = True
            return True
        except ImportError:
            logger.debug("scikit-learn is not installed; continuing with heuristic fallback.")
            return False
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"Model training error: {exc}")
            return False
