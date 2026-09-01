"""Tests for ML Triage and Priority Scoring."""

from inframetrix.ml.feature_extractor import FeatureExtractor
from inframetrix.ml.fp_classifier import FalsePositiveClassifier
from inframetrix.ml.priority_model import PriorityModel
from inframetrix.models.finding import Finding


def test_feature_extractor_dimensions():
    f = Finding(
        id="test-rule",
        title="Test finding",
        severity="high",
        confidence="medium",
        file_path="tests/mock_test.py",
        cve="CVE-2024-0001",
        cvss=7.5,
    )
    features = FeatureExtractor.extract_features(f)
    assert len(features) == len(FeatureExtractor.feature_names())
    assert features[0] == 3.0  # High severity
    assert features[2] == 1.0  # Is test file


def test_fp_classifier_heuristics():
    clf = FalsePositiveClassifier()

    prod_finding = Finding(id="f1", title="Prod SQLi", severity="critical", file_path="src/api.py", confidence="high")
    test_finding = Finding(id="f2", title="Test Mock Key", severity="low", file_path="tests/test_mock.py", confidence="low")

    p_prod = clf.predict_fp_probability(prod_finding)
    p_test = clf.predict_fp_probability(test_finding)

    assert p_prod < p_test


def test_priority_model_calculation():
    f_crit = Finding(id="crit", title="Critical RCE", severity="critical", confidence="high", cvss=9.8, url="https://example.com/api")
    f_low_test = Finding(id="low", title="Low Info", severity="low", confidence="low", file_path="tests/test_dummy.py")

    p_crit = PriorityModel.calculate_priority_score(f_crit)
    p_low = PriorityModel.calculate_priority_score(f_low_test)

    assert p_crit > 70.0
    assert p_low < 30.0
