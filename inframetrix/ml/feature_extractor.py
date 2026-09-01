"""Feature extractor transforming Unified Finding into ML feature vectors."""

from __future__ import annotations

from inframetrix.models.finding import Finding

SEVERITY_MAP = {"critical": 4.0, "high": 3.0, "medium": 2.0, "low": 1.0, "info": 0.0}
CONFIDENCE_MAP = {"high": 2.0, "medium": 1.0, "low": 0.0}

ENGINE_MAP = {
    "native-sast": 0,
    "semgrep": 1,
    "native-secrets": 2,
    "gitleaks": 3,
    "osv-sca": 4,
    "supply-chain": 5,
    "zap-dast": 6,
    "urlscan": 7,
}


class FeatureExtractor:
    """Extracts numeric feature vectors from security findings for ML inference."""

    @classmethod
    def extract_features(cls, finding: Finding) -> list[float]:
        """Convert a Finding into a fixed-length numeric vector."""
        # 1. Severity & Confidence
        sev = SEVERITY_MAP.get(finding.severity, 2.0)
        conf = CONFIDENCE_MAP.get(finding.confidence, 1.0)

        # 2. Path heuristics
        path = (finding.file_path or "").lower()
        is_test = 1.0 if ("test" in path or "spec" in path or "mock" in path) else 0.0
        depth = float(len(path.split("/"))) if path else 0.0

        # 3. Security metadata
        has_cve = 1.0 if finding.cve else 0.0
        cvss = float(finding.cvss) if finding.cvss is not None else 5.0

        # 4. Engine encoding
        engine_idx = float(ENGINE_MAP.get(finding.source_engine, 0))

        # 5. Web & package attributes
        is_web = 1.0 if (finding.url or finding.endpoint) else 0.0
        is_package = 1.0 if finding.package_name else 0.0

        return [sev, conf, is_test, depth, has_cve, cvss, engine_idx, is_web, is_package]

    @classmethod
    def feature_names(cls) -> list[str]:
        return [
            "severity",
            "confidence",
            "is_test",
            "path_depth",
            "has_cve",
            "cvss",
            "engine_idx",
            "is_web",
            "is_package",
        ]
