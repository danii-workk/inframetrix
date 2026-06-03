"""InfraMetrix - Security, architecture, and infrastructure risk analyzer for AI-built projects."""

from inframetrix.finding import Finding
from inframetrix.risk_score import calculate_risk_score
from inframetrix.scanner import scan_project

__version__ = "0.1.0"
__all__ = ["Finding", "calculate_risk_score", "scan_project", "__version__"]