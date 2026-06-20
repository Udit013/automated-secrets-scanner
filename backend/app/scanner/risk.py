"""
Exposure Risk Score (0-100).

A deliberately transparent, explainable heuristic — every point added is
accompanied by a human-readable reason so the score can be defended in a
review. No black-box ML.
"""

from typing import Optional

_SEVERITY_BASE = {
    "CRITICAL": 55,
    "HIGH": 35,
    "MEDIUM": 18,
    "LOW": 8,
}


def compute_risk_score(
    severity: str,
    *,
    is_in_history: bool = False,
    occurrences: int = 1,
    exposure_days: Optional[int] = None,
    authors_count: Optional[int] = None,
    entropy: float = 0.0,
) -> tuple[int, list[str]]:
    """
    Returns (score 0-100, list of contributing reasons).
    """
    factors: list[str] = []

    score = _SEVERITY_BASE.get(severity.upper(), 8)
    factors.append(f"{severity.title()} severity")

    if is_in_history:
        score += 18
        factors.append("Present in Git history")

    if occurrences > 1:
        bonus = min((occurrences - 1) * 3, 12)
        score += bonus
        factors.append(f"Multiple occurrences ({occurrences})")

    if exposure_days is not None and exposure_days > 0:
        if exposure_days >= 30:
            score += 15
            factors.append(f"Long exposure window ({exposure_days} days)")
        elif exposure_days >= 7:
            score += 10
            factors.append(f"Extended exposure ({exposure_days} days)")
        else:
            score += 5
            factors.append(f"Recent exposure ({exposure_days} days)")

    if authors_count is not None and authors_count > 1:
        score += 5
        factors.append(f"Touched by {authors_count} authors")

    if entropy >= 5.0:
        score += 5
        factors.append(f"High entropy ({entropy:.1f} bits)")

    return min(score, 100), factors


def risk_band(score: int) -> str:
    """Coarse band used for color coding in the UI."""
    if score >= 80:
        return "CRITICAL"
    if score >= 55:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"
