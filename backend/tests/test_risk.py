"""Unit tests for the exposure risk scoring heuristic."""

from app.scanner.risk import compute_risk_score, risk_band


class TestComputeRiskScore:
    def test_severity_base_scores(self):
        assert compute_risk_score("CRITICAL")[0] == 55
        assert compute_risk_score("HIGH")[0] == 35
        assert compute_risk_score("MEDIUM")[0] == 18
        assert compute_risk_score("LOW")[0] == 8

    def test_unknown_severity_falls_back_to_low(self):
        score, factors = compute_risk_score("BOGUS")
        assert score == 8
        assert len(factors) == 1

    def test_severity_is_case_insensitive(self):
        assert compute_risk_score("critical")[0] == 55

    def test_git_history_adds_18(self):
        base, _ = compute_risk_score("HIGH")
        with_history, factors = compute_risk_score("HIGH", is_in_history=True)
        assert with_history - base == 18
        assert any("history" in f.lower() for f in factors)

    def test_occurrence_bonus_capped_at_12(self):
        base, _ = compute_risk_score("LOW")
        many, _ = compute_risk_score("LOW", occurrences=100)
        assert many - base == 12

    def test_single_occurrence_adds_nothing(self):
        assert compute_risk_score("LOW", occurrences=1)[0] == 8

    def test_exposure_tiers(self):
        base = compute_risk_score("LOW")[0]
        assert compute_risk_score("LOW", exposure_days=3)[0] - base == 5
        assert compute_risk_score("LOW", exposure_days=7)[0] - base == 10
        assert compute_risk_score("LOW", exposure_days=30)[0] - base == 15

    def test_zero_exposure_days_ignored(self):
        assert compute_risk_score("LOW", exposure_days=0)[0] == 8

    def test_multiple_authors_bonus(self):
        base = compute_risk_score("LOW")[0]
        assert compute_risk_score("LOW", authors_count=1)[0] == base
        assert compute_risk_score("LOW", authors_count=3)[0] - base == 5

    def test_high_entropy_bonus(self):
        base = compute_risk_score("LOW")[0]
        assert compute_risk_score("LOW", entropy=4.9)[0] == base
        assert compute_risk_score("LOW", entropy=5.0)[0] - base == 5

    def test_score_capped_at_100(self):
        score, _ = compute_risk_score(
            "CRITICAL",
            is_in_history=True,
            occurrences=10,
            exposure_days=90,
            authors_count=5,
            entropy=6.0,
        )
        assert score == 100

    def test_every_point_has_a_reason(self):
        score, factors = compute_risk_score(
            "CRITICAL", is_in_history=True, occurrences=3, exposure_days=10
        )
        # severity + history + occurrences + exposure
        assert len(factors) == 4


class TestRiskBand:
    def test_bands(self):
        assert risk_band(100) == "CRITICAL"
        assert risk_band(80) == "CRITICAL"
        assert risk_band(79) == "HIGH"
        assert risk_band(55) == "HIGH"
        assert risk_band(54) == "MEDIUM"
        assert risk_band(30) == "MEDIUM"
        assert risk_band(29) == "LOW"
        assert risk_band(0) == "LOW"
