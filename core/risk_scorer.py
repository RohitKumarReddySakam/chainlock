"""
Risk Scoring Engine
Calculates composite supply chain risk score and letter grade
"""


class RiskScorer:
    def score(self, vulns: list, typo_flags: list, license_issues: list, total_deps: int) -> tuple:
        """Returns (score: float 0-100, grade: str A-F)"""
        if total_deps == 0:
            return 0.0, "A"

        # Vulnerability score (0-60 pts)
        vuln_score = 0
        severity_weights = {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 4, "LOW": 1}
        for v in vulns:
            vuln_score += severity_weights.get(v.get("severity", "LOW"), 1)
        vuln_score = min(vuln_score, 60)

        # Typosquatting score (0-25 pts)
        typo_score = 0
        for flag in typo_flags:
            if flag.get("risk_level") == "HIGH":
                typo_score += 15
            else:
                typo_score += 5
        typo_score = min(typo_score, 25)

        # License score (0-15 pts)
        lic_score = 0
        risk_weights = {"CRITICAL": 15, "HIGH": 8, "MEDIUM": 3}
        for issue in license_issues:
            lic_score += risk_weights.get(issue.get("risk", ""), 0)
        lic_score = min(lic_score, 15)

        # Density factor — more vulnerabilities relative to total deps = higher risk
        density = len(vulns) / max(total_deps, 1)
        density_bonus = min(density * 20, 10)

        raw_score = vuln_score + typo_score + lic_score + density_bonus
        final_score = round(min(raw_score, 100), 1)

        # Letter grade
        grade = "A"
        if final_score >= 80:   grade = "F"
        elif final_score >= 60: grade = "D"
        elif final_score >= 40: grade = "C"
        elif final_score >= 20: grade = "B"

        return final_score, grade
