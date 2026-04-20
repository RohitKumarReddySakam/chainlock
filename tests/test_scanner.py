"""Tests for CHAINLOCK — Supply Chain Security Scanner"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from core.dependency_extractor import DependencyExtractor
from core.vulnerability_checker import VulnerabilityChecker
from core.sbom_generator import SBOMGenerator
from core.typosquat_detector import TyposquatDetector
from core.license_checker import LicenseChecker
from core.risk_scorer import RiskScorer


REQ_TXT = """requests==2.25.0\ncryptography==3.4.6\nnumpy==1.21.0\nflask==2.3.3\n"""
PKG_JSON = '{"dependencies":{"lodash":"4.17.15","react":"^18.0.0","express":"4.18.0"}}'


class TestExtractor:
    def test_parse_requirements(self):
        ext = DependencyExtractor()
        deps, eco = ext.extract("requirements.txt", REQ_TXT)
        assert eco == "pypi"
        assert len(deps) == 4
        names = [d["name"] for d in deps]
        assert "requests" in names

    def test_parse_npm(self):
        ext = DependencyExtractor()
        deps, eco = ext.extract("package.json", PKG_JSON)
        assert eco == "npm"
        assert len(deps) == 3

    def test_version_extraction(self):
        ext = DependencyExtractor()
        deps, _ = ext.extract("requirements.txt", "requests==2.25.0\n")
        assert deps[0]["version"] == "2.25.0"

    def test_comments_ignored(self):
        ext = DependencyExtractor()
        deps, _ = ext.extract("requirements.txt", "# comment\nrequests==2.28.0\n")
        assert len(deps) == 1

    def test_deduplication(self):
        ext = DependencyExtractor()
        deps, _ = ext.extract("requirements.txt", "requests==2.25.0\nrequests==2.28.0\n")
        assert len(deps) == 1


class TestVulnerabilityChecker:
    def test_known_vuln_requests(self):
        checker = VulnerabilityChecker()
        deps = [{"name": "requests", "version": "2.25.0"}]
        vulns = checker.check_all(deps)
        assert len(vulns) >= 1
        assert vulns[0]["cve_id"] == "CVE-2023-32681"

    def test_known_vuln_pyyaml(self):
        checker = VulnerabilityChecker()
        deps = [{"name": "PyYAML", "version": "5.3.1"}]
        vulns = checker.check_all(deps)
        assert any(v["severity"] == "CRITICAL" for v in vulns)

    def test_clean_package(self):
        checker = VulnerabilityChecker()
        deps = [{"name": "requests", "version": "2.31.0"}]
        vulns = checker.check_all(deps)
        assert len(vulns) == 0

    def test_empty_deps(self):
        checker = VulnerabilityChecker()
        assert checker.check_all([]) == []


class TestSBOM:
    def test_generates_cyclonedx(self):
        gen = SBOMGenerator()
        deps = [{"name": "requests", "version": "2.31.0"}]
        sbom = gen.generate(deps, "pypi", "requirements.txt", [])
        assert sbom["bomFormat"] == "CycloneDX"
        assert sbom["specVersion"] == "1.5"
        assert len(sbom["components"]) == 1

    def test_purl_generation(self):
        gen = SBOMGenerator()
        purl = gen._purl("pypi", "requests", "2.31.0")
        assert purl == "pkg:pypi/requests@2.31.0"

    def test_vuln_embedded_in_sbom(self):
        gen = SBOMGenerator()
        deps = [{"name": "requests", "version": "2.25.0"}]
        vulns = [{"package": "requests", "cve_id": "CVE-2023-32681", "severity": "MEDIUM", "cvss": 6.1, "description": "Test", "fixed_version": "2.31.0"}]
        sbom = gen.generate(deps, "pypi", "req.txt", vulns)
        comp = sbom["components"][0]
        assert "vulnerabilities" in comp


class TestTyposquat:
    def test_known_malicious(self):
        det = TyposquatDetector()
        deps = [{"name": "reqeusts", "version": "2.25.0"}]
        flags = det.detect(deps, "pypi")
        assert len(flags) == 1

    def test_legit_package_not_flagged(self):
        det = TyposquatDetector()
        deps = [{"name": "requests", "version": "2.31.0"}]
        flags = det.detect(deps, "pypi")
        assert len(flags) == 0

    def test_typosquat_detection(self):
        det = TyposquatDetector()
        deps = [{"name": "requets", "version": "1.0.0"}]
        flags = det.detect(deps, "pypi")
        assert len(flags) >= 1


class TestRiskScorer:
    def test_zero_risk(self):
        scorer = RiskScorer()
        score, grade = scorer.score([], [], [], 10)
        assert score == 0.0
        assert grade == "A"

    def test_critical_vuln_raises_score(self):
        scorer = RiskScorer()
        vulns = [{"severity": "CRITICAL"}, {"severity": "CRITICAL"}]
        score, grade = scorer.score(vulns, [], [], 10)
        assert score > 30

    def test_grade_f_for_high_score(self):
        scorer = RiskScorer()
        vulns = [{"severity": "CRITICAL"}] * 5
        score, grade = scorer.score(vulns, [{"risk_level": "HIGH"}] * 2, [], 5)
        assert grade in ("D", "F")
