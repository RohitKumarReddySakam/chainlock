"""
Typosquatting Detector
Detects malicious packages mimicking popular libraries
"""
import re
import logging

logger = logging.getLogger(__name__)

# Popular packages that are frequently typosquatted
POPULAR_PACKAGES = {
    "pypi": [
        "requests", "numpy", "pandas", "flask", "django", "fastapi",
        "boto3", "sqlalchemy", "cryptography", "pillow", "pytest",
        "setuptools", "pip", "wheel", "urllib3", "certifi", "pyyaml",
        "paramiko", "beautifulsoup4", "scrapy", "celery", "redis",
        "tensorflow", "torch", "scikit-learn", "matplotlib", "scipy",
    ],
    "npm": [
        "react", "vue", "angular", "express", "lodash", "axios",
        "webpack", "babel", "typescript", "eslint", "prettier",
        "jest", "mocha", "moment", "underscore", "jquery",
        "next", "nuxt", "gatsby", "redux", "rxjs",
    ],
}

# Known malicious/typosquatting packages (historical incidents)
KNOWN_MALICIOUS = {
    "pypi": [
        "reqeusts", "requets", "reqests", "requestss", "request",
        "nump", "numyp", "numpay", "panads", "padas", "pandsa",
        "flaskk", "flaask", "djang", "djangoo", "dajngo",
        "criptography", "cryptograpy", "crytpography",
        "colourama", "colorama2", "coulorrema",
        "python-dateutil2", "python-dates",
        "setup-tools", "setuptoolz",
        "urlib3", "urllib33", "urlib",
        "pycrypto2", "pycryptoo",
    ],
    "npm": [
        "reakt", "reactt", "vuejs2", "vue3js", "expresss",
        "lodahs", "lodash2", "axois", "axioss",
        "momnet", "mooment", "undderscore",
        "webpak", "webpackk",
    ],
}

# Suspicious patterns in package names
SUSPICIOUS_PATTERNS = [
    r"\d{4,}",           # Too many digits: pkg123456
    r"[a-z]+-[a-z]+-[a-z]+-[a-z]+",  # Too many hyphens
    r"test$",            # Ends in 'test' unexpectedly
    r"_setup$",
    r"-setup$",
    r"_install$",
    r"py[0-9]+-",        # pyX-packagename
]


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein distance"""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if not s2:
        return len(s1)
    prev = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            ins = prev[j + 1] + 1
            dele = curr[j] + 1
            sub = prev[j] + (c1 != c2)
            curr.append(min(ins, dele, sub))
        prev = curr
    return prev[-1]


class TyposquatDetector:
    def detect(self, deps: list, ecosystem: str) -> list:
        flags = []
        known_malicious = KNOWN_MALICIOUS.get(ecosystem, [])
        popular = POPULAR_PACKAGES.get(ecosystem, [])

        for dep in deps:
            name = dep["name"].lower()
            issues = []

            # 1. Direct known-malicious match
            if name in known_malicious:
                issues.append({
                    "type": "KNOWN_MALICIOUS",
                    "description": f"'{dep['name']}' is a known malicious/typosquatting package",
                    "confidence": "HIGH",
                    "similar_to": self._find_similar(name, popular),
                })

            # 2. Levenshtein distance from popular packages
            for pop in popular:
                if name == pop:
                    break  # Exact match — legit
                dist = _levenshtein(name, pop)
                if 1 <= dist <= 2 and len(name) > 3:
                    issues.append({
                        "type": "TYPOSQUATTING",
                        "description": f"'{dep['name']}' is suspiciously similar to '{pop}' (edit distance: {dist})",
                        "confidence": "MEDIUM" if dist == 2 else "HIGH",
                        "similar_to": pop,
                    })
                    break

            # 3. Suspicious name patterns
            for pattern in SUSPICIOUS_PATTERNS:
                if re.search(pattern, name):
                    issues.append({
                        "type": "SUSPICIOUS_NAME",
                        "description": f"Package name '{dep['name']}' matches suspicious pattern: {pattern}",
                        "confidence": "LOW",
                        "similar_to": None,
                    })
                    break

            if issues:
                flags.append({
                    "package": dep["name"],
                    "version": dep.get("version", "unknown"),
                    "issues": issues,
                    "risk_level": "HIGH" if any(i["confidence"] == "HIGH" for i in issues) else "MEDIUM",
                })

        return flags

    def _find_similar(self, name: str, popular: list) -> str | None:
        best, best_dist = None, 999
        for p in popular:
            d = _levenshtein(name, p)
            if d < best_dist:
                best, best_dist = p, d
        return best if best_dist <= 3 else None
