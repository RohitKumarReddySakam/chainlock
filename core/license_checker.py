"""
License Compliance Checker
Detects GPL/copyleft licenses in commercial projects and policy violations
"""

SPDX_LICENSES = {
    # Permissive (✅ usually OK in commercial)
    "MIT": {"risk": "LOW", "type": "permissive", "commercial_ok": True},
    "Apache-2.0": {"risk": "LOW", "type": "permissive", "commercial_ok": True},
    "BSD-2-Clause": {"risk": "LOW", "type": "permissive", "commercial_ok": True},
    "BSD-3-Clause": {"risk": "LOW", "type": "permissive", "commercial_ok": True},
    "ISC": {"risk": "LOW", "type": "permissive", "commercial_ok": True},
    "Unlicense": {"risk": "LOW", "type": "public_domain", "commercial_ok": True},
    "CC0-1.0": {"risk": "LOW", "type": "public_domain", "commercial_ok": True},
    "PSF-2.0": {"risk": "LOW", "type": "permissive", "commercial_ok": True},
    # Weak Copyleft (⚠️ review required)
    "LGPL-2.0-only": {"risk": "MEDIUM", "type": "weak_copyleft", "commercial_ok": None},
    "LGPL-2.1-only": {"risk": "MEDIUM", "type": "weak_copyleft", "commercial_ok": None},
    "LGPL-3.0-only": {"risk": "MEDIUM", "type": "weak_copyleft", "commercial_ok": None},
    "MPL-2.0": {"risk": "MEDIUM", "type": "weak_copyleft", "commercial_ok": None},
    "EPL-1.0": {"risk": "MEDIUM", "type": "weak_copyleft", "commercial_ok": None},
    "EPL-2.0": {"risk": "MEDIUM", "type": "weak_copyleft", "commercial_ok": None},
    "CDDL-1.0": {"risk": "MEDIUM", "type": "weak_copyleft", "commercial_ok": None},
    # Strong Copyleft (❌ risk in commercial closed-source)
    "GPL-2.0-only": {"risk": "HIGH", "type": "copyleft", "commercial_ok": False},
    "GPL-2.0-or-later": {"risk": "HIGH", "type": "copyleft", "commercial_ok": False},
    "GPL-3.0-only": {"risk": "HIGH", "type": "copyleft", "commercial_ok": False},
    "GPL-3.0-or-later": {"risk": "HIGH", "type": "copyleft", "commercial_ok": False},
    "AGPL-3.0-only": {"risk": "CRITICAL", "type": "network_copyleft", "commercial_ok": False},
    "SSPL-1.0": {"risk": "CRITICAL", "type": "network_copyleft", "commercial_ok": False},
    "BUSL-1.1": {"risk": "HIGH", "type": "commercial_restricted", "commercial_ok": False},
    "Commons-Clause": {"risk": "HIGH", "type": "commercial_restricted", "commercial_ok": False},
}

# Known licenses for popular packages
PACKAGE_LICENSES = {
    "pypi": {
        "requests": "Apache-2.0", "flask": "BSD-3-Clause", "django": "BSD-3-Clause",
        "numpy": "BSD-3-Clause", "pandas": "BSD-3-Clause", "scipy": "BSD-3-Clause",
        "cryptography": "Apache-2.0", "paramiko": "LGPL-2.1-only",
        "celery": "BSD-3-Clause", "redis": "MIT", "sqlalchemy": "MIT",
        "boto3": "Apache-2.0", "pyyaml": "MIT", "pillow": "HPND",
        "pytest": "MIT", "setuptools": "MIT", "urllib3": "MIT",
        "certifi": "MPL-2.0", "charset-normalizer": "MIT",
        "six": "MIT", "click": "BSD-3-Clause", "werkzeug": "BSD-3-Clause",
        "jinja2": "BSD-3-Clause", "markupsafe": "BSD-3-Clause",
    },
    "npm": {
        "react": "MIT", "vue": "MIT", "express": "MIT",
        "lodash": "MIT", "axios": "MIT", "webpack": "MIT",
        "babel": "MIT", "eslint": "MIT", "moment": "MIT",
        "underscore": "MIT", "jquery": "MIT",
    },
}


class LicenseChecker:
    def check(self, deps: list, ecosystem: str) -> list:
        issues = []
        pkg_licenses = PACKAGE_LICENSES.get(ecosystem, {})

        for dep in deps:
            name_lower = dep["name"].lower()
            license_id = pkg_licenses.get(name_lower)

            if not license_id:
                # Unknown license
                issues.append({
                    "package": dep["name"],
                    "version": dep.get("version", "unknown"),
                    "license": "UNKNOWN",
                    "risk": "MEDIUM",
                    "issue": "License could not be determined — manual review required",
                    "recommendation": "Check package repository for license information",
                })
                continue

            license_info = SPDX_LICENSES.get(license_id)
            if not license_info:
                continue

            if license_info["commercial_ok"] is False:
                issues.append({
                    "package": dep["name"],
                    "version": dep.get("version", "unknown"),
                    "license": license_id,
                    "risk": license_info["risk"],
                    "type": license_info["type"],
                    "issue": f"{license_id} is a {license_info['type']} license — may require open-sourcing your code",
                    "recommendation": "Consult legal team; consider replacing with a permissively-licensed alternative",
                })
            elif license_info["commercial_ok"] is None:
                issues.append({
                    "package": dep["name"],
                    "version": dep.get("version", "unknown"),
                    "license": license_id,
                    "risk": license_info["risk"],
                    "type": license_info["type"],
                    "issue": f"{license_id} is a weak copyleft license — review required for commercial use",
                    "recommendation": "Review license terms; may be acceptable depending on usage pattern",
                })

        return issues
