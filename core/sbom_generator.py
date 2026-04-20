"""
SBOM Generator — CycloneDX 1.5 format
Software Bill of Materials for compliance and supply chain transparency
"""
import uuid
from datetime import datetime


class SBOMGenerator:
    def generate(self, deps: list, ecosystem: str, source_file: str, vulns: list) -> dict:
        """Generate a CycloneDX 1.5 SBOM"""
        vuln_map = {}
        for v in vulns:
            pkg = v.get("package", "").lower()
            if pkg not in vuln_map:
                vuln_map[pkg] = []
            vuln_map[pkg].append(v)

        components = []
        for dep in deps:
            name = dep["name"]
            comp = {
                "type": "library",
                "bom-ref": f"{ecosystem}/{name}@{dep.get('version','unknown')}",
                "name": name,
                "version": dep.get("version", "unknown"),
                "purl": self._purl(ecosystem, name, dep.get("version", "")),
                "properties": [
                    {"name": "ecosystem", "value": ecosystem},
                    {"name": "source_file", "value": source_file},
                ],
            }
            dep_vulns = vuln_map.get(name.lower(), [])
            if dep_vulns:
                comp["vulnerabilities"] = [
                    {
                        "id": v.get("cve_id", v.get("osv_id", "N/A")),
                        "severity": v.get("severity", "UNKNOWN"),
                        "cvss": v.get("cvss", 0.0),
                        "description": v.get("description", "")[:150],
                        "fix": v.get("fixed_version", "N/A"),
                    }
                    for v in dep_vulns
                ]
            components.append(comp)

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "tools": [
                    {
                        "vendor": "RohitKumarReddySakam",
                        "name": "CHAINLOCK",
                        "version": "2.0.0",
                    }
                ],
                "component": {
                    "type": "application",
                    "name": source_file,
                    "version": "unknown",
                },
                "properties": [
                    {"name": "ecosystem", "value": ecosystem},
                    {"name": "total_components", "value": str(len(deps))},
                    {"name": "vulnerable_components", "value": str(len(vuln_map))},
                ],
            },
            "components": components,
        }
        return sbom

    def _purl(self, ecosystem: str, name: str, version: str) -> str:
        purl_types = {
            "pypi": "pypi", "npm": "npm", "maven": "maven",
            "gradle": "maven", "go": "golang", "cargo": "cargo",
            "rubygems": "gem",
        }
        t = purl_types.get(ecosystem, "generic")
        if version and version not in ("unknown", "latest"):
            return f"pkg:{t}/{name}@{version}"
        return f"pkg:{t}/{name}"
