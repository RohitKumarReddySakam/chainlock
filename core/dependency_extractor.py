"""
Dependency Extractor
Parses dependency files across Python, Node.js, Java, Go ecosystems
"""
import re
import json
import logging

logger = logging.getLogger(__name__)

ECOSYSTEM_MAP = {
    "requirements.txt": "pypi",
    "requirements-dev.txt": "pypi",
    "requirements-test.txt": "pypi",
    "Pipfile": "pypi",
    "Pipfile.lock": "pypi",
    "pyproject.toml": "pypi",
    "setup.cfg": "pypi",
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "go.mod": "go",
    "go.sum": "go",
    "Cargo.toml": "cargo",
    "Cargo.lock": "cargo",
    "Gemfile": "rubygems",
    "Gemfile.lock": "rubygems",
}


class DependencyExtractor:
    def extract(self, filename: str, content: str) -> tuple:
        """Returns (list of {name, version}, ecosystem)"""
        # Normalize filename
        base = filename.lower().split("/")[-1]
        ecosystem = ECOSYSTEM_MAP.get(filename, ECOSYSTEM_MAP.get(base, "unknown"))

        parsers = {
            "pypi": self._parse_requirements,
            "npm": self._parse_npm,
            "maven": self._parse_maven,
            "gradle": self._parse_gradle,
            "go": self._parse_go_mod,
            "cargo": self._parse_cargo,
            "rubygems": self._parse_gemfile,
            "unknown": self._parse_requirements,  # fallback
        }

        parser = parsers.get(ecosystem, self._parse_requirements)
        deps = parser(content)

        # Deduplicate
        seen, unique = set(), []
        for d in deps:
            key = d["name"].lower()
            if key not in seen:
                seen.add(key)
                unique.append(d)

        logger.info(f"Extracted {len(unique)} deps from {filename} [{ecosystem}]")
        return unique, ecosystem

    def _parse_requirements(self, content: str) -> list:
        deps = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Remove inline comments
            line = re.sub(r"\s*#.*$", "", line).strip()
            # Handle ==, >=, <=, ~=, !=, >
            match = re.match(r"^([A-Za-z0-9_\-\.]+)\s*([><=!~]+)\s*([\d\.a-zA-Z\*]+)", line)
            if match:
                name, op, ver = match.groups()
                deps.append({"name": name, "version": ver if op == "==" else "latest", "operator": op})
            else:
                # Plain name
                name = re.match(r"^([A-Za-z0-9_\-\.]+)", line)
                if name:
                    deps.append({"name": name.group(1), "version": "unknown", "operator": ""})
        return deps

    def _parse_npm(self, content: str) -> list:
        deps = []
        try:
            data = json.loads(content)
            for section in ["dependencies", "devDependencies", "peerDependencies"]:
                for name, version in data.get(section, {}).items():
                    # Strip ^ ~ from versions
                    ver = re.sub(r"^[\^~>=<]", "", str(version)).strip()
                    deps.append({"name": name, "version": ver or "latest", "operator": ""})
        except json.JSONDecodeError:
            # Try yarn.lock format
            for match in re.finditer(r'"?([^"@\n]+)@[^"]*"?\s*:\s*\n\s+version\s+"([^"]+)"', content):
                deps.append({"name": match.group(1), "version": match.group(2), "operator": "=="})
        return deps

    def _parse_maven(self, content: str) -> list:
        deps = []
        pattern = re.compile(
            r"<dependency>.*?<groupId>(.*?)</groupId>.*?<artifactId>(.*?)</artifactId>"
            r"(?:.*?<version>(.*?)</version>)?.*?</dependency>",
            re.DOTALL
        )
        for m in pattern.finditer(content):
            group, artifact, version = m.groups()
            deps.append({
                "name": f"{group.strip()}:{artifact.strip()}",
                "version": version.strip() if version else "unknown",
                "operator": ""
            })
        return deps

    def _parse_gradle(self, content: str) -> list:
        deps = []
        patterns = [
            r"""implementation\s+['"]([^:'"]+):([^:'"]+):([^'"]+)['"]""",
            r"""compile\s+['"]([^:'"]+):([^:'"]+):([^'"]+)['"]""",
            r"""testImplementation\s+['"]([^:'"]+):([^:'"]+):([^'"]+)['"]""",
        ]
        for pattern in patterns:
            for m in re.finditer(pattern, content):
                group, artifact, version = m.groups()
                deps.append({"name": f"{group}:{artifact}", "version": version, "operator": ""})
        return deps

    def _parse_go_mod(self, content: str) -> list:
        deps = []
        for line in content.splitlines():
            line = line.strip()
            match = re.match(r"^([a-z][a-z0-9\-\.\/]+)\s+v([\d\.]+)", line)
            if match:
                deps.append({"name": match.group(1), "version": match.group(2), "operator": ""})
        return deps

    def _parse_cargo(self, content: str) -> list:
        deps = []
        pattern = re.compile(r'^([a-zA-Z0-9_\-]+)\s*=\s*["\{]([^"}\n]+)', re.MULTILINE)
        for m in pattern.finditer(content):
            name, version = m.groups()
            ver = re.search(r"[\d\.]+", version)
            deps.append({"name": name, "version": ver.group() if ver else "unknown", "operator": ""})
        return deps

    def _parse_gemfile(self, content: str) -> list:
        deps = []
        for line in content.splitlines():
            match = re.match(r"""gem\s+['"]([^'"]+)['"](?:,\s*['"]([^'"]+)['"])?""", line.strip())
            if match:
                name, version = match.groups()
                deps.append({"name": name, "version": version or "latest", "operator": ""})
        return deps
