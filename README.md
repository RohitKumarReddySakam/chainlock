<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&amp;weight=700&amp;size=28&amp;duration=3000&amp;pause=1000&amp;color=64FFDA&amp;center=true&amp;vCenter=true&amp;width=750&amp;lines=CHAINLOCK;CVE+Detection+%7C+SBOM+Generation;Typosquatting+%7C+License+Compliance;OSV.dev+%7C+CycloneDX+1.5" alt="Typing SVG" />

<br/>

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![OSV.dev](https://img.shields.io/badge/CVE_DB-OSV.dev-F97316?style=for-the-badge)](https://osv.dev)
[![CycloneDX](https://img.shields.io/badge/SBOM-CycloneDX_1.5-8B5CF6?style=for-the-badge)](https://cyclonedx.org)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge)](LICENSE)

<br/>

> **Detect vulnerable, malicious, and license-non-compliant dependencies before they reach production.**

<br/>

[![Ecosystems](https://img.shields.io/badge/Ecosystems-6+-64ffda?style=flat-square)](.)
[![CVEs](https://img.shields.io/badge/CVEs-Log4Shell+%2B+10_More-ef4444?style=flat-square)](.)
[![SBOM](https://img.shields.io/badge/SBOM-CycloneDX_1.5-64ffda?style=flat-square)](.)
[![Typosquat](https://img.shields.io/badge/Typosquat-Levenshtein_Analysis-64ffda?style=flat-square)](.)

</div>

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🎯 Problem Statement

Supply chain attacks are the **fastest-growing threat vector**:
- **SolarWinds (2020):** 18,000+ organizations via poisoned update
- **Log4Shell (2021):** CVSS 10.0, 3 billion+ Java installations
- **XZ Utils (2024):** Near-miss backdoor in Linux core library
- **82% of codebases** contain at least one vulnerable dependency

| Feature | Details |
|---------|---------|
| **Ecosystems** | Python, Node.js, Java Maven/Gradle, Go, Rust, Ruby |
| **Vulnerability DB** | OSV.dev API + 11 pre-loaded critical CVEs |
| **Typosquatting** | Levenshtein distance vs 50+ popular packages |
| **License Compliance** | 50+ SPDX license types, GPL/AGPL/SSPL flagging |
| **SBOM Output** | CycloneDX 1.5 with PURL identifiers |
| **Risk Scoring** | Composite 0–100 → letter grade A–F |

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🏗️ Architecture

```
Dependency File (requirements.txt / package.json / pom.xml / go.mod)
                          │
                          ▼
              ┌──────────────────────┐
              │  Dependency Extractor │
              │  Multi-ecosystem      │
              └──────────┬───────────┘
                         │
         ┌───────────────┼───────────────┬──────────────┐
         ▼               ▼               ▼              ▼
  ┌────────────┐  ┌────────────┐  ┌──────────┐  ┌────────────┐
  │Vulnerability│  │Typosquatting│  │ License  │  │    SBOM    │
  │  Checker   │  │  Detector  │  │ Checker  │  │ Generator  │
  │OSV.dev API │  │Levenshtein │  │ 50+ SPDX │  │CycloneDX   │
  │+ Local DB  │  │+ Known-bad │  │ policies │  │   1.5      │
  └─────┬──────┘  └─────┬──────┘  └────┬─────┘  └─────┬──────┘
        └───────────────┴───────────────┴───────────────┘
                                │
                    ┌───────────▼──────────┐
                    │    Risk Scoring       │
                    │  Composite 0–100      │
                    │  Letter Grade A–F     │
                    └──────────────────────┘
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🔍 Real CVEs Detected

| CVE | Package | CVSS | Vulnerability |
|-----|---------|------|--------------|
| CVE-2021-44228 | log4j 2.14.1 | **10.0** | Log4Shell RCE |
| CVE-2022-1471 | PyYAML 5.3.1 | **9.8** | SnakeYAML RCE |
| CVE-2023-49083 | cryptography 3.4.6 | 7.5 | NULL pointer dereference |
| CVE-2023-44271 | Pillow 9.0.0 | 7.5 | DoS via ImageFont |
| CVE-2023-43665 | Django 3.2.0 | 7.5 | DoS via Truncator |
| CVE-2023-30861 | Flask 2.0.0 | 7.5 | Session cookie disclosure |
| CVE-2022-40897 | setuptools 57.0.0 | 7.5 | ReDoS attack |
| CVE-2023-48795 | paramiko 2.8.0 | 5.9 | Terrapin SSH attack |
| CVE-2023-32681 | requests 2.25.0 | 6.1 | SSRF via proxy headers |
| CVE-2023-45803 | urllib3 1.26.4 | 4.2 | Redirect body disclosure |

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## ⚡ Quick Start

```bash
# Clone the repository
git clone https://github.com/RohitKumarReddySakam/chainlock.git
cd chainlock

# Setup
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

# Run
python app.py
# → http://localhost:5001
# Click ⚡ Run Demo Scan to instantly scan 14 vulnerable packages
```

### 🐳 Docker

```bash
git clone https://github.com/RohitKumarReddySakam/chainlock.git
cd chainlock
docker build -t chainlock .
docker run -p 5001:5001 chainlock
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🔌 API Reference

```bash
# Upload dependency file
POST /api/scan
Content-Type: multipart/form-data
file: requirements.txt

# Scan pasted content
POST /api/scan/text
{"content": "requests==2.25.0\n...", "filename": "requirements.txt"}

# Get scan results
GET /api/scan/<scan_id>

# Download SBOM (CycloneDX JSON)
GET /api/sbom/<scan_id>

# Run demo scan
POST /api/demo

# Stats
GET /api/stats
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🔄 CI/CD Integration

```yaml
# .github/workflows/supply-chain-check.yml
- name: Scan dependencies
  run: |
    python -c "
    from core.dependency_extractor import DependencyExtractor
    from core.vulnerability_checker import VulnerabilityChecker
    ext = DependencyExtractor()
    chk = VulnerabilityChecker()
    with open('requirements.txt') as f: content = f.read()
    deps, eco = ext.extract('requirements.txt', content)
    vulns = chk.check_all(deps)
    critical = [v for v in vulns if v.get('severity') == 'CRITICAL']
    if critical:
        exit(1)  # Fail the build
    "
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 📁 Project Structure

```
chainlock/
├── app.py                         # Flask application
├── wsgi.py                        # Gunicorn entry point
├── config.py
├── requirements.txt
├── Dockerfile
│
├── core/
│   ├── dependency_extractor.py    # Multi-ecosystem parser
│   ├── vulnerability_checker.py   # OSV.dev + local CVE DB
│   ├── sbom_generator.py          # CycloneDX 1.5 SBOM
│   ├── typosquat_detector.py      # Levenshtein analysis
│   ├── license_checker.py         # SPDX license compliance
│   └── risk_scorer.py             # Composite risk scoring
│
├── templates/                     # Jinja2 web UI
├── static/                        # CSS, JavaScript
├── tests/                         # 18 pytest tests
└── examples/                      # Sample vulnerable files
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 👨‍💻 Author

<div align="center">

**Rohit Kumar Reddy Sakam**

*DevSecOps Engineer & Security Researcher*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Rohit_Kumar_Reddy_Sakam-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/rohitkumarreddysakam)
[![GitHub](https://img.shields.io/badge/GitHub-RohitKumarReddySakam-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/RohitKumarReddySakam)
[![Portfolio](https://img.shields.io/badge/Portfolio-srkrcyber.com-64FFDA?style=for-the-badge&logo=safari&logoColor=black)](https://srkrcyber.com)

> *"Built after analyzing SolarWinds, Log4Shell, XZ Utils — to give developers automated visibility into dependency risk before attackers exploit it."*

</div>

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

<div align="center">

**⭐ Star this repo if it helped you!**

[![Star](https://img.shields.io/github/stars/RohitKumarReddySakam/chainlock?style=social)](https://github.com/RohitKumarReddySakam/chainlock)

MIT License © 2025 Rohit Kumar Reddy Sakam

</div>
