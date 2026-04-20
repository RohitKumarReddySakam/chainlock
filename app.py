"""
CHAINLOCK — Supply Chain Security Scanner
Author: Rohit Kumar Reddy Sakam
GitHub: https://github.com/RohitKumarReddySakam
Version: 2.0.0

Detects vulnerable, malicious, and license-non-compliant dependencies
across Python, Node.js, Java, and Go ecosystems.
"""

from flask import Flask, render_template, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os, json, uuid, threading
from werkzeug.utils import secure_filename
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)

ALLOWED_EXTENSIONS = {
    "txt", "json", "xml", "toml", "lock", "gradle", "mod", "sum"
}

# ─── Models ───────────────────────────────────────────────────────
class ScanResult(db.Model):
    __tablename__ = "scan_results"
    id             = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    filename       = db.Column(db.String(200))
    ecosystem      = db.Column(db.String(50))
    total_deps     = db.Column(db.Integer, default=0)
    critical_count = db.Column(db.Integer, default=0)
    high_count     = db.Column(db.Integer, default=0)
    medium_count   = db.Column(db.Integer, default=0)
    low_count      = db.Column(db.Integer, default=0)
    clean_count    = db.Column(db.Integer, default=0)
    risk_score     = db.Column(db.Float, default=0.0)
    risk_grade     = db.Column(db.String(2), default="A")
    vulnerabilities = db.Column(db.Text, default="[]")
    sbom            = db.Column(db.Text, default="{}")
    typosquat_flags = db.Column(db.Text, default="[]")
    license_issues  = db.Column(db.Text, default="[]")
    status          = db.Column(db.String(20), default="PENDING")
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "filename": self.filename,
            "ecosystem": self.ecosystem,
            "total_deps": self.total_deps,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "clean_count": self.clean_count,
            "risk_score": self.risk_score,
            "risk_grade": self.risk_grade,
            "vulnerabilities": json.loads(self.vulnerabilities or "[]"),
            "sbom": json.loads(self.sbom or "{}"),
            "typosquat_flags": json.loads(self.typosquat_flags or "[]"),
            "license_issues": json.loads(self.license_issues or "[]"),
            "status": self.status,
            "created_at": self.created_at.isoformat(),
        }


# ─── Helpers ──────────────────────────────────────────────────────
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def run_scan(scan_id: str, filepath: str, filename: str):
    """Run full scan pipeline in background thread"""
    from core.dependency_extractor import DependencyExtractor
    from core.vulnerability_checker import VulnerabilityChecker
    from core.sbom_generator import SBOMGenerator
    from core.typosquat_detector import TyposquatDetector
    from core.license_checker import LicenseChecker
    from core.risk_scorer import RiskScorer

    with app.app_context():
        scan = ScanResult.query.get(scan_id)
        scan.status = "SCANNING"
        db.session.commit()

        try:
            extractor  = DependencyExtractor()
            vuln_chk   = VulnerabilityChecker()
            sbom_gen   = SBOMGenerator()
            typo_det   = TyposquatDetector()
            lic_chk    = LicenseChecker()
            risk_sc    = RiskScorer()

            # 1. Extract dependencies
            with open(filepath) as f:
                content = f.read()
            deps, ecosystem = extractor.extract(filename, content)

            # 2. Vulnerability check
            vulns = vuln_chk.check_all(deps)

            # 3. Typosquatting detection
            typo_flags = typo_det.detect(deps, ecosystem)

            # 4. License compliance
            lic_issues = lic_chk.check(deps, ecosystem)

            # 5. SBOM generation
            sbom = sbom_gen.generate(deps, ecosystem, filename, vulns)

            # 6. Risk scoring
            risk_score, risk_grade = risk_sc.score(vulns, typo_flags, lic_issues, len(deps))

            # Count by severity
            counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for v in vulns:
                counts[v.get("severity", "LOW")] = counts.get(v.get("severity", "LOW"), 0) + 1
            clean = len(deps) - len(set(v["package"] for v in vulns))

            scan.ecosystem       = ecosystem
            scan.total_deps      = len(deps)
            scan.critical_count  = counts["CRITICAL"]
            scan.high_count      = counts["HIGH"]
            scan.medium_count    = counts["MEDIUM"]
            scan.low_count       = counts["LOW"]
            scan.clean_count     = max(clean, 0)
            scan.risk_score      = risk_score
            scan.risk_grade      = risk_grade
            scan.vulnerabilities = json.dumps(vulns)
            scan.sbom            = json.dumps(sbom)
            scan.typosquat_flags = json.dumps(typo_flags)
            scan.license_issues  = json.dumps(lic_issues)
            scan.status          = "COMPLETED"

        except Exception as e:
            scan.status = f"FAILED: {str(e)[:100]}"

        db.session.commit()
        # Cleanup uploaded file
        try:
            os.remove(filepath)
        except Exception:
            pass


# ─── Routes ───────────────────────────────────────────────────────
@app.route("/")
def index():
    recent = ScanResult.query.order_by(ScanResult.created_at.desc()).limit(5).all()
    stats  = _global_stats()
    return render_template("index.html", recent_scans=recent, stats=stats)


@app.route("/scan/<scan_id>")
def scan_detail(scan_id):
    scan = ScanResult.query.get_or_404(scan_id)
    return render_template("results.html", scan=scan, scan_dict=scan.to_dict())


@app.route("/history")
def history():
    scans = ScanResult.query.order_by(ScanResult.created_at.desc()).all()
    return render_template("history.html", scans=scans)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    file = request.files["file"]
    if not file.filename or not allowed_file(file.filename):
        return jsonify({"error": "Invalid file type"}), 400

    filename = secure_filename(file.filename)
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], f"{uuid.uuid4()}_{filename}")
    file.save(filepath)

    scan = ScanResult(filename=filename, status="PENDING")
    db.session.add(scan)
    db.session.commit()

    # Background scan
    t = threading.Thread(target=run_scan, args=(scan.id, filepath, filename), daemon=True)
    t.start()

    return jsonify({"scan_id": scan.id, "status": "SCANNING", "message": "Scan started"}), 202


@app.route("/api/scan/text", methods=["POST"])
def api_scan_text():
    """Scan pasted text content"""
    data = request.get_json()
    content  = data.get("content", "")
    filename = data.get("filename", "requirements.txt")

    if not content:
        return jsonify({"error": "No content provided"}), 400

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], f"{uuid.uuid4()}_{filename}")
    with open(filepath, "w") as f:
        f.write(content)

    scan = ScanResult(filename=filename, status="PENDING")
    db.session.add(scan)
    db.session.commit()

    t = threading.Thread(target=run_scan, args=(scan.id, filepath, filename), daemon=True)
    t.start()

    return jsonify({"scan_id": scan.id, "status": "SCANNING"}), 202


@app.route("/api/scan/<scan_id>", methods=["GET"])
def api_scan_status(scan_id):
    scan = ScanResult.query.get_or_404(scan_id)
    return jsonify(scan.to_dict())


@app.route("/api/scans", methods=["GET"])
def api_scans():
    scans = ScanResult.query.order_by(ScanResult.created_at.desc()).limit(50).all()
    return jsonify({"scans": [s.to_dict() for s in scans]})


@app.route("/api/sbom/<scan_id>", methods=["GET"])
def download_sbom(scan_id):
    scan = ScanResult.query.get_or_404(scan_id)
    sbom_data = json.loads(scan.sbom or "{}")
    sbom_str  = json.dumps(sbom_data, indent=2)
    path = f"/tmp/sbom_{scan_id}.json"
    with open(path, "w") as f:
        f.write(sbom_str)
    return send_file(path, as_attachment=True, download_name=f"sbom_{scan.filename}.json")


@app.route("/api/demo", methods=["POST"])
def api_demo():
    """Run a demo scan with a pre-built vulnerable requirements.txt"""
    demo_content = """# Demo vulnerable requirements.txt
requests==2.25.0
cryptography==3.4.6
Pillow==9.0.0
Django==3.2.0
flask==2.0.0
numpy==1.21.0
paramiko==2.8.0
PyYAML==5.3.1
urllib3==1.26.4
certifi==2021.5.30
setuptools==57.0.0
wheel==0.36.2
boto3==1.17.0
sqlalchemy==1.4.0
"""
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], f"{uuid.uuid4()}_demo_requirements.txt")
    with open(filepath, "w") as f:
        f.write(demo_content)

    scan = ScanResult(filename="demo_requirements.txt", status="PENDING")
    db.session.add(scan)
    db.session.commit()

    t = threading.Thread(target=run_scan, args=(scan.id, filepath, "demo_requirements.txt"), daemon=True)
    t.start()

    return jsonify({"scan_id": scan.id, "message": "Demo scan started"}), 202


@app.route("/api/stats")
def api_stats():
    return jsonify(_global_stats())


@app.route("/health")
def health():
    return jsonify({"status": "healthy", "version": "2.0.0", "timestamp": datetime.utcnow().isoformat()})


def _global_stats():
    total_scans = ScanResult.query.filter_by(status="COMPLETED").count()
    total_vulns = db.session.query(db.func.sum(
        ScanResult.critical_count + ScanResult.high_count +
        ScanResult.medium_count + ScanResult.low_count
    )).scalar() or 0
    critical_found = db.session.query(db.func.sum(ScanResult.critical_count)).scalar() or 0
    total_deps = db.session.query(db.func.sum(ScanResult.total_deps)).scalar() or 0
    return {
        "total_scans": total_scans,
        "total_vulnerabilities": int(total_vulns),
        "critical_found": int(critical_found),
        "total_deps_scanned": int(total_deps),
    }


# ─── Bootstrap ────────────────────────────────────────────────────
def create_app():
    with app.app_context():
        db.create_all()
    return app


if __name__ == "__main__":
    create_app()
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port, debug=False)
