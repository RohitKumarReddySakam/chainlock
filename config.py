import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "chainlock-dev-2025")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///chainlock.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = "uploads"
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5MB
    # OSV API (free, no key needed)
    OSV_API_URL = "https://api.osv.dev/v1"
    # NVD API (optional key for higher rate limits)
    NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
    # GitHub Advisory (optional)
    GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
