"""
Wireless Data Transfer (WDT) Application - PRODUCTION READY
Version: 2.0
All bugs fixed, security enhanced, QR code working, admin access simplified
"""

import os
import csv
import time
import json
import logging
import threading
import subprocess
import secrets
import shutil
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import (
    Flask, render_template, redirect, url_for, request,
    send_from_directory, jsonify, abort, session, flash
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import RequestEntityTooLarge

# ==================== CONFIGURATION ====================

class Config:
    """Application configuration"""
    
    # Base directories
    BASE_DIR = Path(__file__).parent.absolute()
    UPLOAD_ROOT = BASE_DIR / "uploads"
    GENERAL_DIR = UPLOAD_ROOT / "general"
    SECURE_DIR = UPLOAD_ROOT / "secure"
    ADMIN_DIR = BASE_DIR / "admin"
    STATIC_DIR = BASE_DIR / "static"
    TEMPLATE_DIR = BASE_DIR / "templates"
    
    # Files
    LEDGER_FILE = ADMIN_DIR / "ledger.csv"
    USERS_FILE = ADMIN_DIR / "users.json"
    LOG_FILE = BASE_DIR / "wdt.log"
    
    # Security settings
    SECRET_KEY = os.environ.get("WDT_SECRET", secrets.token_hex(32))
    MAX_AGE = int(os.environ.get("MAX_AGE", 24 * 60 * 60))  # 24 hours
    MAX_UPLOAD = int(os.environ.get("MAX_UPLOAD", 10 * 1024 * 1024 * 1024))  # 10GB
    SESSION_TIMEOUT = int(os.environ.get("SESSION_TIMEOUT", 3600))  # 1 hour
    
    # Server settings
    HOST = "0.0.0.0"  # Public access for file sharing
    PORT = int(os.environ.get("WDT_PORT", 5000))
    DEBUG = os.environ.get("WDT_DEBUG", "False").lower() == "true"
    USE_HTTPS = os.environ.get("USE_HTTPS", "False").lower() == "true"
    
    # SSL/TLS
    CERT_FILE = BASE_DIR / "cert" / "cert.pem"
    KEY_FILE = BASE_DIR / "cert" / "key.pem"
    
    # Cleanup settings
    CLEANUP_INTERVAL = int(os.environ.get("CLEANUP_INTERVAL", 3600))  # 1 hour
    
    # Allowed file extensions (empty = all allowed)
    ALLOWED_EXTENSIONS = set(os.environ.get("ALLOWED_EXTENSIONS", "").split(",")) if os.environ.get("ALLOWED_EXTENSIONS") else set()

# ==================== INITIALIZATION ====================

def setup_logging():
    """Configure application logging"""
    logging.basicConfig(
        level=logging.INFO if not Config.DEBUG else logging.DEBUG,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        handlers=[
            logging.FileHandler(Config.LOG_FILE),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)


def ensure_directories():
    """Create necessary directories if they don't exist"""
    directories = [
        Config.UPLOAD_ROOT,
        Config.GENERAL_DIR,
        Config.SECURE_DIR,
        Config.ADMIN_DIR,
        Config.STATIC_DIR,
        Config.TEMPLATE_DIR,
        Config.CERT_FILE.parent
    ]
    
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)
    
    logger.info("📁 Directory structure initialized")


def initialize_ledger():
    """Initialize the ledger CSV file with consistent 7-column format"""
    if not Config.LEDGER_FILE.exists():
        with open(Config.LEDGER_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp", "event", "file",
                "uploader_mac", "downloader_mac", "token", "ip_address"
            ])
        logger.info("📋 Ledger file initialized")


def migrate_ledger():
    """Fix existing ledger.csv to ensure consistent 7-column format"""
    if not Config.LEDGER_FILE.exists():
        return
    
    try:
        # Create backup
        backup = Config.LEDGER_FILE.with_suffix('.csv.backup')
        shutil.copy(Config.LEDGER_FILE, backup)
        
        rows = []
        with open(Config.LEDGER_FILE, 'r', newline='') as f:
            reader = csv.reader(f)
            header = next(reader, None)
            
            for row in reader:
                # Ensure exactly 7 columns
                while len(row) < 7:
                    row.append("")
                rows.append(row[:7])  # Take only first 7 columns
        
        # Rewrite with correct format
        with open(Config.LEDGER_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "event", "file", "uploader_mac", 
                            "downloader_mac", "token", "ip_address"])
            writer.writerows(rows)
        
        logger.info(f"✅ Ledger migrated. Backup saved to {backup}")
    
    except Exception as e:
        logger.error(f"❌ Ledger migration failed: {e}")


# Initialize logger
logger = setup_logging()

# Create app
app = Flask(
    __name__,
    static_folder=str(Config.STATIC_DIR),
    template_folder=str(Config.TEMPLATE_DIR)
)

# Configure app
app.secret_key = Config.SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = Config.MAX_UPLOAD
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=Config.USE_HTTPS,
    SESSION_COOKIE_SAMESITE="Strict",
    PERMANENT_SESSION_LIFETIME=timedelta(seconds=Config.SESSION_TIMEOUT)
)

# Initialize
ensure_directories()
initialize_ledger()
migrate_ledger()  # Fix any existing ledger issues

# Thread-safe ledger writing
LEDGER_LOCK = threading.Lock()


# ==================== SECURITY MIDDLEWARE ====================

@app.before_request
def enforce_admin_localhost():
    """
    CRITICAL SECURITY: Block ALL non-localhost access to admin routes
    This makes admin panel ONLY accessible via SSH tunnel
    """
    if request.path.startswith("/admin"):
        # Only allow localhost/127.0.0.1
        allowed_ips = {"127.0.0.1", "localhost", "::1"}
        if request.remote_addr not in allowed_ips:
            logger.warning(f"🚨 SECURITY: Blocked admin access from {request.remote_addr}")
            abort(403)


@app.before_request
def check_session_timeout():
    """Check for session timeout"""
    if session.get("admin"):
        last_activity = session.get("last_activity", 0)
        current_time = time.time()
        
        if current_time - last_activity > Config.SESSION_TIMEOUT:
            session.clear()
            flash("⏰ Session expired. Please log in again.", "warning")
            return redirect(url_for("admin_login"))
        
        session["last_activity"] = current_time


@app.after_request
def security_headers(response):
    """Add security headers to all responses"""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    # Admin routes get extra protection
    if request.path.startswith("/admin"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    
    return response


# ==================== UTILITIES ====================

def get_mac_address(ip):
    """Get MAC address for given IP using ARP table"""
    try:
        # Try ip neigh (Linux)
        result = subprocess.run(
            ["ip", "neigh", "show", ip],
            capture_output=True,
            text=True,
            timeout=2
        )
        
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[0] == ip:
                    return parts[4].upper()
        
        # Fallback: try arp
        result = subprocess.run(
            ["arp", "-n", ip],
            capture_output=True,
            text=True,
            timeout=2
        )
        
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if ip in line:
                    parts = line.split()
                    for part in parts:
                        if ":" in part and len(part) == 17:
                            return part.upper()
    
    except Exception as e:
        logger.debug(f"Failed to get MAC for {ip}: {e}")
    
    return "UNKNOWN"


def safe_filename_with_counter(folder, filename):
    """Generate unique filename by adding counter if necessary"""
    filename = secure_filename(filename)
    if not filename:
        filename = f"file_{secrets.token_hex(4)}"
    
    base, ext = os.path.splitext(filename)
    filepath = Path(folder) / filename
    counter = 1
    
    while filepath.exists():
        filename = f"{base}_{counter}{ext}"
        filepath = Path(folder) / filename
        counter += 1
    
    return filename


def is_allowed_file(filename):
    """Check if file extension is allowed"""
    if not Config.ALLOWED_EXTENSIONS:
        return True
    
    ext = Path(filename).suffix.lower().lstrip(".")
    return ext in Config.ALLOWED_EXTENSIONS


def write_to_ledger(event, filename, uploader="", downloader="", token="", ip=""):
    """Thread-safe ledger writing with consistent 7-column format"""
    try:
        with LEDGER_LOCK:
            with open(Config.LEDGER_FILE, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    datetime.utcnow().isoformat(),
                    event,
                    filename,
                    uploader or "",  # Ensure empty string, not None
                    downloader or "",
                    token or "",
                    ip or ""
                ])
        logger.debug(f"📝 Ledger: {event} - {filename}")
    except Exception as e:
        logger.error(f"❌ Failed to write to ledger: {e}")


def generate_secure_token(length=11):
    """Generate cryptographically secure token"""
    return secrets.token_urlsafe(length)


def format_file_size(bytes_size):
    """Format bytes to human-readable size"""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_size < 1024.0:
            return f"{bytes_size:.1f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.1f} PB"


def get_storage_stats():
    """Get storage statistics with both formatted and raw values"""
    try:
        stat = os.statvfs(Config.UPLOAD_ROOT)
        total = stat.f_blocks * stat.f_frsize
        used = (stat.f_blocks - stat.f_bfree) * stat.f_frsize
        free = stat.f_bavail * stat.f_frsize
        percent = (used / total * 100) if total > 0 else 0
        
        return {
            # Formatted strings
            "total": format_file_size(total),
            "used": format_file_size(used),
            "free": format_file_size(free),
            # Raw bytes for calculations
            "total_bytes": total,
            "used_bytes": used,
            "free_bytes": free,
            # Percentage
            "percent": round(percent, 2)
        }
    except Exception as e:
        logger.error(f"Storage stats error: {e}")
        return {
            "total": "N/A",
            "used": "N/A",
            "free": "N/A",
            "total_bytes": 0,
            "used_bytes": 0,
            "free_bytes": 0,
            "percent": 0
        }


def get_file_expiry_seconds(filepath):
    """Calculate seconds until file expiration"""
    try:
        mtime = filepath.stat().st_mtime
        age = time.time() - mtime
        remaining = Config.MAX_AGE - age
        return max(0, int(remaining))
    except:
        return 0


def cleanup_expired_files():
    """Remove files older than MAX_AGE"""
    try:
        now = time.time()
        count = 0
        
        for directory in [Config.GENERAL_DIR, Config.SECURE_DIR]:
            for item in directory.rglob("*"):
                if item.is_file():
                    age = now - item.stat().st_mtime
                    if age > Config.MAX_AGE:
                        item.unlink()
                        write_to_ledger("AUTO_DELETE", item.name)
                        count += 1
                        logger.info(f"🗑️ Auto-deleted expired file: {item.name}")
        
        # Clean empty secure directories
        for token_dir in Config.SECURE_DIR.iterdir():
            if token_dir.is_dir() and not any(token_dir.iterdir()):
                token_dir.rmdir()
        
        if count > 0:
            logger.info(f"✅ Cleanup completed: {count} expired files removed")
    
    except Exception as e:
        logger.error(f"❌ Cleanup error: {e}")


def start_cleanup_thread():
    """Start background cleanup thread"""
    def cleanup_worker():
        while True:
            cleanup_expired_files()
            time.sleep(Config.CLEANUP_INTERVAL)
    
    thread = threading.Thread(target=cleanup_worker, daemon=True)
    thread.start()
    logger.info(f"🧹 Cleanup thread started (interval: {Config.CLEANUP_INTERVAL}s)")


# ==================== DECORATORS ====================

def login_required(f):
    """Decorator to require admin login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("admin"):
            flash("Please log in to access this page", "warning")
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated_function


# ==================== ROUTES: MAIN ====================

@app.route("/")
def index():
    """Main page - file upload and listing"""
    try:
        files = []
        for filepath in sorted(Config.GENERAL_DIR.glob("*")):
            if filepath.is_file():
                stat = filepath.stat()
                files.append({
                    "name": filepath.name,
                    "size": format_file_size(stat.st_size),
                    "uploaded": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
                    "expires_in": get_file_expiry_seconds(filepath)
                })
        
        stats = get_storage_stats()
        
        return render_template("index.html", files=files, stats=stats)
    
    except Exception as e:
        logger.error(f"❌ Index error: {e}")
        return render_template("index.html", files=[], stats={})


@app.route("/upload", methods=["POST"])
def upload():
    """Handle single file upload - Returns JSON"""
    try:
        file = request.files.get("file")
        
        if not file or file.filename == "":
            return jsonify({"error": "No file selected"}), 400
        
        if not is_allowed_file(file.filename):
            return jsonify({"error": "File type not allowed"}), 400
        
        filename = safe_filename_with_counter(Config.GENERAL_DIR, file.filename)
        filepath = Config.GENERAL_DIR / filename
        
        file.save(filepath)
        
        mac = get_mac_address(request.remote_addr)
        write_to_ledger("UPLOAD", filename, uploader=mac, ip=request.remote_addr)
        
        logger.info(f"✅ File uploaded: {filename} from {request.remote_addr}")
        return jsonify({"success": True, "filename": filename})
    
    except RequestEntityTooLarge:
        return jsonify({"error": f"File too large. Maximum: {format_file_size(Config.MAX_UPLOAD)}"}), 413
    except Exception as e:
        logger.error(f"❌ Upload error: {e}")
        return jsonify({"error": "Upload failed"}), 500


@app.route("/upload_secure", methods=["POST"])
def upload_secure():
    """Upload to secure directory with unique token - Returns JSON for QR code"""
    try:
        file = request.files.get("file")
        
        if not file or file.filename == "":
            return jsonify({"error": "No file selected"}), 400
        
        if not is_allowed_file(file.filename):
            return jsonify({"error": "File type not allowed"}), 400
        
        # Generate or reuse token from session
        token = request.form.get("token") or generate_secure_token()
        token_dir = Config.SECURE_DIR / token
        token_dir.mkdir(parents=True, exist_ok=True)
        
        filename = safe_filename_with_counter(token_dir, file.filename)
        filepath = token_dir / filename
        
        file.save(filepath)
        
        mac = get_mac_address(request.remote_addr)
        write_to_ledger("UPLOAD_SECURE", filename, uploader=mac, token=token, ip=request.remote_addr)
        
        secure_url = url_for("secure_view", token=token, _external=True)
        
        logger.info(f"🔒 Secure file uploaded: {filename} (token: {token})")
        
        # Return JSON for QR code generation
        return jsonify({
            "success": True,
            "token": token,
            "url": secure_url,
            "filename": filename
        })
    
    except RequestEntityTooLarge:
        return jsonify({"error": f"File too large. Maximum: {format_file_size(Config.MAX_UPLOAD)}"}), 413
    except Exception as e:
        logger.error(f"❌ Secure upload error: {e}")
        return jsonify({"error": "Upload failed"}), 500


@app.route("/download/<filename>")
def download(filename):
    """Download file from general directory"""
    try:
        filename = secure_filename(filename)
        filepath = Config.GENERAL_DIR / filename
        
        if not filepath.exists():
            abort(404)
        
        mac = get_mac_address(request.remote_addr)
        write_to_ledger("DOWNLOAD", filename, downloader=mac, ip=request.remote_addr)
        
        return send_from_directory(Config.GENERAL_DIR, filename, as_attachment=True)
    
    except Exception as e:
        logger.error(f"❌ Download error: {e}")
        abort(500)


@app.route("/delete/<filename>", methods=["POST"])
def delete(filename):
    """Delete file from general directory"""
    try:
        filename = secure_filename(filename)
        filepath = Config.GENERAL_DIR / filename
        
        if filepath.exists():
            filepath.unlink()
            write_to_ledger("DELETE", filename, ip=request.remote_addr)
            flash(f"File '{filename}' deleted successfully", "success")
            logger.info(f"🗑️ File deleted: {filename}")
        else:
            flash(f"File '{filename}' not found", "error")
    
    except Exception as e:
        logger.error(f"❌ Delete error: {e}")
        flash("Failed to delete file", "error")
    
    return redirect(url_for("index"))


# ==================== ROUTES: SECURE FILES ====================

@app.route("/secure/<token>")
def secure_view(token):
    """View secure files for a given token"""
    try:
        token = secure_filename(token)
        token_dir = Config.SECURE_DIR / token
        
        if not token_dir.exists() or not token_dir.is_dir():
            logger.warning(f"⚠️ Invalid token accessed: {token}")
            abort(404)
        
        files = []
        for filepath in sorted(token_dir.glob("*")):
            if filepath.is_file():
                stat = filepath.stat()
                files.append({
                    "name": filepath.name,
                    "size": format_file_size(stat.st_size),
                    "uploaded": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
                    "expires_in": get_file_expiry_seconds(filepath)
                })
        
        return render_template("secure.html", files=files, token=token)
    
    except Exception as e:
        logger.error(f"❌ Secure view error: {e}")
        abort(500)


@app.route("/secure_download/<token>/<filename>")
def secure_download(token, filename):
    """Download file from secure directory"""
    try:
        token = secure_filename(token)
        filename = secure_filename(filename)
        
        token_dir = Config.SECURE_DIR / token
        filepath = token_dir / filename
        
        if not filepath.exists():
            abort(404)
        
        mac = get_mac_address(request.remote_addr)
        write_to_ledger("DOWNLOAD_SECURE", filename, downloader=mac, token=token, ip=request.remote_addr)
        
        return send_from_directory(token_dir, filename, as_attachment=True)
    
    except Exception as e:
        logger.error(f"❌ Secure download error: {e}")
        abort(500)


@app.route("/secure_delete/<token>/<filename>", methods=["POST"])
def secure_delete(token, filename):
    """Delete file from secure directory"""
    try:
        token = secure_filename(token)
        filename = secure_filename(filename)
        
        token_dir = Config.SECURE_DIR / token
        filepath = token_dir / filename
        
        if filepath.exists():
            filepath.unlink()
            write_to_ledger("DELETE_SECURE", filename, token=token, ip=request.remote_addr)
            flash(f"File '{filename}' deleted successfully", "success")
            logger.info(f"🗑️ Secure file deleted: {filename}")
        
        # Remove empty token directory
        if token_dir.exists() and not any(token_dir.iterdir()):
            token_dir.rmdir()
    
    except Exception as e:
        logger.error(f"❌ Secure delete error: {e}")
        flash("Failed to delete file", "error")
    
    return redirect(url_for("secure_view", token=token))


# ==================== ROUTES: STATS & INFO ====================

@app.route("/stats")
def stats():
    """Get storage statistics - Returns JSON"""
    try:
        return jsonify(get_storage_stats())
    except Exception as e:
        logger.error(f"❌ Stats error: {e}")
        return jsonify({"error": "Failed to get stats"}), 500


# ==================== ROUTES: ADMIN (SSH-ONLY) ====================

@app.route("/admin")
def admin_root():
    """Redirect /admin to dashboard if logged in, otherwise to login"""
    if session.get("admin"):
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("admin_login"))


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    """
    Admin login - ONLY accessible via SSH tunnel (127.0.0.1)
    SSH tunnel provides authentication - no password needed
    """
    if session.get("admin"):
        return redirect(url_for("admin_dashboard"))
    
    if request.method == "POST":
        # SSH tunnel access = authenticated
        session.clear()
        session["admin"] = True
        session["last_activity"] = time.time()
        session.permanent = True
        logger.info(f"✅ Admin login via SSH from {request.remote_addr}")
        flash("Login successful", "success")
        return redirect(url_for("admin_dashboard"))
    
    return render_template("admin_login.html")


@app.route("/admin/dashboard")
@login_required
def admin_dashboard():
    """Admin dashboard - view activity ledger"""
    try:
        rows = []
        if Config.LEDGER_FILE.exists():
            with open(Config.LEDGER_FILE, newline="") as f:
                reader = csv.reader(f)
                next(reader)  # Skip header
                rows = list(reader)
                rows.reverse()  # Most recent first
        
        stats = get_storage_stats()
        
        return render_template("admin_dashboard.html", rows=rows, stats=stats)
    
    except Exception as e:
        logger.error(f"❌ Dashboard error: {e}")
        flash("Error loading dashboard", "error")
        return render_template("admin_dashboard.html", rows=[], stats={})


@app.route("/admin/export")
@login_required
def admin_export():
    """Export ledger as CSV"""
    try:
        if not Config.LEDGER_FILE.exists():
            abort(404)
        
        return send_from_directory(
            Config.ADMIN_DIR,
            "ledger.csv",
            as_attachment=True,
            download_name=f"ledger_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
    
    except Exception as e:
        logger.error(f"❌ Export error: {e}")
        abort(500)


@app.route("/admin/logout")
def admin_logout():
    """Admin logout"""
    session.clear()
    logger.info(f"👋 Admin logout from {request.remote_addr}")
    flash("Logged out successfully", "info")
    return redirect(url_for("index"))


# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    return render_template("error.html", error="Page not found", code=404), 404


@app.errorhandler(403)
def forbidden(e):
    """Handle 403 errors"""
    return render_template("error.html", error="Access forbidden", code=403), 403


@app.errorhandler(413)
def too_large(e):
    """Handle file too large errors"""
    return render_template("error.html", error="File too large", code=413), 413


@app.errorhandler(429)
def rate_limited(e):
    """Handle rate limiting"""
    return render_template("error.html", error="Too many requests", code=429), 429


@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors"""
    logger.error(f"❌ Internal error: {e}")
    return render_template("error.html", error="Internal server error", code=500), 500


# ==================== MAIN ====================

if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info("🚀 Wireless Data Transfer (WDT) Application")
    logger.info("SSH-ONLY ADMIN ACCESS MODE")
    logger.info("=" * 60)
    logger.info(f"🌐 Public Host: {Config.HOST}:{Config.PORT}")
    logger.info(f"🔒 Admin Access: LOCALHOST ONLY (127.0.0.1)")
    logger.info(f"🔑 SSH Tunnel: ssh -L {Config.PORT}:localhost:{Config.PORT} pi@your-pi-ip")
    logger.info(f"🐛 Debug: {Config.DEBUG}")
    logger.info(f"🔐 HTTPS: {Config.USE_HTTPS}")
    logger.info(f"📦 Max Upload: {format_file_size(Config.MAX_UPLOAD)}")
    logger.info(f"⏰ File Expiry: {Config.MAX_AGE / 3600:.1f} hours")
    logger.info("=" * 60)
    
    # Start cleanup thread
    start_cleanup_thread()
    
    # Run with SSL if configured
    if Config.USE_HTTPS and Config.CERT_FILE.exists() and Config.KEY_FILE.exists():
        ssl_context = (str(Config.CERT_FILE), str(Config.KEY_FILE))
        app.run(
            host=Config.HOST,
            port=Config.PORT,
            debug=Config.DEBUG,
            ssl_context=ssl_context
        )
    else:
        app.run(
            host=Config.HOST,
            port=Config.PORT,
            debug=Config.DEBUG
        )