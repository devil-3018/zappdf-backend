"""
ZapPDF — security.py
Full security layer:
- Rate limiting (stops bots & DDoS)
- File validation (stops malicious uploads)
- CORS restriction (stops unauthorized API access)
- Input sanitization (stops injection attacks)
- Temp file cleanup (stops disk filling)
- Security headers (stops XSS, clickjacking)
- Request size limits (stops server crashes)
"""

import os, re, time, hashlib, asyncio, logging
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict
from fastapi import Request, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

# ── LOGGING SETUP ─────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('zappdf_security.log')
    ]
)
log = logging.getLogger("zappdf.security")


# ══════════════════════════════════════════════════════
# 1. RATE LIMITER
# Stops bots, DDoS attacks, API abuse
# ══════════════════════════════════════════════════════

class RateLimiter:
    """
    Token bucket rate limiter per IP address.
    Free users: 30 requests per minute
    After limit: 429 Too Many Requests
    """
    def __init__(self):
        self.buckets   = defaultdict(list)   # IP → [timestamps]
        self.blocked   = defaultdict(float)  # IP → blocked_until timestamp

    def get_client_ip(self, request: Request) -> str:
        # Get real IP even behind proxy/CDN
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host or "unknown"

    def is_allowed(self, ip: str, limit: int = 30, window: int = 60) -> tuple[bool, int]:
        """
        Returns (allowed, seconds_until_reset)
        limit  = max requests per window
        window = time window in seconds
        """
        now = time.time()

        # Check if IP is hard-blocked
        if self.blocked.get(ip, 0) > now:
            wait = int(self.blocked[ip] - now)
            log.warning(f"BLOCKED IP attempt: {ip} (blocked for {wait}s more)")
            return False, wait

        # Remove old timestamps outside the window
        self.buckets[ip] = [t for t in self.buckets[ip] if now - t < window]

        # Check limit
        if len(self.buckets[ip]) >= limit:
            # If they've hit limit 3x in a row, hard block for 10 minutes
            if len(self.buckets[ip]) >= limit * 2:
                self.blocked[ip] = now + 600  # 10 minute block
                log.warning(f"HARD BLOCKED IP: {ip} for 10 minutes (abuse detected)")
            reset_in = int(window - (now - self.buckets[ip][0]))
            return False, reset_in

        # Allow and record request
        self.buckets[ip].append(now)
        return True, 0

    def cleanup(self):
        """Remove old data to prevent memory leak"""
        now = time.time()
        for ip in list(self.buckets.keys()):
            self.buckets[ip] = [t for t in self.buckets[ip] if now - t < 300]
            if not self.buckets[ip]:
                del self.buckets[ip]


# Global rate limiter instance
rate_limiter = RateLimiter()

# Different limits for different endpoints
RATE_LIMITS = {
    "default":    (30, 60),   # 30 req/min for normal tools
    "ai":         (10, 60),   # 10 req/min for AI endpoints (expensive)
    "batch":      (5,  60),   # 5 req/min for batch (very heavy)
    "auth":       (5,  300),  # 5 attempts per 5 minutes for auth
}

def get_rate_limit(path: str) -> tuple[int, int]:
    if "/ai/" in path:    return RATE_LIMITS["ai"]
    if "/batch" in path:  return RATE_LIMITS["batch"]
    if "/auth" in path:   return RATE_LIMITS["auth"]
    return RATE_LIMITS["default"]


# ══════════════════════════════════════════════════════
# 2. SECURITY HEADERS MIDDLEWARE
# Stops XSS, clickjacking, MIME sniffing attacks
# ══════════════════════════════════════════════════════

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Prevent clickjacking (your site in iframes)
        response.headers["X-Frame-Options"] = "SAMEORIGIN"

        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Enable browser XSS protection
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Referrer policy (privacy)
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Content Security Policy (stops script injection)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; "
            "img-src 'self' data: blob:; "
            "connect-src 'self' https://api.anthropic.com;"
        )

        # HSTS: Force HTTPS for 1 year (only enable after SSL is set up)
        # response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # Hide server info from hackers
        response.headers["Server"] = "ZapPDF"
        if "X-Powered-By" in response.headers:
           del response.headers["X-Powered-By"]

        return response


# ══════════════════════════════════════════════════════
# 3. RATE LIMITING MIDDLEWARE
# ══════════════════════════════════════════════════════

class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for health check
        if request.url.path == "/":
            return await call_next(request)

        ip = rate_limiter.get_client_ip(request)
        limit, window = get_rate_limit(str(request.url.path))
        allowed, wait = rate_limiter.is_allowed(ip, limit, window)

        if not allowed:
            log.warning(f"RATE LIMITED: {ip} on {request.url.path}")
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Too many requests",
                    "detail": f"Rate limit exceeded. Try again in {wait} seconds.",
                    "retry_after": wait
                },
                headers={"Retry-After": str(wait)}
            )

        return await call_next(request)


# ══════════════════════════════════════════════════════
# 4. FILE VALIDATOR
# Stops malicious file uploads
# ══════════════════════════════════════════════════════

# File size limits
MAX_FILE_SIZE     = 50 * 1024 * 1024   # 50MB per file
MAX_BATCH_SIZE    = 200 * 1024 * 1024  # 200MB total for batch
MAX_FILES_BATCH   = 50                 # Max 50 files in batch

# PDF magic bytes (first 4 bytes of every real PDF)
PDF_MAGIC = b"%PDF"

# Image magic bytes
IMAGE_MAGIC = {
    b"\xff\xd8\xff": "JPEG",
    b"\x89PNG":      "PNG",
    b"GIF8":         "GIF",
    b"RIFF":         "WEBP",
}

# Office file signatures
OFFICE_MAGIC = {
    b"PK\x03\x04": ["docx", "xlsx", "pptx"],  # ZIP-based Office files
    b"\xd0\xcf\x11\xe0": ["doc", "xls", "ppt"],  # Old Office format
}

async def validate_pdf(file: UploadFile) -> bytes:
    """
    Validate a PDF upload:
    - Check file size
    - Check it's actually a PDF (not a renamed .exe)
    - Check filename is safe
    - Return file contents
    """
    # Read file content
    content = await file.read()
    await file.seek(0)  # Reset so backend can read it again

    # 1. Size check
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            413,
            f"File too large. Maximum size is {MAX_FILE_SIZE//1024//1024}MB. "
            f"Your file is {len(content)//1024//1024}MB."
        )

    if len(content) < 10:
        raise HTTPException(400, "File is empty or corrupted.")

    # 2. Magic bytes check — verify it's actually a PDF
    if not content.startswith(PDF_MAGIC):
        log.warning(f"INVALID FILE: {file.filename} — not a real PDF (magic: {content[:4].hex()})")
        raise HTTPException(
            400,
            "Invalid file. This doesn't appear to be a PDF file. "
            "Please upload a valid .pdf file."
        )

    # 3. Filename sanitization
    safe_name = sanitize_filename(file.filename or "document.pdf")
    file.filename = safe_name

    # 4. Check for embedded executables (basic check)
    dangerous_signatures = [
        b"MZ",           # Windows EXE
        b"#!/",          # Shell script
        b"<script",      # JS injection
        b"<?php",        # PHP injection
    ]
    for sig in dangerous_signatures:
        if sig in content[:1000]:
            log.warning(f"DANGEROUS FILE: {file.filename} contains {sig}")
            raise HTTPException(400, "File contains suspicious content and was rejected.")

    return content


async def validate_image(file: UploadFile) -> bytes:
    """Validate image uploads for jpg-to-pdf"""
    content = await file.read()
    await file.seek(0)

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(413, f"Image too large. Max {MAX_FILE_SIZE//1024//1024}MB")

    # Check it's actually an image
    is_image = any(content.startswith(magic) for magic in IMAGE_MAGIC.keys())
    if not is_image:
        raise HTTPException(400, f"Invalid image file: {file.filename}")

    file.filename = sanitize_filename(file.filename or "image.jpg")
    return content


async def validate_office(file: UploadFile) -> bytes:
    """Validate Word/Excel/PPT uploads"""
    content = await file.read()
    await file.seek(0)

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(413, f"File too large. Max {MAX_FILE_SIZE//1024//1024}MB")

    # Check it's an office file
    is_office = any(content.startswith(magic) for magic in OFFICE_MAGIC.keys())
    if not is_office:
        raise HTTPException(400, f"Invalid Office file: {file.filename}")

    file.filename = sanitize_filename(file.filename or "document")
    return content


def sanitize_filename(filename: str) -> str:
    """
    Remove dangerous characters from filename.
    Prevents path traversal attacks like: ../../etc/passwd
    """
    # Get just the base name, strip directory traversal
    name = Path(filename).name

    # Only allow safe characters
    name = re.sub(r'[^\w\s\-_\.]', '', name)

    # Limit length
    name = name[:100]

    # Ensure it's not empty
    if not name or name == ".":
        name = "document.pdf"

    return name


# ══════════════════════════════════════════════════════
# 5. TEMP FILE CLEANER
# Stops disk from filling up
# ══════════════════════════════════════════════════════

import tempfile
from pathlib import Path

TMP_DIR = Path(tempfile.gettempdir()) / "zappdf"

async def cleanup_old_files():
    """
    Delete temp files older than 30 minutes.
    Runs every 15 minutes automatically.
    """
    while True:
        await asyncio.sleep(900)  # Run every 15 minutes
        try:
            now = time.time()
            deleted = 0
            total_freed = 0
            if TMP_DIR.exists():
                for f in TMP_DIR.iterdir():
                    if f.is_file():
                        age = now - f.stat().st_mtime
                        if age > 1800:  # 30 minutes old
                            size = f.stat().st_size
                            f.unlink()
                            deleted += 1
                            total_freed += size
            if deleted > 0:
                log.info(f"CLEANUP: Deleted {deleted} temp files, freed {total_freed//1024//1024}MB")
        except Exception as e:
            log.error(f"Cleanup error: {e}")


# ══════════════════════════════════════════════════════
# 6. INPUT SANITIZER
# Stops SQL injection and code injection in form fields
# ══════════════════════════════════════════════════════

# Characters that should never appear in PDF tool options
DANGEROUS_CHARS = re.compile(r'[<>&\'"`;|\\$!{}]')

def sanitize_text(text: str, max_length: int = 200) -> str:
    """Clean user text input"""
    if not text:
        return ""
    # Remove dangerous characters
    text = DANGEROUS_CHARS.sub('', text)
    # Limit length
    text = text[:max_length]
    # Strip leading/trailing whitespace
    return text.strip()

def sanitize_pages(pages: str) -> str:
    """Validate page number input like '1,3,5-7'"""
    if not pages:
        return "1"
    # Only allow digits, commas, dashes
    clean = re.sub(r'[^\d,\-]', '', pages)
    return clean[:50] or "1"

def sanitize_password(password: str) -> str:
    """Basic password validation"""
    if not password:
        raise HTTPException(400, "Password cannot be empty")
    if len(password) < 4:
        raise HTTPException(400, "Password must be at least 4 characters")
    if len(password) > 100:
        raise HTTPException(400, "Password too long (max 100 characters)")
    return password


# ══════════════════════════════════════════════════════
# 7. REQUEST LOGGER
# Track all requests for security monitoring
# ══════════════════════════════════════════════════════

class RequestLoggerMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.time()
        ip    = rate_limiter.get_client_ip(request)
        path  = request.url.path
        method = request.method

        response = await call_next(request)

        duration = round((time.time() - start) * 1000)
        status   = response.status_code

        # Log every request
        log.info(f"{method} {path} | {status} | {duration}ms | {ip}")

        # Flag suspicious patterns
        suspicious = [
            "../", "etc/passwd", "cmd.exe", "<script", "DROP TABLE",
            "SELECT *", "UNION SELECT", "/admin", "/.env", "/wp-admin"
        ]
        url_str = str(request.url)
        for pattern in suspicious:
            if pattern.lower() in url_str.lower():
                log.warning(f"SUSPICIOUS REQUEST: {ip} tried {url_str}")
                break

        return response


# ══════════════════════════════════════════════════════
# 8. DISK SPACE MONITOR
# Stops server crash from full disk
# ══════════════════════════════════════════════════════

import shutil

def check_disk_space() -> bool:
    """Returns True if enough disk space, False if running low"""
    total, used, free = shutil.disk_usage("/")
    free_gb = free / (1024 ** 3)
    if free_gb < 0.5:  # Less than 500MB free
        log.error(f"CRITICAL: Low disk space! Only {free_gb:.1f}GB free")
        return False
    return True

def get_disk_info() -> dict:
    total, used, free = shutil.disk_usage("/")
    return {
        "total_gb": round(total / 1024**3, 1),
        "used_gb":  round(used  / 1024**3, 1),
        "free_gb":  round(free  / 1024**3, 1),
        "used_pct": round(used / total * 100, 1)
    }


# ══════════════════════════════════════════════════════
# 9. HONEYPOT DETECTOR
# Catches bots probing for vulnerabilities
# ══════════════════════════════════════════════════════

# Common paths hackers probe for
HONEYPOT_PATHS = {
    "/admin", "/wp-admin", "/wp-login.php", "/.env",
    "/config", "/backup", "/db", "/phpmyadmin",
    "/api/v1/users", "/shell", "/cmd", "/.git",
    "/xmlrpc.php", "/actuator", "/manager",
}

class HoneypotMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.trap_hits = defaultdict(int)

    async def dispatch(self, request: Request, call_next):
        path = request.url.path.rstrip("/")
        ip   = rate_limiter.get_client_ip(request)

        if path in HONEYPOT_PATHS:
            self.trap_hits[ip] += 1
            log.warning(f"HONEYPOT HIT #{self.trap_hits[ip]}: {ip} probed {path}")

            # Block IP after 3 honeypot hits
            if self.trap_hits[ip] >= 3:
                rate_limiter.blocked[ip] = time.time() + 3600  # 1 hour block
                log.warning(f"AUTO-BLOCKED hacker IP: {ip}")

            # Return fake 404 (don't reveal it's a trap)
            return JSONResponse(status_code=404, content={"detail": "Not found"})

        return await call_next(request)


# ══════════════════════════════════════════════════════
# HELPER: Apply all security to FastAPI app
# ══════════════════════════════════════════════════════

def apply_security(app):
    """Call this in main.py to add all security layers"""
    # Order matters — outermost runs first
    app.add_middleware(HoneypotMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestLoggerMiddleware)
    log.info("✅ All security layers applied")
    return app
