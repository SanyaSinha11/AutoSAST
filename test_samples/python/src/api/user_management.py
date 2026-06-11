"""
FastAPI User Management API - Test Sample with TP and FP cases
This file contains both true positives and false positives for security testing.
"""

from fastapi import FastAPI, HTTPException, Depends, Query
from pydantic import BaseModel
import sqlite3
import subprocess
import os
import hashlib
import secrets
from typing import Optional

app = FastAPI()


class User(BaseModel):
    username: str
    email: str
    role: str


class LoginRequest(BaseModel):
    username: str
    password: str


# ============================================================================
# TRUE POSITIVE 1: SQL Injection vulnerability
# ============================================================================
@app.get("/users/search")
async def search_users(query: str):
    """
    VULNERABLE: Direct string concatenation in SQL query
    This is a TRUE POSITIVE - real SQL injection vulnerability
    """
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # VULNERABLE: User input directly concatenated into SQL query
    sql = f"SELECT * FROM users WHERE username LIKE '%{query}%'"
    cursor.execute(sql)
    results = cursor.fetchall()
    conn.close()
    return {"users": results}


# ============================================================================
# FALSE POSITIVE 1: Safe parameterized SQL query
# ============================================================================
@app.get("/users/{user_id}")
async def get_user(user_id: int):
    """
    SAFE: Uses parameterized query
    This is a FALSE POSITIVE - SAST tools might flag any SQL query
    """
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # SAFE: Parameterized query prevents SQL injection
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    result = cursor.fetchone()
    conn.close()
    if not result:
        raise HTTPException(status_code=404, detail="User not found")
    return {"user": result}


# ============================================================================
# TRUE POSITIVE 2: Command Injection vulnerability
# ============================================================================
@app.post("/users/export")
async def export_users(filename: str):
    """
    VULNERABLE: Command injection through subprocess
    This is a TRUE POSITIVE - real command injection vulnerability
    """
    # VULNERABLE: User input directly passed to shell command
    output_path = f"/tmp/{filename}"
    subprocess.run(f"sqlite3 users.db .dump > {output_path}", shell=True)
    return {"message": f"Users exported to {output_path}"}


# ============================================================================
# FALSE POSITIVE 2: Safe subprocess usage
# ============================================================================
@app.get("/users/backup")
async def backup_users():
    """
    SAFE: No user input in subprocess, hardcoded safe command
    This is a FALSE POSITIVE - SAST tools might flag any subprocess call
    """
    # SAFE: No user input, hardcoded safe command
    timestamp = secrets.token_hex(8)
    backup_file = f"/var/backups/users_{timestamp}.db"
    subprocess.run(["cp", "users.db", backup_file], shell=False)
    return {"message": "Backup created", "file": backup_file}


# ============================================================================
# TRUE POSITIVE 3: Path Traversal vulnerability
# ============================================================================
@app.get("/users/avatar")
async def get_avatar(filename: str):
    """
    VULNERABLE: Path traversal attack possible
    This is a TRUE POSITIVE - real path traversal vulnerability
    """
    # VULNERABLE: No validation, allows ../../../etc/passwd
    avatar_path = f"/var/www/avatars/{filename}"
    if os.path.exists(avatar_path):
        with open(avatar_path, "rb") as f:
            return {"data": f.read()}
    raise HTTPException(status_code=404, detail="Avatar not found")


# ============================================================================
# FALSE POSITIVE 3: Safe file access with validation
# ============================================================================
@app.get("/users/profile-picture")
async def get_profile_picture(user_id: int):
    """
    SAFE: Controlled file access with validation
    This is a FALSE POSITIVE - SAST tools might flag file operations
    """
    # SAFE: User ID is validated and sanitized
    if user_id < 1 or user_id > 999999:
        raise HTTPException(status_code=400, detail="Invalid user ID")
    
    # SAFE: Filename is constructed from validated integer, no user input
    picture_path = f"/var/www/profiles/{user_id}.jpg"
    
    # SAFE: Additional check to prevent path traversal
    if not os.path.abspath(picture_path).startswith("/var/www/profiles/"):
        raise HTTPException(status_code=403, detail="Access denied")
    
    if os.path.exists(picture_path):
        with open(picture_path, "rb") as f:
            return {"data": f.read()}
    raise HTTPException(status_code=404, detail="Picture not found")


# ============================================================================
# TRUE POSITIVE 4: Hardcoded credentials
# ============================================================================
@app.post("/admin/login")
async def admin_login(credentials: LoginRequest):
    """
    VULNERABLE: Hardcoded admin credentials
    This is a TRUE POSITIVE - real security issue
    """
    # VULNERABLE: Hardcoded credentials
    ADMIN_USERNAME = "admin"
    ADMIN_PASSWORD = "admin123"
    
    if credentials.username == ADMIN_USERNAME and credentials.password == ADMIN_PASSWORD:
        return {"token": "admin-token-12345", "role": "admin"}
    raise HTTPException(status_code=401, detail="Invalid credentials")


# ============================================================================
# FALSE POSITIVE 4: Safe password hashing
# ============================================================================
@app.post("/users/login")
async def user_login(credentials: LoginRequest):
    """
    SAFE: Proper password hashing and comparison
    This is a FALSE POSITIVE - SAST might flag password handling
    """
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # SAFE: Parameterized query
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (credentials.username,))
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # SAFE: Proper password hashing with salt
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        credentials.password.encode('utf-8'),
        b'proper-salt-from-db',
        100000
    )
    
    if secrets.compare_digest(password_hash, result[0].encode()):
        return {"token": secrets.token_urlsafe(32), "role": "user"}
    raise HTTPException(status_code=401, detail="Invalid credentials")


# ============================================================================
# TRUE POSITIVE 5: Insecure Deserialization
# ============================================================================
@app.post("/users/import")
async def import_users(data: str):
    """
    VULNERABLE: Unsafe deserialization using eval
    This is a TRUE POSITIVE - code injection vulnerability
    """
    import pickle
    import base64

    # VULNERABLE: Using eval on user input
    user_data = eval(data)

    # Also VULNERABLE: Unpickling untrusted data
    decoded = base64.b64decode(data)
    users = pickle.loads(decoded)

    return {"imported": len(users)}


# ============================================================================
# FALSE POSITIVE 5: Safe JSON deserialization
# ============================================================================
@app.post("/users/bulk-create")
async def bulk_create_users(users_json: str):
    """
    SAFE: Using safe JSON parsing
    This is a FALSE POSITIVE - SAST might flag deserialization
    """
    import json

    # SAFE: JSON parsing is safe, no code execution
    try:
        users_data = json.loads(users_json)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    # SAFE: Validate data structure
    if not isinstance(users_data, list):
        raise HTTPException(status_code=400, detail="Expected list of users")

    created_count = 0
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    for user in users_data:
        if all(k in user for k in ["username", "email", "role"]):
            # SAFE: Parameterized query
            cursor.execute(
                "INSERT INTO users (username, email, role) VALUES (?, ?, ?)",
                (user["username"], user["email"], user["role"])
            )
            created_count += 1

    conn.commit()
    conn.close()
    return {"created": created_count}


# ============================================================================
# TRUE POSITIVE 6: XML External Entity (XXE) vulnerability
# ============================================================================
@app.post("/users/import-xml")
async def import_xml(xml_data: str):
    """
    VULNERABLE: XXE attack possible
    This is a TRUE POSITIVE - XML external entity vulnerability
    """
    import xml.etree.ElementTree as ET

    # VULNERABLE: Parsing untrusted XML without disabling external entities
    root = ET.fromstring(xml_data)

    users = []
    for user_elem in root.findall("user"):
        users.append({
            "username": user_elem.find("username").text,
            "email": user_elem.find("email").text
        })

    return {"imported": len(users)}


# ============================================================================
# FALSE POSITIVE 6: Safe XML parsing with defusedxml
# ============================================================================
@app.post("/users/safe-import-xml")
async def safe_import_xml(xml_data: str):
    """
    SAFE: Using defusedxml to prevent XXE
    This is a FALSE POSITIVE - SAST might flag XML parsing
    """
    try:
        from defusedxml import ElementTree as DefusedET
    except ImportError:
        # Fallback with manual safety checks
        import xml.etree.ElementTree as ET
        # SAFE: Validate XML structure first
        if "<!ENTITY" in xml_data or "<!DOCTYPE" in xml_data:
            raise HTTPException(status_code=400, detail="External entities not allowed")
        root = ET.fromstring(xml_data)
    else:
        # SAFE: defusedxml prevents XXE attacks
        root = DefusedET.fromstring(xml_data)

    users = []
    for user_elem in root.findall("user"):
        username_elem = user_elem.find("username")
        email_elem = user_elem.find("email")

        if username_elem is not None and email_elem is not None:
            users.append({
                "username": username_elem.text,
                "email": email_elem.text
            })

    return {"imported": len(users)}


# ============================================================================
# TRUE POSITIVE 7: Server-Side Request Forgery (SSRF)
# ============================================================================
@app.get("/users/fetch-avatar")
async def fetch_avatar(url: str):
    """
    VULNERABLE: SSRF attack possible
    This is a TRUE POSITIVE - can access internal services
    """
    import requests

    # VULNERABLE: No URL validation, can access internal services
    response = requests.get(url)
    return {"content": response.text, "status": response.status_code}


# ============================================================================
# FALSE POSITIVE 7: Safe external API call with whitelist
# ============================================================================
@app.get("/users/fetch-gravatar")
async def fetch_gravatar(email: str):
    """
    SAFE: Controlled external API call with whitelist
    This is a FALSE POSITIVE - SAST might flag HTTP requests
    """
    import requests
    import re

    # SAFE: Validate email format
    if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
        raise HTTPException(status_code=400, detail="Invalid email")

    # SAFE: Hardcoded trusted URL, no user input in URL
    email_hash = hashlib.md5(email.lower().encode()).hexdigest()
    gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}"

    # SAFE: Only accessing whitelisted domain
    response = requests.get(gravatar_url, timeout=5)
    return {"avatar_url": gravatar_url, "status": response.status_code}


# ============================================================================
# TRUE POSITIVE 8: Weak Cryptography
# ============================================================================
@app.post("/users/encrypt-data")
async def encrypt_data(data: str, key: str):
    """
    VULNERABLE: Using weak encryption (MD5 for encryption)
    This is a TRUE POSITIVE - weak cryptography
    """
    # VULNERABLE: MD5 is not suitable for encryption
    encrypted = hashlib.md5((data + key).encode()).hexdigest()
    return {"encrypted": encrypted}


# ============================================================================
# FALSE POSITIVE 8: Strong cryptography
# ============================================================================
@app.post("/users/secure-encrypt")
async def secure_encrypt(data: str):
    """
    SAFE: Using proper encryption with Fernet
    This is a FALSE POSITIVE - SAST might flag crypto operations
    """
    from cryptography.fernet import Fernet

    # SAFE: Generate proper encryption key
    key = Fernet.generate_key()
    cipher = Fernet(key)

    # SAFE: Proper symmetric encryption
    encrypted = cipher.encrypt(data.encode())

    return {
        "encrypted": encrypted.decode(),
        "key": key.decode(),
        "algorithm": "Fernet (AES-128-CBC)"
    }


# ============================================================================
# TRUE POSITIVE 9: Race Condition in file operations
# ============================================================================
@app.post("/users/update-config")
async def update_config(setting: str, value: str):
    """
    VULNERABLE: Race condition (TOCTOU)
    This is a TRUE POSITIVE - time-of-check to time-of-use vulnerability
    """
    config_file = "/tmp/user_config.txt"

    # VULNERABLE: Check-then-use pattern creates race condition
    if os.path.exists(config_file):
        with open(config_file, "a") as f:
            f.write(f"{setting}={value}\n")
    else:
        with open(config_file, "w") as f:
            f.write(f"{setting}={value}\n")

    return {"message": "Config updated"}


# ============================================================================
# FALSE POSITIVE 9: Safe atomic file operations
# ============================================================================
@app.post("/users/safe-update-config")
async def safe_update_config(setting: str, value: str):
    """
    SAFE: Atomic file operations
    This is a FALSE POSITIVE - SAST might flag file operations
    """
    import tempfile
    import re

    # SAFE: Validate inputs
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", setting):
        raise HTTPException(status_code=400, detail="Invalid setting name")

    config_file = "/tmp/user_config.txt"

    # SAFE: Use atomic write with temporary file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, dir='/tmp') as tmp:
        tmp.write(f"{setting}={value}\n")
        tmp_path = tmp.name

    # SAFE: Atomic rename
    os.replace(tmp_path, config_file)

    return {"message": "Config updated safely"}


# ============================================================================
# TRUE POSITIVE 10: Regex Denial of Service (ReDoS)
# ============================================================================
@app.get("/users/validate-email")
async def validate_email(email: str):
    """
    VULNERABLE: ReDoS attack possible
    This is a TRUE POSITIVE - catastrophic backtracking in regex
    """
    import re

    # VULNERABLE: Complex regex with catastrophic backtracking
    pattern = r"^([a-zA-Z0-9]+)*@([a-zA-Z0-9]+)*\.([a-zA-Z0-9]+)*$"

    if re.match(pattern, email):
        return {"valid": True}
    return {"valid": False}


# ============================================================================
# FALSE POSITIVE 10: Safe regex with simple pattern
# ============================================================================
@app.get("/users/safe-validate-email")
async def safe_validate_email(email: str):
    """
    SAFE: Simple regex without backtracking issues
    This is a FALSE POSITIVE - SAST might flag all regex
    """
    import re

    # SAFE: Simple regex without nested quantifiers
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

    # SAFE: Also add length check to prevent DoS
    if len(email) > 254:
        return {"valid": False, "reason": "Email too long"}

    if re.match(pattern, email):
        return {"valid": True}
    return {"valid": False}

