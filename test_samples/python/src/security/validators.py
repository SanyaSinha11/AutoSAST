import re
import os
from pathlib import Path
from urllib.parse import urlparse

SAFE_IDENTIFIER = re.compile(r'^[a-zA-Z][a-zA-Z0-9_]{0,63}$')
SQL_INJECTION_PATTERN = re.compile(
    r"(--|;|'|\"|\\|UNION|SELECT|INSERT|UPDATE|DELETE|DROP|EXEC)",
    re.IGNORECASE
)

ALLOWED_HOSTS = frozenset([
    'api.company.com', 'cdn.company.com', 'assets.company.com'
])

SHELL_METACHAR = re.compile(r'[;&|`$(){}[\]<>!\\"\']')
SAFE_HOSTNAME = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9.-]{0,253}[a-zA-Z0-9]$')


def sanitize_sql_input(value):
    if value is None:
        return ''
    cleaned = SQL_INJECTION_PATTERN.sub('', str(value))
    return cleaned.strip()


def is_safe_identifier(value):
    if not value:
        return False
    return bool(SAFE_IDENTIFIER.match(value))


def validate_path(base_dir, requested_path):
    if not requested_path:
        raise ValueError("Path cannot be empty")
    
    base = Path(base_dir).resolve()
    full_path = (base / requested_path).resolve()
    
    if not str(full_path).startswith(str(base)):
        raise PermissionError("Path traversal detected")
    
    return full_path


def sanitize_path(input_path):
    if not input_path:
        return ''
    blocked = ['..', '~', '$', '%', '|', ';', '&', '`']
    result = input_path
    for char in blocked:
        result = result.replace(char, '')
    return result


def validate_url(url_string):
    if not url_string:
        raise ValueError("URL cannot be empty")
    
    parsed = urlparse(url_string)
    
    if parsed.scheme != 'https':
        raise ValueError("Only HTTPS URLs allowed")
    
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError(f"Host not allowed: {parsed.hostname}")
    
    return url_string


def sanitize_command_arg(arg):
    if arg is None:
        return ''
    return SHELL_METACHAR.sub('', str(arg))


def is_valid_hostname(hostname):
    if not hostname:
        return False
    return bool(SAFE_HOSTNAME.match(hostname))

