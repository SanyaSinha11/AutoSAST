"""Network utilities."""
import requests
import socket
from urllib.parse import urlparse

ALLOWED_HOSTS = {'api.internal.acme.com', 'cdn.acme.com'}


def fetch_url(url: str) -> bytes:
    """TP: SSRF - no URL validation."""
    response = requests.get(url, timeout=30)
    return response.content


def fetch_internal(endpoint: str) -> bytes:
    """FP: Only allows specific hosts."""
    parsed = urlparse(endpoint)
    
    if parsed.scheme not in ('http', 'https'):
        raise ValueError("Invalid scheme")
    
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Host not allowed")
    
    response = requests.get(endpoint, timeout=30)
    return response.content


def resolve_host(hostname: str) -> str:
    """FP: Just DNS resolution, no connection."""
    return socket.gethostbyname(hostname)


def check_port(host: str, port: int) -> bool:
    """TP: Port scanning capability."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

