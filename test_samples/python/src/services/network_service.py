import subprocess
import requests
from security.validators import (
    validate_url, sanitize_command_arg, is_valid_hostname
)

ALLOWED_COMMANDS = frozenset(['ping', 'nslookup', 'traceroute', 'dig'])


class NetworkService:
    def __init__(self):
        pass
    
    def ping_host(self, hostname):
        safe_host = sanitize_command_arg(hostname)
        if not is_valid_hostname(safe_host):
            raise ValueError("Invalid hostname format")
        
        result = subprocess.run(
            ['ping', '-c', '4', safe_host],
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.stdout
    
    def dns_lookup(self, hostname):
        safe_host = sanitize_command_arg(hostname)
        if not is_valid_hostname(safe_host):
            raise ValueError("Invalid hostname format")
        
        result = subprocess.run(
            ['nslookup', safe_host],
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.stdout
    
    def fetch_from_cdn(self, url):
        validated_url = validate_url(url)
        response = requests.get(validated_url, timeout=10)
        response.raise_for_status()
        return response.text
    
    def is_reachable(self, hostname):
        try:
            safe_host = sanitize_command_arg(hostname)
            if not is_valid_hostname(safe_host):
                return False
            
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '2', safe_host],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

