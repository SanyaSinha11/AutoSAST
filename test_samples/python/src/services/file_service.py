import os
from pathlib import Path
from security.validators import validate_path, sanitize_path


class FileService:
    def __init__(self, base_directory):
        self.base_dir = Path(base_directory).resolve()
    
    def read_file(self, filename):
        safe_path = validate_path(self.base_dir, filename)
        with open(safe_path, 'rb') as f:
            return f.read()
    
    def read_text(self, filename):
        safe_path = validate_path(self.base_dir, filename)
        with open(safe_path, 'r', encoding='utf-8') as f:
            return f.read()
    
    def file_exists(self, filename):
        try:
            sanitized = sanitize_path(filename)
            safe_path = validate_path(self.base_dir, sanitized)
            return safe_path.exists()
        except (PermissionError, ValueError):
            return False
    
    def get_file_info(self, filename):
        safe_path = validate_path(self.base_dir, filename)
        stat = safe_path.stat()
        return {
            'name': safe_path.name,
            'size': stat.st_size,
            'modified': stat.st_mtime
        }
    
    def list_directory(self, subdir=''):
        if subdir:
            safe_path = validate_path(self.base_dir, subdir)
        else:
            safe_path = self.base_dir
        
        if not safe_path.is_dir():
            raise ValueError("Not a directory")
        
        return [f.name for f in safe_path.iterdir() if f.is_file()]

