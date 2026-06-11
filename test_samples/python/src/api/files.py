"""File management API."""
import os
import subprocess
import shlex
from pathlib import Path
from flask import Flask, request, send_file, abort

app = Flask(__name__)
BASE_DIR = Path('/var/data/uploads')


@app.route('/files/download')
def download_file():
    filename = request.args.get('name', '')
    filepath = os.path.join(str(BASE_DIR), filename)
    return send_file(filepath)


@app.route('/files/get')
def get_file():
    filename = request.args.get('name', '')
    target = (BASE_DIR / filename).resolve()
    
    if not str(target).startswith(str(BASE_DIR.resolve())):
        abort(403)
    
    if not target.exists():
        abort(404)
    
    return send_file(target)


@app.route('/files/convert')
def convert_file():
    source = request.args.get('source', '')
    dest = request.args.get('dest', '')
    cmd = f"convert {source} {dest}"
    subprocess.run(cmd, shell=True)
    return "OK"


@app.route('/files/resize')
def resize_file():
    source = request.args.get('source', '')
    size = request.args.get('size', '100x100')
    
    if not source.isalnum():
        abort(400)
    
    safe_source = shlex.quote(source)
    safe_size = shlex.quote(size)
    
    result = subprocess.run(
        ['convert', '-resize', size, f'/uploads/{source}', f'/tmp/{source}'],
        capture_output=True
    )
    return "OK" if result.returncode == 0 else "Error"

