from flask import Blueprint, request, jsonify, send_file
from services.file_service import FileService

files_bp = Blueprint('files', __name__)
file_service = FileService('/var/lib/app/documents')


@files_bp.route('/download', methods=['GET'])
def download_file():
    filename = request.args.get('file')
    
    try:
        content = file_service.read_file(filename)
        return content, 200, {'Content-Type': 'application/octet-stream'}
    except PermissionError:
        return jsonify({'error': 'Access denied'}), 403
    except FileNotFoundError:
        return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'error': 'Internal error'}), 500


@files_bp.route('/read', methods=['GET'])
def read_file():
    filename = request.args.get('file')
    
    try:
        content = file_service.read_text(filename)
        return jsonify({'content': content})
    except PermissionError:
        return jsonify({'error': 'Access denied'}), 403
    except FileNotFoundError:
        return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'error': 'Internal error'}), 500


@files_bp.route('/info', methods=['GET'])
def file_info():
    filename = request.args.get('file')
    
    try:
        info = file_service.get_file_info(filename)
        return jsonify(info)
    except PermissionError:
        return jsonify({'error': 'Access denied'}), 403
    except FileNotFoundError:
        return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'error': 'Internal error'}), 500


@files_bp.route('/exists', methods=['GET'])
def check_exists():
    filename = request.args.get('file')
    exists = file_service.file_exists(filename)
    return jsonify({'exists': exists})


@files_bp.route('/list', methods=['GET'])
def list_files():
    subdir = request.args.get('dir', '')
    
    try:
        files = file_service.list_directory(subdir)
        return jsonify({'files': files})
    except PermissionError:
        return jsonify({'error': 'Access denied'}), 403
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': 'Internal error'}), 500

