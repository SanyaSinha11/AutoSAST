from flask import Blueprint, request, jsonify
from services.network_service import NetworkService

network_bp = Blueprint('network', __name__)
network_service = NetworkService()


@network_bp.route('/ping', methods=['GET'])
def ping_host():
    hostname = request.args.get('host')
    
    try:
        output = network_service.ping_host(hostname)
        return jsonify({'output': output})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': 'Command failed'}), 500


@network_bp.route('/dns', methods=['GET'])
def dns_lookup():
    hostname = request.args.get('host')
    
    try:
        output = network_service.dns_lookup(hostname)
        return jsonify({'output': output})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': 'Command failed'}), 500


@network_bp.route('/fetch', methods=['GET'])
def fetch_url():
    url = request.args.get('url')
    
    try:
        content = network_service.fetch_from_cdn(url)
        return jsonify({'content': content})
    except ValueError as e:
        return jsonify({'error': str(e)}), 403
    except Exception as e:
        return jsonify({'error': 'Fetch failed'}), 500


@network_bp.route('/check', methods=['GET'])
def check_host():
    hostname = request.args.get('host')
    reachable = network_service.is_reachable(hostname)
    return jsonify({'reachable': reachable})

