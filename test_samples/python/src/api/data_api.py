from flask import Blueprint, request, jsonify
from services.data_service import DataService

data_bp = Blueprint('data', __name__)
data_service = DataService('/var/lib/app/data.db')


@data_bp.route('/search', methods=['GET'])
def search_data():
    table = request.args.get('table')
    column = request.args.get('column')
    value = request.args.get('value')
    
    try:
        results = data_service.search_records(table, column, value)
        return jsonify({'results': results})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': 'Internal error'}), 500


@data_bp.route('/search/like', methods=['GET'])
def search_like():
    table = request.args.get('table')
    column = request.args.get('column')
    pattern = request.args.get('pattern')
    
    try:
        results = data_service.search_with_like(table, column, pattern)
        return jsonify({'results': results})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': 'Internal error'}), 500


@data_bp.route('/record/<table>/<record_id>', methods=['GET'])
def get_record(table, record_id):
    try:
        result = data_service.get_by_id(table, record_id)
        if result:
            return jsonify({'record': result})
        return jsonify({'error': 'Not found'}), 404
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': 'Internal error'}), 500

