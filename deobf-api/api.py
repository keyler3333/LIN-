import os
import traceback
from flask import Flask, request, jsonify
from engine import DeobfEngine

app = Flask(__name__)
engine = DeobfEngine()

MAX_BYTES = 4 * 1024 * 1024
DIAG_PREFIXES = ('__SANDBOX_ERROR__', '__SANDBOX_DIAG__', '__LUA_STDERR__')


@app.route('/health')
def health():
    from sandbox import LUA_BIN
    return jsonify({'ok': True, 'lua': LUA_BIN})


@app.route('/deobf', methods=['POST'])
def deobf():
    data = request.get_json(silent=True)
    if not data or not data.get('source', '').strip():
        return jsonify({'error': 'No source provided'}), 400
    if len(data['source'].encode()) > MAX_BYTES:
        return jsonify({'error': 'Source exceeds 4 MB'}), 413
    try:
        result, method, diag = engine.process(data['source'])
        return jsonify({'result': result, 'method': method, 'diagnostic': diag})
    except Exception as exc:
        detail = traceback.format_exc() if app.debug else str(exc)
        return jsonify({'error': detail}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=os.getenv('FLASK_DEBUG', '0') == '1')
