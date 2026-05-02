import os
import traceback
from flask import Flask, request, jsonify
from engine import DeobfEngine

app = Flask(__name__)
engine = DeobfEngine()

MAX_SOURCE_BYTES = 4 * 1024 * 1024


@app.route('/health')
def health():
    from sandbox import LUA_BIN
    return jsonify({'ok': True, 'engine': 'wearedevs', 'lua_bin': LUA_BIN})


@app.route('/deobf', methods=['POST'])
def deobf():
    data = request.get_json(silent=True)
    if not data or not data.get('source', '').strip():
        return jsonify({'error': 'No source code provided'}), 400
    if len(data['source'].encode()) > MAX_SOURCE_BYTES:
        return jsonify({'error': 'Source exceeds 4 MB limit'}), 413
    try:
        result, obf_type, diag = engine.process(data['source'])
        return jsonify({'result': result, 'detected': obf_type, 'diagnostic': diag})
    except Exception as exc:
        detail = traceback.format_exc() if app.debug else str(exc)
        return jsonify({'error': detail}), 500


if __name__ == '__main__':
    debug = os.getenv('FLASK_DEBUG', '0') == '1'
    app.run(host='0.0.0.0', port=5000, debug=debug)
