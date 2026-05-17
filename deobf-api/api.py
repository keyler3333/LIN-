import os
import base64
from flask import Flask, request, jsonify
from engine import DeobfEngine

app = Flask(__name__)
engine = DeobfEngine()
API_KEY = os.environ.get('API_KEY')

@app.before_request
def check_auth():
    if API_KEY and request.headers.get('X-API-Key') != API_KEY:
        return jsonify({'error': 'Unauthorized'}), 401

@app.route('/health')
def health():
    return jsonify({'ok': True})

@app.route('/deobf', methods=['POST'])
async def deobf():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    source_b64 = data.get('source_b64', '')
    if not source_b64:
        return jsonify({'error': 'No source_b64 provided'}), 400
    try:
        raw_bytes = base64.b64decode(source_b64)
    except Exception:
        return jsonify({'error': 'Invalid base64 data'}), 400
    if len(raw_bytes) > 5 * 1024 * 1024:
        return jsonify({'error': 'Source exceeds 5MB limit'}), 413
    source_str = raw_bytes.decode('latin-1')
    try:
        result = await engine.process(source_str)
        return jsonify({
            'result': result.output or '',
            'detected': 'success' if result.success else 'unable',
            'diagnostic': result.summary(),
            'raw_bytecode_b64': base64.b64encode(result.raw_bytecode).decode('ascii') if result.raw_bytecode else None
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
