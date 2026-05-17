import os
import base64
from flask import Flask, request, jsonify
from engine import DeobfEngine

app = Flask(__name__)
engine = DeobfEngine()

@app.route('/health')
def health():
    return jsonify({'ok': True})

@app.route('/deobf', methods=['POST'])
def deobf():
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
        result, obf_type, diag = engine.process(source_str)
        response = {
            'result': result,
            'detected': obf_type,
            'diagnostic': diag
        }
        return jsonify(response)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
