import os, subprocess, tempfile
from flask import Flask, request, jsonify
from pipeline import deep_deobfuscate, detect_vm

app = Flask(__name__)

LUA_BIN = 'lua5.1'

@app.route('/health')
def health():
    try:
        subprocess.run([LUA_BIN, '-v'], capture_output=True, timeout=2)
        return jsonify({'ok': True, 'lua': True})
    except:
        return jsonify({'ok': True, 'lua': False})

@app.route('/deobf', methods=['POST'])
def deobf():
    data = request.get_json(force=True)
    source = data.get('source', '')
    if not source.strip():
        return jsonify({'error': 'no source'}), 400
    try:
        result = deep_deobfuscate(source, LUA_BIN)
        return jsonify({'result': result, 'method': 'pipeline'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
