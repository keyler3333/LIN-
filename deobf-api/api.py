from flask import Flask, request, jsonify
from engine import DeobfEngine

app = Flask(__name__)
engine = DeobfEngine()

@app.route('/health')
def health():
    return jsonify({'ok': True, 'engine': 'wearedevs'})

@app.route('/deobf', methods=['POST'])
def deobf():
    data = request.get_json(silent=True)
    if not data or not data.get('source', '').strip():
        return jsonify({'error': 'No source code provided'}), 400

    try:
        result, obf_type, diag = engine.process(data['source'])
        return jsonify({
            'result': result,
            'detected': obf_type,
            'diagnostic': diag
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
