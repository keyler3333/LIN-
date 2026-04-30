from flask import Flask, request, jsonify
from engine import DeobfEngine

app = Flask(__name__)
engine = DeobfEngine()

@app.route('/deobf', methods=['POST'])
def deobf():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'No data'}), 400
    source = data.get('source', '')
    if not source.strip():
        return jsonify({'error': 'No source'}), 400
    try:
        result, status = engine.process(source)
        return jsonify({
            'result': result,
            'status': status,
            'success': True
        })
    except Exception as e:
        return jsonify({'error': str(e), 'success': False}), 500

@app.route('/health')
def health():
    return jsonify({'ok': True})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
