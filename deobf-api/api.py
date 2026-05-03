from flask import Flask, request, jsonify
from wrd_engine import WRDPipeline

app = Flask(__name__)
engine = WRDPipeline()

@app.route('/health')
def health():
    return jsonify({'ok': True, 'engine': 'wrd_focused'})

@app.route('/deobf', methods=['POST'])
def deobf():
    data = request.get_json(silent=True)
    if not data or not data.get('source', '').strip():
        return jsonify({'error': 'No source provided'}), 400
    if len(data['source'].encode()) > 4 * 1024 * 1024:
        return jsonify({'error': 'Source exceeds 4MB limit'}), 413
    try:
        result = engine.run(data['source'])
        return jsonify({
            'result': result,
            'detected': 'wearedevs',
            'diagnostic': 'Extraction completed'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
