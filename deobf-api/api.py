import os
from flask import Flask, request, jsonify
from ai_engine import AIEngine

app = Flask(__name__)
GROQ_API_KEY = os.environ.get('GROQ_API_KEY', '')
engine = AIEngine(api_key=GROQ_API_KEY)

@app.route('/health')
def health():
    return jsonify({'ok': True, 'engine': 'ai_driven', 'groq_configured': bool(GROQ_API_KEY)})

@app.route('/deobf', methods=['POST'])
def deobf():
    data = request.get_json(silent=True)
    if not data or not data.get('source', '').strip():
        return jsonify({'error': 'No source code provided'}), 400

    try:
        result = engine.process(data['source'])
        response = {
            'result': result['result'],
            'detected': result['detected'],
            'diagnostic': result['diagnostic'],
            'method': 'ai_pipeline'
        }
        feedback = result.get('ai_feedback', '')
        if feedback:
            response['ai_feedback'] = feedback
        return jsonify(response)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
