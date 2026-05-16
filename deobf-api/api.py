import os
import re
import struct
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

    if len(raw_bytes) > 4 * 1024 * 1024:
        return jsonify({'error': 'Source exceeds 4MB limit'}), 413

    # Build a string where each character's code point is the same as the
    # original byte value (0–255).  This is safe because we never attempt
    # to interpret the string as text – it's only used to write the file.
    source_str = ''.join(chr(b) for b in raw_bytes)

    try:
        result, obf_type, diag = engine.process(source_str)
        return jsonify({'result': result, 'detected': obf_type, 'diagnostic': diag})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/debug_b64', methods=['POST'])
def debug_b64():
    data = request.get_json(silent=True)
    if not data or not data.get('source', '').strip():
        return jsonify({'error': 'No source provided'}), 400
    source = data['source']
    try:
        from transformers import WeAreDevsLifter
        lifter = WeAreDevsLifter()
        cmap = lifter._build_char_map(source)
        strings = lifter._extract_n_strings(source)
        pairs = lifter._extract_shuffle_pairs(source)
        working = list(strings) if strings else []
        if pairs and len(pairs) == 3:
            for a, b in pairs:
                lo, hi = a - 1, b - 1
                if 0 <= lo < len(working) and 0 <= hi < len(working) and lo < hi:
                    working[lo:hi+1] = working[lo:hi+1][::-1]
        decoded = []
        if cmap and working:
            for s in working[:10]:
                buf = lifter._decode_b64(s, cmap)
                if buf:
                    try:
                        decoded.append(buf.decode('latin-1', errors='replace'))
                    except:
                        decoded.append(repr(buf))
        return jsonify({
            'map_size': len(cmap),
            'map_sample': dict(list(cmap.items())[:20]),
            'string_count': len(strings) if strings else 0,
            'shuffle_pairs': pairs,
            'sample_decoded': decoded
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
