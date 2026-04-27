import os, re, subprocess, tempfile, shutil
from flask import Flask, request, jsonify
import live_trace

app = Flask(__name__)

def find_lua():
    for binary in ['lua5.1', 'lua51', 'lua']:
        path = shutil.which(binary)
        if path: return path
    for binary in ['lua5.1', 'lua51', 'lua']:
        try:
            if subprocess.run([binary, '-v'], capture_output=True, timeout=2).returncode == 0:
                return binary
        except: pass
    return 'lua5.1'

LUA_BIN = os.environ.get('LUA_BIN') or find_lua()

def detect_profile(text):
    features = {}
    if re.search(r'getfenv\s*\(\)', text) and re.search(r'loadstring', text):
        features['ironbrew'] = 1
    if len(re.findall(r'\\[0-9]{3}', text)) > 50:
        features['string_obf'] = 1
    if re.search(r'while\s+true\s+do\s+local\s+\w+=\w+\[[^\]]+\]', text):
        features['vm_dispatch'] = 1
    if re.search(r'MoonSec', text, re.IGNORECASE):
        features['moonsec'] = 1
    if re.search(r'bytecode\s*=\s*"\d+\s*\d+', text) or re.search(r'number_to_bytes', text):
        features['prometheus'] = 1
    if re.search(r'loadstring\s*\(\s*\(function', text) and re.search(r'bytecode\s*=\s*["\'][A-Za-z0-9+/=]{50,}', text):
        features['luraph'] = 1
    if re.search(r'show_\w+\s*=\s*function', text) and re.search(r'getfenv\s*\(\s*\)', text):
        features['wearedevs'] = 1
    vm_score = features.get('vm_dispatch',0) + features.get('prometheus',0) + features.get('luraph',0)
    features['vm_score'] = vm_score
    if features.get('wearedevs'):
        return 'wearedevs', features
    if features.get('ironbrew') or features.get('string_obf'):
        return 'ironbrew', features
    if vm_score >= 2:
        return 'vm', features
    if features.get('moonsec'):
        return 'moonsec', features
    return 'unknown', features

def static_decode(code):
    code = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), code)
    code = re.sub(r'\\(\d{1,3})', lambda m: chr(int(m.group(1))) if int(m.group(1)) < 256 else m.group(0), code)
    def sc(m):
        nums = re.findall(r'\d+', m.group(1))
        try: return '"' + ''.join(chr(int(n)) for n in nums if int(n) < 256) + '"'
        except: return m.group(0)
    code = re.sub(r'string\.char\s*\(\s*([\d,\s]+)\s*\)', sc, code)
    return code

def beautify(code):
    out, indent = [], 0
    for line in code.split('\n'):
        s = line.strip()
        if not s: out.append(''); continue
        if re.match(r'^(end|else|elseif|until)\b', s): indent = max(0, indent-1)
        out.append('    '*indent + s)
        if re.match(r'^(if|for|while|repeat|do)\b', s) and not s.endswith('end'): indent += 1
        if re.match(r'^(function|local\s+function)\b', s): indent += 1
    return '\n'.join(out)

@app.route('/health')
def health():
    lua_ok = False
    active_bin = LUA_BIN
    for binary in [LUA_BIN, 'lua5.1', 'lua51', 'lua']:
        try:
            r = subprocess.run([binary, '-v'], capture_output=True, timeout=2)
            out = (r.stderr.decode() + r.stdout.decode()).strip()
            if '5.1' in out:
                lua_ok = True; active_bin = binary; break
        except: pass
    return jsonify({'ok': True, 'lua': lua_ok, 'lua_bin': active_bin})

@app.route('/deobf', methods=['POST'])
def deobf():
    data = request.get_json(force=True)
    source = data.get('source', '')
    if not source.strip():
        return jsonify({'error': 'no source'}), 400
    profile, features = detect_profile(source)
    if profile in ('wearedevs', 'ironbrew'):
        try:
            result = live_trace.trace_deobfuscate(source, lua_bin=LUA_BIN)
            return jsonify({
                'profile': profile,
                'result': result,
                'method': 'trace',
                'features': features
            })
        except Exception as e:
            static = beautify(static_decode(source))
            return jsonify({
                'profile': profile,
                'result': static,
                'method': 'static',
                'trace_error': str(e)
            })
    static = beautify(static_decode(source))
    return jsonify({'profile': profile, 'result': static, 'method': 'static'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
