import os, re, subprocess, tempfile, shutil
from flask import Flask, request, jsonify
from strategies.ironbrew import IronBrewDeobfuscator
from strategies.moonsec_v3 import MoonsecV3Deobfuscator
from strategies.wearedevs import WeAreDevsDeobfuscator

app = Flask(__name__)

def find_lua():
    for b in ['lua5.1','lua51','lua']:
        path = shutil.which(b)
        if path:
            try:
                r = subprocess.run([path,'-v'],capture_output=True,timeout=2)
                out = (r.stderr+r.stdout).decode(errors='replace')
                if '5.1' in out: return path
            except: pass
    return 'lua5.1'

LUA_BIN = os.environ.get('LUA_BIN') or find_lua()
RUNTIME_PATH = os.path.join(os.path.dirname(__file__),'sandbox_runtime.lua')

def run_sandbox(source, timeout=25):
    with tempfile.TemporaryDirectory() as d:
        inp = os.path.join(d,'input.lua')
        with open(inp,'w',encoding='utf-8') as f: f.write(source)
        with open(RUNTIME_PATH,'r',encoding='utf-8') as f: runtime = f.read()
        esc_d = d.replace('\\','\\\\').replace('"','\\"')
        esc_i = inp.replace('\\','\\\\').replace('"','\\"')
        driver = runtime.replace('OUTDIR_PLACEHOLDER',esc_d).replace('INPATH_PLACEHOLDER',esc_i)
        drv = os.path.join(d,'driver.lua')
        with open(drv,'w',encoding='utf-8') as f: f.write(driver)
        try:
            proc = subprocess.run([LUA_BIN,drv],capture_output=True,text=True,timeout=timeout,cwd=d)
            stdout = proc.stdout.strip()
            stderr = proc.stderr.strip()
        except subprocess.TimeoutExpired: return [],[],'timeout','',''
        except Exception as e: return [],[],str(e),'',''
        layers = []
        i = 1
        while True:
            p = os.path.join(d,f'layer_{i}.lua')
            if not os.path.exists(p): break
            with open(p,encoding='utf-8',errors='replace') as f: layers.append(f.read())
            i += 1
        cap = []
        cp = os.path.join(d,'cap.txt')
        if os.path.exists(cp):
            with open(cp,encoding='utf-8',errors='replace') as f: raw = f.read()
            for part in raw.split('---SEP---'):
                s = part.strip().replace('\\n','\n')
                if len(s) > 20: cap.append(s)
        diag = ''
        dp = os.path.join(d,'diag.txt')
        if os.path.exists(dp):
            with open(dp,encoding='utf-8',errors='replace') as f: diag = f.read()
        return layers, cap, diag, stdout, stderr

def detect_obfuscator(text):
    if re.search(r'return table\.concat|return \w+\(true,\s*\{\}|bit\.bxor', text):
        return 'ironbrew'
    if re.search(r'local\s+\w+\s*=\s*\{[\d\s,]{20,}\}|_moon\s*=\s*function|MoonSec', text):
        return 'moonsec_v3'
    if re.search(r'show_\w+\s*=\s*function|getfenv\s*\(\s*\)|string\.reverse', text):
        return 'wearedevs'
    if re.search(r'loadstring\s*\(\s*\(function|Luraph', text):
        return 'luraph'
    if re.search(r'Prometheus|number_to_bytes', text):
        return 'prometheus'
    if re.search(r'Hercules|Str\s*=\s*string\.sub', text):
        return 'hercules'
    return 'generic'

def static_decode(code):
    code = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1),16)), code)
    code = re.sub(r'\\(\d{1,3})', lambda m: chr(int(m.group(1))) if int(m.group(1))<256 else m.group(0), code)
    def sc(m):
        nums = re.findall(r'\d+', m.group(1))
        try: return '"' + ''.join(chr(int(n)) for n in nums if int(n)<256) + '"'
        except: return m.group(0)
    code = re.sub(r'string\.char\s*\(\s*([\d,\s]+)\s*\)', sc, code)
    return code

def beautify(code):
    out, indent = [], 0
    for line in code.split('\n'):
        s = line.strip()
        if not s: out.append(''); continue
        if re.match(r'^(end\b|else\b|elseif\b|until\b)', s): indent = max(0, indent-1)
        out.append('    '*indent + s)
        if re.match(r'^(if\b|for\b|while\b|repeat\b|do\b)', s) and not s.endswith('end'): indent += 1
        if re.match(r'^(function\b|local\s+function\b)', s): indent += 1
    return '\n'.join(out)

@app.route('/health')
def health():
    lua_ok = False
    for b in [LUA_BIN,'lua5.1','lua51','lua']:
        try:
            r = subprocess.run([b,'-v'],capture_output=True,timeout=2)
            out = (r.stderr+r.stdout).decode(errors='replace')
            if '5.1' in out: lua_ok = True; break
        except: pass
    return jsonify({'ok':True,'lua':lua_ok})

ironbrew = IronBrewDeobfuscator()
moonsec = MoonsecV3Deobfuscator()
wearedevs = WeAreDevsDeobfuscator()

@app.route('/deobf', methods=['POST'])
def deobf():
    data = request.get_json(force=True)
    source = data.get('source','')
    if not source.strip(): return jsonify({'error':'no source'}), 400

    obf_type = detect_obfuscator(source)
    result = None
    layers = 0
    method = 'static'
    diag = ''

    if obf_type == 'ironbrew':
        try:
            result = ironbrew.deobfuscate(source)
            if result: method = 'ironbrew_devirtualizer'; layers = 1
        except Exception as e: diag = str(e)

    elif obf_type == 'moonsec_v3':
        try:
            result = moonsec.deobfuscate(source)
            if result: method = 'moonsec_v3_decoder'; layers = 1
        except Exception as e: diag = str(e)

    elif obf_type == 'wearedevs':
        try:
            result = wearedevs.deobfuscate(source)
            if result: method = 'wearedevs_extractor'; layers = 1
        except Exception as e: diag = str(e)

    if not result:
        layers_list, cap, sandbox_diag, stdout, stderr = run_sandbox(source)
        diag = diag or sandbox_diag or stderr
        if layers_list:
            result = max(layers_list, key=len)
            method = 'sandbox_layer'
            layers = len(layers_list)
        elif cap:
            result = max(cap, key=len)
            method = 'captured_string'
        else:
            result = static_decode(source)

    result = beautify(result)

    return jsonify({
        'result': result,
        'layers': layers,
        'method': method,
        'detected': obf_type,
        'diagnostic': diag[:1000] if diag else '',
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT',5000)))
