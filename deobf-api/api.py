import os
import re
import subprocess
import tempfile
import shutil
import struct
from flask import Flask, request, jsonify

app = Flask(__name__)

def find_lua():
    for b in ['lua5.1','lua51','lua']:
        path = shutil.which(b)
        if path:
            try:
                r = subprocess.run([path,'-v'],capture_output=True,timeout=2)
                out = (r.stderr+r.stdout).decode(errors='replace')
                if '5.1' in out:
                    return path
            except:
                pass
    return 'lua5.1'

LUA_BIN = os.environ.get('LUA_BIN') or find_lua()
RUNTIME_PATH = os.path.join(os.path.dirname(__file__),'sandbox_runtime.lua')

def run_sandbox(source, timeout=25):
    with tempfile.TemporaryDirectory() as d:
        inp = os.path.join(d,'input.lua')
        with open(inp,'w',encoding='utf-8') as f:
            f.write(source)
        with open(RUNTIME_PATH,'r',encoding='utf-8') as f:
            runtime = f.read()
        esc_d = d.replace('\\','\\\\').replace('"','\\"')
        esc_i = inp.replace('\\','\\\\').replace('"','\\"')
        driver = runtime.replace('OUTDIR_PLACEHOLDER',esc_d).replace('INPATH_PLACEHOLDER',esc_i)
        drv = os.path.join(d,'driver.lua')
        with open(drv,'w',encoding='utf-8') as f:
            f.write(driver)
        try:
            proc = subprocess.run([LUA_BIN,drv],capture_output=True,text=True,timeout=timeout,cwd=d)
            stdout = proc.stdout.strip()
            stderr = proc.stderr.strip()
        except subprocess.TimeoutExpired:
            stdout, stderr = '','timeout'
        except Exception as e:
            return [],[],str(e),'',''
        layers = []
        i = 1
        while True:
            p = os.path.join(d,f'layer_{i}.lua')
            if not os.path.exists(p):
                break
            with open(p,encoding='utf-8',errors='replace') as f:
                layers.append(f.read())
            i += 1
        dump_path = os.path.join(d, 'dump.bin')
        if os.path.exists(dump_path):
            with open(dump_path, 'rb') as f:
                bc_data = f.read()
            if bc_data.startswith(b'\x1bLua'):
                layers.append(bc_data)
        cap = []
        cp = os.path.join(d,'cap.txt')
        if os.path.exists(cp):
            with open(cp,encoding='utf-8',errors='replace') as f:
                raw = f.read()
                for part in raw.split('---SEP---'):
                    s = part.strip().replace('\\n','\n')
                    if len(s) > 20:
                        cap.append(s)
        diag = ''
        dp = os.path.join(d,'diag.txt')
        if os.path.exists(dp):
            with open(dp,encoding='utf-8',errors='replace') as f:
                diag = f.read()
        return layers, cap, diag, stdout, stderr

from deobfuscator_utils import Deobfuscator, PatternScanner
import wearedevs_lifter

def static_decode(code):
    code = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), code)
    code = re.sub(r'\\(\d{1,3})', lambda m: chr(int(m.group(1))) if int(m.group(1)) < 256 else m.group(0), code)
    def sc(m):
        nums = re.findall(r'\d+', m.group(1))
        try:
            return '"' + ''.join(chr(int(n)) for n in nums if int(n) < 256) + '"'
        except:
            return m.group(0)
    code = re.sub(r'string\.char\s*\(\s*([\d,\s]+)\s*\)', sc, code)
    return code

def simple_beautify(code):
    out, indent = [], 0
    dedent_pat = r'^(end\b|else\b|elseif\b|until\b|\})'
    indent_pat = r'^(if\b|for\b|while\b|repeat\b|do\b|else\b|elseif\b|local\s+function\b|function\b)'
    for line in code.split('\n'):
        line = line.strip()
        if not line:
            out.append('')
            continue
        if re.match(dedent_pat, line):
            indent = max(0, indent - 1)
        out.append('    ' * indent + line)
        if re.match(indent_pat, line) and not (line.endswith('end') or line.endswith('}')):
            indent += 1
    return '\n'.join(out)

def lua_beautify(code):
    try:
        from luaparser import ast
        tree = ast.parse(code)
        return ast.to_lua_source(tree)
    except Exception:
        return simple_beautify(code)

def is_lua_bytecode(data):
    return isinstance(data, bytes) and len(data) >= 12 and data[:4] == b'\x1bLua'

def deobfuscate(source, depth=0):
    if depth > 5:
        return source, 'generic', 0, 'max_depth', 'Max recursion reached'

    lifted = wearedevs_lifter.lift_wearedevs(source)
    if lifted is not None and isinstance(lifted, str) and len(lifted) > 20:
        return lua_beautify(lifted), 'vm_lift', 0, 'string_table_lift', 'Bytecode found in N table'

    scanner = PatternScanner()
    scan_result = scanner.analyze_target_content(source)
    risk = scan_result.get('risk_assessment', 'Low')
    if risk == 'High':
        method = 'dynamic'
    else:
        method = 'sandbox_peel'

    if method == 'dynamic':
        from roblox_emulator import run_emulator
        emu_layers, emu_err, emu_stdout, emu_stderr = run_emulator(source)
        if emu_layers:
            payload = max(emu_layers, key=len)
            return deobfuscate(payload, depth+1)

    layers, cap, diag, _, _ = run_sandbox(source)
    for item in layers:
        if isinstance(item, bytes) and is_lua_bytecode(item):
            lifted = wearedevs_lifter.try_lift_bytes(item)
            if lifted:
                return lua_beautify(lifted), 'vm_lift', 0, 'sandbox_dump', 'Bytecode dumped from sandbox'
        elif isinstance(item, str):
            data = item.encode('latin-1')
            if is_lua_bytecode(data):
                lifted = wearedevs_lifter.try_lift_bytes(data)
                if lifted:
                    return lua_beautify(lifted), 'vm_lift', 0, 'sandbox_layer', 'Bytecode in layer'

    if layers:
        payload = max(layers, key=len)
        return deobfuscate(payload, depth+1)

    for c in cap:
        if c.startswith('\x1bLua') or (len(c) > 100 and 'function' in c):
            return lua_beautify(c), 'generic', 0, 'captured', 'Captured from sandbox'

    result = static_decode(source)
    return lua_beautify(result), 'generic', 0, 'static', diag

@app.route('/health')
def health():
    lua_ok, active = False, LUA_BIN
    for b in [LUA_BIN, 'lua5.1', 'lua51', 'lua']:
        try:
            r = subprocess.run([b, '-v'], capture_output=True, timeout=2)
            out = (r.stderr + r.stdout).decode(errors='replace')
            if '5.1' in out:
                lua_ok = True
                active = b
                break
        except:
            pass
    return jsonify({'ok': True, 'lua': lua_ok, 'lua_bin': active})

@app.route('/deobf', methods=['POST'])
def deobf():
    data = request.get_json(force=True)
    source = data.get('source', '')
    if not source.strip():
        return jsonify({'error': 'no source'}), 400
    result, obf_type, layers, method, diag = deobfuscate(source)
    return jsonify({
        'result': result,
        'layers': layers,
        'method': method,
        'detected': obf_type,
        'diagnostic': diag[:1000] if diag else '',
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
