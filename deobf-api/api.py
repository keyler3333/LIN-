import os, re, subprocess, tempfile, shutil
from flask import Flask, request, jsonify

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

SANDBOX_TEMPLATE = r"""
local hooks = require("hooks")
hooks.init("{OUTDIR}")

local __proxy_mt = {
    __index = function(t, k)
        local v = rawget(t, k)
        if v ~= nil then return v end
        local p = setmetatable({}, __proxy_mt)
        rawset(t, k, p)
        return p
    end,
    __call = function(...) return select(1, ...) end,
    __newindex = function(t, k, v) rawset(t, k, v) end,
}

_G = setmetatable({}, __proxy_mt)
_ENV = _G

for _, k in ipairs({
    "print", "warn", "error", "assert", "tick", "time", "elapsedtime", "wait",
    "spawn", "delay", "pcall", "xpcall", "select", "ipairs", "pairs", "next",
    "tostring", "tonumber", "type", "rawget", "rawset", "rawequal", "rawlen",
    "setmetatable", "getmetatable", "unpack", "coroutine",
    "math", "string", "table", "bit", "bit32", "getfenv", "setfenv",
    "debug", "syn", "rconsole", "writefile", "readfile", "isfile", "isfolder",
    "makefolder", "listfiles", "request", "http", "identifyexecutor",
    "getexecutorname", "checkcaller", "isrbxactive", "hookfunction",
    "newcclosure", "clonefunction", "Drawing", "game", "workspace", "script",
    "Players", "RunService", "UserInputService", "HttpService", "TweenService",
    "Instance", "Vector3", "Vector2", "CFrame", "Color3", "UDim2", "UDim",
    "Enum", "shared", "task", "os", "io", "collectgarbage", "package",
    "dofile", "loadfile", "require", "module", "newproxy"
}) do
    _G[k] = setmetatable({}, __proxy_mt)
end

loadstring = require("hooks").init and function() end or loadstring

local chunk, err = loadstring("return function(...) " .. [[{USER_CODE}]] .. " end")
if not chunk then
    io.stderr:write("LOAD_ERROR: " .. tostring(err) .. "\n")
    os.exit(1)
end

local func = chunk()
local co = coroutine.create(function() func() end)

local steps = 0
local start = os.time()
while coroutine.status(co) ~= "dead" do
    steps = steps + 1
    if steps > 50000 then io.stderr:write("STEPS\n"); break end
    if os.time() - start > 8 then io.stderr:write("TIMEOUT\n"); break end
    local ok, e = coroutine.resume(co)
    if not ok then io.stderr:write("ERROR: "..tostring(e).."\n"); break end
end
"""

def run_sandbox(source, timeout=12):
    with tempfile.TemporaryDirectory() as d:
        escaped = d.replace('\\', '\\\\').replace('"', '\\"')
        script = SANDBOX_TEMPLATE.replace('{OUTDIR}', escaped).replace('{USER_CODE}', source)
        spath = os.path.join(d, 'script.lua')
        with open(spath, 'w', encoding='utf-8') as f:
            f.write(script)
        env = os.environ.copy()
        env['LUA_CPATH'] = '/app/?.so'
        try:
            proc = subprocess.run([LUA_BIN, spath], timeout=timeout, capture_output=True, cwd=d, env=env)
        except subprocess.TimeoutExpired:
            return None, 'timeout'
        except FileNotFoundError:
            return None, f'{LUA_BIN} not found'
        except Exception as e:
            return None, str(e)
        stderr = proc.stderr.decode('utf-8', errors='replace').strip()
        captured = []
        i = 1
        while True:
            p = os.path.join(d, f'layer_{i}.lua')
            if not os.path.exists(p): break
            with open(p, 'r', encoding='utf-8', errors='replace') as f:
                data = f.read()
            if data.strip(): captured.append(data)
            i += 1
        if captured: return captured, None
        diag = []
        if stderr: diag.append(stderr[:500])
        if not diag: diag.append("no output")
        return None, ' | '.join(diag)

def peel(source, max_layers=8, timeout=12):
    current, count, previews = source, 0, []
    for _ in range(max_layers):
        captured, err = run_sandbox(current, timeout)
        if captured is None: return current, count, previews, err
        if not captured: break
        best = max(captured, key=len)
        if len(best.strip()) < 10 or best == current: break
        previews.append(best[:120].replace('\n', ' '))
        current = best
        count += 1
    return current, count, previews, None

def detect_profile(text):
    patterns = {
        'ironbrew':  [r'bit and bit\.bxor', r'return table\.concat\(', r'return \w+\(true,\s*\{\}'],
        'moonsec':   [r'local\s+\w+\s*=\s*\{[\d\s,]{20,}\}', r'_moon\s*=\s*function'],
        'luraph':    [r'loadstring\s*\(\s*\(function', r'bytecode\s*=\s*["\'][A-Za-z0-9+/=]{50,}'],
        'wearedevs': [r'show_\w+\s*=\s*function', r'getfenv\s*\(\s*\)'],
        'prometheus':[r'Prometheus', r'number_to_bytes'],
    }
    scores = {}
    for name, pats in patterns.items():
        s = sum(1 for p in pats if re.search(p, text, re.IGNORECASE))
        if s: scores[name] = s
    vm_score = 0
    if re.search(r'loadstring\s*\(\s*\w+\s*\)\s*\(\s*\)', text): vm_score += 1
    if re.search(r'while\s+true\s+do\s+local\s+\w+\s*=\s*\w+\[', text): vm_score += 2
    if len(re.findall(r'\\x[0-9a-fA-F]{2}', text)) > 50: vm_score += 1
    ent = len(set(text)) / max(1, len(text))
    if ent > 0.6: vm_score += 1
    best_name = max(scores, key=lambda k: scores[k]) if scores else 'generic'
    confidence = min(1.0, (scores.get(best_name, 0) / 4) + (vm_score / 10))
    vm = vm_score >= 3
    return {
        'obfuscator': best_name,
        'confidence': round(confidence, 2),
        'vm_likely': vm,
        'vm_score': vm_score,
        'patterns': scores,
    }

def static_decode(code):
    code = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), code)
    code = re.sub(r'\\(\d{1,3})', lambda m: chr(int(m.group(1))) if int(m.group(1)) < 256 else m.group(0), code)
    def sc(m):
        nums = re.findall(r'\d+', m.group(1))
        try: return '"' + ''.join(chr(int(n)) for n in nums if int(n) < 256) + '"'
        except: return m.group(0)
    code = re.sub(r'string\.char\s*\(\s*([\d,\s]+)\s*\)', sc, code)
    def fold(m):
        try:
            a, op, b = float(m.group(1)), m.group(2), float(m.group(3))
            r = {'+': a+b, '-': a-b, '*': a*b, '/': a/b if b else None, '%': a%b if b else None}.get(op)
            return str(int(r)) if r is not None else m.group(0)
        except: return m.group(0)
    parts = re.split(r'("(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\')', code)
    code  = ''.join(re.sub(r'\b(\d+(?:\.\d+)?)\s*([+\-*/%])\s*(\d+(?:\.\d+)?)\b', fold, p) if i%2==0 else p for i,p in enumerate(parts))
    code = re.sub(r'if\s+false\s+then.*?end', '', code, flags=re.DOTALL)
    code = re.sub(r'while\s+false\s+do.*?end', '', code, flags=re.DOTALL)
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
    if not source.strip(): return jsonify({'error': 'no source'}), 400
    profile = detect_profile(source)
    obf = profile['obfuscator']
    peeled, layers, previews, err = peel(source)
    if err:
        result = static_decode(beautify(source))
        return jsonify({'result': result, 'layers': 0, 'method': 'static', 'detected': obf, 'profile': profile, 'error': err})
    if layers > 0:
        result = static_decode(beautify(peeled))
        method = 'sandbox'
    else:
        result = static_decode(beautify(source))
        method = 'static'
    return jsonify({'result': result, 'layers': layers, 'previews': previews if layers else [], 'method': method, 'detected': obf, 'profile': profile})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
