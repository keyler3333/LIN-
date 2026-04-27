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
local __outdir = [[{OUTDIR}]]
local __n = 0

local __orig_loadstring = loadstring
local __orig_load       = load

local function __hook(code, ...)
    if type(code) == "string" and #code > 5 then
        __n = __n + 1
        local f = io.open(__outdir .. "/layer_" .. __n .. ".lua", "w")
        if f then f:write(code) f:close() end
        io.stderr:write("HOOK_CAPTURED_LAYER_" .. __n .. "\n")
    end
    return function() end
end

loadstring = __hook
load       = __hook

local function __proxy(extra)
    return setmetatable(extra or {}, {
        __index = function(t, k)
            if rawget(t, k) ~= nil then return rawget(t, k) end
            return function() end
        end,
        __newindex = function(t, k, v) rawset(t, k, v) end
    })
end

getfenv = function() return __proxy({
    string=string, math=math, table=table, bit=bit or {},
    pairs=pairs, ipairs=ipairs, select=select, next=next,
    tostring=tostring, tonumber=tonumber, type=type,
    rawget=rawget, rawset=rawset, rawequal=rawequal,
    setmetatable=setmetatable, getmetatable=getmetatable,
    unpack=table.unpack or unpack,
    loadstring=loadstring, load=load,
    pcall=pcall, xpcall=xpcall, error=error, assert=assert,
    print=print, warn=warn, game=game, workspace=workspace,
    script=script, coroutine=coroutine, shared=shared
}) end

game             = __proxy()
workspace        = __proxy()
script           = __proxy()
Players          = __proxy({LocalPlayer=__proxy({Name="Player",UserId=1,Character=__proxy()})})
RunService       = __proxy({Heartbeat=__proxy({Connect=function()end}),RenderStepped=__proxy({Connect=function()end})})
UserInputService = __proxy()
HttpService      = __proxy({JSONDecode=function() return {} end,JSONEncode=function() return "{}" end})
TweenService     = __proxy()
Instance         = {new=function() return __proxy() end}
Vector3          = {new=function(...) return __proxy() end}
Vector2          = {new=function(...) return __proxy() end}
CFrame           = {new=function(...) return __proxy() end,Angles=function(...) return __proxy() end}
Color3           = {new=function(...) return __proxy() end,fromRGB=function(...) return __proxy() end}
UDim2            = {new=function(...) return __proxy() end}
Enum             = __proxy()
Drawing          = __proxy()
debug            = {traceback=function() return "" end,getinfo=function() return {} end}
syn              = __proxy({protect_gui=function()end,queue_on_teleport=function()end,request=function() return __proxy({Body="",StatusCode=200}) end})
rconsole         = __proxy({print=function()end,clear=function()end,settitle=function()end})
writefile        = function() end
readfile         = function() return "" end
isfile           = function() return false end
isfolder         = function() return false end
makefolder       = function() end
listfiles        = function() return {} end
request          = function() return __proxy({Body="",StatusCode=200,Success=true}) end
http             = {request=function() return __proxy({Body="",StatusCode=200}) end}
identifyexecutor = function() return "synapse","2.0" end
getexecutorname  = function() return "synapse" end
checkcaller      = function() return true end
isrbxactive      = function() return true end
hookfunction     = function(a,b) return a end
newcclosure      = function(f) return f end
clonefunction    = function(f) return f end
tick             = function() return 0 end
time             = function() return 0 end
elapsedtime      = function() return 0 end

local __wait_count = 0
wait = function(n)
    __wait_count = __wait_count + 1
    if __wait_count > 5000 then
        io.stderr:write("WAIT_LIMIT_EXCEEDED\n")
        os.exit(0)
    end
    if coroutine.running() then
        coroutine.yield()
    end
end

spawn            = function(f) if f then pcall(f) end end
delay            = function(t, f) if f then pcall(f) end end
warn             = function() end

local __print_count = 0
print = function(...)
    __print_count = __print_count + 1
    if __print_count <= 10 then
        local args = {...}
        for i, v in ipairs(args) do
            io.stderr:write(tostring(v) .. "\t")
        end
        io.stderr:write("\n")
    end
end

error            = function(e) io.stderr:write("ERROR: " .. tostring(e) .. "\n") end
assert           = function(v,m) if not v then error(m or "assert") end return v end
shared           = __proxy()

bit = bit or {}
bit.bxor=function(a,b) local r,p=0,1 while a>0 or b>0 do if a%2~=b%2 then r=r+p end a=math.floor(a/2) b=math.floor(b/2) p=p*2 end return r end
bit.band=function(a,b) local r,p=0,1 while a>0 and b>0 do if a%2==1 and b%2==1 then r=r+p end a=math.floor(a/2) b=math.floor(b/2) p=p*2 end return r end
bit.bor =function(a,b) local r,p=0,1 while a>0 or b>0 do if a%2==1 or b%2==1 then r=r+p end a=math.floor(a/2) b=math.floor(b/2) p=p*2 end return r end
bit.bnot=function(a) return -a-1 end
bit.rshift=function(a,b) return math.floor(a/(2^b)) end
bit.lshift=function(a,b) return math.floor(a*(2^b)) end
bit32 = bit

coroutine.wrap   = coroutine.wrap   or function(f) return f end
coroutine.create = coroutine.create or function(f) return f end
table.pack   = table.pack   or function(...) return {n=select('#',...), ...} end
table.unpack = table.unpack or unpack
math.pow     = math.pow     or function(a,b) return a^b end
_G.game      = game
_G.workspace = workspace

io.stderr:write("SANDBOX_STARTED\n")

local __chunk, __load_err = __orig_loadstring("return function(...) " .. [[{USER_CODE}]] .. " end")
if not __chunk then
    io.stderr:write("LOAD_ERROR: " .. tostring(__load_err) .. "\n")
    os.exit(1)
end

local __func = __chunk()
local __co = coroutine.create(function()
    __func()
end)

local __start = os.time()
local __steps = 0
while coroutine.status(__co) ~= "dead" do
    __steps = __steps + 1
    if __steps > 100000 then
        io.stderr:write("STEPS_LIMIT_EXCEEDED\n")
        break
    end
    if os.time() - __start > 8 then
        io.stderr:write("TIMEOUT\n")
        break
    end
    local ok, err = coroutine.resume(__co)
    if not ok then
        io.stderr:write("LUA_ERROR: " .. tostring(err) .. "\n")
        break
    end
end
"""

def run_sandbox(source, timeout=12):
    with tempfile.TemporaryDirectory() as d:
        escaped = d.replace('\\', '\\\\').replace('"', '\\"')
        script = SANDBOX_TEMPLATE.replace('{OUTDIR}', escaped).replace('{USER_CODE}', source)
        spath = os.path.join(d, 'script.lua')
        with open(spath, 'w', encoding='utf-8') as f:
            f.write(script)
        try:
            proc = subprocess.run([LUA_BIN, spath], timeout=timeout, capture_output=True, cwd=d)
        except subprocess.TimeoutExpired:
            return None, 'timeout'
        except FileNotFoundError:
            return None, f'{LUA_BIN} not found'
        except Exception as e:
            return None, str(e)
        stderr = proc.stderr.decode('utf-8', errors='replace').strip()
        stdout = proc.stdout.decode('utf-8', errors='replace').strip()
        captured = []
        i = 1
        while True:
            p = os.path.join(d, f'layer_{i}.lua')
            if not os.path.exists(p):
                break
            with open(p, 'r', encoding='utf-8', errors='replace') as f:
                data = f.read()
            if data.strip():
                captured.append(data)
            i += 1
        if captured:
            return captured, None
        else:
            diag = []
            if stderr: diag.append(stderr[:500])
            if stdout: diag.append("stdout: " + stdout[:300])
            if not diag: diag.append("no output")
            return None, ' | '.join(diag)

def peel(source, max_layers=8, timeout=12):
    current, count, previews = source, 0, []
    for _ in range(max_layers):
        captured, err = run_sandbox(current, timeout)
        if captured is None:
            return current, count, previews, err
        if not captured:
            break
        best = max(captured, key=len)
        if len(best.strip()) < 10 or best == current:
            break
        previews.append(best[:120].replace('\n', ' '))
        current = best
        count  += 1
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
    data   = request.get_json(force=True)
    source = data.get('source', '')
    if not source.strip():
        return jsonify({'error': 'no source'}), 400
    profile = detect_profile(source)
    obf     = profile['obfuscator']
    peeled, layers, previews, err = peel(source)
    if err:
        result = static_decode(beautify(source))
        return jsonify({
            'result': result,
            'layers': 0,
            'method': 'static',
            'detected': obf,
            'profile': profile,
            'error': err
        })
    if layers > 0:
        result = static_decode(beautify(peeled))
        method = 'sandbox'
    else:
        result = static_decode(beautify(source))
        method = 'static'
    return jsonify({
        'result': result,
        'layers': layers,
        'previews': previews if layers else [],
        'method': method,
        'detected': obf,
        'profile': profile,
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
