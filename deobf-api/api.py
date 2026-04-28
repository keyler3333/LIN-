import os, re, subprocess, tempfile, shutil
from flask import Flask, request, jsonify

app = Flask(__name__)

def find_lua():
    for b in ['luajit', 'lua5.1', 'lua51', 'lua']:
        path = shutil.which(b)
        if path:
            try:
                r = subprocess.run([path, '-v'], capture_output=True, timeout=2)
                out = (r.stderr + r.stdout).decode(errors='replace')
                if '5.1' in out or 'LuaJIT' in out:
                    return path
            except:
                pass
    return 'lua5.1'

LUA_BIN = os.environ.get('LUA_BIN') or find_lua()

SANDBOX = r'''
local _out = "OUTDIR_PLACEHOLDER"
local _inp = "INPATH_PLACEHOLDER"
local _lyr = 0
local _seen = {}
local _cap  = {}
local _log  = {}
local _wait_cnt = 0
local _step_cnt = 0
local _max_steps = 5000000

local function _L(s) _log[#_log+1] = s end

local _ls = loadstring
local _lo = load
local _pc = pcall
local _ty = type
local _ts = tostring
local _pa = pairs
local _ip = ipairs
local _sm = setmetatable
local _gm = getmetatable
local _rg = rawget
local _rs = rawset
local _sc = string.char
local _tc = table.concat
local _un = unpack or table.unpack
local _sl = select
local _nx = next
local _er = error
local _as = assert
local _pr = print

debug.sethook(function(ev)
    _step_cnt = _step_cnt + 1
    if _step_cnt > _max_steps then
        _L("INSTRUCTION_LIMIT (" .. _max_steps .. ")")
        _er("__INSTRUCTION_LIMIT__")
    end
end, "", 1)

local function _capture(v)
    if _ty(v) == "string" and #v > 10 then
        _cap[#_cap+1] = v
    end
end

local function _hook_ls(code, name)
    if _ty(code) == "function" then
        local parts = {}
        while true do
            local p = code()
            if not p then break end
            if _ty(p) == "string" then parts[#parts+1] = p end
            if #parts > 5000 then break end
        end
        code = _tc(parts)
    end
    if _ty(code) ~= "string" or #code < 5 then return function() end end
    _capture(code)
    if not _seen[code] then
        _seen[code] = true
        _lyr = _lyr + 1
        _L("LAYER " .. _lyr .. " (" .. #code .. " bytes)")
        local f = io.open(_out .. "/layer_" .. _lyr .. ".lua", "w")
        if f then f:write(code) f:close() end
    end
    local fn, err = _ls(code, name)
    if not fn then
        _L("COMPILE_ERR: " .. _ts(err))
        return function() end
    end
    return fn
end

loadstring = _hook_ls
load       = _hook_ls

string.char = function(...)
    local r = _sc(...)
    _capture(r)
    return r
end

table.concat = function(t, sep, i, j)
    local r = _tc(t, sep, i, j)
    _capture(r)
    return r
end

if not bit then
    bit = {}
    bit.bxor = function(a,b) local r,p=0,1 while a>0 or b>0 do if a%2~=b%2 then r=r+p end a=math.floor(a/2) b=math.floor(b/2) p=p*2 end return r end
    bit.band = function(a,b) local r,p=0,1 while a>0 and b>0 do if a%2==1 and b%2==1 then r=r+p end a=math.floor(a/2) b=math.floor(b/2) p=p*2 end return r end
    bit.bor  = function(a,b) local r,p=0,1 while a>0 or b>0 do if a%2==1 or b%2==1 then r=r+p end a=math.floor(a/2) b=math.floor(b/2) p=p*2 end return r end
    bit.bnot    = function(a) return -a-1 end
    bit.rshift  = function(a,b) return math.floor(a/(2^b)) end
    bit.lshift  = function(a,b) return math.floor(a*(2^b)) end
    bit.arshift = function(a,b) return math.floor(a/(2^b)) end
    bit.btest   = function(a,b) return bit.band(a,b)~=0 end
    bit.tobit   = function(a) return a end
    bit32 = bit
end

local function _dummy(name)
    local d = {}
    _sm(d, {
        __index    = function(_, k) return _dummy(name .. "." .. _ts(k)) end,
        __newindex = function(_, k, v) _rs(d, k, v) end,
        __call     = function(_, ...)
            local args = {...}
            for _, v in _ip(args) do
                if _ty(v) == "function" then _pc(v, _dummy("a"), _dummy("b")) end
                _capture(v)
            end
            return _dummy(name .. "()")
        end,
        __tostring = function() return name end,
        __concat   = function(a,b) return _ts(a).._ts(b) end,
        __add      = function(a,b) return _dummy(name.."+") end,
        __sub      = function(a,b) return _dummy(name.."-") end,
        __mul      = function(a,b) return _dummy(name.."*") end,
        __div      = function(a,b) return _dummy(name.."/") end,
        __mod      = function(a,b) return _dummy(name.."%") end,
        __pow      = function(a,b) return _dummy(name.."^") end,
        __unm      = function(a)   return _dummy("-"..name) end,
        __len      = function()    return 1 end,
        __lt       = function(a,b) return false end,
        __le       = function(a,b) return true end,
        __eq       = function(a,b) return false end,
    })
    return d
end

_env = {}
local _safe = {
    string   = string, math = math, table = table, bit = bit, bit32 = bit,
    pairs    = _pa, ipairs = _ip, select = _sl, next = _nx,
    tostring = _ts, tonumber = tonumber, type = _ty, typeof = _ty,
    rawget   = _rg, rawset = _rs, rawequal = rawequal, rawlen = rawlen,
    setmetatable = _sm, getmetatable = _gm, unpack = _un,
    pcall    = _pc, xpcall = xpcall, error = _er, assert = _as,
    print    = function() end, warn = function() end,
    loadstring = _hook_ls, load = _hook_ls, coroutine = coroutine,
    debug    = {
        traceback    = function() return "" end,
        getinfo      = function() return {short_src="script.lua",currentline=0,what="Lua"} end,
        sethook      = function() end,
        getupvalue   = function() return nil end,
        setupvalue   = function() end,
        getmetatable = _gm,
    },
    os       = {
        clock    = function() return 0 end,
        time     = function() return 1000000 end,
        date     = function() return "2024-01-01" end,
        difftime = function() return 0 end,
    },
    tick        = function() return 0 end,
    time        = function() return 0 end,
    elapsedtime = function() return 0 end,
    wait        = function(n)
        _wait_cnt = _wait_cnt + 1
        if _wait_cnt > 500 then _er("__WAIT_LIMIT__") end
        return n or 0
    end,
    spawn       = function(f) if _ty(f)=="function" then _pc(f) end end,
    delay       = function(t,f) if _ty(f)=="function" then _pc(f) end end,
    shared      = {}, _VERSION = "Lua 5.1",
    game        = _dummy("game"), workspace = _dummy("workspace"),
    script      = _dummy("script"), Players = _dummy("Players"),
    RunService  = _dummy("RunService"), UserInputService = _dummy("UserInputService"),
    TweenService = _dummy("TweenService"), HttpService = _dummy("HttpService"),
    Instance    = {new=function(n) return _dummy("Instance:"..n) end},
    Vector3     = {new=function(...) return _dummy("Vector3") end},
    Vector2     = {new=function(...) return _dummy("Vector2") end},
    CFrame      = {new=function(...) return _dummy("CFrame") end, Angles=function(...) return _dummy("CFrame") end},
    Color3      = {new=function(...) return _dummy("Color3") end, fromRGB=function(...) return _dummy("Color3") end},
    UDim2       = {new=function(...) return _dummy("UDim2") end},
    Enum        = _dummy("Enum"), Drawing = _dummy("Drawing"), syn = _dummy("syn"),
    writefile   = function() end, readfile = function() return "" end,
    isfile      = function() return false end, isfolder = function() return false end,
    makefolder  = function() end, listfiles = function() return {} end,
    request     = function() return {Body="",StatusCode=200,Success=true} end,
    http        = {request=function() return {Body="",StatusCode=200} end},
    identifyexecutor = function() return "synapse","2.0" end,
    getexecutorname  = function() return "synapse" end,
    checkcaller      = function() return true end,
    isrbxactive      = function() return true end,
    hookfunction     = function(a,b) return a end,
    newcclosure      = function(f) return f end,
    clonefunction    = function(f) return f end,
    rconsole         = {print=function()end,clear=function()end},
}

_sm(_env, {
    __index = function(_, k)
        if _safe[k] ~= nil then return _safe[k] end
        if k == "getfenv" then return function(n) return _env end end
        if k == "setfenv" then
            return function(n,t)
                if _ty(t)=="table" then
                    for kk,vv in _pa(t) do _rs(_env, kk, vv) end
                end
                return t
            end
        end
        if k=="_G" or k=="_ENV" or k=="shared" then return _env end
        if k=="getgenv" or k=="getrenv" then return function() return _env end end
        return _dummy(k)
    end,
    __newindex = function(_, k, v) _rs(_env, k, v) end,
})

_rs(_env, "loadstring",   _hook_ls)
_rs(_env, "load",         _hook_ls)
_rs(_env, "getfenv",      function(n) return _env end)
_rs(_env, "setfenv",      function(n,t)
    if _ty(t)=="table" then for k,v in _pa(t) do _rs(_env, k, v) end end return t end)
_rs(_env, "_G",           _env)
_rs(_env, "_ENV",         _env)
_rs(_env, "shared",       _env)
_rs(_env, "string",       string)
_rs(_env, "math",         math)
_rs(_env, "table",        table)
_rs(_env, "bit",          bit)
_rs(_env, "bit32",        bit)
_rs(_env, "pairs",        _pa)
_rs(_env, "ipairs",       _ip)
_rs(_env, "select",       _sl)
_rs(_env, "next",         _nx)
_rs(_env, "tostring",     _ts)
_rs(_env, "tonumber",     tonumber)
_rs(_env, "type",         _ty)
_rs(_env, "rawget",       _rg)
_rs(_env, "rawset",       _rs)
_rs(_env, "rawequal",     rawequal)
_rs(_env, "rawlen",       rawlen)
_rs(_env, "setmetatable", _sm)
_rs(_env, "getmetatable", _gm)
_rs(_env, "unpack",       _un)
_rs(_env, "pcall",        _pc)
_rs(_env, "xpcall",       xpcall)
_rs(_env, "error",        _er)
_rs(_env, "assert",       _as)
_rs(_env, "print",        function() end)
_rs(_env, "warn",         function() end)
_rs(_env, "coroutine",    coroutine)
_rs(_env, "debug",        _safe.debug)
_rs(_env, "os",           _safe.os)
_rs(_env, "tick",         _safe.tick)
_rs(_env, "time",         _safe.time)
_rs(_env, "wait",         _safe.wait)
_rs(_env, "spawn",        _safe.spawn)
_rs(_env, "delay",        _safe.delay)
_rs(_env, "game",         _safe.game)
_rs(_env, "workspace",    _safe.workspace)
_rs(_env, "script",       _safe.script)
_rs(_env, "Players",      _safe.Players)
_rs(_env, "Instance",     _safe.Instance)
_rs(_env, "Vector3",      _safe.Vector3)
_rs(_env, "CFrame",       _safe.CFrame)
_rs(_env, "Enum",         _safe.Enum)
_rs(_env, "syn",          _safe.syn)

local function _run()
    local f = io.open(_inp, "r")
    if not f then
        _L("CANNOT_OPEN_INPUT")
        local df = io.open(_out .. "/diag.txt", "w")
        if df then df:write(_tc(_log, "\n")) df:close() end
        return
    end
    local code = f:read("*a")
    f:close()
    _L("Script size: " .. #code .. " bytes")

    code = code:gsub("getfenv%s*%(%)%s*or%s*_ENV", "getfenv()")
    code = code:gsub("getfenv%s*%(%)%s*or%s*_G",   "getfenv()")

    local chunk, err = _ls(code)
    if not chunk then
        _L("COMPILE ERROR: " .. _ts(err))
    else
        setfenv(chunk, _env)
        _L("Executing...")
        local ok, res = _pc(chunk)
        if ok then
            _L("OK. layers=" .. _lyr)
        else
            _L("RUNTIME ERROR: " .. _ts(res))
        end
    end

    local sf = io.open(_out .. "/cap.txt", "w")
    if sf then
        for _, s in _ip(_cap) do
            sf:write(s:gsub("\n", "\\n") .. "\n---SEP---\n")
        end
        sf:close()
    end
    local df = io.open(_out .. "/diag.txt", "w")
    if df then df:write(_tc(_log, "\n")) df:close() end
end

_run()
'''


def run_sandbox(source, timeout=20):
    with tempfile.TemporaryDirectory() as d:
        in_path = os.path.join(d, 'input.lua')
        with open(in_path, 'w', encoding='utf-8') as f:
            f.write(source)

        esc_dir = d.replace('\\', '\\\\')
        esc_inp = in_path.replace('\\', '\\\\')

        script = SANDBOX.replace('OUTDIR_PLACEHOLDER', esc_dir)
        script = script.replace('INPATH_PLACEHOLDER', esc_inp)

        drv = os.path.join(d, 'driver.lua')
        with open(drv, 'w', encoding='utf-8') as f:
            f.write(script)

        try:
            proc = subprocess.run(
                [LUA_BIN, drv],
                capture_output=True, text=True, timeout=timeout, cwd=d
            )
            stdout = proc.stdout.strip()
            stderr = proc.stderr.strip()
        except subprocess.TimeoutExpired:
            stdout, stderr = 'timeout', ''
        except Exception as e:
            stdout, stderr = '', str(e)

        diag = ''
        dp = os.path.join(d, 'diag.txt')
        if os.path.exists(dp):
            with open(dp, encoding='utf-8', errors='replace') as f:
                diag = f.read()

        layers = []
        i = 1
        while True:
            p = os.path.join(d, f'layer_{i}.lua')
            if not os.path.exists(p):
                break
            with open(p, encoding='utf-8', errors='replace') as f:
                data = f.read()
            if data.strip():
                layers.append(data)
            i += 1

        cap_strings = []
        cp = os.path.join(d, 'cap.txt')
        if os.path.exists(cp):
            with open(cp, encoding='utf-8', errors='replace') as f:
                raw = f.read()
            for part in raw.split('---SEP---'):
                s = part.strip().replace('\\n', '\n')
                if len(s) > 20:
                    cap_strings.append(s)

        return layers, cap_strings, diag, stdout, stderr


def score(code):
    return (code.count('function'), code.count('local'), code.count('end'), len(code))


def peel(source, max_layers=8, timeout=20):
    current, count, previews, seen = source, 0, [], set()
    last_diag = ''
    for _ in range(max_layers):
        layers, cap_strings, diag, stdout, stderr = run_sandbox(current, timeout)
        last_diag = diag
        if layers:
            best = max(layers, key=score)
            if len(best.strip()) < 10 or best == current or best in seen:
                break
            seen.add(best)
            previews.append(best[:100].replace('\n', ' '))
            current = best
            count += 1
        else:
            break
    return current, count, previews, last_diag


def detect_obfuscator(text):
    patterns = {
        'ironbrew':  [r'bit\.bxor', r'getfenv\s*\(\s*\)\s*\[', r'IronBrew'],
        'moonsec':   [r'local\s+\w+\s*=\s*\{[\d\s,]{20,}\}', r'_moon\s*=\s*function'],
        'luraph':    [r'loadstring\s*\(\s*\(function', r'bytecode\s*=\s*["\'][A-Za-z0-9+/=]{50,}'],
        'wearedevs': [r'show_\w+\s*=\s*function', r'getfenv\s*\(\s*\)', r'string\.reverse'],
        'prometheus':[r'Prometheus', r'number_to_bytes'],
        'custom_vm': [r'mkexec', r'constTags', r'protoFormats'],
    }
    scores = {}
    for name, pats in patterns.items():
        s = sum(1 for p in pats if re.search(p, text, re.IGNORECASE))
        if s:
            scores[name] = s
    return max(scores, key=lambda k: scores[k]) if scores else 'generic'


def static_decode(code):
    code = re.sub(r'\\x([0-9a-fA-F]{2})',
                  lambda m: chr(int(m.group(1), 16)), code)
    code = re.sub(r'\\(\d{1,3})',
                  lambda m: chr(int(m.group(1))) if int(m.group(1)) < 256 else m.group(0), code)
    def sc(m):
        nums = re.findall(r'\d+', m.group(1))
        try:
            return '"' + ''.join(chr(int(n)) for n in nums if int(n) < 256) + '"'
        except:
            return m.group(0)
    code = re.sub(r'string\.char\s*\(\s*([\d,\s]+)\s*\)', sc, code)
    return code


def beautify(code):
    out, indent = [], 0
    for line in code.split('\n'):
        s = line.strip()
        if not s:
            out.append(''); continue
        if re.match(r'^(end\b|else\b|elseif\b|until\b)', s):
            indent = max(0, indent - 1)
        out.append('    ' * indent + s)
        if re.match(r'^(if\b|for\b|while\b|repeat\b|do\b)', s) and not s.endswith('end'):
            indent += 1
        if re.match(r'^(function\b|local\s+function\b)', s):
            indent += 1
    return '\n'.join(out)


@app.route('/health')
def health():
    lua_ok, active = False, LUA_BIN
    for b in [LUA_BIN, 'lua5.1', 'lua51', 'lua']:
        try:
            r = subprocess.run([b, '-v'], capture_output=True, timeout=2)
            out = (r.stderr + r.stdout).decode(errors='replace')
            if '5.1' in out or 'LuaJIT' in out:
                lua_ok = True; active = b; break
        except:
            pass
    return jsonify({'ok': True, 'lua': lua_ok, 'lua_bin': active})


@app.route('/deobf', methods=['POST'])
def deobf():
    data   = request.get_json(force=True)
    source = data.get('source', '')
    if not source.strip():
        return jsonify({'error': 'no source'}), 400

    obf = detect_obfuscator(source)
    result, layers, previews, diag = peel(source)

    if layers > 0:
        result = static_decode(result)
        result = beautify(result)
        method = 'sandbox'
    else:
        result = static_decode(source)
        result = beautify(result)
        method = 'static'

    return jsonify({
        'result':     result,
        'layers':     layers,
        'previews':   previews,
        'method':     method,
        'detected':   obf,
        'diagnostic': diag[:1000],
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
