import os, subprocess, tempfile, json
from flask import Flask, request, jsonify

app = Flask(__name__)

def find_lua():
    import shutil
    for binary in ['lua5.1', 'lua51', 'lua']:
        path = shutil.which(binary)
        if path:
            try:
                if subprocess.run([path, '-v'], capture_output=True, timeout=2).returncode == 0:
                    return path
            except:
                pass
    return 'lua5.1'

LUA_BIN = os.environ.get('LUA_BIN') or find_lua()

SANDBOX_PREAMBLE = r"""
local __outdir = "{OUTDIR}"
local __layer = 0
local __captured = {{}}
local __orig_loadstring = loadstring
local __orig_load = load
local __orig_pcall = pcall
local __orig_type = type
local __orig_tostring = tostring
local __orig_pairs = pairs
local __orig_ipairs = ipairs
local __orig_setmetatable = setmetatable
local __orig_getmetatable = getmetatable
local __orig_rawget = rawget
local __orig_rawset = rawset
local __orig_char = string.char
local __orig_concat = table.concat
local __orig_error = error
local __orig_print = print

local function __hook_loadstring(code, chunkname)
    if __orig_type(code) == "string" and #code > 5 then
        __layer = __layer + 1
        local f = io.open(__outdir .. "/layer_" .. __layer .. ".lua", "w")
        if f then f:write(code) f:close() end
        table.insert(__captured, code)
        __orig_print("[SANDBOX] CAPTURED LAYER " .. __layer .. " (" .. #code .. " bytes)")
    end
    local fn, err = __orig_loadstring(code, chunkname)
    if not fn then
        __orig_print("[SANDBOX] LOADSTRING ERROR: " .. __orig_tostring(err))
        return function() end
    end
    return fn
end

local function __hook_load(code, chunkname)
    if __orig_type(code) == "function" then
        local parts = {{}}
        while true do
            local part = code()
            if not part then break end
            if __orig_type(part) == "string" then
                table.insert(parts, part)
            end
            if #parts > 5000 then break end
        end
        code = __orig_concat(parts)
    end
    if __orig_type(code) == "string" and #code > 5 then
        return __hook_loadstring(code, chunkname)
    end
    return __orig_load(code, chunkname)
end

loadstring = __hook_loadstring
load = __hook_load
rawset(_G, "loadstring", __hook_loadstring)
rawset(_G, "load", __hook_load)

string.char = function(...)
    local result = __orig_char(...)
    if #result > 0 then
        table.insert(__captured, "string.char: " .. result)
    end
    return result
end

table.concat = function(t, sep, i, j)
    local result = __orig_concat(t, sep, i, j)
    if __orig_type(result) == "string" and #result > 5 then
        table.insert(__captured, "table.concat: " .. result:sub(1, 200))
    end
    return result
end

local __safe_env = {{
    string = string,
    math = math,
    table = table,
    bit = bit or {{}},
    bit32 = bit32 or {{}},
    pairs = __orig_pairs,
    ipairs = __orig_ipairs,
    select = select,
    next = next,
    tostring = __orig_tostring,
    tonumber = tonumber,
    type = __orig_type,
    rawget = __orig_rawget,
    rawset = __orig_rawset,
    rawequal = rawequal,
    setmetatable = __orig_setmetatable,
    getmetatable = __orig_getmetatable,
    unpack = unpack or table.unpack,
    loadstring = __hook_loadstring,
    load = __hook_load,
    pcall = __orig_pcall,
    xpcall = xpcall,
    error = __orig_error,
    assert = assert,
    print = function(...)
        local args = {{...}}
        for i=1, select('#', ...) do
            __orig_print("[SANDBOX PRINT] " .. __orig_tostring(args[i]))
        end
    end,
    warn = function() end,
    coroutine = coroutine,
    debug = {{
        traceback = function() return "" end,
        getinfo = function() return {{short_src="script.lua", currentline=0, what="Lua"}} end,
        sethook = function() end,
        getupvalue = function() return nil end,
        setupvalue = function() end,
    }},
    os = {{
        clock = function() return 0 end,
        time = function() return 1000000 end,
        date = function() return "2024-01-01" end,
        difftime = function() return 0 end,
    }},
    tick = function() return 0 end,
    time = function() return 0 end,
    wait = function(n) return n or 0 end,
    spawn = function(f) if __orig_type(f) == "function" then __orig_pcall(f) end end,
    delay = function(t,f) if __orig_type(f) == "function" then __orig_pcall(f) end end,
    _VERSION = "Lua 5.1",
    _G = {{}},
    shared = {{}},
}}

local function __make_proxy(name)
    local proxy = {{}}
    __orig_setmetatable(proxy, {{
        __index = function(self, key)
            local child_name = name .. "." .. __orig_tostring(key)
            local child = __make_proxy(child_name)
            rawset(self, key, child)
            return child
        end,
        __newindex = function(self, key, value) rawset(self, key, value) end,
        __call = function(self, ...)
            local args = {{...}}
            for _, v in __orig_ipairs(args) do
                if __orig_type(v) == "function" then
                    __orig_pcall(v)
                end
            end
            return __make_proxy(name .. "()")
        end,
        __tostring = function() return name end,
        __concat = function(a,b) return __orig_tostring(a) .. __orig_tostring(b) end,
        __add = function(a,b) return __make_proxy(name.."+") end,
        __sub = function(a,b) return __make_proxy(name.."-") end,
        __mul = function(a,b) return __make_proxy(name.."*") end,
        __div = function(a,b) return __make_proxy(name.."/") end,
        __mod = function(a,b) return __make_proxy(name.."%") end,
        __pow = function(a,b) return __make_proxy(name.."^") end,
        __unm = function(a) return __make_proxy("-"..name) end,
        __len = function() return 0 end,
        __lt = function(a,b) return false end,
        __le = function(a,b) return true end,
        __eq = function(a,b) return name == __orig_tostring(b) end,
    }})
    return proxy
end

local __env = __make_proxy("env")
for k, v in __orig_pairs(__safe_env) do
    rawset(__env, k, v)
end
rawset(__env, "_G", __env)
rawset(__env, "_ENV", __env)
rawset(__env, "shared", __env)

getfenv = function(n) return __env end
setfenv = function(n, t)
    if __orig_type(t) == "table" then
        for k, v in __orig_pairs(t) do rawset(__env, k, v) end
    end
    return t
end

_ENV = __env
_G = __env

local function __run()
    local f = io.open("{INPATH}", "r")
    if not f then
        __orig_print("[SANDBOX] CANNOT OPEN INPUT FILE")
        return
    end
    local code = f:read("*a")
    f:close()
    code = code:gsub("getfenv%s*%(%)%s*or%s*_ENV", "getfenv()")
    code = code:gsub("getfenv%s*%(%)%s*or%s*_G", "getfenv()")
    local chunk, err = __orig_loadstring(code)
    if not chunk then
        __orig_print("[SANDBOX] COMPILE ERROR: " .. __orig_tostring(err))
        return
    end
    setfenv(chunk, __env)
    local ok, err = __orig_pcall(chunk)
    if not ok then
        __orig_print("[SANDBOX] RUNTIME ERROR: " .. __orig_tostring(err))
    end
    __orig_print("[SANDBOX] EXECUTION COMPLETE. LAYERS CAPTURED: " .. __layer)
    local sf = io.open(__outdir .. "/captured_strings.txt", "w")
    if sf then
        for _, s in __orig_ipairs(__captured) do
            sf:write(s:gsub("\n", "\\n") .. "\n---SEP---\n")
        end
        sf:close()
    end
    local lf = io.open(__outdir .. "/layer_count.txt", "w")
    if lf then lf:write(__orig_tostring(__layer)) lf:close() end
end

__run()
"""

def run_sandbox(source, timeout=15):
    with tempfile.TemporaryDirectory() as d:
        in_path = os.path.join(d, 'input.lua')
        with open(in_path, 'w', encoding='utf-8') as f:
            f.write(source)
        esc_dir = d.replace('\\', '\\\\').replace('"', '\\"')
        esc_input = in_path.replace('\\', '\\\\').replace('"', '\\"')
        driver = SANDBOX_PREAMBLE.replace('{OUTDIR}', esc_dir).replace('{INPATH}', esc_input)
        drv_path = os.path.join(d, 'driver.lua')
        with open(drv_path, 'w', encoding='utf-8') as f:
            f.write(driver)
        try:
            proc = subprocess.run([LUA_BIN, drv_path], capture_output=True, text=True, timeout=timeout, cwd=d)
        except subprocess.TimeoutExpired:
            proc = None
        except Exception:
            proc = None
        sandbox_output = proc.stdout.strip() if proc else 'timeout'
        sandbox_error  = proc.stderr.strip() if proc else ''
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
        captured_strs = ''
        cp = os.path.join(d, 'captured_strings.txt')
        if os.path.exists(cp):
            with open(cp, encoding='utf-8', errors='replace') as f:
                captured_strs = f.read()
        layer_count = 0
        lc = os.path.join(d, 'layer_count.txt')
        if os.path.exists(lc):
            with open(lc) as f:
                try:
                    layer_count = int(f.read().strip())
                except:
                    pass
        return layers, sandbox_output, sandbox_error, captured_strs, layer_count

def detect_obfuscator(text):
    patterns = {
        'ironbrew':  [r'bit and bit\.bxor', r'return table\.concat\(', r'return \w+\(true,\s*\{\}'],
        'ironbrew2': [r'while\s+true\s+do\s+local\s+\w+\s*=\s*\w+\[\w+\]', r'local\s+\w+,\s*\w+,\s*\w+\s*=\s*\w+\s*&'],
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
    if not scores:
        return 'generic'
    return max(scores, key=lambda k: scores[k])

import re

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

@app.route('/health')
def health():
    lua_ok = False
    for binary in [LUA_BIN, 'lua5.1', 'lua51', 'lua']:
        try:
            r = subprocess.run([binary, '-v'], capture_output=True, timeout=2)
            if '5.1' in (r.stderr.decode() + r.stdout.decode()):
                lua_ok = True
                break
        except:
            pass
    return jsonify({'ok': True, 'lua': lua_ok})

@app.route('/deobf', methods=['POST'])
def deobf():
    data = request.get_json(force=True)
    source = data.get('source', '')
    if not source.strip():
        return jsonify({'error': 'no source'}), 400
    obf_type = detect_obfuscator(source)
    layers, stdout, stderr, cap_strings, layer_count = run_sandbox(source)
    if layer_count > 0 and layers:
        result = layers[-1]
        method = 'sandbox'
    else:
        result = static_decode(source)
        method = 'static'
    diagnostic = ''
    if stdout:
        diagnostic += 'SANDBOX OUTPUT:\n' + stdout[:1000] + '\n'
    if stderr:
        diagnostic += 'SANDBOX STDERR:\n' + stderr[:1000] + '\n'
    if cap_strings:
        diagnostic += 'CAPTURED STRINGS:\n' + cap_strings[:1000] + '\n'
    if not diagnostic:
        diagnostic = 'No sandbox output captured.'
    return jsonify({
        'result': result,
        'layers': layer_count,
        'method': method,
        'detected': obf_type,
        'diagnostic': diagnostic[:2000],
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
