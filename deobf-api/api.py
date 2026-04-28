import os, re, subprocess, tempfile, shutil, base64
from flask import Flask, request, jsonify

app = Flask(__name__)

def find_lua():
    for path in [shutil.which(b) for b in ['lua5.1','lua51','lua'] if shutil.which(b)]:
        try:
            if subprocess.run([path, '-v'], capture_output=True, timeout=2).returncode == 0:
                return path
        except:
            pass
    return 'lua5.1'

LUA_BIN = os.environ.get('LUA_BIN') or find_lua()

class SandboxTemplate:
    def __init__(self):
        self.preamble = r'''
local __outdir  = "{OUTDIR}"
local __layer   = 0
local __captured = {{}}
local __orig_loadstring = loadstring
local __orig_load       = load
local __orig_pcall      = pcall
local __orig_type       = type
local __orig_tostring   = tostring
local __orig_pairs      = pairs
local __orig_ipairs     = ipairs
local __orig_setmt      = setmetatable
local __orig_getmt      = getmetatable
local __orig_rawset     = rawset
local __orig_rawget     = rawget
local __orig_char       = string.char
local __orig_concat     = table.concat
local __orig_print      = print
local __orig_error      = error
local __orig_select     = select

local function __capture(v)
    if __orig_type(v) == "string" and #v > 20 then
        table.insert(__captured, v)
    end
end

local function __hook_loadstring(code, chunkname)
    if __orig_type(code) == "string" and #code > 5 then
        __layer = __layer + 1
        local f = io.open(__outdir .. "/layer_" .. __layer .. ".lua", "w")
        if f then f:write(code) f:close() end
        __capture(code)
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
load       = __hook_load
rawset(_G, "loadstring", __hook_loadstring)
rawset(_G, "load", __hook_load)

string.char = function(...)
    local result = __orig_char(...)
    if #result > 20 then
        __capture(result)
    end
    return result
end

table.concat = function(t, sep, i, j)
    local result = __orig_concat(t, sep, i, j)
    if __orig_type(result) == "string" and #result > 20 then
        __capture(result)
    end
    return result
end

local function __make_proxy(name)
    local proxy = {{}}
    __orig_setmt(proxy, {{
        __index = function(self, key)
            local child_name = name .. "." .. __orig_tostring(key)
            local child = __make_proxy(child_name)
            rawset(self, key, child)
            return child
        end,
        __newindex = function(self, key, value)
            rawset(self, key, value)
            __capture(value)
        end,
        __call = function(self, ...)
            local args = {{...}}
            for _, v in __orig_ipairs(args) do
                if __orig_type(v) == "function" then
                    __orig_pcall(v)
                end
                __capture(v)
            end
            local child = __make_proxy(name .. "()")
            __capture(__orig_tostring(child))
            return child
        end,
        __tostring = function() return name end,
        __concat   = function(a, b)
            local s = __orig_tostring(a) .. __orig_tostring(b)
            __capture(s)
            return s
        end,
        __add = function(a,b) return __make_proxy(name.."+") end,
        __sub = function(a,b) return __make_proxy(name.."-") end,
        __mul = function(a,b) return __make_proxy(name.."*") end,
        __div = function(a,b) return __make_proxy(name.."/") end,
        __mod = function(a,b) return __make_proxy(name.."%") end,
        __pow = function(a,b) return __make_proxy(name.."^") end,
        __unm = function(a)   return __make_proxy("-"..name) end,
        __len = function()    return 1 end,
        __lt  = function(a,b) return false end,
        __le  = function(a,b) return true end,
        __eq  = function(a,b) return false end,
    }})
    return proxy
end

local __env = __make_proxy("env")
__env.string  = string
__env.math    = math
__env.table   = table
__env.bit     = bit or {{}}
__env.bit32   = bit32 or {{}}
__env.pairs   = __orig_pairs
__env.ipairs  = __orig_ipairs
__env.select  = __orig_select
__env.next    = next
__env.tostring = __orig_tostring
__env.tonumber = tonumber
__env.type     = __orig_type
__env.rawget   = __orig_rawget
__env.rawset   = __orig_rawset
__env.setmetatable = __orig_setmt
__env.getmetatable = __orig_getmt
__env.unpack   = unpack or table.unpack
__env.loadstring = __hook_loadstring
__env.load     = __hook_load
__env.pcall    = __orig_pcall
__env.xpcall   = xpcall
__env.error    = __orig_error
__env.assert   = assert
__env.print    = function(...)
    local parts = {{}}
    for i=1, __orig_select('#', ...) do
        parts[i] = __orig_tostring(__orig_select(i, ...))
    end
    __orig_print("[SANDBOX PRINT] " .. __orig_concat(parts, "\t"))
end
__env.warn = function() end
__env.coroutine = coroutine
__env.debug = {{
    traceback = function() return "" end,
    getinfo   = function()
        return {{short_src="script.lua", currentline=0, what="Lua"}}
    end,
    sethook   = function() end,
    getupvalue = function() return nil end,
    setupvalue = function() end,
}}
__env.os = {{
    clock  = function() return 0 end,
    time   = function() return 1000000 end,
    date   = function() return "2024-01-01" end,
    difftime = function() return 0 end,
}}
__env.tick = function() return 0 end
__env.time = function() return 0 end
__env.wait = function(n) return n or 0 end
__env.spawn = function(f)
    if __orig_type(f) == "function" then
        __orig_pcall(f)
    end
end
__env.delay = function(t,f)
    if __orig_type(f) == "function" then
        __orig_pcall(f)
    end
end
__env._VERSION = "Lua 5.1"
__env._G = __env
__env._ENV = __env
__env.shared = __env
__env.game = {{
    GetService = function(self, name)
        return __make_proxy("Service:" .. name)
    end
}}
__env.Players = __make_proxy("Players")
__env.RunService = __make_proxy("RunService")
__env.UserInputService = __make_proxy("UserInputService")
__env.TweenService = __make_proxy("TweenService")
__env.HttpService = __make_proxy("HttpService")
__env.Instance = {{
    new = function(className)
        return __make_proxy("Instance:" .. className)
    end
}}
__env.Vector3 = {new = function(...) return __make_proxy("Vector3") end}
__env.Vector2 = {new = function(...) return __make_proxy("Vector2") end}
__env.CFrame = {{
    new    = function(...) return __make_proxy("CFrame") end,
    Angles = function(...) return __make_proxy("CFrame.Angles") end,
}}
__env.Color3 = {{
    new    = function(...) return __make_proxy("Color3") end,
    fromRGB = function(...) return __make_proxy("Color3") end,
}}
__env.UDim2 = {new = function(...) return __make_proxy("UDim2") end}
__env.Enum = __make_proxy("Enum")
__env.Drawing = __make_proxy("Drawing")
__env.syn = __make_proxy("syn")
__env.writefile = function() end
__env.readfile  = function() return "" end
__env.isfile    = function() return false end
__env.isfolder  = function() return false end
__env.makefolder = function() end
__env.listfiles  = function() return {{}} end
__env.request    = function() return {{Body="", StatusCode=200, Success=true}} end
__env.http       = {{
    request = function() return {{Body="", StatusCode=200}} end
}}
__env.identifyexecutor = function() return "synapse", "2.0" end
__env.getexecutorname  = function() return "synapse" end
__env.checkcaller      = function() return true end
__env.isrbxactive      = function() return true end
__env.hookfunction     = function(a,b) return a end
__env.newcclosure      = function(f) return f end
__env.clonefunction    = function(f) return f end
__env.elapsedtime      = function() return 0 end
__env.rconsole         = {{print=function()end,clear=function()end}}
getfenv = function(n) return __env end
setfenv = function(n, t)
    if __orig_type(t) == "table" then
        for k, v in __orig_pairs(t) do rawset(__env, k, v) end
    end
    return t
end
_ENV = __env
_G   = __env

local function __run()
    local f = io.open("{INPATH}", "r")
    if not f then
        __orig_print("[SANDBOX] CANNOT OPEN INPUT")
        return
    end
    local code = f:read("*a")
    f:close()

    code = code:gsub("getfenv%s*%(%)%s*or%s*_ENV", "getfenv()")
    code = code:gsub("getfenv%s*%(%)%s*or%s*_G",   "getfenv()")

    local chunk, err = __orig_loadstring(code)
    if not chunk then
        __orig_print("[SANDBOX] COMPILE ERROR: " .. __orig_tostring(err))
        return
    end
    setfenv(chunk, __env)

    local ok, result = __orig_pcall(chunk)
    if ok then
        __capture(result)
        __orig_print("[SANDBOX] EXECUTION DONE. LAYERS: " .. __layer)
    else
        __orig_print("[SANDBOX] RUNTIME ERROR: " .. __orig_tostring(result))
    end

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
'''
    def render(self, outdir, inpath):
        return self.preamble.replace('{OUTDIR}', outdir).replace('{INPATH}', inpath)

sandbox_template = SandboxTemplate()

def force_execute_patch(code):
    code = re.sub(r'\bif\s+(.+?)\s+then', 'if true then', code)
    return code

def run_sandbox(source, mode='normal', timeout=25):
    with tempfile.TemporaryDirectory() as d:
        in_path = os.path.join(d, 'input.lua')
        with open(in_path, 'w', encoding='utf-8') as f:
            f.write(source)

        esc_dir    = d.replace('\\', '\\\\').replace('"', '\\"')
        esc_input  = in_path.replace('\\', '\\\\').replace('"', '\\"')

        driver = sandbox_template.render(esc_dir, esc_input)

        drv_path = os.path.join(d, 'driver.lua')
        with open(drv_path, 'w', encoding='utf-8') as f:
            f.write(driver)

        try:
            proc = subprocess.run(
                [LUA_BIN, drv_path], capture_output=True, text=True,
                timeout=timeout, cwd=d
            )
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
    return max(scores, key=lambda k: scores[k]) if scores else 'generic'

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

def extract_best_payload(layers, captured_strs_pairs):
    if layers:
        return max(layers, key=len), 'layer'
    candidates = []
    for raw in captured_strs_pairs:
        for part in raw.split('---SEP---'):
            part = part.strip().replace('\\n','\n')
            if part and len(part) > 50:
                candidates.append(part)
    if candidates:
        return max(candidates, key=len), 'captured_string'
    return None, None

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

    modes = [
        ('normal', source, 25),
        ('normal', static_decode(source), 25),
        ('forced', force_execute_patch(source), 30),
    ]

    all_layers = []
    all_captured = []
    diag = []

    for mode_name, src, timeout in modes:
        layers, stdout, stderr, cap_strings, count = run_sandbox(src, mode=mode_name, timeout=timeout)
        all_layers.extend(layers)
        all_captured.append(cap_strings)
        diag.append(f"--- Mode: {mode_name} ---\n{stdout[:800]}\n{stderr[:800]}\nLayers: {count}\n")

    best_payload, source_type = extract_best_payload(all_layers, all_captured)

    if best_payload:
        result = best_payload
        method = source_type
        layers_found = len(all_layers)
    else:
        result = static_decode(source)
        method = 'static'
        layers_found = 0

    diagnostic = '\n'.join(diag)

    return jsonify({
        'result': result,
        'layers': layers_found,
        'method': method,
        'detected': obf_type,
        'diagnostic': diagnostic[:2000],
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
