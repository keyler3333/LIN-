import os, re, subprocess, tempfile, shutil, base64, hashlib
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

RUNTIME_PATH = os.path.join(os.path.dirname(__file__), 'sandbox_runtime.lua')

def run_sandbox(source, timeout=25):
    with tempfile.TemporaryDirectory() as d:
        in_path = os.path.join(d, 'input.lua')
        with open(in_path, 'w', encoding='utf-8') as f:
            f.write(source)

        with open(RUNTIME_PATH, 'r', encoding='utf-8') as f:
            runtime = f.read()

        esc_dir = d.replace('\\', '\\\\')
        esc_inp = in_path.replace('\\', '\\\\')

        driver = runtime
        driver = driver.replace('OUTDIR_PLACEHOLDER', esc_dir)
        driver = driver.replace('INPATH_PLACEHOLDER', esc_inp)

        drv = os.path.join(d, 'driver.lua')
        with open(drv, 'w', encoding='utf-8') as f:
            f.write(driver)

        try:
            proc = subprocess.run([LUA_BIN, drv], capture_output=True, text=True, timeout=timeout, cwd=d)
        except subprocess.TimeoutExpired:
            return [], [], 'timeout', '', ''
        except Exception as e:
            return [], [], str(e), '', ''

        stdout = proc.stdout.strip() if proc else ''
        stderr = proc.stderr.strip() if proc else ''

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

        diag = ''
        dp = os.path.join(d, 'diag.txt')
        if os.path.exists(dp):
            with open(dp, encoding='utf-8', errors='replace') as f:
                diag = f.read()

        return layers, cap_strings, diag, stdout, stderr


def lupa_sandbox(source, timeout=15):
    captured = []
    try:
        import lupa
        lua = lupa.LuaRuntime(unpack_returned_tuples=True)

        for name in ['io', 'os', 'require', 'dofile', 'loadfile', 'package',
                     'collectgarbage', 'newproxy', 'module']:
            try:
                lua.execute(f"{name} = nil")
            except:
                pass

        lua.execute("""
            game = setmetatable({}, {__index = function() return function() end end})
            workspace = game
            script = setmetatable({}, {__index = function() return "" end})
            Players = {LocalPlayer = {Name = "Player", UserId = 1, Character = {}}}
            RunService = {Heartbeat = {Connect = function() end}, RenderStepped = {Connect = function() end}}
            UserInputService = setmetatable({}, {__index = function() return function() end end})
            HttpService = {JSONDecode = function() return {} end, JSONEncode = function() return "{}" end}
            TweenService = setmetatable({}, {__index = function() return function() end end})
            Instance = {new = function() return setmetatable({}, {__index = function() return function() end end}) end}
            Vector3 = {new = function(...) return {} end}
            Vector2 = {new = function(...) return {} end}
            CFrame = {new = function(...) return {} end, Angles = function(...) return {} end}
            Color3 = {new = function(...) return {} end, fromRGB = function(...) return {} end}
            UDim2 = {new = function(...) return {} end}
            Enum = setmetatable({}, {__index = function() return setmetatable({}, {__index = function() return 0 end}) end})
            Drawing = setmetatable({}, {__index = function() return function() end end})
            debug = {traceback = function() return "" end, getinfo = function() return {} end}
            syn = {protect_gui = function() end, queue_on_teleport = function() end, request = function() return {Body = "", StatusCode = 200} end}
            writefile = function() end
            readfile = function() return "" end
            isfile = function() return false end
            makefolder = function() end
            listfiles = function() return {} end
            request = function() return {Body = "", StatusCode = 200, Success = true} end
            http = {request = function() return {Body = "", StatusCode = 200} end}
            identifyexecutor = function() return "synapse", "2.0" end
            getexecutorname = function() return "synapse" end
            checkcaller = function() return true end
            isrbxactive = function() return true end
            hookfunction = function(a, b) return a end
            newcclosure = function(f) return f end
            clonefunction = function(f) return f end
            tick = function() return 0 end
            time = function() return 0 end
            elapsedtime = function() return 0 end
            wait = function(n) return n or 0 end
            spawn = function(f) if type(f) == "function" then pcall(f) end end
            delay = function(t, f) if type(f) == "function" then pcall(f) end end
            print = function() end
            warn = function() end
            error = function(e) end
            assert = function(v, m) if not v then error(m or "assert") end return v end
            shared = {}
            _VERSION = "Lua 5.1"
            _G = {}
            _ENV = {}

            if not bit then
                bit = {}
                bit.bxor = function(a, b) local r, p = 0, 1 while a > 0 or b > 0 do if a % 2 ~= b % 2 then r = r + p end a = math.floor(a / 2) b = math.floor(b / 2) p = p * 2 end return r end
                bit.band = function(a, b) local r, p = 0, 1 while a > 0 and b > 0 do if a % 2 == 1 and b % 2 == 1 then r = r + p end a = math.floor(a / 2) b = math.floor(b / 2) p = p * 2 end return r end
                bit.bor = function(a, b) local r, p = 0, 1 while a > 0 or b > 0 do if a % 2 == 1 or b % 2 == 1 then r = r + p end a = math.floor(a / 2) b = math.floor(b / 2) p = p * 2 end return r end
                bit.bnot = function(a) return -a - 1 end
                bit.rshift = function(a, b) return math.floor(a / (2 ^ b)) end
                bit.lshift = function(a, b) return math.floor(a * (2 ^ b)) end
                bit32 = bit
            end

            coroutine.wrap = coroutine.wrap or function(f) return f end
            coroutine.create = coroutine.create or function(f) return f end
            table.pack = table.pack or function(...) return {n = select('#', ...), ...} end
            table.unpack = table.unpack or unpack
        """)

        def safe_ls(code, *args):
            if callable(code):
                chunks = []
                try:
                    while True:
                        c = code()
                        if not c:
                            break
                        chunks.append(str(c))
                except:
                    pass
                code = ''.join(chunks)
            s = str(code) if code else ''
            if len(s.strip()) > 5:
                captured.append(s)
            return lua.eval("function(...) end")

        lua.globals()['loadstring'] = safe_ls
        lua.globals()['load'] = safe_ls

        try:
            lua.execute(source)
        except:
            pass

        return captured

    except ImportError:
        return []


import roblox_emulator

def detect_obfuscator(text):
    patterns = {
        'luraph': {
            'checks': [r'loadstring\s*\(\s*\(function', r'bytecode\s*=\s*["\'][A-Za-z0-9+/=]{50,}',
                       r'Luraph', r'l_\d+_\d+', r'initv4', r'\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}'],
            'method': 'roblox_emulator'
        },
        'ironbrew2': {
            'checks': [r'while\s+true\s+do\s+local\s+\w+\s*=\s*\w+\[\w+\]',
                       r'pc\s*=\s*pc\s*\+\s*1', r'op\s*=\s*\w+\[pc\]',
                       r'local\s+\w+,\s*\w+,\s*\w+\s*=\s*\w+\s*&'],
            'method': 'bytecode_extraction'
        },
        'ironbrew1': {
            'checks': [r'bit\.bxor', r'getfenv\s*\(\s*\)\s*\[', r'IronBrew'],
            'method': 'sandbox_peel'
        },
        'moonsec_v3': {
            'checks': [r'local\s+\w+\s*=\s*\{[\d\s,]{20,}\}', r'_moon\s*=\s*function',
                       r'MoonSec', r'constantprotection'],
            'method': 'sandbox_peel'
        },
        'moonsec_v2': {
            'checks': [r'local\s+\w+\s*=\s*\{[\d\s,]{10,}\}', r'moon_\w+\s*='],
            'method': 'sandbox_peel'
        },
        'wearedevs': {
            'checks': [r'show_\w+\s*=\s*function', r'getfenv\s*\(\s*\)', r'string\.reverse'],
            'method': 'sandbox_peel'
        },
        'prometheus': {
            'checks': [r'Prometheus', r'number_to_bytes', r'local\s+L\s*=\s*\{'],
            'method': 'sandbox_peel'
        },
        'hercules': {
            'checks': [r'Hercules', r'Str\s*=\s*string\.sub'],
            'method': 'sandbox_peel'
        },
        'generic_vm': {
            'checks': [r'mkexec', r'constTags', r'protoFormats'],
            'method': 'lupa_sandbox'
        },
    }

    scores = {}
    for name, info in patterns.items():
        s = sum(1 for p in info['checks'] if re.search(p, text, re.IGNORECASE))
        if s > 0:
            scores[name] = s

    if not scores:
        return 'generic', 'sandbox_peel'

    best = max(scores, key=lambda k: scores[k])
    return best, patterns[best]['method']


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


def score(code):
    return (code.count('function'), code.count('local'), code.count('end'), len(code))


def peel(source, max_layers=8, timeout=25):
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


def deobfuscate(source):
    obf_type, method = detect_obfuscator(source)
    diag = ''

    if method == 'roblox_emulator':
        emu_layers, emu_err, emu_stdout, emu_stderr = roblox_emulator.run_emulator(source)
        if emu_layers:
            result = max(emu_layers, key=len)
            result = static_decode(result)
            result = beautify(result)
            return result, obf_type, 1, 'roblox_emulator', 'Emulator captured payload'

    if method == 'sandbox_peel':
        result, layers, previews, diag = peel(source)
        if layers > 0:
            result = static_decode(result)
            result = beautify(result)
            return result, obf_type, layers, 'sandbox', diag
        else:
            result = static_decode(source)
            result = beautify(result)
            return result, obf_type, 0, 'static', diag

    elif method == 'lupa_sandbox':
        captured = lupa_sandbox(source)
        if captured:
            best = max(captured, key=len)
            if len(best.strip()) > 20 and best != source:
                best = static_decode(best)
                best = beautify(best)
                return best, obf_type, 1, 'lupa_sandbox', 'Captured via Lupa sandbox'
        result, layers, previews, diag = peel(source)
        if layers > 0:
            result = static_decode(result)
            result = beautify(result)
            return result, obf_type, layers, 'sandbox', diag
        else:
            result = static_decode(source)
            result = beautify(result)
            return result, obf_type, 0, 'static', diag

    elif method == 'bytecode_extraction':
        result, layers, previews, diag = peel(source)
        if layers > 0:
            result = static_decode(result)
            result = beautify(result)
            return result, obf_type, layers, 'sandbox', diag
        else:
            result = static_decode(source)
            result = beautify(result)
            diag += '\nIronBrew 2 requires bytecode-level C# deobfuscator for full reversal.'
            return result, obf_type, 0, 'static', diag

    result, layers, previews, diag = peel(source)
    if layers > 0:
        result = static_decode(result)
        result = beautify(result)
        return result, obf_type, layers, 'sandbox', diag
    else:
        result = static_decode(source)
        result = beautify(result)
        return result, obf_type, 0, 'static', diag


@app.route('/health')
def health():
    lua_ok, lupa_ok, active = False, False, LUA_BIN
    for b in [LUA_BIN, 'lua5.1', 'lua51', 'lua']:
        try:
            r = subprocess.run([b, '-v'], capture_output=True, timeout=2)
            out = (r.stderr + r.stdout).decode(errors='replace')
            if '5.1' in out or 'LuaJIT' in out:
                lua_ok = True; active = b; break
        except:
            pass
    try:
        import lupa
        lupa_ok = True
    except:
        pass
    return jsonify({'ok': True, 'lua': lua_ok, 'lupa': lupa_ok, 'lua_bin': active})


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
