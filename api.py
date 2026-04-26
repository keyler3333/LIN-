import os
import re
import struct
import base64
import subprocess
import tempfile
from flask import Flask, request, jsonify

app = Flask(__name__)
LUA_BIN = os.environ.get('LUA_BIN', 'lua5.1')

HOOK = """
local __outdir = {OUTDIR}
local __n = 0

local function __hook(code, ...)
    if type(code) == "string" and #code > 5 then
        __n = __n + 1
        local f = io.open(__outdir .. "/layer_" .. __n .. ".lua", "w")
        if f then f:write(code) f:close() end
    end
    return function() end
end

loadstring = __hook
load       = __hook

local function __getfenv(n)
    return {
        string=string, math=math, table=table, bit=bit or {},
        pairs=pairs, ipairs=ipairs, select=select, next=next,
        tostring=tostring, tonumber=tonumber, type=type,
        rawget=rawget, rawset=rawset,
        setmetatable=setmetatable, getmetatable=getmetatable,
        unpack=unpack or table.unpack,
        loadstring=loadstring, load=load,
        pcall=pcall, xpcall=xpcall,
        error=error, assert=assert, print=print
    }
end
getfenv = __getfenv
setfenv = function(n, t) return t end

game             = setmetatable({}, {__index=function() return function() end end})
workspace        = game
script           = {}
Players          = {LocalPlayer={Name="Player",UserId=1}}
RunService       = {Heartbeat={Connect=function()end},RenderStepped={Connect=function()end}}
UserInputService = setmetatable({},{__index=function() return function() end end})
HttpService      = {JSONDecode=function() return {} end,JSONEncode=function() return "{}" end}
TweenService     = setmetatable({},{__index=function() return function() end end})
Instance         = {new=function() return setmetatable({},{__index=function()return function()end end}) end}
Vector3          = {new=function(...) return {} end}
Vector2          = {new=function(...) return {} end}
CFrame           = {new=function(...) return {} end,Angles=function(...) return {} end}
Color3           = {new=function(...) return {} end,fromRGB=function(...) return {} end}
UDim2            = {new=function(...) return {} end}
Enum             = setmetatable({},{__index=function() return setmetatable({},{__index=function() return 0 end}) end})
Drawing          = setmetatable({},{__index=function() return function() end end})
debug            = {traceback=function() return "" end,getinfo=function() return {} end}
syn              = {protect_gui=function()end,queue_on_teleport=function()end}
writefile        = function() end
readfile         = function() return "" end
isfile           = function() return false end
isfolder         = function() return false end
makefolder       = function() end
listfiles        = function() return {} end
request          = function() return {Body="",StatusCode=200,Success=true} end
http             = {request=function() return {Body="",StatusCode=200} end}
identifyexecutor = function() return "synapse","2.0" end
getexecutorname  = function() return "synapse" end
checkcaller      = function() return true end
isrbxactive      = function() return true end
hookfunction     = function(a,b) return a end
newcclosure      = function(f) return f end
clonefunction    = function(f) return f end
tick             = function() return 0 end
time             = function() return 0 end
wait             = function(n) return n or 0 end
spawn            = function() end
delay            = function() end
warn             = function() end
print            = function() end
error            = function(e) end
assert           = function(v,m) if not v then error(m or "assert") end return v end
shared           = {}
rconsole         = {print=function()end,clear=function()end}

if not bit then
    bit = {}
    bit.bxor=function(a,b) local r,p=0,1 while a>0 or b>0 do if a%2~=b%2 then r=r+p end a=math.floor(a/2) b=math.floor(b/2) p=p*2 end return r end
    bit.band=function(a,b) local r,p=0,1 while a>0 and b>0 do if a%2==1 and b%2==1 then r=r+p end a=math.floor(a/2) b=math.floor(b/2) p=p*2 end return r end
    bit.bor =function(a,b) local r,p=0,1 while a>0 or b>0 do if a%2==1 or b%2==1 then r=r+p end a=math.floor(a/2) b=math.floor(b/2) p=p*2 end return r end
    bit.bnot=function(a) return -a-1 end
    bit.rshift=function(a,b) return math.floor(a/(2^b)) end
    bit.lshift=function(a,b) return math.floor(a*(2^b)) end
    bit.arshift=function(a,b) return math.floor(a/(2^b)) end
    bit.btest=function(a,b) return bit.band(a,b)~=0 end
    bit.tobit=function(a) return a end
    bit32 = bit
end

table.pack   = table.pack   or function(...) return {n=select('#',...), ...} end
table.unpack = table.unpack or unpack
table.move   = table.move   or function(a,f,e,t,b) b=b or a for i=f,e do b[t+(i-f)]=a[i] end return b end
math.pow     = math.pow     or function(a,b) return a^b end
_G.game      = game
_G.workspace = workspace
"""


def run_sandbox(source, timeout=8):
    with tempfile.TemporaryDirectory() as d:
        escaped = d.replace('\\', '\\\\').replace('"', '\\"')
        hook    = HOOK.replace('{OUTDIR}', f'"{escaped}"')
        script  = hook + '\n' + source
        spath   = os.path.join(d, 'script.lua')
        with open(spath, 'w', encoding='utf-8') as f:
            f.write(script)
        try:
            subprocess.run([LUA_BIN, spath], timeout=timeout, capture_output=True, cwd=d)
        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            return None, 'lua5.1 not found'
        except Exception as e:
            return [], str(e)
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
        return captured, None


def peel(source, max_layers=8, timeout=8):
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
    def fold(m):
        try:
            a, op, b = float(m.group(1)), m.group(2), float(m.group(3))
            r = {'+': a+b, '-': a-b, '*': a*b, '/': a/b if b else None, '%': a%b if b else None}.get(op)
            if r is None: return m.group(0)
            return str(int(r)) if r == int(r) else str(r)
        except:
            return m.group(0)
    parts = re.split(r'("(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\')', code)
    code  = ''.join(
        re.sub(r'\b(\d+(?:\.\d+)?)\s*([+\-*/%])\s*(\d+(?:\.\d+)?)\b', fold, p) if i % 2 == 0 else p
        for i, p in enumerate(parts)
    )
    code = re.sub(r'if\s+false\s+then.*?end', '', code, flags=re.DOTALL)
    code = re.sub(r'while\s+false\s+do.*?end', '', code, flags=re.DOTALL)
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


@app.route('/health', methods=['GET'])
def health():
    try:
        subprocess.run([LUA_BIN, '-v'], capture_output=True, timeout=2)
        lua_ok = True
    except:
        lua_ok = False
    return jsonify({'ok': True, 'lua': lua_ok, 'lua_bin': LUA_BIN})


@app.route('/deobf', methods=['POST'])
def deobf():
    data   = request.get_json(force=True)
    source = data.get('source', '')
    if not source.strip():
        return jsonify({'error': 'no source provided'}), 400
    result, layers, previews, err = peel(source)
    if err:
        return jsonify({'error': err}), 500
    if layers > 0:
        result = static_decode(result)
        result = beautify(result)
        method = 'sandbox'
    else:
        result = static_decode(source)
        result = beautify(result)
        method = 'static'
    return jsonify({'result': result, 'layers': layers, 'previews': previews, 'method': method})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
