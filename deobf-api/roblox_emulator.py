import os, subprocess, tempfile

EMULATOR_BIN = os.environ.get('LUNE_BIN', 'lune')

def run_emulator(source, timeout=30):
    with tempfile.TemporaryDirectory() as d:
        inp = os.path.join(d, 'input.lua')
        with open(inp, 'w', encoding='utf-8') as f:
            f.write(source)
        driver = r'''
local _out = os.getenv("OUTDIR") or "/tmp"
os.setenv("OUTDIR", "''' + d.replace('\\','/') + r'''")

local _lyr = 0
local _seen = {}

local _ls = loadstring
loadstring = function(code, chunkname)
    if type(code) == "string" and #code > 5 then
        if not _seen[code] then
            _seen[code] = true
            _lyr = _lyr + 1
            local f = io.open(_out .. "/layer_" .. _lyr .. ".lua", "w")
            if f then f:write(code) f:close() end
        end
    end
    return _ls(code, chunkname)
end
load = loadstring

game = setmetatable({}, {__index = function() return function() end end})
workspace = game
script = setmetatable({}, {__index = function() return "" end})
Instance = {new = function(n) return setmetatable({}, {__index = function() return function() end end}) end}
getfenv = function() return _G end

local f = io.open("''' + inp.replace('\\','/') + r'''", "r")
local code = f:read("*a")
f:close()
local chunk, err = loadstring(code)
if chunk then
    pcall(chunk)
end
'''
        drv = os.path.join(d, 'driver.lua')
        with open(drv, 'w', encoding='utf-8') as f:
            f.write(driver)
        try:
            env = os.environ.copy()
            env['OUTDIR'] = d.replace('\\','/')
            proc = subprocess.run([EMULATOR_BIN, 'run', drv],
                                  capture_output=True, text=True,
                                  timeout=timeout, cwd=d, env=env)
            stdout = proc.stdout.strip()
            stderr = proc.stderr.strip()
        except subprocess.TimeoutExpired:
            stdout, stderr = '', 'timeout'
        except FileNotFoundError:
            return [], 'lune_not_installed', '', ''
        except Exception as e:
            return [], str(e), '', ''

        layers = []
        i = 1
        while True:
            p = os.path.join(d, f'layer_{i}.lua')
            if not os.path.exists(p): break
            with open(p, encoding='utf-8', errors='replace') as f:
                data = f.read()
            if data.strip():
                layers.append(data)
            i += 1
        return layers, '', stdout, stderr
