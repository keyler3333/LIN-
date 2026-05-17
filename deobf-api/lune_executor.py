import asyncio
import os
import tempfile
import hashlib
import logging

logger = logging.getLogger("deobf")

EXECUTION_TIMEOUT = 10
LUNE_BIN = os.environ.get("LUNE_BIN", "lune")

SHIM_TEMPLATE = r"""
local function make_proxy(name)
    local proxy = {}
    local mt = {}
    mt.__index = function(t, k)
        if type(k) == "number" then return 0 end
        return make_proxy(tostring(name) .. "." .. tostring(k))
    end
    mt.__newindex = function() end
    mt.__call = function(t, ...)
        return make_proxy(tostring(name) .. "()")
    end
    mt.__tostring = function() return tostring(name) end
    mt.__len = function() return 0 end
    mt.__add = function() return 0 end
    mt.__sub = function() return 0 end
    mt.__mul = function() return 0 end
    mt.__div = function() return 0 end
    mt.__mod = function() return 0 end
    mt.__unm = function() return 0 end
    mt.__concat = function(a, b) return tostring(a) .. tostring(b) end
    mt.__lt  = function() return false end
    mt.__le  = function() return false end
    mt.__eq  = function() return false end
    setmetatable(proxy, mt)
    return proxy
end

local _player = {
    UserId = 1,
    Name = "Player",
    DisplayName = "Player",
    AccountAge = 100,
    MembershipType = make_proxy("MembershipType"),
}

local _game = make_proxy("game")
rawset(_game, "GetService", function(self, name)
    return make_proxy("game:" .. name)
end)
rawset(_game, "Players", {
    LocalPlayer = _player,
    GetPlayers = function() return {_player} end,
})
rawset(_game, "HttpGet",       function() return "" end)
rawset(_game, "HttpGetAsync",  function() return "" end)
rawset(_game, "PlaceId",       1)
rawset(_game, "JobId",         "00000000-0000-0000-0000-000000000000")

game      = _game
workspace = make_proxy("workspace")
script    = make_proxy("script")
shared    = {}
_G        = {}

local _env_mt = {}
_env_mt.__index = function(t, k)
    io.write("STUB_GLOBAL: " .. tostring(k) .. "\n")
    return make_proxy(k)
end
_env_mt.__newindex = function() end
setmetatable(_G, _env_mt)

task = {
    wait  = function(n) end,
    spawn = function(f) pcall(f) end,
    defer = function(f) pcall(f) end,
}
wait        = function(n) end
spawn       = function(f) pcall(f) end
delay       = function(t, f) pcall(f) end
tick        = function() return 0 end
time        = function() return 0 end
os          = { time = function() return 0 end, clock = os.clock, date = os.date }
math        = math
string      = string
table       = table
bit32       = bit32 or make_proxy("bit32")

local _captured = false
local _outpath  = {outpath!r}

local _orig_loadstring = loadstring
loadstring = function(chunk, chunkname)
    if not _captured and chunk and #chunk > 0 then
        _captured = true
        io.write("CAPTURE_SUCCESS: " .. #chunk .. " bytes\n")
        local f = io.open(_outpath, "wb")
        if f then
            f:write(chunk)
            f:close()
        end
    end
    return function() end
end
load = loadstring

local ok, err = pcall(function()
{indented_user_script}
end)

if not ok then
    io.write("RUNTIME_ERROR: " .. tostring(err) .. "\n")
end

if not _captured then
    io.write("CAPTURE_FAILED: loadstring was never called\n")
end
"""

async def execute_and_capture(lua_source):
    info = {"stub_globals": [], "runtime_error": None, "capture_success": False}

    with tempfile.TemporaryDirectory() as tmpdir:
        tag = hashlib.md5(lua_source.encode()).hexdigest()[:8]
        script_path = os.path.join(tmpdir, f"input_{tag}.luau")
        output_path = os.path.join(tmpdir, f"captured_{tag}.luac")

        indented = "\n".join("    " + line for line in lua_source.splitlines())
        shim = SHIM_TEMPLATE.format(
            outpath=output_path,
            indented_user_script=indented,
        )

        with open(script_path, "w", encoding="utf-8") as f:
            f.write(shim)

        try:
            proc = await asyncio.create_subprocess_exec(
                LUNE_BIN, "run", script_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=EXECUTION_TIMEOUT
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                return None, {"error": "timeout"}

        except FileNotFoundError:
            return None, {"error": "lune not found"}

        for line in stdout.decode("utf-8", errors="replace").splitlines():
            if line.startswith("STUB_GLOBAL: "):
                info["stub_globals"].append(line[len("STUB_GLOBAL: "):])
            elif line.startswith("RUNTIME_ERROR: "):
                info["runtime_error"] = line[len("RUNTIME_ERROR: "):]
            elif line.startswith("CAPTURE_SUCCESS: "):
                info["capture_success"] = True

        if info["stub_globals"]:
            logger.debug(f"Stubbed globals: {', '.join(info['stub_globals'])}")

        if os.path.isfile(output_path):
            with open(output_path, "rb") as f:
                data = f.read()
            return data, info

        return None, info
