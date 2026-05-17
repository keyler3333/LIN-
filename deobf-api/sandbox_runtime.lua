local _out = "OUTDIR_PLACEHOLDER"
local _inp = "INPATH_PLACEHOLDER"
local _log = {}
local _layer_count = 0
local _step_count = 0
local _tracked = {}
local _capture_count = 0

local _orig_loadstring = loadstring
local _orig_pcall = pcall
local _orig_xpcall = xpcall
local _orig_rawset = rawset
local _orig_rawget = rawget
local _orig_table_concat = table.concat
local _orig_string_char = string.char
local _orig_string_dump = string.dump
local _orig_newproxy = newproxy
local _orig_unpack = unpack
local _orig_getfenv = getfenv
local _orig_setfenv = setfenv
local _orig_type = type
local _orig_pairs = pairs
local _orig_tostring = tostring
local _orig_rawequal = rawequal
local _orig_select = select
local _orig_debug_traceback = debug.traceback

local _io = io
if not _io then
    pcall(function()
        local b_fs = require("@lune/fs")
        _io = {
            open = function(path, mode)
                mode = tostring(mode or "r")
                if mode:find("r") then
                    local ok, data = pcall(b_fs.readFile, tostring(path))
                    if not ok then return nil end
                    return { read = function() return data end, close = function() end }
                elseif mode:find("w") then
                    local chunks = {}
                    return {
                        write = function(_, ...)
                            for i = 1, select("#", ...) do
                                chunks[#chunks+1] = tostring(select(i, ...))
                            end
                        end,
                        close = function() b_fs.writeFile(tostring(path), table.concat(chunks)) end
                    }
                end
            end
        }
    end)
end

local function _L(s) _log[#_log+1] = tostring(s) end
local function _write_file(path, data, mode)
    local f = _io.open(path, mode or "w")
    if not f then return false end
    f:write(data)
    f:close()
    return true
end
local function _write_layer(data)
    _layer_count = _layer_count + 1
    _write_file(_out .. "/layer_" .. _layer_count .. ".lua", data)
    _L("LAYER_" .. _layer_count .. " " .. #data .. " bytes")
end
local function _write_capture(data)
    if not data or #data == 0 then return end
    local f = _io.open(_out .. "/cap.txt", "a")
    if f then
        if _capture_count > 0 then f:write("---SEP---\n") end
        _capture_count = _capture_count + 1
        f:write(data .. "\n")
        f:close()
    end
end
local function _track_string(v)
    if _orig_type(v) == "string" and #v > 5 and not _tracked[v] then
        _tracked[v] = true
        _write_capture(v)
    end
end

pcall(function()
    debug.sethook(function()
        _step_count = _step_count + 1000
        if _step_count > 100000000 then error("__LIMIT__") end
    end, "", 1000)
end)

local _proxy_mt = {}
_proxy_mt.__index = function(t, k)
    local v = _orig_rawget(t, k)
    if v ~= nil then return v end
    v = setmetatable({}, _proxy_mt)
    _orig_rawset(t, k, v)
    return v
end
_proxy_mt.__newindex = function(t, k, v) _orig_rawset(t, k, v) end
_proxy_mt.__call = function(t, ...) return setmetatable({}, _proxy_mt) end
_proxy_mt.__gc = function() end
_proxy_mt.__tostring = function() return "Instance" end
_proxy_mt.__len = function() return 0 end
_proxy_mt.__unm = function() return 0 end
_proxy_mt.__add = function() return 0 end
_proxy_mt.__sub = function() return 0 end
_proxy_mt.__mul = function() return 0 end
_proxy_mt.__div = function() return 0 end
_proxy_mt.__mod = function() return 0 end
_proxy_mt.__pow = function() return 0 end
_proxy_mt.__eq = function(a, b) return a == b end
_proxy_mt.__lt = function() return false end
_proxy_mt.__le = function() return false end
_proxy_mt.__concat = function(a, b) return _orig_tostring(a) .. _orig_tostring(b) end

local function _new_proxy() return setmetatable({}, _proxy_mt) end

rawset = function(t, k, v)
    _track_string(v)
    return _orig_rawset(t, k, v)
end
rawget = _orig_rawget
table.concat = function(t, sep, i, j)
    local r = _orig_table_concat(t, sep, i, j)
    _track_string(r)
    return r
end
string.char = function(...)
    local r = _orig_string_char(...)
    _track_string(r)
    return r
end
string.dump = function(fn)
    local bc = _orig_string_dump(fn)
    if bc and #bc > 20 then
        _write_file(_out .. "/dump.bin", bc, "wb")
        _L("DUMPED " .. #bc .. " bytes")
    end
    return bc
end

local function _hooked_loadstring(code, name)
    if _orig_type(code) == "function" then
        local parts = {}
        while true do
            local ok, p = pcall(code)
            if not ok or not p then break end
            if _orig_type(p) == "string" then parts[#parts+1] = p end
            if #parts > 5000 then break end
        end
        code = table.concat(parts)
    end
    if _orig_type(code) == "string" and #code > 5 then
        _write_layer(code)
    end
    return _orig_loadstring(code, name)
end
loadstring = _hooked_loadstring
load = _hooked_loadstring
getfenv = _orig_getfenv
setfenv = _orig_setfenv

local Players = {
    LocalPlayer = {
        Name = "Player", UserId = 1,
        Character = _new_proxy(), PlayerGui = _new_proxy(), Backpack = _new_proxy(),
        PlayerScripts = _new_proxy(), Team = nil, membershipType = 0
    },
    GetPlayers = function() return {} end,
    GetPlayerByUserId = function(id) return Players.LocalPlayer end,
    PlayerAdded = { connect = function() return { disconnect = function() end } end },
    PlayerRemoving = { connect = function() return { disconnect = function() end } end }
}

local game = {
    PlaceId = 12345678,
    JobId = "00000000-0000-0000-0000-000000000000",
    GetService = function(self, name)
        if name == "Players" then return Players
        else return _new_proxy() end
    end,
    IsLoaded = function() return true end
}

local _safe_env = {
    assert = assert,
    error = function(msg, level)
        if msg == "detected by LeakD" then return nil end
        error(msg, level or 0)
    end,
    ipairs = ipairs, next = next, pairs = pairs, pcall = _orig_pcall,
    rawequal = _orig_rawequal, rawget = rawget, rawlen = rawlen, rawset = rawset,
    select = _orig_select, setmetatable = setmetatable, getmetatable = getmetatable,
    tonumber = tonumber, tostring = tostring, type = type, typeof = _orig_type,
    xpcall = _orig_xpcall, unpack = _orig_unpack or table.unpack,
    getfenv = getfenv, setfenv = setfenv, loadstring = loadstring, load = load,
    newproxy = function(add)
        local u = _orig_newproxy(add)
        if add then local mt = getmetatable(u); if mt then mt.__gc = function() end end end
        return u
    end,
    string = {
        byte = string.byte, char = string.char, find = string.find, format = string.format,
        gmatch = string.gmatch, gsub = string.gsub, len = string.len, lower = string.lower,
        match = string.match, rep = string.rep, reverse = string.reverse, sub = string.sub,
        upper = string.upper, dump = string.dump
    },
    math = {
        abs = math.abs, acos = math.acos, asin = math.asin, atan = math.atan, atan2 = math.atan2,
        ceil = math.ceil, cos = math.cos, cosh = math.cosh, deg = math.deg, exp = math.exp,
        floor = math.floor, fmod = math.fmod, frexp = math.frexp, huge = math.huge,
        ldexp = math.ldexp, log = math.log, log10 = math.log10, max = math.max, min = math.min,
        modf = math.modf, pi = math.pi, pow = math.pow, rad = math.rad, random = math.random,
        randomseed = math.randomseed, sin = math.sin, sinh = math.sinh, sqrt = math.sqrt,
        tan = math.tan, tanh = math.tanh
    },
    table = {
        concat = table.concat, insert = table.insert,
        maxn = function(t) local n = 0; for k in pairs(t) do if type(k) == "number" and k > n then n = k end end; return n end,
        remove = table.remove, sort = table.sort, unpack = _orig_unpack or table.unpack
    },
    os = { clock = os.clock, date = os.date, difftime = os.difftime, time = os.time },
    coroutine = {
        create = coroutine.create, resume = coroutine.resume, running = coroutine.running,
        status = coroutine.status, wrap = coroutine.wrap, yield = coroutine.yield
    },
    print = function(...) end, warn = function(...) end,
    game = game, workspace = _new_proxy(), Players = Players,
    MarketplaceService = _new_proxy(), ReplicatedStorage = _new_proxy(),
    ServerStorage = _new_proxy(), ServerScriptService = _new_proxy(),
    Lighting = _new_proxy(), StarterGui = _new_proxy(), StarterPack = _new_proxy(),
    SoundService = _new_proxy(), HttpService = _new_proxy(),
    TeleportService = _new_proxy(), Chat = _new_proxy(), InsertService = _new_proxy(),
    RunService = _new_proxy(), Instance = { new = function() return _new_proxy() end },
    Vector3 = { new = function(x, y, z) return { X = x or 0, Y = y or 0, Z = z or 0 } end },
    CFrame = { new = function() return {} end, Angles = function() return {} end },
    Color3 = { new = function(r, g, b) return { R = r or 0, G = g or 0, B = b or 0 } end },
    BrickColor = { new = function(name) return { Name = name } end },
    Enum = { MembershipType = { None = 0, Premium = 4 } },
    shared = {}, getconnections = function() return {} end,
    hookfunction = function(f, h) return f end, isscript = function() return false end,
    wait = function(t) return t or 0 end, delay = function(t, f) end, spawn = function(f) pcall(f) end,
    tick = function() return os.time() end, time = function() return os.time() end,
    elapsedTime = function() return os.time() end,
    bit32 = bit32 or {
        bxor = function(a, b) return a ~ b end, band = function(a, b) return a & b end,
        bor = function(a, b) return a | b end, bnot = function(a) return ~a end,
        lshift = function(a, b) return a << b end, rshift = function(a, b) return a >> b end,
        arshift = function(a, b) return a >> b end
    },
    utf8 = utf8 or { char = function(...) return string.char(...) end, len = function(s) return #s end },
    task = {
        spawn = function(f) pcall(f) end, defer = function(f) pcall(f) end,
        delay = function(t, f) pcall(f) end, wait = function(t) end, cancel = function() end
    },
    debug = {
        getinfo = debug.getinfo, getregistry = function() return _safe_env end,
        getmetatable = debug.getmetatable, setmetatable = setmetatable,
        getupvalue = debug.getupvalue, setupvalue = debug.setupvalue,
        getlocal = debug.getlocal, setlocal = debug.setlocal,
        traceback = _orig_debug_traceback, sethook = debug.sethook,
        getupvalues = function() return {} end, getconstants = function() return {} end,
        getproto = function() return nil end, getprotos = function() return {} end
    }
}

_safe_env._G = _safe_env
_safe_env._ENV = _safe_env
_safe_env.shared = {}
_safe_env.Shared = _safe_env.shared

local _env_mt = {
    __index = function(t, k)
        local v = _orig_rawget(_safe_env, k)
        if v ~= nil then return v end
        return _new_proxy()
    end,
    __newindex = function(t, k, v)
        _track_string(v)
        _orig_rawset(_safe_env, k, v)
    end
}
local env = setmetatable({}, _env_mt)

local fh = _io.open(_inp, "rb")
if not fh then
    _write_file(_out .. "/error.txt", "cannot open input")
else
    local source = fh:read("*a")
    fh:close()
    if not source then
        _write_file(_out .. "/error.txt", "cannot read input")
    else
        local chunk, parse_err = _orig_loadstring(source, "@input")
        if not chunk then
            _write_file(_out .. "/error.txt", "parse error: " .. tostring(parse_err))
        else
            _orig_setfenv(chunk, env)
            local function error_handler(e)
                return _orig_debug_traceback(tostring(e), 2)
            end
            local ok, res = _orig_xpcall(chunk, error_handler)
            if not ok then
                _write_file(_out .. "/error.txt", tostring(res))
            else
                if res and _orig_type(res) == "string" and #res > 5 then
                    _write_layer(res)
                elseif res and _orig_type(res) == "function" then
                    local ok2, bc = pcall(string.dump, res)
                    if ok2 then _write_file(_out .. "/dump.bin", bc, "wb") end
                end
            end
        end
    end
end

local found_bytecode = {}
local visited = {}
local function _scan(t, depth)
    if depth > 6 then return end
    if visited[t] then return end
    visited[t] = true
    for k, v in pairs(t) do
        if _orig_type(v) == "string" and #v >= 12 and v:sub(1, 4) == "\27Lua" then
            found_bytecode[#found_bytecode + 1] = v
        elseif _orig_type(v) == "table" then
            _scan(v, depth + 1)
        end
    end
end
_scan(_safe_env, 0)
_scan(env, 0)
if _safe_env.shared then _scan(_safe_env.shared, 0) end

local out_parts = {}
out_parts[#out_parts + 1] = "SANDBOX_OUTPUT_START\n"
out_parts[#out_parts + 1] = "return {\n"
for i, bc in ipairs(found_bytecode) do
    local escaped = bc:gsub(".", function(c) return string.format("\\%03d", string.byte(c)) end)
    out_parts[#out_parts + 1] = '  ["bytecode_' .. i .. '"] = "' .. escaped .. '",\n'
end
out_parts[#out_parts + 1] = "}\n"
out_parts[#out_parts + 1] = "SANDBOX_OUTPUT_END\n"
_write_file(_out .. "/sandbox_output.lua", table.concat(out_parts))

for _, text in ipairs(_tracked) do _write_capture(text) end

local df = _io.open(_out .. "/diag.txt", "w")
if df then df:write(table.concat(_log, "\n")); df:close() end
