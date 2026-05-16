local _out = "OUTDIR_PLACEHOLDER"
local _inp = "INPATH_PLACEHOLDER"
local _log = {}
local _layer_count = 0
local _step_count = 0

local function _L(s)
    _log[#_log+1] = tostring(s)
end

local function _write_file(path, data, mode)
    local f = io.open(path, mode or "w")
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
    local f = io.open(_out .. "/cap.txt", "a")
    if f then
        if f:seek("end") > 0 then f:write("---SEP---\n") end
        f:write(data .. "\n")
        f:close()
    end
end

local function _repair_malformed(code)
    return (tostring(code or "")):gsub("(%d)([a-zA-Z_])", "%1 %2")
end

do
    local ok, err = pcall(function()
        debug.sethook(function()
            _step_count = _step_count + 1000
            if _step_count > 100000000 then
                error("__LIMIT__")
            end
        end, "", 1000)
    end)
end

local _orig_loadstring = loadstring
local _orig_pcall = pcall
local _orig_xpcall = xpcall
local _orig_rawset = rawset
local _orig_table_concat = table.concat
local _orig_string_char = string.char
local _orig_newproxy = newproxy
local _orig_unpack = unpack

rawset = function(t, k, v)
    if type(v) == "string" and #v > 20 then
        _write_capture(v)
    end
    return _orig_rawset(t, k, v)
end

table.concat = function(t, sep, i, j)
    local r = _orig_table_concat(t, sep, i, j)
    if type(r) == "string" and #r > 20 then
        _write_capture(r)
    end
    return r
end

string.char = function(...)
    local r = _orig_string_char(...)
    return r
end

local function _hooked_loadstring(code, name)
    if type(code) == "function" then
        local parts = {}
        while true do
            local ok, p = pcall(code)
            if not ok or not p then break end
            if type(p) == "string" then parts[#parts+1] = p end
            if #parts > 5000 then break end
        end
        code = table.concat(parts)
    end
    if type(code) == "string" and #code > 5 then
        code = _repair_malformed(code)
        _write_layer(code)
    end
    return _orig_loadstring(code, name)
end

loadstring = _hooked_loadstring
load = _hooked_loadstring

local _safe_env = {
    assert = assert,
    error = function(msg, level)
        if msg == "detected by LeakD" then return nil end
        error(msg, level or 0)
    end,
    ipairs = ipairs,
    next = next,
    pairs = pairs,
    pcall = pcall,
    rawequal = rawequal,
    rawget = rawget,
    rawlen = rawlen,
    rawset = rawset,
    select = select,
    setmetatable = setmetatable,
    getmetatable = getmetatable,
    tonumber = tonumber,
    tostring = tostring,
    type = type,
    xpcall = xpcall,
    unpack = _orig_unpack or table.unpack or function(t, i, j) return t[i], t[i+1], t[i+2] end,
    string = {
        byte = string.byte, char = string.char, find = string.find,
        format = string.format, gmatch = string.gmatch, gsub = string.gsub,
        len = string.len, lower = string.lower, match = string.match,
        rep = string.rep, reverse = string.reverse, sub = string.sub,
        upper = string.upper,
    },
    math = {
        abs = math.abs, acos = math.acos, asin = math.asin, atan = math.atan,
        atan2 = math.atan2, ceil = math.ceil, cos = math.cos, cosh = math.cosh,
        deg = math.deg, exp = math.exp, floor = math.floor, fmod = math.fmod,
        frexp = math.frexp, huge = math.huge, ldexp = math.ldexp, log = math.log,
        log10 = math.log10, max = math.max, min = math.min, modf = math.modf,
        pi = math.pi, pow = math.pow, rad = math.rad, random = math.random,
        randomseed = math.randomseed, sin = math.sin, sinh = math.sinh,
        sqrt = math.sqrt, tan = math.tan, tanh = math.tanh,
    },
    table = {
        concat = table.concat, insert = table.insert,
        maxn = function(t) return #t end, remove = table.remove, sort = table.sort,
        unpack = _orig_unpack or function(t, i, j) return t[i], t[i+1], t[i+2] end,
    },
    os = { clock = os.clock, date = os.date, difftime = os.difftime, time = os.time },
    coroutine = {
        create = coroutine.create, resume = coroutine.resume,
        running = coroutine.running, status = coroutine.status,
        wrap = coroutine.wrap, yield = coroutine.yield,
    },
    print = function(...) end,
    warn = function() end,
    getfenv = function(f) return _safe_env end,
    setfenv = function(f, e) return f end,
    newproxy = function(add)
        local u = _orig_newproxy(true)
        if add then
            local mt = getmetatable(u)
            if mt then mt.__gc = function() end end
        end
        return u
    end,
    game = {
        PlaceId = 12345678,
        JobId = "00000000-0000-0000-0000-000000000000",
        GetService = function(self, name) return _safe_env[name] or {} end,
    },
    workspace = {},
    Players = {
        LocalPlayer = {
            Name = "Player", UserId = 1, Character = {},
            PlayerGui = {}, Backpack = {},
        },
        GetPlayers = function() return {} end,
    },
    MarketplaceService = {}, ReplicatedStorage = {},
    ServerStorage = {}, ServerScriptService = {}, Lighting = {},
    StarterGui = {}, StarterPack = {}, SoundService = {},
    HttpService = {
        GetAsync = function() return "" end,
        PostAsync = function() return "" end,
    },
    Enum = {},
}

_safe_env._G = _safe_env
_safe_env._ENV = _safe_env

local _env_mt = {
    __index = function(t, k)
        local v = rawget(_safe_env, k)
        if v ~= nil then return v end
        _L("MISSING: " .. tostring(k))
        return {}
    end,
    __newindex = function(t, k, v)
        rawset(_safe_env, k, v)
    end,
}

local env = setmetatable({}, _env_mt)

local fh = io.open(_inp, "rb")
if not fh then
    _L("OPEN_ERROR")
    _write_file(_out .. "/error.txt", "cannot open input")
else
    local source = fh:read("*a")
    fh:close()
    if not source then
        _L("READ_ERROR")
        _write_file(_out .. "/error.txt", "cannot read input")
    else
        _L("SIZE: " .. #source .. " bytes")
        source = _repair_malformed(source)
        local chunk, parse_err = _orig_loadstring(source, "@input")
        if not chunk then
            _L("PARSE: " .. tostring(parse_err))
            _write_file(_out .. "/error.txt", "parse error: " .. tostring(parse_err))
        else
            setfenv(chunk, env)
            local function error_handler(e)
                local tb = debug.traceback(tostring(e), 2)
                _L("TRACE: " .. tb)
                return tb
            end
            local ok, res = _orig_xpcall(chunk, error_handler)
            if not ok then
                _L("RUNTIME: " .. tostring(res))
                _write_file(_out .. "/error.txt", tostring(res))
            else
                _L("DONE: " .. type(res))
                if res and type(res) == "function" then
                    local ok2, bc = pcall(string.dump, res)
                    if ok2 then
                        _write_file(_out .. "/dump.bin", bc, "wb")
                        _L("DUMPED " .. #bc .. " bytes")
                    end
                elseif res and type(res) == "string" and #res > 5 then
                    _write_layer(res)
                    _L("RETURNED " .. #res .. " bytes")
                end
            end
        end
    end
end

do
    local df = io.open(_out .. "/diag.txt", "w")
    if df then
        df:write(table.concat(_log, "\n"))
        df:close()
    end
end
