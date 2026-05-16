local _out = "OUTDIR_PLACEHOLDER"
local _inp = "INPATH_PLACEHOLDER"
local _log = {}
local _layer_count = 0
local _step_count = 0
local _tracked = {}

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

local function _track_string(v)
    if type(v) == "string" and #v > 3 and not _tracked[v] then
        _tracked[v] = true
        _write_capture(v)
    end
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

rawset = function(t, k, v)
    _track_string(v)
    return _orig_rawset(t, k, v)
end

rawget = function(t, k)
    local v = _orig_rawget(t, k)
    if v ~= nil then return v end
    local mt = getmetatable(t)
    if mt and mt.__index then
        local index = mt.__index
        if _orig_type(index) == "function" then
            return index(t, k)
        elseif _orig_type(index) == "table" then
            return index[k]
        end
    end
    return nil
end

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
        _L("STRING.DUMP captured " .. #bc .. " bytes")
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

getfenv = function(f)
    return _orig_getfenv(f)
end

setfenv = function(f, e)
    if _orig_type(e) == "table" then
        for k, v in _orig_pairs(e) do
            _track_string(v)
        end
    end
    return _orig_setfenv(f, e)
end

local function _make_proxy()
    local data = {}
    local mt = {
        __index = function(t, k)
            local v = _orig_rawget(data, k)
            if v ~= nil then return v end
            v = _make_proxy()
            _orig_rawset(data, k, v)
            return v
        end,
        __call = function(t, ...)
            return t
        end,
        __newindex = function(t, k, v)
            _orig_rawset(data, k, v)
        end,
        __gc = function() end,
        __tostring = function() return "proxy" end,
        __len = function() return 0 end,
        __unm = function() return 0 end,
        __add = function() return 0 end,
        __sub = function() return 0 end,
        __mul = function() return 0 end,
        __div = function() return 0 end,
        __mod = function() return 0 end,
        __pow = function() return 0 end,
        __eq = function(a, b) return a == b end,
        __lt = function() return false end,
        __le = function() return false end,
        __concat = function(a, b) return tostring(a) .. tostring(b) end,
    }
    return setmetatable({}, mt)
end

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
    unpack = _orig_unpack or table.unpack,
    getfenv = getfenv,
    setfenv = setfenv,
    loadstring = loadstring,
    load = load,
    string = {
        byte = string.byte, char = string.char, find = string.find,
        format = string.format, gmatch = string.gmatch, gsub = string.gsub,
        len = string.len, lower = string.lower, match = string.match,
        rep = string.rep, reverse = string.reverse, sub = string.sub,
        upper = string.upper, dump = string.dump,
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
        maxn = function(t)
            local n = 0
            for k in pairs(t) do
                if type(k) == "number" and k > n then n = k end
            end
            return n
        end,
        remove = table.remove, sort = table.sort,
        unpack = _orig_unpack or table.unpack,
    },
    os = { clock = os.clock, date = os.date, difftime = os.difftime, time = os.time },
    coroutine = {
        create = coroutine.create, resume = coroutine.resume,
        running = coroutine.running, status = coroutine.status,
        wrap = coroutine.wrap, yield = coroutine.yield,
    },
    print = function(...) end,
    warn = function() end,
    newproxy = function(add)
        local u = _orig_newproxy(add)
        if add then
            local mt = getmetatable(u)
            if mt then mt.__gc = function() end end
        end
        return u
    end,
    game = _make_proxy(),
    workspace = _make_proxy(),
    Players = _make_proxy(),
    MarketplaceService = _make_proxy(),
    ReplicatedStorage = _make_proxy(),
    ServerStorage = _make_proxy(),
    ServerScriptService = _make_proxy(),
    Lighting = _make_proxy(),
    StarterGui = _make_proxy(),
    StarterPack = _make_proxy(),
    SoundService = _make_proxy(),
    HttpService = _make_proxy(),
    Enum = _make_proxy(),
    shared = _make_proxy(),
    getconnections = _make_proxy(),
    hookfunction = _make_proxy(),
    isscript = _make_proxy(),
}

_safe_env._G = _safe_env
_safe_env._ENV = _safe_env

local _env_mt = {
    __index = function(t, k)
        local v = _orig_rawget(_safe_env, k)
        if v ~= nil then return v end
        _L("MISSING: " .. tostring(k))
        return _make_proxy()
    end,
    __newindex = function(t, k, v)
        _track_string(v)
        _orig_rawset(_safe_env, k, v)
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
        local chunk, parse_err = _orig_loadstring(source, "@input")
        if not chunk then
            _L("PARSE: " .. tostring(parse_err))
            _write_file(_out .. "/error.txt", "parse error: " .. tostring(parse_err))
        else
            _orig_setfenv(chunk, env)
            local function error_handler(e)
                local tb = debug.traceback(_orig_tostring(e), 2)
                _L("TRACE: " .. tb)
                return tb
            end
            local ok, res = _orig_xpcall(chunk, error_handler)
            if not ok then
                _L("RUNTIME: " .. _orig_tostring(res))
                _write_file(_out .. "/error.txt", _orig_tostring(res))
            else
                _L("DONE: " .. _orig_type(res))
                if res and _orig_type(res) == "function" then
                    local ok2, bc = pcall(string.dump, res)
                    if ok2 then
                        _write_file(_out .. "/dump.bin", bc, "wb")
                        _L("DUMPED " .. #bc .. " bytes")
                    end
                elseif res and _orig_type(res) == "string" and #res > 5 then
                    _write_layer(res)
                    _L("RETURNED " .. #res .. " bytes")
                end
                _L("MEMORY_SCAN_START")
                local mem_parts = {}
                local function _scan_table(t, depth, path)
                    if depth > 4 then return end
                    for k, v in _orig_pairs(t) do
                        local full_path = path .. "[" .. _orig_tostring(k) .. "]"
                        if _orig_type(v) == "string" and #v > 5 then
                            _track_string(v)
                            mem_parts[#mem_parts+1] = v
                        elseif _orig_type(v) == "table" then
                            _scan_table(v, depth + 1, full_path)
                        end
                    end
                end
                _scan_table(_safe_env, 0, "_G")
                _scan_table(env, 0, "env")
                if #mem_parts > 0 then
                    local mf = io.open(_out .. "/memory.txt", "w")
                    if mf then
                        for i, s in ipairs(mem_parts) do
                            if i > 1 then mf:write("---MEMSEP---\n") end
                            mf:write(s .. "\n")
                        end
                        mf:close()
                    end
                end
                _L("MEMORY_SCAN_END: " .. #mem_parts .. " strings found")
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
