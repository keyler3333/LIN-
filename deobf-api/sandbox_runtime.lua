local _out = "OUTDIR_PLACEHOLDER"
local _inp = "INPATH_PLACEHOLDER"
local _cap, _log, _step = {}, {}, 0

local function _L(s) _log[#_log+1] = s end

debug.sethook(function()
    _step = _step + 5000
    if _step > 5000000 then
        _L("STEP_LIMIT")
        error("__LIMIT__")
    end
end, "", 5000)

local _captured = {}
local function _capture(v)
    if type(v) == "string" and #v > 3 and not _captured[v] then
        _captured[v] = true
        _cap[#_cap+1] = v
    end
end

local _orig_loadstring   = loadstring
local _orig_pcall        = pcall
local _orig_rawget       = rawget
local _orig_rawset       = rawset
local _orig_string_char  = string.char
local _orig_table_concat = table.concat
local _orig_type         = type
local _orig_next         = next

rawget = function(t, k)
    local v = _orig_rawget(t, k)
    if _orig_type(v) == "string" and #v > 3 then
        _capture(v)
    end
    return v
end

rawset = function(t, k, v)
    if _orig_type(v) == "string" and #v > 3 then
        _capture(v)
    end
    return _orig_rawset(t, k, v)
end

string.char = function(...)
    local r = _orig_string_char(...)
    _capture(r)
    return r
end

table.concat = function(t, sep, i, j)
    local r = _orig_table_concat(t, sep, i, j)
    if #r > 3 then
        _capture(r)
    end
    return r
end

local function _dummy()
    local d = {}
    setmetatable(d, {
        __index = function(_, k)
            local child = _dummy()
            rawset(d, k, child)
            return child
        end,
        __call = function() return _dummy() end,
        __add = function() return 0 end,
        __sub = function() return 0 end,
        __mul = function() return 0 end,
        __div = function() return 0 end,
        __mod = function() return 0 end,
        __pow = function() return 0 end,
        __unm = function() return 0 end,
        __len = function() return 0 end,
        __lt = function() return false end,
        __le = function() return true end,
        __eq = function() return false end,
        __concat = function(a, b) return tostring(a) .. tostring(b) end,
        __tostring = function() return "0" end,
    })
    return d
end

local env = {
    _G = nil,
    _VERSION = "Luau",
    assert = function(v) return v end,
    error = function() end,
    ipairs = ipairs,
    next = _orig_next,
    pairs = pairs,
    pcall = _orig_pcall,
    rawequal = rawequal,
    rawget = rawget,
    rawlen = rawlen,
    rawset = rawset,
    select = select,
    setmetatable = setmetatable,
    getmetatable = function(obj)
        if _orig_type(obj) == "string" then return nil end
        return getmetatable(obj)
    end,
    tonumber = tonumber,
    tostring = tostring,
    type = _orig_type,
    xpcall = xpcall,
    string = {
        byte = string.byte,
        char = string.char,
        find = string.find,
        format = string.format,
        gmatch = string.gmatch,
        gsub = string.gsub,
        len = string.len,
        lower = string.lower,
        match = string.match,
        rep = string.rep,
        reverse = string.reverse,
        sub = string.sub,
        upper = string.upper,
    },
    math = {
        abs = math.abs, acos = math.acos, asin = math.asin, atan = math.atan,
        ceil = math.ceil, cos = math.cos, cosh = math.cosh, deg = math.deg,
        exp = math.exp, floor = math.floor, fmod = math.fmod, huge = math.huge,
        log = math.log, max = math.max, min = math.min, modf = math.modf,
        pi = math.pi, pow = math.pow, rad = math.rad, random = math.random,
        randomseed = math.randomseed, sin = math.sin, sinh = math.sinh,
        sqrt = math.sqrt, tan = math.tan, tanh = math.tanh,
    },
    table = {
        concat = table.concat, insert = table.insert, maxn = table.maxn,
        remove = table.remove, sort = table.sort,
    },
    os = {
        clock = function() return 0 end,
        date = function() return "2024-01-01" end,
        difftime = function() return 0 end,
        time = function() return 1680000000 + math.random(0, 30000000) end,
    },
    coroutine = {
        create = coroutine.create, resume = coroutine.resume,
        running = coroutine.running, status = coroutine.status,
        wrap = coroutine.wrap, yield = coroutine.yield,
    },
    debug = {
        getinfo = function() return { short_src = "input", currentline = 0, what = "Lua" } end,
        traceback = function() return "" end,
        sethook = function() end,
        getupvalue = function() return nil end,
        setupvalue = function() end,
    },
    getfenv = function() return env end,
    setfenv = function(fn, e) return fn end,
}

env._G = env
setmetatable(env, { __index = function() return _dummy() end })

local fh = io.open(_inp, "r")
if not fh then
    local ef = io.open(_out .. "/error.txt", "w")
    if ef then ef:write("cannot open input: " .. _inp) ef:close() end
    return
end
local source = fh:read("*a")
fh:close()

local chunk, err = _orig_loadstring(source, "@input")
if not chunk then
    local ef = io.open(_out .. "/error.txt", "w")
    if ef then ef:write("parse error: " .. tostring(err)) ef:close() end
else
    setfenv(chunk, env)
    local ok, res = _orig_pcall(chunk)
    if not ok then _L("runtime error: " .. tostring(res)) end
    if ok and _orig_type(res) == "string" then
        _capture(res)
    end
end

local sf = io.open(_out .. "/cap.txt", "w")
if sf then
    for _, s in ipairs(_cap) do
        sf:write(s:gsub("\n", "\\n") .. "\n---SEP---\n")
    end
    sf:close()
end
local df = io.open(_out .. "/diag.txt", "w")
if df then
    df:write(table.concat(_log, "\n"))
    df:close()
end
