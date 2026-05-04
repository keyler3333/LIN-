local _out = "OUTDIR_PLACEHOLDER"
local _inp = "INPATH_PLACEHOLDER"
local _cap, _log, _step = {}, {}, 0

local function _L(s)
    _log[#_log+1] = s
end

debug.sethook(function()
    _step = _step + 1000
    if _step > 10000000 then
        _L("STEP_LIMIT")
        error("__LIMIT__")
    end
end, "", 1000)

local _captured = {}
local function _capture(v)
    if type(v) == "string" and #v > 3 and not _captured[v] then
        _captured[v] = true
        _cap[#_cap+1] = v
    end
end

local _orig_loadstring = loadstring
local _orig_pcall = pcall

local _safe_mt = {
    __index = function(t, k)
        local child = setmetatable({}, _safe_mt)
        rawset(t, k, child)
        return child
    end,
    __call = function() return setmetatable({}, _safe_mt) end,
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
}

local function _safe()
    return setmetatable({}, _safe_mt)
end

local env = setmetatable({}, {
    __index = function(_, k)
        local v = rawget(env, k)
        if v ~= nil then
            return v
        end
        return _safe()
    end
})

for name, func in pairs({
    assert = function(v) return v end,
    error = function() end,
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
    string = {
        byte = string.byte, char = string.char, find = string.find,
        format = string.format, gmatch = string.gmatch, gsub = string.gsub,
        len = string.len, lower = string.lower, match = string.match,
        rep = string.rep, reverse = string.reverse, sub = string.sub,
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
        time = function() return math.random(1680000000, 1710000000) end,
    },
    coroutine = {
        create = coroutine.create, resume = coroutine.resume,
        running = coroutine.running, status = coroutine.status,
        wrap = coroutine.wrap, yield = coroutine.yield,
    },
}) do
    rawset(env, name, func)
end

rawset(env, "_G", env)
rawset(env, "_VERSION", "Luau")
rawset(env, "getfenv", function() return env end)
rawset(env, "setfenv", function(fn, e) return fn end)
rawset(env, "print", function() end)
rawset(env, "warn", function() end)
rawset(env, "loadstring", function(code, name)
    if type(code) == "function" then
        local parts = {}
        while true do
            local p = code()
            if not p then break end
            if type(p) == "string" then parts[#parts+1] = p end
            if #parts > 5000 then break end
        end
        code = table.concat(parts)
    end
    if type(code) == "string" and #code > 5 then
        _capture(code)
        local f = io.open(_out .. "/layer_1.lua", "w")
        if f then f:write(code) f:close() end
        _L("CAPTURED: " .. string.sub(code, 1, 80))
    end
    return _orig_loadstring(code, name)
end)
rawset(env, "load", rawget(env, "loadstring"))

local fh = io.open(_inp, "r")
if not fh then
    local ef = io.open(_out .. "/error.txt", "w")
    if ef then ef:write("cannot open input") ef:close() end
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
    if not ok then
        _L("RUNTIME ERROR: " .. tostring(res))
    else
        if type(res) == "string" then
            _capture(res)
        elseif type(res) == "function" then
            local ok2, bc = _orig_pcall(string.dump, res)
            if ok2 then
                local df = io.open(_out .. "/dump.bin", "wb")
                if df then df:write(bc) df:close() end
            end
        end
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
