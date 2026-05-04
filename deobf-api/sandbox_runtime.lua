local _out = "OUTDIR_PLACEHOLDER"
local _inp = "INPATH_PLACEHOLDER"
local _cap, _log, _step = {}, {}, 0

local function _L(s)
    _log[#_log+1] = s
end

debug.sethook(function()
    _step = _step + 1000
    if _step > 30000000 then
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
local _orig_rawget = rawget
local _orig_rawset = rawset

rawget = function(t, k)
    if type(t) ~= "table" then
        return nil
    end
    return _orig_rawget(t, k)
end

rawset = function(t, k, v)
    if type(t) ~= "table" then
        return t
    end
    return _orig_rawset(t, k, v)
end

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

local function _safe_library(lib)
    local t = {}
    for k, v in pairs(lib) do
        t[k] = v
    end
    return setmetatable(t, {
        __index = function(_, k)
            return _safe()
        end,
    })
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

rawset(env, "_G", env)
rawset(env, "_VERSION", "Luau")
rawset(env, "assert", function(v) return v end)
rawset(env, "error", function() end)
rawset(env, "ipairs", ipairs)
rawset(env, "next", next)
rawset(env, "pairs", pairs)
rawset(env, "pcall", pcall)
rawset(env, "rawequal", rawequal)
rawset(env, "rawget", rawget)
rawset(env, "rawlen", rawlen)
rawset(env, "rawset", rawset)
rawset(env, "select", select)
rawset(env, "setmetatable", setmetatable)
rawset(env, "getmetatable", getmetatable)
rawset(env, "tonumber", tonumber)
rawset(env, "tostring", tostring)
rawset(env, "type", type)
rawset(env, "xpcall", xpcall)
rawset(env, "string", _safe_library(string))
rawset(env, "math", _safe_library(math))
rawset(env, "table", _safe_library(table))
rawset(env, "os", _safe_library(os))
rawset(env, "coroutine", _safe_library(coroutine))
rawset(env, "debug", _safe_library(debug))
rawset(env, "getfenv", function() return env end)
rawset(env, "setfenv", function(fn, e) return fn end)
rawset(env, "print", function() end)
rawset(env, "warn", function() end)
rawset(env, "newproxy", function(add)
    local u = {}
    if add then
        setmetatable(u, {})
    end
    return u
end)
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
        _L("CAPTURED " .. #code .. " bytes")
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
                _L("DUMPED")
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
