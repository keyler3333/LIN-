local _out = "OUTDIR_PLACEHOLDER"
local _inp = "INPATH_PLACEHOLDER"
local _layer = 0
local _cap, _log, _step = {}, {}, 0

local function _L(s) _log[#_log+1] = s end

debug.sethook(function()
    _step = _step + 5000
    if _step > 2000000 then
        _L("STEP_LIMIT")
        error("__LIMIT__")
    end
end, "", 5000)

local _seen = {}
local function _capture(v)
    if type(v) == "string" and #v > 3 and not _seen[v] then
        _seen[v] = true
        _cap[#_cap+1] = v
    end
end

local _orig_rawget        = rawget
local _orig_string_char   = string.char
local _orig_string_byte   = string.byte
local _orig_string_rep    = string.rep
local _orig_table_concat  = table.concat
local _orig_loadstring    = loadstring
local _orig_pcall         = pcall
local _orig_xpcall        = xpcall
local _orig_pairs         = pairs
local _orig_ipairs        = ipairs
local _orig_next          = next
local _orig_setmetatable  = setmetatable
local _orig_getmetatable  = getmetatable
local _orig_type          = type

rawget = function(t, k)
    local v = _orig_rawget(t, k)
    if _orig_type(v) == "string" and #v > 3 then _capture(v) end
    return v
end
_G.rawget = rawget

string.char = function(...)
    local r = _orig_string_char(...)
    _capture(r)
    return r
end

string.byte = function(s, ...)
    if _orig_type(s) == "string" and #s > 3 then _capture(s) end
    return _orig_string_byte(s, ...)
end

string.rep = function(s, n, ...)
    if n > 100000 then n = 100000 end
    return _orig_string_rep(s, n, ...)
end

table.concat = function(t, sep, i, j)
    local r = _orig_table_concat(t, sep, i, j)
    if #r > 3 then _capture(r) end
    return r
end

pcall = function(fn, ...)
    if _orig_type(fn) ~= "function" then
        return false, "attempt to call a non-function value"
    end
    local ok, res = _orig_pcall(fn, ...)
    if _orig_type(res) == "string" then _capture(res) end
    return ok, res
end
_G.pcall = pcall

xpcall = function(fn, handler, ...)
    if _orig_type(fn) ~= "function" then return false, nil end
    local ok, res = _orig_xpcall(fn, handler, ...)
    if _orig_type(res) == "string" then _capture(res) end
    return ok, res
end
_G.xpcall = xpcall

getmetatable = function(obj)
    if _orig_type(obj) == "string" then return nil end
    return _orig_getmetatable(obj)
end
_G.getmetatable = getmetatable

setmetatable = function(t, mt)
    local ok, r = _orig_pcall(_orig_setmetatable, t, mt)
    if ok then return r end
    return t
end
_G.setmetatable = setmetatable

pairs = function(t)
    if _orig_type(t) == "table" then
        for k, v in _orig_next, t do
            if _orig_type(k) == "string" then _capture(k) end
            if _orig_type(v) == "string" then _capture(v) end
        end
    end
    return _orig_pairs(t)
end
_G.pairs = pairs

ipairs = function(t)
    if _orig_type(t) == "table" then
        for _, v in _orig_ipairs(t) do
            if _orig_type(v) == "string" then _capture(v) end
        end
    end
    return _orig_ipairs(t)
end
_G.ipairs = ipairs

next = function(t, k)
    local nk, nv = _orig_next(t, k)
    if _orig_type(nk) == "string" then _capture(nk) end
    if _orig_type(nv) == "string" then _capture(nv) end
    return nk, nv
end
_G.next = next

local function _hooked_load(code, name)
    if _orig_type(code) == "function" then
        local parts = {}
        while true do
            local p = code()
            if not p then break end
            if _orig_type(p) == "string" then parts[#parts+1] = p end
            if #parts > 5000 then break end
        end
        code = _orig_table_concat(parts)
    end
    if code == nil then return nil, "attempt to load nil" end
    if _orig_type(code) == "string" and #code > 5 then
        _capture(code)
        _layer = _layer + 1
        local f = io.open(_out .. "/layer_" .. _layer .. ".lua", "w")
        if f then f:write(code); f:close() end
        _L("layer " .. _layer .. " captured (" .. #code .. " bytes)")
    end
    return _orig_loadstring(code, name)
end

_G.loadstring = _hooked_load
_G.load       = _hooked_load

local _fenv_store = {}
setmetatable(_fenv_store, {__mode = "k"})

local _orig_getfenv = getfenv
local _orig_setfenv = setfenv

getfenv = function(fn)
    if _orig_type(fn) == "function" and _fenv_store[fn] then
        return _fenv_store[fn]
    end
    return _orig_getfenv(fn or 1)
end
_G.getfenv = getfenv

setfenv = function(fn, env)
    if _orig_type(fn) == "function" then
        _fenv_store[fn] = env
    end
    return _orig_setfenv(fn, env)
end
_G.setfenv = setfenv

local _G_real = _G
local _G_proxy = _orig_setmetatable({}, {
    __index    = _G_real,
    __newindex = function(_, k, v)
        if _orig_type(v) == "string" and #v > 3 then _capture(v) end
        rawset(_G_real, k, v)
    end,
})

local function _noop(...)  return end
local function _retnil(...) return nil end
local function _rettrue(...) return true end
local function _retfalse(...) return false end
local function _retrand(...) return math.random() * 0.9 + 0.1 end

local function _inst(class)
    local t = {ClassName = class or "Instance"}
    return _orig_setmetatable(t, {
        __index = function(self, k)
            if k == "FindFirstChild" or k == "FindFirstChildWhichIsA"
               or k == "FindFirstChildOfClass" then
                return function() return nil end
            end
            if k == "IsA" then return function(_, cls) return cls == (class or "Instance") end end
            if k == "GetFullName" then return function() return "Game." .. (class or "Instance") end end
            if k == "ClearAllChildren" or k == "Shutdown" or k == "Destroy" then
                return _noop
            end
            if k == "Connect" or k == "connect" then
                return function(_, fn)
                    return {Disconnect = _noop, disconnect = _noop}
                end
            end
            return _inst(k)
        end,
        __tostring = function() return class or "Instance" end,
        __call    = _retnil,
    })
end

local _game = _inst("DataModel")
rawset(_game, "PlaceVersion", math.random(1, 500))
rawset(_game, "PostAsync",    function(_, url, data) return "{}" end)
rawset(_game, "GetFullName",  function() return "Game" end)
rawset(_game, "GameObjects",  function() return {} end)

local _rs_callbacks = {}
local _RunService = _orig_setmetatable({}, {
    __index = function(_, k)
        if k == "Heartbeat" or k == "RenderStepped" or k == "Stepped" then
            return {
                Connect = function(_, fn)
                    if _orig_type(fn) == "function" then
                        _rs_callbacks[#_rs_callbacks+1] = fn
                    end
                    return {Disconnect = _noop}
                end,
                Wait = function() return _retrand() end,
            }
        end
        return _noop
    end
})
for _tick = 1, 3 do
    local dt = _retrand() * 0.033
    for _, fn in _orig_ipairs(_rs_callbacks) do
        _orig_pcall(fn, dt)
    end
end

local _WebSocket = {
    connect = function(url)
        return {
            Send         = _noop,
            Close        = _noop,
            OnMessage    = {Connect = function(_, fn) return {Disconnect=_noop} end},
            OnClose      = {Connect = function(_, fn) return {Disconnect=_noop} end},
        }
    end
}

local _orig_debug = debug
local _debug_stub = _orig_setmetatable({}, {
    __index = function(_, k)
        if k == "info" then
            return function(lvl, opts)
                local res = {}
                for c in tostring(opts):gmatch(".") do
                    if c == "s" then res[#res+1] = "input" end
                    if c == "l" then res[#res+1] = 0 end
                    if c == "n" then res[#res+1] = "?" end
                end
                return table.unpack(res)
            end
        end
        return _orig_debug[k]
    end
})
_G.debug = _debug_stub

local _orig_assert = assert
assert = function(v, msg, ...)
    if not v then
        _L("assert failed: " .. tostring(msg or "assertion failed"))
        return
    end
    return v, msg, ...
end
_G.assert = assert

require = function(mod)
    _L("require called: " .. tostring(mod))
    return _orig_setmetatable({}, {__call = function() return nil end, __index = function() return _noop end})
end
_G.require = require

local function _fire_stub(name)
    return function(obj, ...)
        _L(name .. " called")
        _capture(tostring(obj))
    end
end

local _stubs = {
    getgenv         = function() return _G end,
    getrenv         = function() return _G end,
    getsenv         = function() return _G end,
    gettenv         = function() return _G end,
    getgc           = function() return {} end,
    setidentity     = _noop,
    getidentity     = function() return 8 end,
    setreadonly     = _noop,
    isreadonly      = _retfalse,
    cloneref        = function(v) return v end,
    checkcaller     = _retfalse,
    islclosure      = _rettrue,
    iscclosure      = _retfalse,
    hookfunction    = function(a, b) return a end,
    getcustomasset  = function(p) return "rbxasset://" .. tostring(p) end,
    tick            = _retrand,
    wait            = _noop,
    delay           = _noop,
    ["task.wait"]   = _noop,
    ["task.defer"]  = _noop,
    ["task.spawn"]  = function(fn, ...) if _orig_type(fn)=="function" then _orig_pcall(fn, ...) end end,
    spawn           = function(fn, ...) if _orig_type(fn)=="function" then _orig_pcall(fn, ...) end end,
    game            = _game,
    workspace       = _inst("Workspace"),
    RunService      = _RunService,
    WebSocket       = _WebSocket,
    version         = function() return "0.600.0.6650407" end,
    warn            = print,
    _g              = _G,
    arg             = nil,
    fireclickdetector    = _fire_stub("fireclickdetector"),
    firesignal           = _fire_stub("firesignal"),
    fireproximityprompt  = _fire_stub("fireproximityprompt"),
    firetouchinterest    = _fire_stub("firetouchinterest"),
}

os.time  = function() return math.random(1680000000, 1710000000) end
os.clock = _retrand

for k, v in _orig_pairs(_stubs) do
    if rawget(_G, k) == nil then
        rawset(_G, k, v)
    end
end

local fh = io.open(_inp, "r")
if not fh then
    local ef = io.open(_out .. "/error.txt", "w")
    if ef then ef:write("cannot open input: " .. _inp); ef:close() end
    return
end
local source_code = fh:read("*a")
fh:close()

local chunk, err = _orig_loadstring(source_code, "@input")
if not chunk then
    local ef = io.open(_out .. "/error.txt", "w")
    if ef then ef:write("parse error: " .. tostring(err)); ef:close() end
else
    local env = _orig_setmetatable({}, {__index = _G})
    rawset(env, "loadstring", _hooked_load)
    rawset(env, "load",       _hooked_load)
    local ok, res = _orig_pcall(_orig_setfenv(chunk, env))
    if not ok then _L("runtime error: " .. tostring(res)) end
    if ok and _orig_type(res) == "function" then
        local ok2, bc = _orig_pcall(string.dump, res)
        if ok2 then
            local df = io.open(_out .. "/dump.bin", "wb")
            if df then df:write(bc); df:close() end
        end
    end
end

local sf = io.open(_out .. "/cap.txt", "w")
if sf then
    for _, s in _orig_ipairs(_cap) do
        sf:write(s:gsub("\n", "\\n") .. "\n---SEP---\n")
    end
    sf:close()
end

local df = io.open(_out .. "/diag.txt", "w")
if df then
    df:write(_orig_table_concat(_log, "\n"))
    df:close()
end
