local _out = "OUTDIR_PLACEHOLDER"
local _inp = "INPATH_PLACEHOLDER"
local _layer = 0
local _cap, _log, _step = {}, {}, 0

local function _L(s) _log[#_log+1] = tostring(s) end

debug.sethook(function()
    _step = _step + 5000
    if _step > 16000000 then
        _L("STEP_LIMIT_REACHED at " .. _step)
        error("__LIMIT__")
    end
end, "", 5000)

local function _capture(v)
    if type(v) == "string" and #v > 3 then
        _cap[#_cap+1] = v
    end
end

local _orig_rawget        = rawget
local _orig_rawset        = rawset
local _orig_string_char   = string.char
local _orig_string_byte   = string.byte
local _orig_string_rep    = string.rep
local _orig_string_sub    = string.sub
local _orig_string_len    = string.len
local _orig_string_find   = string.find
local _orig_string_format = string.format
local _orig_table_concat  = table.concat
local _orig_table_insert  = table.insert
local _orig_table_remove  = table.remove
local _orig_loadstring    = loadstring
local _orig_pcall         = pcall
local _orig_xpcall        = xpcall
local _orig_pairs         = pairs
local _orig_ipairs        = ipairs
local _orig_next          = next
local _orig_select        = select
local _orig_unpack        = unpack
local _orig_setmetatable  = setmetatable
local _orig_getmetatable  = getmetatable
local _orig_type          = type
local _orig_tostring      = tostring
local _orig_tonumber      = tonumber
local _orig_getfenv       = getfenv
local _orig_setfenv       = setfenv
local _orig_io_open       = io.open

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
    local ok, r = _orig_pcall(_orig_table_concat, t, sep, i, j)
    if not ok then return "" end
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
    local mt = _orig_getmetatable(obj)
    if mt and _orig_rawget(mt, "__metatable") ~= nil then
        return _orig_rawget(mt, "__metatable")
    end
    return mt
end
_G.getmetatable = getmetatable

setmetatable = function(t, mt)
    if _orig_type(t) ~= "table" then return t end
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
        local f = _orig_io_open(_out .. "/layer_" .. _layer .. ".lua", "w")
        if f then f:write(code); f:close() end
        _L("layer " .. _layer .. " captured (" .. #code .. " bytes)")
    end
    return _orig_loadstring(code, name)
end
_G.loadstring = _hooked_load
_G.load       = _hooked_load

local _fenv_store = setmetatable({}, {__mode = "k"})

getfenv = function(fn)
    if _orig_type(fn) == "function" and _fenv_store[fn] then
        return _fenv_store[fn]
    end
    local ok, r = _orig_pcall(_orig_getfenv, fn or 1)
    if ok then return r end
    return _G
end
_G.getfenv = getfenv

setfenv = function(fn, env)
    if _orig_type(fn) == "function" then
        _fenv_store[fn] = env
    end
    local ok, r = _orig_pcall(_orig_setfenv, fn, env)
    if ok then return r end
    return fn
end
_G.setfenv = setfenv

local function _noop(...) return end
local function _retnil(...) return nil end
local function _rettrue(...) return true end
local function _retfalse(...) return false end
local function _retrand(...) return math.random() * 0.9 + 0.1 end

-- newproxy: Lua 5.1 only, may not exist in all builds
if not newproxy then
    newproxy = function(has_mt)
        if has_mt then
            return _orig_setmetatable({}, {})
        end
        return {}
    end
end
_G.newproxy = newproxy

-- unpack: must be the real one
if not unpack then unpack = table.unpack end
_G.unpack = unpack

local function _inst(class)
    local t = {ClassName = class or "Instance"}
    return _orig_setmetatable(t, {
        __index = function(self, k)
            if k == "FindFirstChild" or k == "FindFirstChildWhichIsA" or k == "FindFirstChildOfClass" then
                return function() return nil end
            end
            if k == "IsA" then return function(_, cls) return cls == (class or "Instance") end end
            if k == "GetFullName" then return function() return "Game." .. (class or "Instance") end end
            if k == "ClearAllChildren" or k == "Shutdown" or k == "Destroy" then return _noop end
            if k == "Connect" or k == "connect" then
                return function(_, fn) return {Disconnect = _noop, disconnect = _noop} end
            end
            if k == "GetChildren" or k == "GetDescendants" then return function() return {} end end
            return _inst(k)
        end,
        __tostring = function() return class or "Instance" end,
        __call = _retnil,
    })
end

local _game = _inst("DataModel")
_orig_rawset(_game, "PlaceVersion", math.random(1, 500))
_orig_rawset(_game, "PostAsync", function(_, url, data) return "{}" end)
_orig_rawset(_game, "GetFullName", function() return "Game" end)
_orig_rawset(_game, "GameObjects", function() return {} end)
_orig_rawset(_game, "GetService", function(_, svc) return _inst(svc) end)
_orig_rawset(_game, "FindService", function(_, svc) return _inst(svc) end)

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
                Wait = _retrand,
            }
        end
        if k == "IsClient" then return _rettrue end
        if k == "IsServer" then return _retfalse end
        if k == "IsStudio" then return _retfalse end
        return _noop
    end
})

for _tick = 1, 3 do
    local dt = math.random() * 0.033
    for _, fn in _orig_ipairs(_rs_callbacks) do
        _orig_pcall(fn, dt)
    end
end

local _orig_debug = debug
local _debug_stub = _orig_setmetatable({}, {
    __index = function(_, k)
        if k == "info" then
            return function(lvl, opts)
                local res = {}
                for c in _orig_tostring(opts):gmatch(".") do
                    if c == "s" then res[#res+1] = "input" end
                    if c == "l" then res[#res+1] = 0 end
                    if c == "n" then res[#res+1] = "?" end
                end
                return _orig_unpack(res)
            end
        end
        if k == "sethook" then return _noop end
        return _orig_debug[k]
    end
})
_G.debug = _debug_stub

assert = function(v, msg, ...)
    if not v then
        _L("assert_failed: " .. _orig_tostring(msg or "assertion failed"))
        return
    end
    return v, msg, ...
end
_G.assert = assert

require = function(mod)
    _L("require: " .. _orig_tostring(mod))
    return _orig_setmetatable({}, {
        __call  = function() return nil end,
        __index = function() return _noop end,
    })
end
_G.require = require

os.time  = function() return math.random(1680000000, 1710000000) end
os.clock = _retrand

local function _fire_stub(name)
    return function(obj, ...)
        _L(name .. " called")
        _capture(_orig_tostring(obj))
    end
end

local _WebSocket = {
    connect = function(url)
        _L("WebSocket.connect: " .. _orig_tostring(url))
        return {
            Send = _noop, Close = _noop,
            OnMessage = {Connect = function(_, fn) return {Disconnect = _noop} end},
            OnClose   = {Connect = function(_, fn) return {Disconnect = _noop} end},
        }
    end
}

local _stubs = {
    game                  = _game,
    workspace             = _inst("Workspace"),
    RunService            = _RunService,
    WebSocket             = _WebSocket,
    getgenv               = function() return _G end,
    getrenv               = function() return _G end,
    getsenv               = function() return _G end,
    gettenv               = function() return _G end,
    getgc                 = function() return {} end,
    setidentity           = _noop,
    getidentity           = function() return 8 end,
    setthreadidentity     = _noop,
    getthreadidentity     = function() return 8 end,
    setreadonly           = _noop,
    isreadonly            = _retfalse,
    makereadonly          = function(t) return t end,
    makewriteable         = function(t) return t end,
    cloneref              = function(v) return v end,
    checkcaller           = _retfalse,
    islclosure            = _rettrue,
    iscclosure            = _retfalse,
    hookfunction          = function(a, b) return a end,
    newcclosure           = function(f) return f end,
    getcustomasset        = function(p) return "rbxasset://" .. _orig_tostring(p) end,
    getrawmetatable       = _orig_getmetatable,
    setrawmetatable       = _orig_setmetatable,
    identifyexecutor      = function() return "Executor", "1.0" end,
    getexecutorname       = function() return "Executor" end,
    isluau                = _rettrue,
    tick                  = _retrand,
    wait                  = function(t) return t or 0.03 end,
    delay                 = function(t, fn) if _orig_type(fn) == "function" then _orig_pcall(fn) end end,
    spawn                 = function(fn) if _orig_type(fn) == "function" then _orig_pcall(fn) end end,
    task                  = {
        spawn   = function(fn, ...) if _orig_type(fn) == "function" then _orig_pcall(fn, ...) end end,
        defer   = function(fn, ...) if _orig_type(fn) == "function" then _orig_pcall(fn, ...) end end,
        wait    = function(t) return t or 0.03 end,
        delay   = function(t, fn) if _orig_type(fn) == "function" then _orig_pcall(fn) end end,
        cancel  = _noop,
    },
    version               = function() return "0.600.0.6650407" end,
    warn                  = function(...) _L("warn: " .. _orig_table_concat({...}, "\t")) end,
    _g                    = _G,
    arg                   = nil,
    KRNL_LOADED           = true,
    SENTINEL_V2           = true,
    syn                   = _orig_setmetatable({}, {__index = function() return _noop end}),
    fluxus                = _orig_setmetatable({}, {__index = function() return _noop end}),
    fireclickdetector     = _fire_stub("fireclickdetector"),
    firesignal            = _fire_stub("firesignal"),
    fireproximityprompt   = _fire_stub("fireproximityprompt"),
    firetouchinterest     = _fire_stub("firetouchinterest"),
    Vector3               = {new = function(x,y,z) return {X=x or 0,Y=y or 0,Z=z or 0} end, zero = {X=0,Y=0,Z=0}},
    Vector2               = {new = function(x,y) return {X=x or 0,Y=y or 0} end},
    CFrame                = {new = function(...) return {} end, Angles = function(...) return {} end, identity = {}},
    Color3                = {new = function(r,g,b) return {R=r or 0,G=g or 0,B=b or 0} end, fromRGB = function(r,g,b) return {R=(r or 0)/255,G=(g or 0)/255,B=(b or 0)/255} end},
    UDim2                 = {new = function(xs,xo,ys,yo) return {X={Scale=xs,Offset=xo},Y={Scale=ys,Offset=yo}} end, fromScale = function(x,y) return {X={Scale=x,Offset=0},Y={Scale=y,Offset=0}} end},
    UDim                  = {new = function(s,o) return {Scale=s,Offset=o} end},
    BrickColor            = {new = function(n) return {Name=n or "Medium stone grey"} end, Random = function() return {Name="Bright red"} end},
    TweenInfo             = {new = function(t,...) return {Time=t or 1} end},
    Instance              = {new = function(cn, parent) return _inst(cn) end},
    Enum                  = _orig_setmetatable({}, {__index = function(_, k)
        return _orig_setmetatable({}, {__index = function(_, v) return {Name=v, Value=0} end})
    end}),
    typeof                = function(v)
        local t = _orig_type(v)
        if t == "table" and v.ClassName then return "Instance" end
        return t
    end,
    printidentity         = function() end,
    Drawing               = _orig_setmetatable({}, {__index = function() return function() return {Remove=_noop} end end}),
    HttpGet               = function(_, url) _L("HttpGet:" .. _orig_tostring(url)); return "" end,
    HttpPost              = function(_, url) _L("HttpPost:" .. _orig_tostring(url)); return "" end,
    select                = _orig_select,
    unpack                = _orig_unpack,
    newproxy              = newproxy,
}

for k, v in _orig_pairs(_stubs) do
    if _orig_rawget(_G, k) == nil then
        _orig_rawset(_G, k, v)
    end
end

local fh = _orig_io_open(_inp, "r")
if not fh then
    local ef = _orig_io_open(_out .. "/error.txt", "w")
    if ef then ef:write("cannot open input: " .. _inp); ef:close() end
    return
end
local source_code = fh:read("*a")
fh:close()

local chunk, err = _orig_loadstring(source_code, "@input")
if not chunk then
    local ef = _orig_io_open(_out .. "/error.txt", "w")
    if ef then ef:write("parse error: " .. _orig_tostring(err)); ef:close() end
else
    local env = _orig_setmetatable({}, {
        __index    = _G,
        __newindex = function(t, k, v) _orig_rawset(_G, k, v) end,
    })
    _orig_rawset(env, "loadstring", _hooked_load)
    _orig_rawset(env, "load",       _hooked_load)
    _orig_rawset(env, "select",     _orig_select)
    _orig_rawset(env, "unpack",     _orig_unpack)
    _orig_rawset(env, "newproxy",   newproxy)
    local ok, res = _orig_pcall(_orig_setfenv(chunk, env))
    if not ok then
        _L("runtime_error: " .. _orig_tostring(res))
        local ef = _orig_io_open(_out .. "/error.txt", "w")
        if ef then ef:write(_orig_tostring(res)); ef:close() end
    end
    if ok and _orig_type(res) == "function" then
        local ok2, bc = _orig_pcall(string.dump, res)
        if ok2 then
            local df = _orig_io_open(_out .. "/dump.bin", "wb")
            if df then df:write(bc); df:close() end
        end
    end
end

local sf = _orig_io_open(_out .. "/cap.txt", "w")
if sf then
    for _, s in _orig_ipairs(_cap) do
        sf:write(s:gsub("\n", "\\n") .. "\n---SEP---\n")
    end
    sf:close()
end

local df = _orig_io_open(_out .. "/diag.txt", "w")
if df then
    df:write(_orig_table_concat(_log, "\n"))
    df:close()
end
