local _out = "OUTDIR_PLACEHOLDER"
local _inp = "INPATH_PLACEHOLDER"
local _lyr = 0
local _seen = {}
local _cap = {}
local _log = {}
local _wait_cnt = 0
local _step_cnt = 0
local _max_steps = 2000000

local function _L(s)
    _log[#_log+1] = s
end

local _ls = loadstring
local _lo = load
local _pc = pcall
local _ty = type
local _ts = tostring
local _pa = pairs
local _ip = ipairs
local _sm = setmetatable
local _gm = getmetatable
local _rg = rawget
local _rs = rawset
local _sc = string.char
local _tc = table.concat
local _un = unpack or table.unpack
local _sl = select
local _nx = next
local _er = error
local _as = assert

debug.sethook(function()
    _step_cnt = _step_cnt + 5000
    if _step_cnt > _max_steps then
        _L("STEP_LIMIT_HIT")
        _er("__INSTRUCTION_LIMIT__")
    end
end, "", 5000)

local function _capture(v)
    if _ty(v) == "string" and #v > 3 then
        _cap[#_cap+1] = v
    end
end

rawget = function(t, k)
    local v = _rg(t, k)
    if _ty(v) == "string" and #v > 3 then
        _capture(v)
    end
    return v
end
rawset(_G, "rawget", rawget)

local _orig_ls = _ls
loadstring = function(code, chunkname)
    if _ty(code) == "function" then
        local parts = {}
        while true do
            local p = code()
            if not p then break end
            if _ty(p) == "string" then
                parts[#parts+1] = p
            end
            if #parts > 5000 then
                break
            end
        end
        code = _tc(parts)
    end
    if _ty(code) == "string" and #code > 5 then
        _capture(code)
        if not _seen[code] then
            _seen[code] = true
            _lyr = _lyr + 1
            _L("LAYER " .. _lyr .. " (" .. #code .. " bytes)")
            local f = io.open(_out .. "/layer_" .. _lyr .. ".lua", "w")
            if f then
                f:write(code)
                f:close()
            end
        end
    end
    local fn, err = _orig_ls(code, chunkname)
    if not fn then
        _L("COMPILE_ERR: " .. _ts(err))
        return function() end
    end
    return fn
end
load = loadstring
rawset(_G, "loadstring", loadstring)
rawset(_G, "load", loadstring)

string.char = function(...)
    local r = _sc(...)
    _capture(r)
    return r
end
table.concat = function(t, sep, i, j)
    local r = _tc(t, sep, i, j)
    if #r > 3 then
        _capture(r)
    end
    return r
end

if not bit then
    bit = {}
    bit.bxor = function(a, b)
        local r, p = 0, 1
        while a > 0 or b > 0 do
            if a % 2 ~= b % 2 then r = r + p end
            a = math.floor(a / 2)
            b = math.floor(b / 2)
            p = p * 2
        end
        return r
    end
    bit.band = function(a, b)
        local r, p = 0, 1
        while a > 0 and b > 0 do
            if a % 2 == 1 and b % 2 == 1 then r = r + p end
            a = math.floor(a / 2)
            b = math.floor(b / 2)
            p = p * 2
        end
        return r
    end
    bit.bor = function(a, b)
        local r, p = 0, 1
        while a > 0 or b > 0 do
            if a % 2 == 1 or b % 2 == 1 then r = r + p end
            a = math.floor(a / 2)
            b = math.floor(b / 2)
            p = p * 2
        end
        return r
    end
    bit.bnot = function(a)
        return -a - 1
    end
    bit.rshift = function(a, b)
        return math.floor(a / (2 ^ b))
    end
    bit.lshift = function(a, b)
        return math.floor(a * (2 ^ b))
    end
    bit.arshift = function(a, b)
        return math.floor(a / (2 ^ b))
    end
    bit.btest = function(a, b)
        return bit.band(a, b) ~= 0
    end
    bit.tobit = function(a)
        return a
    end
    bit32 = bit
end

local _dummy_cache = {}
local function _dummy(name)
    if _dummy_cache[name] then
        return _dummy_cache[name]
    end
    local d = {}
    _sm(d, {
        __index = function(_, k)
            local child = _dummy(name .. "." .. _ts(k))
            _rs(d, k, child)
            return child
        end,
        __newindex = function(_, k, v)
            _rs(d, k, v)
        end,
        __call = function(_, ...)
            local args = {...}
            for _, v in _ip(args) do
                if _ty(v) == "function" then
                    _pc(v, _dummy("a"), _dummy("b"))
                end
                _capture(v)
            end
            return _dummy(name .. "()")
        end,
        __tostring = function()
            return name
        end,
        __concat = function(a, b)
            return _ts(a) .. _ts(b)
        end,
        __add = function(a, b)
            return _dummy(name .. "+")
        end,
        __sub = function(a, b)
            return _dummy(name .. "-")
        end,
        __mul = function(a, b)
            return _dummy(name .. "*")
        end,
        __div = function(a, b)
            return _dummy(name .. "/")
        end,
        __mod = function(a, b)
            return _dummy(name .. "%")
        end,
        __pow = function(a, b)
            return _dummy(name .. "^")
        end,
        __unm = function(a)
            return _dummy("-" .. name)
        end,
        __len = function()
            return 1
        end,
        __lt = function(a, b)
            return false
        end,
        __le = function(a, b)
            return true
        end,
        __eq = function(a, b)
            return false
        end,
    })
    _dummy_cache[name] = d
    return d
end

local _newproxy_userdata = {}
local function _newproxy(addMeta)
    local u = {}
    if addMeta then
        _sm(u, {
            __index = function(_, k) return _dummy("userdata." .. _ts(k)) end,
            __newindex = function(_, k, v) _rs(u, k, v) end,
            __gc = function() end,
        })
    end
    return u
end

_env = {}
local _safe = {
    string = string,
    math = math,
    table = table,
    bit = bit,
    bit32 = bit,
    pairs = _pa,
    ipairs = _ip,
    select = _sl,
    next = _nx,
    tostring = _ts,
    tonumber = tonumber,
    type = _ty,
    typeof = _ty,
    rawget = rawget,
    rawset = _rs,
    rawequal = rawequal,
    rawlen = rawlen,
    setmetatable = _sm,
    getmetatable = _gm,
    unpack = _un,
    pcall = _pc,
    xpcall = xpcall,
    error = _er,
    assert = _as,
    print = function() end,
    warn = function() end,
    loadstring = loadstring,
    load = loadstring,
    coroutine = coroutine,
    newproxy = _newproxy,
    debug = {
        traceback = function() return "" end,
        getinfo = function()
            return { short_src = "script.lua", currentline = 0, what = "Lua" }
        end,
        sethook = function() end,
        getupvalue = function() return nil end,
        setupvalue = function() end,
        getmetatable = _gm,
        getregistry = function() return {} end,
    },
    os = {
        clock = function() return 0 end,
        time = function() return 1000000 end,
        date = function() return "2024-01-01" end,
        difftime = function() return 0 end,
    },
    tick = function() return 0 end,
    time = function() return 0 end,
    elapsedtime = function() return 0 end,
    wait = function(n)
        _wait_cnt = _wait_cnt + 1
        if _wait_cnt > 500 then
            _er("__WAIT_LIMIT__")
        end
        return n or 0
    end,
    spawn = function(f)
        if _ty(f) == "function" then
            _pc(f)
        end
    end,
    delay = function(t, f)
        if _ty(f) == "function" then
            _pc(f)
        end
    end,
    task = {
        spawn = function(f)
            if _ty(f) == "function" then
                _pc(f)
            end
        end,
        delay = function(t, f)
            if _ty(f) == "function" then
                _pc(f)
            end
        end,
        wait = function(n)
            return n or 0
        end,
    },
    shared = {},
    _VERSION = "Lua 5.1",
    game = _dummy("game"),
    workspace = _dummy("workspace"),
    script = _dummy("script"),
    Players = _dummy("Players"),
    RunService = _dummy("RunService"),
    UserInputService = _dummy("UserInputService"),
    TweenService = _dummy("TweenService"),
    HttpService = _dummy("HttpService"),
    Instance = {
        new = function(className)
            local inst = _dummy("Instance:" .. className)
            _rs(inst, "IsA", function(self, c) return false end)
            _rs(inst, "Destroy", function(self) end)
            return inst
        end
    },
    Vector3 = { new = function(...) return _dummy("Vector3") end },
    Vector2 = { new = function(...) return _dummy("Vector2") end },
    CFrame = {
        new = function(...) return _dummy("CFrame") end,
        Angles = function(...) return _dummy("CFrame") end
    },
    Color3 = {
        new = function(...) return _dummy("Color3") end,
        fromRGB = function(...) return _dummy("Color3") end
    },
    UDim2 = { new = function(...) return _dummy("UDim2") end },
    Enum = setmetatable({}, { __index = function(t, k) return k end }),
    Drawing = _dummy("Drawing"),
    syn = _dummy("syn"),
    writefile = function() end,
    readfile = function() return "" end,
    isfile = function() return false end,
    isfolder = function() return false end,
    makefolder = function() end,
    listfiles = function() return {} end,
    request = function()
        return { Body = "", StatusCode = 200, Success = true }
    end,
    http = {
        request = function()
            return { Body = "", StatusCode = 200 }
        end
    },
    identifyexecutor = function() return "synapse", "2.0" end,
    getexecutorname = function() return "synapse" end,
    checkcaller = function() return true end,
    isrbxactive = function() return true end,
    hookfunction = function(a, b) return a end,
    newcclosure = function(f) return f end,
    clonefunction = function(f) return f end,
    rconsole = { print = function() end, clear = function() end },
}

_sm(_env, {
    __index = function(_, k)
        _L("ENV_ACCESS: " .. _ts(k))
        if _safe[k] ~= nil then
            return _safe[k]
        end
        if k == "getfenv" then
            return function(n)
                return _env
            end
        end
        if k == "setfenv" then
            return function(n, t)
                if _ty(t) == "table" then
                    for kk, vv in _pa(t) do
                        _rs(_env, kk, vv)
                    end
                end
                return t
            end
        end
        if k == "_G" or k == "_ENV" or k == "shared" then
            return _env
        end
        if k == "getgenv" or k == "getrenv" then
            return function() return _env end
        end
        local child = _dummy(k)
        _rs(_env, k, child)
        return child
    end,
    __newindex = function(_, k, v)
        _rs(_env, k, v)
    end,
})

_rs(_env, "loadstring", loadstring)
_rs(_env, "load", loadstring)
_rs(_env, "getfenv", function(n) return _env end)
_rs(_env, "setfenv", function(n, t)
    if _ty(t) == "table" then
        for k, v in _pa(t) do
            _rs(_env, k, v)
        end
    end
    return t
end)
_rs(_env, "_G", _env)
_rs(_env, "_ENV", _env)
_rs(_env, "shared", _env)
_rs(_env, "string", string)
_rs(_env, "math", math)
_rs(_env, "table", table)
_rs(_env, "bit", bit)
_rs(_env, "bit32", bit)
_rs(_env, "pairs", _pa)
_rs(_env, "ipairs", _ip)
_rs(_env, "select", _sl)
_rs(_env, "next", _nx)
_rs(_env, "tostring", _ts)
_rs(_env, "tonumber", tonumber)
_rs(_env, "type", _ty)
_rs(_env, "rawget", rawget)
_rs(_env, "rawset", _rs)
_rs(_env, "rawequal", rawequal)
_rs(_env, "rawlen", rawlen)
_rs(_env, "setmetatable", _sm)
_rs(_env, "getmetatable", _gm)
_rs(_env, "unpack", _un)
_rs(_env, "pcall", _pc)
_rs(_env, "xpcall", xpcall)
_rs(_env, "error", _er)
_rs(_env, "assert", _as)
_rs(_env, "print", function() end)
_rs(_env, "warn", function() end)
_rs(_env, "newproxy", _newproxy)
_rs(_env, "coroutine", coroutine)
_rs(_env, "debug", _safe.debug)
_rs(_env, "os", _safe.os)
_rs(_env, "tick", _safe.tick)
_rs(_env, "time", _safe.time)
_rs(_env, "wait", _safe.wait)
_rs(_env, "spawn", _safe.spawn)
_rs(_env, "delay", _safe.delay)
_rs(_env, "task", _safe.task)
_rs(_env, "game", _safe.game)
_rs(_env, "workspace", _safe.workspace)
_rs(_env, "script", _safe.script)
_rs(_env, "Players", _safe.Players)
_rs(_env, "Instance", _safe.Instance)
_rs(_env, "Vector3", _safe.Vector3)
_rs(_env, "Vector2", _safe.Vector2)
_rs(_env, "CFrame", _safe.CFrame)
_rs(_env, "Color3", _safe.Color3)
_rs(_env, "UDim2", _safe.UDim2)
_rs(_env, "Enum", _safe.Enum)
_rs(_env, "syn", _safe.syn)
_rs(_env, "Drawing", _safe.Drawing)
_rs(_env, "writefile", _safe.writefile)
_rs(_env, "readfile", _safe.readfile)
_rs(_env, "request", _safe.request)
_rs(_env, "identifyexecutor", _safe.identifyexecutor)
_rs(_env, "checkcaller", _safe.checkcaller)

local function _run()
    local f = io.open(_inp, "r")
    if not f then
        _L("CANNOT_OPEN_INPUT")
        local df = io.open(_out .. "/diag.txt", "w")
        if df then
            df:write(_tc(_log, "\n"))
            df:close()
        end
        return
    end
    local code = f:read("*a")
    f:close()
    _L("Script size: " .. #code .. " bytes")

    code = code:gsub("getfenv%s*%(%)%s*or%s*_ENV", "getfenv()")
    code = code:gsub("getfenv%s*%(%)%s*or%s*_G", "getfenv()")

    local chunk, err = _ls(code)
    if not chunk then
        _L("COMPILE ERROR: " .. _ts(err))
    else
        setfenv(chunk, _env)
        _L("Executing...")
        local ok, res = _pc(chunk)
        if ok then
            _L("OK. layers=" .. _lyr)
            if _ty(res) == "function" then
                local bc = string.dump(res)
                local df = io.open(_out .. "/dump.bin", "wb")
                if df then
                    df:write(bc)
                    df:close()
                    _L("DUMPED_FUNCTION")
                end
            end
        else
            if _ts(res) ~= "__INSTRUCTION_LIMIT__" and _ts(res) ~= "__WAIT_LIMIT__" then
                _L("RUNTIME ERROR: " .. _ts(res))
            end
        end
    end

    local sf = io.open(_out .. "/cap.txt", "w")
    if sf then
        for _, s in _ip(_cap) do
            sf:write(s:gsub("\n", "\\n") .. "\n---SEP---\n")
        end
        sf:close()
    end
    local df = io.open(_out .. "/diag.txt", "w")
    if df then
        df:write(_tc(_log, "\n"))
        df:close()
    end
end

_run()
