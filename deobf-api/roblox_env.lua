local _out = os.getenv("OUTDIR") or "/tmp"
local _lyr = 0
local _seen = {}
local _cap  = {}
local _log  = {}

local function _L(s) table.insert(_log, s) end
local function _capture(v)
    if type(v) == "string" and #v > 10 then
        table.insert(_cap, v)
    end
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

local function _hook_ls(code, name)
    if _ty(code) == "function" then
        local parts = {}
        while true do
            local p = code()
            if not p then break end
            if _ty(p) == "string" then parts[#parts+1] = p end
            if #parts > 5000 then break end
        end
        code = _tc(parts)
    end
    if _ty(code) ~= "string" or #code < 5 then return function() end end
    _capture(code)
    if not _seen[code] then
        _seen[code] = true
        _lyr = _lyr + 1
        _L("LAYER " .. _lyr .. " (" .. #code .. " bytes)")
        local f = io.open(_out .. "/layer_" .. _lyr .. ".lua", "w")
        if f then f:write(code) f:close() end
    end
    local fn, err = _ls(code, name)
    if not fn then
        _L("COMPILE_ERR: " .. _ts(err))
        return function() end
    end
    return fn
end

loadstring = _hook_ls
load       = _hook_ls

string.char = function(...)
    local r = _sc(...)
    _capture(r)
    return r
end

table.concat = function(t, sep, i, j)
    local r = _tc(t, sep, i, j)
    _capture(r)
    return r
end

local function _dummy(name)
    local d = {}
    _sm(d, {
        __index    = function(_, k)
            local child = _dummy(name .. "." .. _ts(k))
            _rs(d, k, child)
            return child
        end,
        __newindex = function(_, k, v) _rs(d, k, v) end,
        __call     = function(_, ...)
            local args = {...}
            for _, v in _ip(args) do
                if _ty(v) == "function" then _pc(v, _dummy("a"), _dummy("b")) end
                _capture(v)
            end
            return _dummy(name .. "()")
        end,
        __tostring = function() return name end,
        __concat   = function(a,b) return _ts(a).._ts(b) end,
        __add      = function(a,b) return _dummy(name.."+") end,
        __sub      = function(a,b) return _dummy(name.."-") end,
        __mul      = function(a,b) return _dummy(name.."*") end,
        __div      = function(a,b) return _dummy(name.."/") end,
        __mod      = function(a,b) return _dummy(name.."%") end,
        __pow      = function(a,b) return _dummy(name.."^") end,
        __unm      = function(a)   return _dummy("-"..name) end,
        __len      = function()    return 1 end,
        __lt       = function(a,b) return false end,
        __le       = function(a,b) return true end,
        __eq       = function(a,b) return false end,
    })
    return d
end

local _env = {}
local _safe = {
    string   = string, math = math, table = table,
    pairs    = _pa, ipairs = _ip, select = _sl, next = _nx,
    tostring = _ts, tonumber = tonumber, type = _ty, typeof = _ty,
    rawget   = _rg, rawset = _rs, rawequal = rawequal, rawlen = rawlen,
    setmetatable = _sm, getmetatable = _gm, unpack = _un,
    pcall    = _pc, xpcall = xpcall, error = error, assert = assert,
    print    = function() end, warn = function() end,
    loadstring = _hook_ls, load = _hook_ls, coroutine = coroutine,
    os       = {
        clock = function() return 0 end,
        time  = function() return 1000000 end,
        date  = function() return "2024-01-01" end,
    },
    tick     = function() return 0 end,
    time     = function() return 0 end,
    wait     = function(n) return n or 0 end,
    spawn    = function(f) if _ty(f)=="function" then _pc(f) end end,
    delay    = function(t,f) if _ty(f)=="function" then _pc(f) end end,
    shared   = {}, _VERSION = "Lua 5.1",
    game     = _dummy("game"),
    workspace = _dummy("workspace"),
    script   = _dummy("script"),
    Instance = {new = function(n) return _dummy("Instance:"..n) end},
    Vector3  = {new = function(...) return _dummy("Vector3") end},
}

_sm(_env, {
    __index = function(_, k)
        if _safe[k] ~= nil then return _safe[k] end
        if k == "getfenv" then return function() return _env end end
        if k == "setfenv" then
            return function(n,t)
                if _ty(t)=="table" then
                    for kk,vv in _pa(t) do _rs(_env, kk, vv) end
                end
                return t
            end
        end
        if k == "_G" or k == "_ENV" then return _env end
        local child = _dummy(k)
        _rs(_env, k, child)
        return child
    end,
    __newindex = function(_, k, v) _rs(_env, k, v) end,
})

function _run(code)
    local chunk, err = _ls(code)
    if not chunk then
        print("COMPILE ERROR: " .. _ts(err))
        return
    end
    setfenv(chunk, _env)
    local ok, res = pcall(chunk)
    if ok then
        print("OK. layers=" .. _lyr)
    else
        print("RUNTIME ERROR: " .. _ts(res))
    end

    local sf = io.open(_out .. "/cap.txt", "w")
    if sf then
        for _, s in _ip(_cap) do
            sf:write(s:gsub("\n", "\\n") .. "\n---SEP---\n")
        end
        sf:close()
    end
end
