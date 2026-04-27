local _orig_loadstring = loadstring
local _orig_load       = load
local _orig_char       = string.char
local _orig_concat     = table.concat
local _orig_type       = type
local _orig_tostring   = tostring
local _orig_pairs      = pairs
local _orig_ipairs     = ipairs
local _orig_setmt      = setmetatable
local _orig_getmt      = getmetatable
local _orig_rawset     = rawset
local _orig_rawget     = rawget
local _orig_pcall      = pcall
local _orig_xpcall     = xpcall
local _orig_select     = select
local _orig_unpack     = unpack or table.unpack

local _layer       = 0
local _MAX_LAYERS  = 8
local _line_count  = 0
local _MAX_LINES   = 200000
local _running     = false
local _start_time  = os.time()
local _TIME_LIMIT  = 5
local _outdir      = os.getenv("OUTDIR") or "."
local _captured_strings = {}
local _string_bytes = 0
local _MAX_STRING_BYTES = 1000000
local _char_buffer = ""
local _seen_layers = {}
local _table_growth = 0
local _MAX_TABLE_GROWTH = 5000

debug.sethook(function(event, line)
    if _running then
        _line_count = _line_count + 1
        if _line_count > _MAX_LINES then
            error("__LOOP_LIMIT__", 2)
        end
        if os.time() - _start_time > _TIME_LIMIT then
            error("__TIME_LIMIT__", 2)
        end
    end
end, "l")

local function capture_string(s)
    if _orig_type(s) == "string" and #s > 4 and #s < 100000 and _string_bytes < _MAX_STRING_BYTES then
        _captured_strings[#_captured_strings + 1] = s
        _string_bytes = _string_bytes + #s
    end
end

local function hook_load(code, chunkname, ...)
    if _layer >= _MAX_LAYERS then
        return function() end
    end
    if _orig_type(code) == "function" then
        local chunks = {}
        local reader = code
        while true do
            local part = reader()
            if not part then break end
            if _orig_type(part) == "string" then
                chunks[#chunks + 1] = part
            end
            if #chunks > 1000 then break end
        end
        code = table.concat(chunks)
    end
    if _orig_type(code) ~= "string" or #code < 5 then
        return function() end
    end
    capture_string(code)
    if not _seen_layers[code] then
        _seen_layers[code] = true
        _layer = _layer + 1
        local f = io.open(_outdir .. "/layer_" .. _layer .. ".lua", "w")
        if f then f:write(code) f:close() end
    end
    local chunk, err = _orig_loadstring(code)
    if chunk then
        setfenv(chunk, _env)
        return function(...) return chunk(...) end
    end
    return function() end
end

loadstring = hook_load
load       = hook_load

string.char = function(...)
    local result = _orig_char(...)
    _char_buffer = _char_buffer .. result
    if #_char_buffer >= 16 then
        capture_string(_char_buffer)
        _char_buffer = ""
    elseif #result <= 4 then
        capture_string(result)
    end
    return result
end

table.concat = function(t, sep, i, j)
    local result = _orig_concat(t, sep, i, j)
    capture_string(result)
    return result
end

local orig_table_insert = table.insert
table.insert = function(t, ...)
    _table_growth = _table_growth + 1
    if _table_growth > _MAX_TABLE_GROWTH then
        error("__TABLE_LIMIT__", 2)
    end
    return orig_table_insert(t, ...)
end

if not bit then
    bit = {}
    bit.bxor = function(a,b)
        local r,p = 0,1
        while a>0 or b>0 do
            if a%2~=b%2 then r=r+p end
            a=math.floor(a/2); b=math.floor(b/2); p=p*2
        end
        return r
    end
    bit.band = function(a,b)
        local r,p = 0,1
        while a>0 and b>0 do
            if a%2==1 and b%2==1 then r=r+p end
            a=math.floor(a/2); b=math.floor(b/2); p=p*2
        end
        return r
    end
    bit.bor = function(a,b)
        local r,p = 0,1
        while a>0 or b>0 do
            if a%2==1 or b%2==1 then r=r+p end
            a=math.floor(a/2); b=math.floor(b/2); p=p*2
        end
        return r
    end
    bit.bnot   = function(a) return -a-1 end
    bit.rshift = function(a,b) return math.floor(a/(2^b)) end
    bit.lshift = function(a,b) return math.floor(a*(2^b)) end
    bit.arshift= function(a,b) return math.floor(a/(2^b)) end
    bit.btest  = function(a,b) return bit.band(a,b)~=0 end
    bit.tobit  = function(a) return a end
    bit.tohex  = function(a) return string.format("%x",a) end
    bit32 = bit
end

local function create_dummy(name)
    local d = {}
    _orig_setmt(d, {
        __is_dummy  = true,
        __index     = function(_, k)
            return create_dummy(_orig_tostring(name) .. "." .. _orig_tostring(k))
        end,
        __newindex  = function(_, k, v) end,
        __call      = function(_, ...)
            local args = {...}
            for _, v in _orig_ipairs(args) do
                if _orig_type(v) == "function" then
                    _orig_pcall(v, create_dummy("cb1"), create_dummy("cb2"))
                end
            end
            return create_dummy(_orig_tostring(name) .. "()")
        end,
        __tostring  = function() return _orig_tostring(name) end,
        __concat    = function(a,b) return _orig_tostring(a) .. _orig_tostring(b) end,
        __add       = function(a,b) return create_dummy(_orig_tostring(a).."+") end,
        __sub       = function(a,b) return create_dummy(_orig_tostring(a).."-") end,
        __mul       = function(a,b) return create_dummy(_orig_tostring(a).."*") end,
        __div       = function(a,b) return create_dummy(_orig_tostring(a).."/") end,
        __mod       = function(a,b) return create_dummy(_orig_tostring(a).."%") end,
        __pow       = function(a,b) return create_dummy(_orig_tostring(a).."^") end,
        __unm       = function(a)   return create_dummy("-".._orig_tostring(a)) end,
        __len       = function(a)   return 0 end,
        __lt        = function(a,b) return false end,
        __le        = function(a,b) return true end,
        __eq        = function(a,b) return _orig_tostring(a) == _orig_tostring(b) end,
    })
    return d
end

_env = {}

local _safe = {
    string=string, math=math, table=table,
    bit=bit, bit32=bit32,
    pairs=_orig_pairs, ipairs=_orig_ipairs,
    select=_orig_select, next=next,
    tostring=_orig_tostring, tonumber=tonumber,
    type=_orig_type, typeof=_orig_type,
    rawget=_orig_rawget, rawset=_orig_rawset,
    rawequal=rawequal, rawlen=rawlen,
    setmetatable=_orig_setmt, getmetatable=_orig_getmt,
    unpack=_orig_unpack,
    pcall=_orig_pcall, xpcall=_orig_xpcall,
    error=error, assert=assert,
    print=function() end,
    warn=function() end,
    loadstring=hook_load, load=hook_load,
    coroutine={
        create=function(f) return f end,
        resume=function(f,...) return _orig_pcall(f,...) end,
        yield=function(...) return ... end,
        wrap=function(f) return f end,
        status=function() return "dead" end,
        running=function() return nil end,
    },
    debug={
        traceback     = function() return "" end,
        getinfo       = function() return {short_src="script.lua", currentline=0, what="Lua"} end,
        sethook       = function() end,
        getupvalue    = function() return nil end,
        setupvalue    = function() end,
        getmetatable  = _orig_getmt,
        getregistry   = function() return {} end,
        getlocal      = function() return nil, 0 end,
        setlocal      = function() end,
    },
    game             = create_dummy("game"),
    workspace        = create_dummy("workspace"),
    script           = create_dummy("script"),
    Players          = create_dummy("Players"),
    RunService       = create_dummy("RunService"),
    UserInputService = create_dummy("UserInputService"),
    TweenService     = create_dummy("TweenService"),
    HttpService      = create_dummy("HttpService"),
    Instance         = create_dummy("Instance"),
    Vector3          = create_dummy("Vector3"),
    Vector2          = create_dummy("Vector2"),
    CFrame           = create_dummy("CFrame"),
    Color3           = create_dummy("Color3"),
    UDim2            = create_dummy("UDim2"),
    Enum             = create_dummy("Enum"),
    Drawing          = create_dummy("Drawing"),
    syn              = create_dummy("syn"),
    writefile        = function() end,
    readfile         = function() return "" end,
    isfile           = function() return false end,
    isfolder         = function() return false end,
    makefolder       = function() end,
    listfiles        = function() return {} end,
    request          = function() return {Body="",StatusCode=200,Success=true} end,
    http             = {request=function() return {Body="",StatusCode=200} end},
    identifyexecutor = function() return "synapse","2.0" end,
    getexecutorname  = function() return "synapse" end,
    checkcaller      = function() return true end,
    isrbxactive      = function() return true end,
    hookfunction     = function(a,b) return a end,
    newcclosure      = function(f) return f end,
    clonefunction    = function(f) return f end,
    tick             = function() return 0 end,
    time             = function() return 0 end,
    elapsedtime      = function() return 0 end,
    wait             = function(n) return n or 0 end,
    spawn            = function(f) if _orig_type(f)=="function" then _orig_pcall(f) end end,
    delay            = function(t,f) if _orig_type(f)=="function" then _orig_pcall(f) end end,
    shared           = {},
    _VERSION         = "Lua 5.1",
    table = {
        insert  = table.insert,
        remove  = table.remove,
        sort    = table.sort,
        concat  = table.concat,
        unpack  = _orig_unpack,
        pack    = table.pack or function(...) return {n=_orig_select('#',...), ...} end,
        move    = table.move or function(a,f,e,t,b)
            b=b or a
            for i=f,e do b[t+(i-f)]=a[i] end
            return b
        end,
    },
    math = {
        abs=math.abs, floor=math.floor, ceil=math.ceil,
        max=math.max, min=math.min, sqrt=math.sqrt,
        random=math.random, huge=math.huge, pi=math.pi,
        sin=math.sin, cos=math.cos, tan=math.tan,
        log=math.log, exp=math.exp, fmod=math.fmod, modf=math.modf,
        pow=function(a,b) return a^b end,
        log10=function(a) return math.log(a)/math.log(10) end,
    },
}

_orig_setmt(_env, {
    __index = function(_, k)
        if _safe[k] ~= nil then return _safe[k] end
        if k == "getfenv" then return function(n) return _env end end
        if k == "setfenv" then
            return function(n, t)
                if _orig_type(t) == "table" then
                    for kk,vv in _orig_pairs(t) do _env[kk] = vv end
                end
                return t
            end
        end
        if k == "_G" or k == "_ENV" or k == "shared" then return _env end
        if k == "getgenv" or k == "getrenv" then return function() return _env end end
        return create_dummy(k)
    end,
    __newindex = function(_, k, v)
        _safe[k] = v
    end,
})

_safe["_G"]      = _env
_safe["_ENV"]    = _env
_safe["getfenv"] = function(n) return _env end
_safe["setfenv"] = function(n, t)
    if _orig_type(t) == "table" then
        for k,v in _orig_pairs(t) do _env[k] = v end
    end
    return t
end
