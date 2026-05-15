local _out = "OUTDIR_PLACEHOLDER"
local _inp = "INPATH_PLACEHOLDER"
local _log = {}
local _captured = {}
local _step_count = 0

local function _L(s)
    _log[#_log+1] = s
end

local function _repair_malformed(code)
    return (tostring(code or "")):gsub("(%d)([a-zA-Z_])", "%1 %2")
end

debug.sethook(function()
    _step_count = _step_count + 1000
    if _step_count > 100000000 then
        _L("STEP_LIMIT_REACHED")
        error("__LIMIT__")
    end
end, "", 1000)

local _orig_loadstring = loadstring
local _orig_pcall = pcall
local _orig_xpcall = xpcall
local _orig_rawset = rawset
local _orig_table_concat = table.concat
local _orig_string_char = string.char

rawset = function(t, k, v)
    if type(v) == "string" and #v > 1 and not _captured[v] then
        _captured[v] = true
        _L("RAWSET captured " .. #v .. " bytes: " .. string.sub(v, 1, 80):gsub("%c", "."))
    end
    return _orig_rawset(t, k, v)
end

table.concat = function(t, sep, i, j)
    local r = _orig_table_concat(t, sep, i, j)
    if type(r) == "string" and #r > 1 and not _captured[r] then
        _captured[r] = true
        _L("TABLE.CONCAT captured " .. #r .. " bytes: " .. string.sub(r, 1, 80):gsub("%c", "."))
    end
    return r
end

string.char = function(...)
    local r = _orig_string_char(...)
    if #r > 1 and not _captured[r] then
        _captured[r] = true
        _L("STRING.CHAR captured " .. #r .. " bytes: " .. string.sub(r, 1, 80):gsub("%c", "."))
    end
    return r
end

local function _hooked_loadstring(code, name)
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
        code = _repair_malformed(code)
        if not _captured[code] then
            _captured[code] = true
            _L("LOADSTRING captured " .. #code .. " bytes")
            local layer_num = 1
            while io.open(_out .. "/layer_" .. layer_num .. ".lua") do
                layer_num = layer_num + 1
            end
            local f = io.open(_out .. "/layer_" .. layer_num .. ".lua", "w")
            if f then f:write(code) f:close() end
        end
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
        abs = math.abs,
        acos = math.acos,
        asin = math.asin,
        atan = math.atan,
        atan2 = math.atan2,
        ceil = math.ceil,
        cos = math.cos,
        cosh = math.cosh,
        deg = math.deg,
        exp = math.exp,
        floor = math.floor,
        fmod = math.fmod,
        frexp = math.frexp,
        huge = math.huge,
        ldexp = math.ldexp,
        log = math.log,
        log10 = math.log10,
        max = math.max,
        min = math.min,
        modf = math.modf,
        pi = math.pi,
        pow = math.pow,
        rad = math.rad,
        random = math.random,
        randomseed = math.randomseed,
        sin = math.sin,
        sinh = math.sinh,
        sqrt = math.sqrt,
        tan = math.tan,
        tanh = math.tanh,
    },
    table = {
        concat = table.concat,
        insert = table.insert,
        maxn = function(t) return #t end,
        remove = table.remove,
        sort = table.sort,
    },
    os = {
        clock = os.clock,
        date = os.date,
        difftime = os.difftime,
        time = os.time,
    },
    coroutine = {
        create = coroutine.create,
        resume = coroutine.resume,
        running = coroutine.running,
        status = coroutine.status,
        wrap = coroutine.wrap,
        yield = coroutine.yield,
    },
    print = function(...)
        local args = {...}
        for i, v in ipairs(args) do
            args[i] = tostring(v)
        end
        _L("PRINT: " .. table.concat(args, "\t"))
    end,
    warn = function() end,
    getfenv = function(f) return _safe_env end,
    setfenv = function(f, e) return f end,
    newproxy = function(add)
        local u = newproxy(true)
        if add then
            getmetatable(u).__gc = function() end
        end
        return u
    end,
    game = {
        PlaceId = 12345678,
        JobId = "00000000-0000-0000-0000-000000000000",
        GetService = function(self, name)
            return _safe_env[name] or {}
        end,
    },
    workspace = {},
    Players = {
        LocalPlayer = {
            Name = "Player",
            UserId = 1,
            Character = {},
            PlayerGui = {},
            Backpack = {},
        },
        GetPlayers = function() return {} end,
    },
    MarketplaceService = {},
    ReplicatedStorage = {},
    ServerStorage = {},
    ServerScriptService = {},
    Lighting = {},
    StarterGui = {},
    StarterPack = {},
    SoundService = {},
    HttpService = {
        GetAsync = function() return "" end,
        PostAsync = function() return "" end,
    },
    Enum = {},
}

_safe_env._G = _safe_env

local _env_mt = {
    __index = function(t, k)
        local v = rawget(_safe_env, k)
        if v ~= nil then
            return v
        end
        _L("MISSING_GLOBAL: " .. tostring(k))
        return {}
    end,
    __newindex = function(t, k, v)
        rawset(_safe_env, k, v)
    end,
}

local env = setmetatable({}, _env_mt)

local fh = io.open(_inp, "rb")
if not fh then
    _L("CANNOT_OPEN_INPUT")
    local ef = io.open(_out .. "/error.txt", "w")
    if ef then ef:write("cannot open input file") ef:close() end
else
    local source = fh:read("*a")
    fh:close()

    _L("FILE_SIZE: " .. #source .. " bytes")
    _L("FIRST_HEX: " .. string.sub(source, 1, 100):gsub(".", function(c)
        return string.format("%02X ", string.byte(c))
    end))

    source = _repair_malformed(source)

    local chunk, err = _orig_loadstring(source, "@input")
    if not chunk then
        _L("PARSE_ERROR: " .. tostring(err))
        local ef = io.open(_out .. "/error.txt", "w")
        if ef then ef:write("parse error: " .. tostring(err)) ef:close() end
    else
        setfenv(chunk, env)
        local function error_handler(e)
            local tb = debug.traceback(tostring(e), 2)
            _L("STACK_TRACE: " .. tb)
            return tb
        end
        local ok, res = _orig_xpcall(chunk, error_handler)
        if not ok then
            _L("RUNTIME_ERROR: " .. tostring(res))
            local ef = io.open(_out .. "/error.txt", "w")
            if ef then ef:write(tostring(res)) ef:close() end
        else
            _L("EXECUTION_COMPLETE. Return type: " .. type(res))
            
            if res and type(res) == "function" then
                local ok2, bc = pcall(string.dump, res)
                if ok2 then
                    local df = io.open(_out .. "/dump.bin", "wb")
                    if df then df:write(bc) df:close() end
                    _L("DUMPED " .. #bc .. " bytes")
                else
                    _L("DUMP_FAILED: " .. tostring(bc))
                end
            elseif res and type(res) == "string" and #res > 5 then
                local layer_num = 1
                while io.open(_out .. "/layer_" .. layer_num .. ".lua") do
                    layer_num = layer_num + 1
                end
                local f = io.open(_out .. "/layer_" .. layer_num .. ".lua", "w")
                if f then f:write(res) f:close() end
                _L("RETURNED_STRING " .. #res .. " bytes")
            end
            
            local cap_file = io.open(_out .. "/cap.txt", "w")
            if cap_file then
                for i, v in ipairs(_captured) do
                    if i > 1 then cap_file:write("---SEP---\n") end
                    cap_file:write(v .. "\n")
                end
                cap_file:close()
            end
        end
    end
end

local df = io.open(_out .. "/diag.txt", "w")
if df then
    df:write(table.concat(_log, "\n"))
    df:close()
end
