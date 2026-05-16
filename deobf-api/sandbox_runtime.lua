local _out = "OUTDIR_PLACEHOLDER"
local _inp = "INPATH_PLACEHOLDER"
local _log = {}
local _captured = {}
local _step_count = 0

local function _L(s)
    local ok, err = pcall(function()
        _log[#_log+1] = tostring(s)
    end)
    if not ok then
        _log[#_log+1] = "LOG_ERROR: " .. tostring(err)
    end
end

local function _safe_call(fn, ...)
    local ok, res = pcall(fn, ...)
    if not ok then
        _L("CALL_ERROR: " .. tostring(res))
        return nil
    end
    return res
end

local function _write_file(path, data, mode)
    local ok, err = pcall(function()
        local f = io.open(path, mode or "w")
        if not f then
            error("Cannot open " .. path)
        end
        f:write(data)
        f:close()
    end)
    if not ok then
        _L("WRITE_ERROR: " .. tostring(err) .. " for " .. path)
        return false
    end
    return true
end

local function _repair_malformed(code)
    local ok, result = pcall(function()
        return (tostring(code or "")):gsub("(%d)([a-zA-Z_])", "%1 %2")
    end)
    if not ok then
        return tostring(code or "")
    end
    return result
end

do
    local ok, err = pcall(function()
        debug.sethook(function()
            _step_count = _step_count + 1000
            if _step_count > 100000000 then
                _L("STEP_LIMIT_REACHED")
                error("__LIMIT__")
            end
        end, "", 1000)
    end)
    if not ok then
        _L("HOOK_ERROR: " .. tostring(err))
    end
end

local _orig_loadstring = loadstring
local _orig_pcall = pcall
local _orig_xpcall = xpcall
local _orig_rawset = rawset
local _orig_table_concat = table.concat
local _orig_string_char = string.char

do
    local ok, err = pcall(function()
        rawset = function(t, k, v)
            if type(v) == "string" and #v > 1 then
                local captured = false
                for _, existing in ipairs(_captured) do
                    if existing == v then
                        captured = true
                        break
                    end
                end
                if not captured then
                    _captured[#_captured + 1] = v
                    _L("RAWSET " .. #v .. " bytes: " .. string.sub(v, 1, 80):gsub("%c", "."))
                end
            end
            return _orig_rawset(t, k, v)
        end
    end)
    if not ok then
        _L("RAWSET_HOOK_ERROR: " .. tostring(err))
        rawset = _orig_rawset
    end
end

do
    local ok, err = pcall(function()
        table.concat = function(t, sep, i, j)
            local r = _orig_table_concat(t, sep, i, j)
            if type(r) == "string" and #r > 1 then
                local captured = false
                for _, existing in ipairs(_captured) do
                    if existing == r then
                        captured = true
                        break
                    end
                end
                if not captured then
                    _captured[#_captured + 1] = r
                    _L("CONCAT " .. #r .. " bytes: " .. string.sub(r, 1, 80):gsub("%c", "."))
                end
            end
            return r
        end
    end)
    if not ok then
        _L("CONCAT_HOOK_ERROR: " .. tostring(err))
        table.concat = _orig_table_concat
    end
end

do
    local ok, err = pcall(function()
        string.char = function(...)
            local r = _orig_string_char(...)
            if #r > 1 then
                local captured = false
                for _, existing in ipairs(_captured) do
                    if existing == r then
                        captured = true
                        break
                    end
                end
                if not captured then
                    _captured[#_captured + 1] = r
                    _L("CHAR " .. #r .. " bytes: " .. string.sub(r, 1, 80):gsub("%c", "."))
                end
            end
            return r
        end
    end)
    if not ok then
        _L("CHAR_HOOK_ERROR: " .. tostring(err))
        string.char = _orig_string_char
    end
end

local function _capture_and_save(code)
    local captured = false
    for _, existing in ipairs(_captured) do
        if existing == code then
            captured = true
            break
        end
    end
    if not captured then
        _captured[#_captured + 1] = code
        local layer_num = 1
        while io.open(_out .. "/layer_" .. layer_num .. ".lua") do
            layer_num = layer_num + 1
        end
        local path = _out .. "/layer_" .. layer_num .. ".lua"
        _write_file(path, code)
        _L("LAYER_" .. layer_num .. " " .. #code .. " bytes")
    end
end

local function _hooked_loadstring(code, name)
    if type(code) == "function" then
        local parts = {}
        local max_parts = 5000
        local part_count = 0
        while part_count < max_parts do
            local ok, p = pcall(code)
            if not ok or not p then break end
            if type(p) == "string" then
                parts[#parts+1] = p
                part_count = part_count + 1
            end
        end
        code = table.concat(parts)
    end
    if type(code) == "string" and #code > 5 then
        code = _repair_malformed(code)
        _capture_and_save(code)
        _L("LOADSTRING " .. #code .. " bytes")
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
        local ok, v = pcall(rawget, _safe_env, k)
        if ok and v ~= nil then
            return v
        end
        _L("MISSING: " .. tostring(k))
        return {}
    end,
    __newindex = function(t, k, v)
        pcall(rawset, _safe_env, k, v)
    end,
}

local env = setmetatable({}, _env_mt)

do
    local fh, err = io.open(_inp, "rb")
    if not fh then
        _L("OPEN_ERROR: " .. tostring(err))
        _write_file(_out .. "/error.txt", "cannot open input: " .. tostring(err))
    else
        local source, read_err = fh:read("*a")
        fh:close()
        
        if not source then
            _L("READ_ERROR: " .. tostring(read_err))
            _write_file(_out .. "/error.txt", "cannot read input: " .. tostring(read_err))
        else
            _L("SIZE: " .. #source .. " bytes")
            
            do
                local hex = ""
                local max_hex = math.min(#source, 100)
                for i = 1, max_hex do
                    hex = hex .. string.format("%02X ", string.byte(source, i))
                end
                _L("HEX: " .. hex)
            end

            source = _repair_malformed(source)

            local chunk, parse_err = _orig_loadstring(source, "@input")
            if not chunk then
                _L("PARSE: " .. tostring(parse_err))
                _write_file(_out .. "/error.txt", "parse error: " .. tostring(parse_err))
            else
                setfenv(chunk, env)
                
                local function error_handler(e)
                    local tb = debug.traceback(tostring(e), 2)
                    _L("TRACE: " .. tb)
                    return tb
                end
                
                local ok, res = _orig_xpcall(chunk, error_handler)
                if not ok then
                    _L("RUNTIME: " .. tostring(res))
                    _write_file(_out .. "/error.txt", tostring(res))
                else
                    _L("DONE: " .. type(res))
                    
                    if res and type(res) == "function" then
                        local ok2, bc = pcall(string.dump, res)
                        if ok2 then
                            _write_file(_out .. "/dump.bin", bc, "wb")
                            _L("DUMPED " .. #bc .. " bytes")
                        else
                            _L("DUMP_FAIL: " .. tostring(bc))
                        end
                    elseif res and type(res) == "string" and #res > 5 then
                        _capture_and_save(res)
                        _L("RETURNED " .. #res .. " bytes")
                    end
                    
                    if #_captured > 0 then
                        local parts = {}
                        for i, v in ipairs(_captured) do
                            if i > 1 then
                                parts[#parts + 1] = "---SEP---\n"
                            end
                            parts[#parts + 1] = v .. "\n"
                        end
                        _write_file(_out .. "/cap.txt", table.concat(parts))
                    end
                end
            end
        end
    end
end

do
    local ok, err = pcall(function()
        local df = io.open(_out .. "/diag.txt", "w")
        if df then
            df:write(table.concat(_log, "\n"))
            df:close()
        end
    end)
    if not ok then
        io.stderr:write("FINAL_ERROR: " .. tostring(err) .. "\n")
    end
end
