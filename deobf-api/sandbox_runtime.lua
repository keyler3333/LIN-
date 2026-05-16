local _out = "OUTDIR_PLACEHOLDER"
local _inp = "INPATH_PLACEHOLDER"
local _log = {}
local _layer_count = 0
local _step_count = 0
local _tracked = {}

local function _L(s)
    _log[#_log+1] = tostring(s)
end

local function _write_file(path, data, mode)
    local f = io.open(path, mode or "w")
    if not f then return false end
    f:write(data)
    f:close()
    return true
end

local function _write_layer(data)
    _layer_count = _layer_count + 1
    _write_file(_out .. "/layer_" .. _layer_count .. ".lua", data)
    _L("LAYER_" .. _layer_count .. " " .. #data .. " bytes")
end

local function _write_capture(data)
    local f = io.open(_out .. "/cap.txt", "a")
    if f then
        if f:seek("end") > 0 then f:write("---SEP---\n") end
        f:write(data .. "\n")
        f:close()
    end
end

local function _track_string(v)
    if type(v) == "string" and #v > 3 and not _tracked[v] then
        _tracked[v] = true
        _write_capture(v)
    end
end

do
    pcall(function()
        debug.sethook(function()
            _step_count = _step_count + 1000
            if _step_count > 100000000 then error("__LIMIT__") end
        end, "", 1000)
    end)
end

local _orig_loadstring = loadstring
local _orig_pcall = pcall
local _orig_xpcall = xpcall
local _orig_rawset = rawset
local _orig_rawget = rawget
local _orig_table_concat = table.concat
local _orig_string_char = string.char
local _orig_string_dump = string.dump
local _orig_newproxy = newproxy
local _orig_unpack = unpack
local _orig_getfenv = getfenv
local _orig_setfenv = setfenv
local _orig_type = type
local _orig_pairs = pairs
local _orig_tostring = tostring

rawset = function(t, k, v)
    _track_string(v)
    return _orig_rawset(t, k, v)
end

rawget = function(t, k)
    local v = _orig_rawget(t, k)
    if v ~= nil then return v end
    local mt = getmetatable(t)
    if mt and mt.__index then
        local index = mt.__index
        if _orig_type(index) == "function" then return index(t, k)
        elseif _orig_type(index) == "table" then return index[k] end
    end
    return nil
end

table.concat = function(t, sep, i, j)
    local r = _orig_table_concat(t, sep, i, j)
    _track_string(r)
    return r
end

string.char = function(...)
    local r = _orig_string_char(...)
    _track_string(r)
    return r
end

string.dump = function(fn)
    local bc = _orig_string_dump(fn)
    if bc and #bc > 20 then
        _write_file(_out .. "/dump.bin", bc, "wb")
        _L("STRING.DUMP captured " .. #bc .. " bytes")
    end
    return bc
end

local function _hooked_loadstring(code, name)
    if _orig_type(code) == "function" then
        local parts = {}
        while true do
            local ok, p = pcall(code)
            if not ok or not p then break end
            if _orig_type(p) == "string" then parts[#parts+1] = p end
            if #parts > 5000 then break end
        end
        code = table.concat(parts)
    end
    if _orig_type(code) == "string" and #code > 5 then
        _write_layer(code)
    end
    return _orig_loadstring(code, name)
end

loadstring = _hooked_loadstring
load = _hooked_loadstring

getfenv = _orig_getfenv
setfenv = _orig_setfenv

local _roproxy_mt
local function _roproxy()
    local data = {}
    local mt = {
        __index = function(t, k)
            local v = _orig_rawget(data, k)
            if v ~= nil then return v end
            v = _roproxy()
            _orig_rawset(data, k, v)
            return v
        end,
        __call = function(t, ...) return t end,
        __newindex = function(t, k, v) _orig_rawset(data, k, v) end,
        __gc = function() end,
        __tostring = function() return "Instance" end,
        __len = function() return 0 end,
        __unm = function() return 0 end,
        __add = function() return 0 end,
        __sub = function() return 0 end,
        __mul = function() return 0 end,
        __div = function() return 0 end,
        __mod = function() return 0 end,
        __pow = function() return 0 end,
        __eq = function(a, b) return a == b end,
        __lt = function() return false end,
        __le = function() return false end,
        __concat = function(a, b) return _orig_tostring(a) .. _orig_tostring(b) end,
    }
    return setmetatable({}, mt)
end
_roproxy_mt = getmetatable(_roproxy())

local function _make_service(name)
    return _roproxy()
end

local Players = {
    LocalPlayer = {
        Name = "Player",
        UserId = 1,
        Character = _roproxy(),
        PlayerGui = _roproxy(),
        Backpack = _roproxy(),
        PlayerScripts = _roproxy(),
        Team = nil,
        membershipType = 0,
    },
    GetPlayers = function() return {} end,
    GetPlayerByUserId = function(id) return Players.LocalPlayer end,
    PlayerAdded = { connect = function() return { disconnect = function() end } end },
    PlayerRemoving = { connect = function() return { disconnect = function() end } end },
}

local game = {
    PlaceId = 12345678,
    JobId = "00000000-0000-0000-0000-000000000000",
    GetService = function(self, name)
        if name == "Players" then return Players
        elseif name == "Workspace" then return _roproxy()
        elseif name == "Lighting" then return _roproxy()
        elseif name == "ReplicatedStorage" then return _roproxy()
        elseif name == "ServerStorage" then return _roproxy()
        elseif name == "ServerScriptService" then return _roproxy()
        elseif name == "StarterGui" then return _roproxy()
        elseif name == "StarterPack" then return _roproxy()
        elseif name == "SoundService" then return _roproxy()
        elseif name == "MarketplaceService" then return _make_service(name)
        elseif name == "HttpService" then return _make_service(name)
        elseif name == "TeleportService" then return _make_service(name)
        elseif name == "Chat" then return _make_service(name)
        elseif name == "InsertService" then return _make_service(name)
        elseif name == "RunService" then return _make_service(name)
        else return _roproxy() end
    end,
    IsLoaded = function() return true end,
}

local Instance = {
    new = function(className)
        local obj = _roproxy()
        obj.Name = className
        obj.className = className
        obj.Parent = nil
        obj:Destroy = function() end
        obj:Clone = function() return obj end
        obj:FindFirstChild = function() return nil end
        obj:WaitForChild = function() return nil end
        return obj
    end,
}

local Vector3 = {
    new = function(x, y, z) return { x = x or 0, y = y or 0, z = z or 0 } end,
}

local CFrame = {
    new = function(...)
        local args = {...}
        if #args == 3 then
            return { x = args[1], y = args[2], z = args[3], lookVector = Vector3.new(0,0,1) }
        elseif #args == 12 then
            return {}
        end
        return {}
    end,
    Angles = function(rx, ry, rz) return {} end,
}

local Color3 = {
    new = function(r, g, b) return { r = r or 255, g = g or 255, b = b or 255 } end,
    fromRGB = function(r, g, b) return Color3.new(r, g, b) end,
}

local BrickColor = {
    new = function(name) return { Name = name } end,
    Random = function() return { Name = "Bright red" } end,
}

local Enum = {
    MembershipType = { None = 0, Premium = 4 },
    Material = { Plastic = 256, Wood = 512 },
    Shape = { Ball = 0, Block = 1 },
}

local wait = function(t) return t or 0 end
local delay = function(t, fn) end
local spawn = function(fn) pcall(fn) end
local tick = function() return os.time() end
local time = tick
local elapsedTime = tick

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
    unpack = _orig_unpack or table.unpack,
    getfenv = getfenv,
    setfenv = setfenv,
    loadstring = loadstring,
    load = load,
    string = {
        byte = string.byte, char = string.char, find = string.find,
        format = string.format, gmatch = string.gmatch, gsub = string.gsub,
        len = string.len, lower = string.lower, match = string.match,
        rep = string.rep, reverse = string.reverse, sub = string.sub,
        upper = string.upper, dump = string.dump,
    },
    math = {
        abs = math.abs, acos = math.acos, asin = math.asin, atan = math.atan,
        atan2 = math.atan2, ceil = math.ceil, cos = math.cos, cosh = math.cosh,
        deg = math.deg, exp = math.exp, floor = math.floor, fmod = math.fmod,
        frexp = math.frexp, huge = math.huge, ldexp = math.ldexp, log = math.log,
        log10 = math.log10, max = math.max, min = math.min, modf = math.modf,
        pi = math.pi, pow = math.pow, rad = math.rad, random = math.random,
        randomseed = math.randomseed, sin = math.sin, sinh = math.sinh,
        sqrt = math.sqrt, tan = math.tan, tanh = math.tanh,
    },
    table = {
        concat = table.concat, insert = table.insert,
        maxn = function(t)
            local n = 0
            for k in pairs(t) do if type(k) == "number" and k > n then n = k end end
            return n
        end,
        remove = table.remove, sort = table.sort,
        unpack = _orig_unpack or table.unpack,
    },
    os = { clock = os.clock, date = os.date, difftime = os.difftime, time = os.time },
    coroutine = {
        create = coroutine.create, resume = coroutine.resume,
        running = coroutine.running, status = coroutine.status,
        wrap = coroutine.wrap, yield = coroutine.yield,
    },
    print = function(...) end,
    warn = function() end,
    newproxy = function(add)
        local u = _orig_newproxy(add)
        if add then
            local mt = getmetatable(u)
            if mt then mt.__gc = function() end end
        end
        return u
    end,
    game = game,
    workspace = _roproxy(),
    Players = Players,
    MarketplaceService = _make_service("MarketplaceService"),
    ReplicatedStorage = _roproxy(),
    ServerStorage = _roproxy(),
    ServerScriptService = _roproxy(),
    Lighting = _roproxy(),
    StarterGui = _roproxy(),
    StarterPack = _roproxy(),
    SoundService = _make_service("SoundService"),
    HttpService = _make_service("HttpService"),
    TeleportService = _make_service("TeleportService"),
    Chat = _make_service("Chat"),
    InsertService = _make_service("InsertService"),
    RunService = _make_service("RunService"),
    Instance = Instance,
    Vector3 = Vector3,
    CFrame = CFrame,
    Color3 = Color3,
    BrickColor = BrickColor,
    Enum = Enum,
    shared = {},
    getconnections = function() return {} end,
    hookfunction = function(f, h) return f end,
    isscript = function() return false end,
    wait = wait,
    delay = delay,
    spawn = spawn,
    tick = tick,
    time = time,
    elapsedTime = elapsedTime,
    _G = nil,
    _ENV = nil,
}

_safe_env._G = _safe_env
_safe_env._ENV = _safe_env

local _env_mt = {
    __index = function(t, k)
        local v = _orig_rawget(_safe_env, k)
        if v ~= nil then return v end
        _L("MISSING: " .. tostring(k))
        return _roproxy()
    end,
    __newindex = function(t, k, v)
        _track_string(v)
        _orig_rawset(_safe_env, k, v)
    end,
}

local env = setmetatable({}, _env_mt)

local fh = io.open(_inp, "rb")
if not fh then
    _L("OPEN_ERROR")
    _write_file(_out .. "/error.txt", "cannot open input")
else
    local source = fh:read("*a")
    fh:close()
    if not source then
        _L("READ_ERROR")
        _write_file(_out .. "/error.txt", "cannot read input")
    else
        _L("SIZE: " .. #source .. " bytes")
        local chunk, parse_err = _orig_loadstring(source, "@input")
        if not chunk then
            _L("PARSE: " .. tostring(parse_err))
            _write_file(_out .. "/error.txt", "parse error: " .. tostring(parse_err))
        else
            _orig_setfenv(chunk, env)
            local function error_handler(e)
                local tb = debug.traceback(_orig_tostring(e), 2)
                _L("TRACE: " .. tb)
                return tb
            end
            local ok, res = _orig_xpcall(chunk, error_handler)
            if not ok then
                _L("RUNTIME: " .. _orig_tostring(res))
                _write_file(_out .. "/error.txt", _orig_tostring(res))
            else
                _L("DONE: " .. _orig_type(res))
                if res and _orig_type(res) == "function" then
                    local ok2, bc = pcall(string.dump, res)
                    if ok2 then
                        _write_file(_out .. "/dump.bin", bc, "wb")
                        _L("DUMPED " .. #bc .. " bytes")
                    end
                elseif res and _orig_type(res) == "string" and #res > 5 then
                    _write_layer(res)
                    _L("RETURNED " .. #res .. " bytes")
                end
            end
            _L("MEMORY_SCAN_START")
            local mem_parts = {}
            local function _scan_table(t, depth, path)
                if depth > 4 then return end
                for k, v in _orig_pairs(t) do
                    if _orig_type(v) == "string" and #v > 5 then
                        _track_string(v)
                        mem_parts[#mem_parts+1] = v
                    elseif _orig_type(v) == "table" then
                        _scan_table(v, depth + 1, path .. "[" .. _orig_tostring(k) .. "]")
                    end
                end
            end
            _scan_table(_safe_env, 0, "_G")
            _scan_table(env, 0, "env")
            if #mem_parts > 0 then
                local mf = io.open(_out .. "/memory.txt", "w")
                if mf then
                    for i, s in ipairs(mem_parts) do
                        if i > 1 then mf:write("---MEMSEP---\n") end
                        mf:write(s .. "\n")
                    end
                    mf:close()
                end
            end
            _L("MEMORY_SCAN_END: " .. #mem_parts .. " strings found")
        end
    end
end

do
    local df = io.open(_out .. "/diag.txt", "w")
    if df then
        df:write(table.concat(_log, "\n"))
        df:close()
    end
end
