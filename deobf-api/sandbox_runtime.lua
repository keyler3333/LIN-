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

rawset = function(t, k, v)
    _capture(k)
    _capture(v)
    _rs(t, k, v)
end
rawset(_G, "rawset", rawset)

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

pcall = function(f, ...)
    _capture(f)
    return _pc(f, ...)
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

local function _stub(v, name)
    if v ~= nil then return v end
    return _dummy(name)
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
    rawset = rawset,
    rawequal = rawequal,
    rawlen = rawlen,
    setmetatable = _sm,
    getmetatable = _gm,
    unpack = _un,
    pcall = pcall,
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
        defer = function(f) _pc(f) end,
        cancel = function() end
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
    Enum = setmetatable({}, { __index = function(t, k)
        local enum = _dummy("Enum." .. k)
        rawset(t, k, enum)
        return enum
    end }),
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
    getgenv = function() return _env end,
    getrenv = function() return _G end,
    getgc = function() return {} end,
    getloadedmodules = function() return {} end,
    getconnections = function() return {} end,
    firesignal = function() end,
    fireclickdetector = function() end,
    fireproximityprompt = function() end,
    firetouchinterest = function() end,
    cloneref = function(i) return i end,
    compareinstances = function(a,b) return a==b end,
    isluau = function() return true end,
    setclipboard = function() end,
    queueteleport = function() end,
    syn_queue_on_teleport = function() end,
    setreadonly = function() end,
    makereadonly = function() end,
    makewriteable = function() end,
    getrawmetatable = function() return nil end,
    setrawmetatable = function() end,
    getconstants = function() return {} end,
    setconstant = function() end,
    getupvalues = function() return {} end,
    setupvalue = function() end,
    getupvalue = function() return nil end,
    getscriptclosure = function() return function() end,
    restorefunction = function(f) return f end,
    detourfunction = function(f) return f end,
    replaceclosure = function() end,
    unhookfunction = function() end,
    getcallingscript = function() return _dummy("Script") end,
    getscripthash = function() return "" end,
    getscripts = function() return {} end,
    getmodules = function() return {} end,
    getproperties = function() return {} end,
    getnilinstances = function() return {} end,
    debug_getregistry = function() return {} end,
    debug_traceback = function() return "" end,
    crypt = {
        base64encode = function() return "" end,
        base64decode = function() return "" end,
        encrypt = function() return "" end,
        decrypt = function() return "" end,
    },
    gethui = function() return _dummy("Gui") end,
    --- All Roblox Services list
    Lighting = _dummy("Lighting"),
    ReplicatedStorage = _dummy("ReplicatedStorage"),
    ServerStorage = _dummy("ServerStorage"),
    ServerScriptService = _dummy("ServerScriptService"),
    StarterGui = _dummy("StarterGui"),
    StarterPlayer = _dummy("StarterPlayer"),
    StarterPack = _dummy("StarterPack"),
    Chat = _dummy("Chat"),
    SoundService = _dummy("SoundService"),
    Debris = _dummy("Debris"),
    Teams = _dummy("Teams"),
    InsertService = _dummy("InsertService"),
    MarketplaceService = _dummy("MarketplaceService"),
    TeleportService = _dummy("TeleportService"),
    ContextActionService = _dummy("ContextActionService"),
    CollectionService = _dummy("CollectionService"),
    PathfindingService = _dummy("PathfindingService"),
    BadgeService = _dummy("BadgeService"),
    PointsService = _dummy("PointsService"),
    SocialService = _dummy("SocialService"),
    GroupService = _dummy("GroupService"),
    DataStoreService = _dummy("DataStoreService"),
    MessagingService = _dummy("MessagingService"),
    ScriptContext = _dummy("ScriptContext"),
    LogService = _dummy("LogService"),
    TestService = _dummy("TestService"),
    AnalyticsService = _dummy("AnalyticsService"),
    AvatarEditorService = _dummy("AvatarEditorService"),
    AccountService = _dummy("AccountService"),
    AssetService = _dummy("AssetService"),
    BrowserService = _dummy("BrowserService"),
    VRService = _dummy("VRService"),
    HapticService = _dummy("HapticService"),
    TouchInputService = _dummy("TouchInputService"),
    NotificationService = _dummy("NotificationService"),
    PolicyService = _dummy("PolicyService"),
    GamepadService = _dummy("GamepadService"),
    GuiService = _dummy("GuiService"),
    NetworkClient = _dummy("NetworkClient"),
    PhysicsService = _dummy("PhysicsService"),
    ScriptService = _dummy("ScriptService"),
    StarterScripts = _dummy("StarterScripts"),
    StudioService = _dummy("StudioService"),
    MouseService = _dummy("MouseService"),
    WebService = _dummy("WebService"),
    DataModelPatchService = _dummy("DataModelPatchService"),
    MemoryStoreService = _dummy("MemoryStoreService"),
    TextChatService = _dummy("TextChatService"),
    KeyframeSequenceProvider = _dummy("KeyframeSequenceProvider"),
    ExperienceAuthService = _dummy("ExperienceAuthService"),
    AssetDeliveryService = _dummy("AssetDeliveryService"),
    OmniRecommendationsService = _dummy("OmniRecommendationsService"),
    PackageService = _dummy("PackageService"),
}

_sm(_env, {
    __index = function(_, k)
        _L("ENV_ACCESS: " .. _ts(k))
        local v = _safe[k]
        if v ~= nil then
            return v
        end
        if k == "getfenv" then
            return function(n) return _env end
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
        _safe[k] = child
        return child
    end,
    __newindex = function(_, k, v)
        _rs(_env, k, v)
    end,
})

for k, v in pairs(_safe) do
    _rs(_env, k, v)
end

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
