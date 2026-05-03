local _out = "OUTDIR_PLACEHOLDER"
local _inp = "INPATH_PLACEHOLDER"
local _layer = 0
local _cap, _log, _step = {}, {}, 0

local function _L(s) _log[#_log+1] = s end

debug.sethook(function()
    _step = _step + 5000
    if _step > 10000000 then
        _L("STEP_LIMIT")
        error("__LIMIT__")
    end
end, "", 5000)

local _captured = {}
local function _capture(v)
    if type(v) == "string" and #v > 3 and not _captured[v] then
        _captured[v] = true
        _cap[#_cap+1] = v
    end
end

local _orig_loadstring   = loadstring
local _orig_pcall        = pcall
local _orig_table_concat = table.concat
local _orig_type         = type

local _rnd_val = 0
local function _rnd()
    _rnd_val = _rnd_val + 1
    return 1000 + (_rnd_val % 1000)
end

local function _dummy(name)
    local d = {}
    setmetatable(d, {
        __index = function(_, k)
            local child = _dummy(name .. "." .. tostring(k))
            rawset(d, k, child)
            return child
        end,
        __call = function() return _dummy(name .. "()") end,
    })
    return d
end

local _inst_mt = {
    __index = function(self, k)
        local child = _dummy(k)
        rawset(self, k, child)
        return child
    end,
    __call = function() return nil end,
}

local function _inst(class)
    local t = { ClassName = class or "Instance" }
    setmetatable(t, _inst_mt)
    return t
end

local env = {
    _G = nil,
    _VERSION = "Luau",
    game = _inst("DataModel"),
    workspace = _inst("Workspace"),
    script = _inst("Script"),
    shared = {},
    task = {
        wait = function() end,
        spawn = function(f) if type(f)=="function" then pcall(f) end end,
        defer = function(f) if type(f)=="function" then pcall(f) end end,
        delay = function(_, f) if type(f)=="function" then pcall(f) end end,
        cancel = function() end,
    },
    delay = function(_, f) if type(f)=="function" then pcall(f) end end,
    spawn = function(f) if type(f)=="function" then pcall(f) end end,
    wait = function() end,
    tick = function() return os.clock() end,
    time = function() return os.time() end,
    elapsedTime = function() return 0 end,
    typeof = _orig_type,
    Instance = { new = _inst },
    Enum = setmetatable({}, { __index = function(_, k) return setmetatable({}, { __index = function(_, v) return { Name = v, Value = 0 } end }) end }),
    Vector3 = { new = function(x, y, z) return { X = x or 0, Y = y or 0, Z = z or 0 } end },
    Vector2 = { new = function(x, y) return { X = x or 0, Y = y or 0 } end },
    CFrame = { new = function(...) return {} end, Angles = function(...) return {} end },
    Color3 = { new = function(r,g,b) return { R = r, G = g, B = b } end, fromRGB = function(r,g,b) return { R = r/255, G = g/255, B = b/255 } end },
    UDim2 = { new = function(xs, xo, ys, yo) return { X = { Scale = xs, Offset = xo }, Y = { Scale = ys, Offset = yo } } end },
    UDim = { new = function(s, o) return { Scale = s, Offset = o } end },
    BrickColor = { new = function() return { Name = "Medium stone grey" } end, Random = function() return { Name = "Bright red" } end },
    TweenInfo = { new = function(t) return { Time = t } end },
    Region3 = { new = function() return {} end },
    Ray = { new = function() return {} end },
    NumberRange = { new = function(min, max) return { Min = min, Max = max } end },
    NumberSequence = { new = function(...) return {} end },
    ColorSequence = { new = function(...) return {} end },
    PhysicalProperties = { new = function(...) return {} end },
    Region3int16 = { new = function() return {} end },
    Vector3int16 = { new = function(x,y,z) return { X = x, Y = y, Z = z } end },
    PathWaypoint = { new = function() return {} end },
    RaycastResult = { new = function() return {} end },
    RBXScriptSignal = _inst("Signal"),
    RBXScriptConnection = { Disconnect = function() end, Connected = true },
    Dock WidgetPluginGuiInfo = { new = function() return {} end },
    Content = { new = function() return {} end },
    Axes = { new = function() return {} end },
    print = function() end,
    warn = function() end,
    error = function() end,
    assert = function(v) return v end,
    require = function() return _inst("Module") end,
    getfenv = function(fn) return env end,
    setfenv = function(fn, e) return fn end,
}

env._G = env

local services = {
    "Players", "TweenService", "HttpService", "Workspace", "Lighting", "ReplicatedStorage",
    "ServerStorage", "ServerScriptService", "StarterGui", "StarterPlayer", "StarterPack",
    "Chat", "SoundService", "Debris", "Teams", "InsertService", "MarketplaceService",
    "TeleportService", "RunService", "UserInputService", "ContextActionService",
    "CollectionService", "PathfindingService", "BadgeService", "PointsService",
    "SocialService", "GroupService", "DataStoreService", "MessagingService",
    "ScriptContext", "LogService", "TestService", "AnalyticsService",
    "AvatarEditorService", "AccountService", "AssetService", "BrowserService",
    "VRService", "HapticService", "TouchInputService", "NotificationService",
    "PolicyService", "GamepadService", "GuiService", "NetworkClient",
    "PhysicsService", "ScriptService", "StudioService", "MouseService",
    "WebService", "DataModelPatchService", "MemoryStoreService", "TextChatService",
    "KeyframeSequenceProvider", "ExperienceAuthService", "AssetDeliveryService",
    "OmniRecommendationsService", "PackageService",
}

for _, s in ipairs(services) do
    env[s] = _inst(s)
end

local executor_globals = {
    getgenv = function() return env end,
    getrenv = function() return env end,
    getsenv = function() return env end,
    gettenv = function() return env end,
    getgc = function() return {} end,
    setidentity = function() end,
    getidentity = function() return 8 end,
    setthreadidentity = function() end,
    getthreadidentity = function() return 8 end,
    setreadonly = function() end,
    isreadonly = function() return false end,
    makereadonly = function(t) return t end,
    makewriteable = function(t) return t end,
    cloneref = function(v) return v end,
    checkcaller = function() return false end,
    islclosure = function() return true end,
    iscclosure = function() return false end,
    hookfunction = function(a, b) return a end,
    newcclosure = function(f) return f end,
    getcustomasset = function(p) return "rbxasset://" .. tostring(p) end,
    getrawmetatable = function() return nil end,
    setrawmetatable = function() end,
    identifyexecutor = function() return "Executor", "1.0" end,
    getexecutorname = function() return "Executor" end,
    isluau = function() return true end,
    queue_on_teleport = function() end,
    syn = _dummy("syn"),
    fluxus = _dummy("fluxus"),
    fireclickdetector = function() end,
    firesignal = function() end,
    fireproximityprompt = function() end,
    firetouchinterest = function() end,
    gethui = function() return _inst("Gui") end,
    getconnections = function() return {} end,
    getsignal = function() return { Connect = function() return { Disconnect = function() end } end } end,
    WebSocket = { connect = function() return { Send = function() end, Close = function() end, OnMessage = { Connect = function() return { Disconnect = function() end } end } } end },
    Drawing = setmetatable({}, { __index = function() return function() return { Remove = function() end } end end }),
    KRNL_LOADED = true,
}

for k, v in pairs(executor_globals) do
    env[k] = v
end

os.time = function() return 1680000000 + math.random(0, 30000000) end
os.clock = function() return os.time() + math.random() end

local function _hooked_load(code, name)
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
        _layer = _layer + 1
        local f = io.open(_out .. "/layer_" .. _layer .. ".lua", "w")
        if f then f:write(code) f:close() end
        _L("layer " .. _layer .. " captured (" .. #code .. " bytes)")
    end
    return _orig_loadstring(code, name)
end
env.loadstring = _hooked_load
env.load = _hooked_load

local fh = io.open(_inp, "r")
if not fh then
    local ef = io.open(_out .. "/error.txt", "w")
    if ef then ef:write("cannot open input: " .. _inp) ef:close() end
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
    if not ok then _L("runtime error: " .. tostring(res)) end
    if ok and type(res) == "function" then
        local ok2, bc = _orig_pcall(string.dump, res)
        if ok2 then
            local df = io.open(_out .. "/dump.bin", "wb")
            if df then df:write(bc) df:close() end
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
