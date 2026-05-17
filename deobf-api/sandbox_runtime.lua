local _out = "OUTDIR_PLACEHOLDER"
local _inp = "INPATH_PLACEHOLDER"
local _log = {}
local _layer_count = 0
local _step_count = 0
local _tracked = {}
local _capture_count = 0
local _fake_time = 0

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
local _orig_rawequal = rawequal
local _orig_select = select
local _orig_debug_traceback = debug.traceback

local _io = io
if not _io then
    pcall(function()
        local b_fs = require("@lune/fs")
        _io = {
            open = function(path, mode)
                mode = tostring(mode or "r")
                if mode:find("r") then
                    local ok, data = pcall(b_fs.readFile, tostring(path))
                    if not ok then return nil end
                    return { read = function() return data end, close = function() end }
                elseif mode:find("w") then
                    local chunks = {}
                    return {
                        write = function(_, ...)
                            for i = 1, select("#", ...) do
                                chunks[#chunks+1] = tostring(select(i, ...))
                            end
                        end,
                        close = function() b_fs.writeFile(tostring(path), table.concat(chunks)) end
                    }
                end
            end
        }
    end)
end

local function _L(s) _log[#_log+1] = tostring(s) end
local function _write_file(path, data, mode)
    local f = _io.open(path, mode or "w")
    if not f then return false end
    f:write(data); f:close()
    return true
end
local function _write_layer(data)
    _layer_count = _layer_count + 1
    _write_file(_out .. "/layer_" .. _layer_count .. ".lua", data)
    _L("LAYER_" .. _layer_count .. " " .. #data .. " bytes")
end
local function _write_capture(data)
    if not data or #data == 0 then return end
    local f = _io.open(_out .. "/cap.txt", "a")
    if f then
        if _capture_count > 0 then f:write("---SEP---\n") end
        _capture_count = _capture_count + 1
        f:write(data .. "\n")
        f:close()
    end
end
local function _track_string(v)
    if _orig_type(v) == "string" and #v > 5 and not _tracked[v] then
        _tracked[v] = true
        _write_capture(v)
    end
end

pcall(function()
    debug.sethook(function()
        _step_count = _step_count + 1000
        if _step_count > 100000000 then error("__LIMIT__") end
    end, "", 1000)
end)

local _proxy_mt = {}
_proxy_mt.__index = function(t, k)
    local v = _orig_rawget(t, k)
    if v ~= nil then return v end
    v = setmetatable({}, _proxy_mt)
    _orig_rawset(t, k, v)
    return v
end
_proxy_mt.__newindex = function(t, k, v) _orig_rawset(t, k, v) end
_proxy_mt.__call = function(t, ...) return setmetatable({}, _proxy_mt) end
_proxy_mt.__gc = function() end
_proxy_mt.__tostring = function() return "Instance" end
_proxy_mt.__len = function() return 0 end
_proxy_mt.__unm = function() return 0 end
_proxy_mt.__add = function() return 0 end
_proxy_mt.__sub = function() return 0 end
_proxy_mt.__mul = function() return 0 end
_proxy_mt.__div = function() return 0 end
_proxy_mt.__mod = function() return 0 end
_proxy_mt.__pow = function() return 0 end
_proxy_mt.__eq = function(a, b) return a == b end
_proxy_mt.__lt = function() return false end
_proxy_mt.__le = function() return false end
_proxy_mt.__concat = function(a, b) return _orig_tostring(a) .. _orig_tostring(b) end

local function _new_proxy() return setmetatable({}, _proxy_mt) end

rawset = function(t, k, v)
    _track_string(v)
    return _orig_rawset(t, k, v)
end
rawget = _orig_rawget
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
        _L("DUMPED " .. #bc .. " bytes")
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

local _Vector3 = { new = function(x, y, z) return { X = x or 0, Y = y or 0, Z = z or 0 } end }
local _CFrame = { new = function(...) return {} end, Angles = function() return {} end }
local _Color3 = { new = function(r, g, b) return { R = r or 0, G = g or 0, B = b or 0 } end }
local _BrickColor = { new = function(name) return { Name = name } end, Random = function() return { Name = "Bright red" } end }
local _UDim2 = { new = function(xScale, xOffset, yScale, yOffset) return {} end }
local _Vector2 = { new = function(x, y) return { X = x or 0, Y = y or 0 } end }
local _NumberSequence = { new = function(...) return { Keypoints = {...} } end }
local _NumberSequenceKeypoint = { new = function(time, value, envelope) return { Time = time or 0, Value = value or 0, Envelope = envelope or 0 } end }
local _ColorSequence = { new = function(...) return { Keypoints = {...} } end }
local _ColorSequenceKeypoint = { new = function(time, color) return { Time = time or 0, Value = color or _Color3.new() } end }
local _PhysicalProperties = { new = function(density, friction, elasticity, frictionWeight, elasticityWeight) return {} end }
local _TweenInfo = { new = function(time, easingStyle, easingDirection, repeatCount, reverses, delayTime) return {} end }
local _Faces = { new = function(faces) return { Faces = faces or 0 } end }
local _Axes = { new = function(axes) return { Axes = axes or 0 } end }
local _Ray = { new = function(origin, direction) return { Origin = origin or _Vector3.new(), Direction = direction or _Vector3.new(0,0,-1) } end }
local _Region3 = { new = function(min, max) return {} end }
local _Region3int16 = { new = function(min, max) return {} end }
local _RaycastParams = { new = function() return {} end }
local _RaycastResult = { new = function() return {} end }
local _DateTime = { now = function() return { UnixTimestamp = os.time() } end, fromUnixTimestamp = function(ts) return { UnixTimestamp = ts } end, fromUniversalTime = function(y,m,d,h,min,s) return { UnixTimestamp = os.time() } end, fromLocalTime = function(y,m,d,h,min,s) return { UnixTimestamp = os.time() } end }
local _DockWidgetPluginGuiInfo = { new = function(initDockState, initEnabled, initOverrideEnabledRestore, initFloatXSize, initFloatYSize, initMinWidth, initMinHeight) return {} end }
local _CatalogSearchParams = { new = function() return {} end }
local _PathWaypoint = { new = function(position, action) return { Position = position, Action = action or 0 } end }
local _OverlapParams = { new = function() return {} end }
local _Random = { new = function(seed) return { NextNumber = function(self) return math.random() end, NextInteger = function(self, min, max) return math.random(min, max) end } end }
local _NumberRange = { new = function(min, max) return { Min = min or 0, Max = max or 0 } end }

local Enum = {
    Material = { Plastic = 256, Wood = 512 },
    Shape = { Ball = 0, Block = 1 },
    FormFactor = { Symmetric = 0, Brick = 1, Plate = 2, Custom = 3 },
    MembershipType = { None = 0, Premium = 4 },
    EasingStyle = { Linear = 0, Sine = 1, Back = 2, Quad = 3, Quart = 4, Quint = 5, Bounce = 6, Elastic = 7, Exponential = 8, Circular = 9, Cubic = 10 },
    EasingDirection = { In = 0, Out = 1, InOut = 2 },
    Font = { Legacy = 0, Arial = 1, SourceSans = 3 },
    ScaleType = { Stretch = 0, Slice = 1, Tile = 2, Fit = 3, Crop = 4 },
    TextXAlignment = { Left = 0, Center = 1, Right = 2 },
    TextYAlignment = { Top = 0, Center = 1, Bottom = 2 },
    SortOrder = { Name = 0, Size = 1, Custom = 2 },
    FillDirection = { Horizontal = 0, Vertical = 1 },
    HorizontalAlignment = { Left = 0, Center = 1, Right = 2 },
    VerticalAlignment = { Top = 0, Center = 1, Bottom = 2 },
    AutocompleteMode = { Off = 0, Suggestions = 1, Complete = 2 },
    HumanoidRigType = { R6 = 0, R15 = 1 },
    HumanoidStateType = { RunningNoPhysics = 0, Running = 1, Climbing = 2, FallingDown = 3, Flying = 4, Freefall = 5, GettingUp = 6, Jumping = 7, Landed = 8, Physics = 9, PlatformStanding = 10, Ragdoll = 11, Seated = 12, StrafingNoPhysics = 13, Swimming = 14, Dead = 15 },
    KeyCode = { A = 65, Space = 32, Unknown = 0 },
    UserInputType = { MouseButton1 = 1, MouseButton2 = 2, MouseButton3 = 3, Keyboard = 4, Touch = 5 },
    UserInputState = { Begin = 0, Change = 1, End = 2, Cancel = 3 },
    Platform = { Windows = 0, OSX = 1, IOS = 2, Android = 3, XboxOne = 4, PS4 = 5, Unknown = 6 },
    SurfaceType = { Smooth = 0, Glue = 1, Weld = 2, Studs = 3, Inlet = 4, Universal = 5, Hinge = 6, Motor = 7, SteppingMotor = 8 },
    NormalId = { Top = 0, Bottom = 1, Left = 2, Right = 3, Front = 4, Back = 5 },
    Genre = { All = 0, Tutorial = 1, Adventure = 2 },
    PoseEasingStyle = { Linear = 0, Constant = 1 },
    PoseEasingDirection = { In = 0, Out = 1, InOut = 2 },
}

local _signal_class = {}
_signal_class.new = function()
    local connections = {}
    local signal = {}
    signal.Connect = function(self, callback)
        local conn = { Connected = true }
        conn.Disconnect = function() conn.Connected = false end
        connections[conn] = callback
        return conn
    end
    signal.Fire = function(self, ...)
        local args = {...}
        for conn, callback in pairs(connections) do
            if conn.Connected then pcall(callback, unpack(args)) end
        end
    end
    signal.Once = function(self, callback)
        local conn
        conn = signal:Connect(function(...)
            callback(...)
            conn:Disconnect()
        end)
        return conn
    end
    return signal
end

local _instances = {}

local function _create_instance(className)
    local obj = _new_proxy()
    obj.className = className
    obj.Name = className
    obj.Parent = nil
    obj.Changed = _signal_class.new()
    obj.AncestryChanged = _signal_class.new()
    obj.Destroying = _signal_class.new()
    obj.ClearAllChildren = function(self)
        for _, child in ipairs(_instances) do
            if child.Parent == self then child.Parent = nil end
        end
    end
    obj.Clone = function(self) return _create_instance(className) end
    obj.Destroy = function(self)
        self.Parent = nil
        for i, inst in ipairs(_instances) do
            if inst == self then table.remove(_instances, i); break end
        end
    end
    obj.FindFirstChild = function(self, name)
        for _, child in ipairs(_instances) do
            if child.Parent == self and child.Name == name then return child end
        end
        return nil
    end
    obj.FindFirstChildOfClass = function() return nil end
    obj.FindFirstChildWhichIsA = function() return nil end
    obj.GetChildren = function(self)
        local children = {}
        for _, child in ipairs(_instances) do
            if child.Parent == self then children[#children+1] = child end
        end
        return children
    end
    obj.IsA = function(self, cn) return className == cn end
    obj.IsDescendantOf = function(self, ancestor)
        local parent = self.Parent
        while parent do
            if parent == ancestor then return true end
            parent = parent.Parent
        end
        return false
    end
    obj.WaitForChild = function() return nil end
    _instances[#_instances + 1] = obj
    return obj
end

local _local_player = {
    Name = "Player", DisplayName = "Player", UserId = 1, AccountAge = 365,
    MembershipType = Enum.MembershipType.Premium,
    Team = nil, TeamColor = _BrickColor.new("Medium stone grey"),
    Character = nil, Backpack = _create_instance("Tool"),
    PlayerGui = _create_instance("ScreenGui"), PlayerScripts = _create_instance("Script"),
    CharacterAdded = _signal_class.new(), CharacterRemoving = _signal_class.new(),
    Idled = _signal_class.new(), Chatted = _signal_class.new(),
    RespawnLocation = nil, Neutral = false,
    GetMouse = function() return _new_proxy() end,
    IsFriendsWith = function() return false end,
    IsInGroup = function() return false end,
    Kick = function() end, LoadCharacter = function() end,
    DistanceFromCharacter = function() return 0 end,
}

local Players = {
    LocalPlayer = _local_player,
    PlayerAdded = _signal_class.new(),
    PlayerRemoving = _signal_class.new(),
    GetPlayers = function() return {_local_player} end,
    GetPlayerByUserId = function(id) return _local_player end,
    GetPlayerFromCharacter = function(char) return _local_player end,
    GetNameFromUserIdAsync = function(id) return "Player" end,
    GetUserIdFromNameAsync = function(name) return 1 end,
    GetFriendsAsync = function(id) return {} end,
    GetGroupsAsync = function(id) return {} end,
}

local _services = {
    Players = Players,
    Workspace = _create_instance("Workspace"),
    Lighting = _create_instance("Lighting"),
    ReplicatedStorage = _create_instance("ReplicatedStorage"),
    ServerStorage = _create_instance("ServerStorage"),
    ServerScriptService = _create_instance("ServerScriptService"),
    StarterGui = _create_instance("StarterGui"),
    StarterPack = _create_instance("StarterPack"),
    StarterPlayer = _create_instance("StarterPlayer"),
    SoundService = _create_instance("SoundService"),
    HttpService = {
        GetAsync = function() return "" end,
        PostAsync = function() return "" end,
        GenerateGUID = function() return "00000000-0000-0000-0000-000000000000" end,
        JSONEncode = function() return "{}" end,
        JSONDecode = function() return {} end,
    },
    MarketplaceService = {
        PlayerOwnsAsset = function() return false end,
        PromptPurchase = function() end,
        PromptGamePassPurchase = function() end,
        GetProductInfo = function() return {} end,
    },
    TeleportService = {
        Teleport = function() end,
        TeleportAsync = function() end,
        GetLocalPlayerTeleportData = function() return {} end,
        SetTeleportData = function() end,
    },
    Chat = {
        FilterStringAsync = function(msg, from, to) return msg end,
        CanUsersChatAsync = function() return true end,
    },
    InsertService = {
        LoadAsset = function() return {} end,
        LoadAssetVersion = function() return {} end,
        GetFreeModels = function() return {} end,
    },
    RunService = {
        Heartbeat = { Connect = function(_, cb) return { Disconnect = function() end } end },
        RenderStepped = { Connect = function(_, cb) return { Disconnect = function() end } end },
        Stepped = { Connect = function(_, cb) return { Disconnect = function() end } end },
        IsRunning = function() return true end,
        IsClient = function() return true end,
        IsServer = function() return false end,
        IsStudio = function() return false end,
    },
    LogService = { GetLogHistory = function() return {} end, ClearLog = function() end },
    AnalyticsService = { LogCustomEvent = function() end, FireEvent = function() end },
    AssetService = { CreatePlaceAsync = function() return 0 end, SavePlaceAsync = function() end, GetGamePlacesAsync = function() return {} end },
    BadgeService = { AwardBadge = function() return true end, UserHasBadge = function() return false end, GetBadgeInfoAsync = function() return {} end },
    BrowserService = { OpenBrowserWindow = function() end, ExecuteJavaScript = function() end, OpenScreenshots = function() end },
    ContextActionService = { BindAction = function() end, UnbindAction = function() end, GetAllBoundActionInfo = function() return {} end },
    CoreGui = _create_instance("ScreenGui"),
    CorePackages = _create_instance("Folder"),
    VRService = { GetDeviceInfo = function() return {} end, IsVRDeviceActive = function() return false end, VREnabled = false },
    UserInputService = {
        InputBegan = _signal_class.new(), InputChanged = _signal_class.new(), InputEnded = _signal_class.new(),
        TouchStarted = _signal_class.new(), TouchMoved = _signal_class.new(), TouchEnded = _signal_class.new(),
        MouseEnabled = true, TouchEnabled = true, KeyboardEnabled = true, GamepadEnabled = false,
        IsKeyDown = function() return false end, IsMouseButtonPressed = function() return false end,
        GetMouseDelta = function() return _Vector2.new() end, GetMouseLocation = function() return _Vector2.new() end,
        GetPlatform = function() return Enum.Platform.Windows end, IsNavigationBlocked = function() return false end,
        GetConnectedGamepads = function() return {} end,
    },
    GuiService = { GetGuiInset = function() return _Vector2.new() end, IsModal = function() return false end, IsTenFootInterface = function() return false end },
    SocialService = { CanSendGameInviteAsync = function() return true end, PromptGameInvite = function() end, GetFriendsInfo = function() return {} end },
    GameSettings = _create_instance("GameSettings"),
    PhysicsService = {
        CreateCollisionGroup = function() return 0 end, CollisionGroupSetCollidable = function() end,
        GetRegisteredCollisionGroups = function() return {} end, SetPartCollisionGroup = function() end,
    },
    TextService = { GetTextSize = function() return _Vector2.new() end, FilterStringAsync = function(text, from) return text end },
    TweenService = { Create = function() return { Play = function() end, Pause = function() end, Cancel = function() end } end },
    CollectionService = {
        GetInstanceAddedSignal = function() return _signal_class.new() end, GetTagged = function() return {} end,
        HasTag = function() return false end, AddTag = function() end, RemoveTag = function() end, GetAllTags = function() return {} end,
    },
    Debris = { AddItem = function(item, lifetime) end },
    PathfindingService = { CreatePath = function() return { ComputeAsync = function() return 0 end, GetWaypoints = function() return {} end } end },
    GroupService = { GetGroupInfoAsync = function() return {} end, GetGroupsAsync = function() return {} end, IsInGroup = function() return false end },
    LocalizationService = { GetTranslatorForPlayerAsync = function() return { FormatByKey = function(key, args) return key end } end },
    MessagingService = { PublishAsync = function() end, SubscribeAsync = function() return { Disconnect = function() end } end },
    MemoryStoreService = { GetHashMap = function() return { GetAsync = function() return nil end, SetAsync = function() end } end },
    AvatarEditorService = { PromptCreateOutfit = function() end, PromptSaveAvatar = function() end, SearchCatalog = function() return {} end },
    DataStoreService = { GetDataStore = function() return { GetAsync = function() return nil end, SetAsync = function() end, UpdateAsync = function() return nil end, RemoveAsync = function() end, IncrementAsync = function() return 0 end, ListKeysAsync = function() return {} end } end },
}

local _game = setmetatable({
    PlaceId = 12345678, PlaceVersion = 1, JobId = "00000000-0000-0000-0000-000000000000",
    CreatorId = 1, CreatorType = 0,
    Workspace = _services.Workspace, Players = _services.Players,
    Lighting = _services.Lighting, ReplicatedStorage = _services.ReplicatedStorage,
    ServerStorage = _services.ServerStorage, ServerScriptService = _services.ServerScriptService,
    StarterGui = _services.StarterGui, StarterPack = _services.StarterPack,
    StarterPlayer = _services.StarterPlayer, SoundService = _services.SoundService,
    GetService = function(self, name)
        local svc = _services[name]
        if svc then return svc end
        local new_svc = _create_instance(name)
        _services[name] = new_svc
        return new_svc
    end,
    IsLoaded = function() return true end,
    HttpGet = function() return "" end,
    HttpGetAsync = function() return "" end,
    DefineFastFlag = function(name, default) return default end,
    DefineFastInt = function(name, default) return default end,
    DefineFastString = function(name, default) return default end,
    GetFastFlag = function() return false end,
    GetFastInt = function() return 0 end,
    GetFastString = function() return "" end,
    GetEngineFeature = function() return false end,
    ReportInGoogleAnalytics = function() end,
    IsGreyListed = function() return false end,
}, _proxy_mt)

local _shared = {}
local _script_obj = _create_instance("Script")
_script_obj.Source = ""
_script_obj.Disabled = false
_script_obj.Enabled = true
_script_obj:GetHash = function() return "" end

local _debug_lib = {
    getinfo = debug.getinfo,
    getregistry = function() return _safe_env end,
    getmetatable = debug.getmetatable,
    getupvalue = debug.getupvalue,
    setupvalue = debug.setupvalue,
    getlocal = debug.getlocal,
    setlocal = debug.setlocal,
    traceback = _orig_debug_traceback,
    sethook = debug.sethook,
    setmetatable = setmetatable,
    getupvalues = function() return {} end,
    setupvalues = function() end,
    getconstants = function() return {} end,
    setconstant = function() end,
    getproto = function() return nil end,
    getprotos = function() return {} end,
    setproto = function() end,
    getstack = function() return {} end,
    setstack = function() end,
    info = function() return {} end,
}

local _safe_env = {
    _G = nil, _ENV = nil, _VERSION = "Luau",
    assert = assert,
    error = function(msg, level)
        if msg == "detected by LeakD" then return nil end
        error(msg, level or 0)
    end,
    ipairs = ipairs, next = next, pairs = pairs, pcall = _orig_pcall,
    rawequal = _orig_rawequal, rawget = rawget, rawlen = rawlen, rawset = rawset,
    select = _orig_select, setmetatable = setmetatable, getmetatable = getmetatable,
    tonumber = tonumber, tostring = tostring, type = type, typeof = _orig_type,
    xpcall = _orig_xpcall,
    unpack = _orig_unpack or table.unpack,
    getfenv = getfenv, setfenv = setfenv, loadstring = loadstring, load = load,
    newproxy = function(add)
        local u = _orig_newproxy(add)
        if add then local mt = getmetatable(u); if mt then mt.__gc = function() end end end
        return u
    end,
    string = { byte = string.byte, char = string.char, find = string.find, format = string.format, gmatch = string.gmatch, gsub = string.gsub, len = string.len, lower = string.lower, match = string.match, rep = string.rep, reverse = string.reverse, sub = string.sub, upper = string.upper, dump = string.dump },
    math = { abs = math.abs, acos = math.acos, asin = math.asin, atan = math.atan, atan2 = math.atan2, ceil = math.ceil, cos = math.cos, cosh = math.cosh, deg = math.deg, exp = math.exp, floor = math.floor, fmod = math.fmod, frexp = math.frexp, huge = math.huge, ldexp = math.ldexp, log = math.log, log10 = math.log10, max = math.max, min = math.min, modf = math.modf, pi = math.pi, pow = math.pow, rad = math.rad, random = math.random, randomseed = math.randomseed, sin = math.sin, sinh = math.sinh, sqrt = math.sqrt, tan = math.tan, tanh = math.tanh, clamp = function(v, mn, mx) return math.max(mn, math.min(mx, v)) end, sign = function(v) return v > 0 and 1 or (v < 0 and -1 or 0) end, noise = function() return 0 end, round = function(v) return math.floor(v + 0.5) end },
    table = { concat = table.concat, insert = table.insert, maxn = function(t) local n = 0; for k in pairs(t) do if type(k) == "number" and k > n then n = k end end; return n end, remove = table.remove, sort = table.sort, unpack = _orig_unpack or table.unpack, clear = function(t) for k in pairs(t) do t[k] = nil end end, create = function(count, value) local t = {}; for i = 1, count do t[i] = value end; return t end, find = function(t, value) for i, v in ipairs(t) do if v == value then return i end end; return nil end, pack = function(...) return {n = select("#", ...), ...} end, isfrozen = function() return false end, freeze = function() end, clone = function(t) local r = {}; for k, v in pairs(t) do r[k] = v end; return r end, keys = function(t) local r = {}; for k in pairs(t) do r[#r+1] = k end; return r end, values = function(t) local r = {}; for _, v in pairs(t) do r[#r+1] = v end; return r end },
    os = { clock = os.clock, date = os.date, difftime = os.difftime, time = os.time, exit = function() end, execute = function() return 0 end, getenv = function() return "" end, remove = function() end, rename = function() end, setlocale = function() return "" end, tmpname = function() return "" end },
    coroutine = { create = coroutine.create, resume = coroutine.resume, running = coroutine.running, status = coroutine.status, wrap = coroutine.wrap, yield = coroutine.yield, close = function() return true end, isyieldable = function() return false end },
    print = function(...) end, warn = function(...) end,
    game = _game, Game = _game,
    workspace = _services.Workspace, Workspace = _services.Workspace,
    script = _script_obj, Script = _script_obj,
    shared = _shared, Shared = _shared,
    plugin = _new_proxy(),
    debug = _debug_lib,
    Enum = Enum,
    Instance = { new = function(className) return _create_instance(className or "Part") end, FromExisting = function(obj) return obj end },
    Vector3 = _Vector3, Vector2 = _Vector2, CFrame = _CFrame, Color3 = _Color3, BrickColor = _BrickColor,
    UDim = { new = function(scale, offset) return { Scale = scale or 0, Offset = offset or 0 } end },
    UDim2 = _UDim2, Ray = _Ray, Region3 = _Region3, Region3int16 = _Region3int16,
    NumberRange = _NumberRange, NumberSequence = _NumberSequence, NumberSequenceKeypoint = _NumberSequenceKeypoint,
    ColorSequence = _ColorSequence, ColorSequenceKeypoint = _ColorSequenceKeypoint,
    TweenInfo = _TweenInfo, Faces = _Faces, Axes = _Axes, PhysicalProperties = _PhysicalProperties,
    DateTime = _DateTime, RaycastParams = _RaycastParams, RaycastResult = _RaycastResult,
    DockWidgetPluginGuiInfo = _DockWidgetPluginGuiInfo, CatalogSearchParams = _CatalogSearchParams,
    PathWaypoint = _PathWaypoint, OverlapParams = _OverlapParams, Random = _Random,
    bit32 = bit32 or { bxor = function(a, b) return a ~ b end, band = function(a, b) return a & b end, bor = function(a, b) return a | b end, bnot = function(a) return ~a end, lshift = function(a, b) return a << b end, rshift = function(a, b) return a >> b end, arshift = function(a, b) return a >> b end, btst = function(a, b) return (a & (1 << b)) ~= 0 end, bset = function(a, b) return a | (1 << b) end, bclear = function(a, b) return a & ~(1 << b) end, extract = function(a, field, width) return (a >> field) & ((1 << width) - 1) end, replace = function(a, v, field, width) return a & ~(((1 << width) - 1) << field) | (v << field) end },
    utf8 = utf8 or { char = function(...) return string.char(...) end, codes = function(s) return function() return 0 end end, codepoint = function(s, i, j) return nil end, graphemes = function(s) return function() return "" end end, len = function(s, i, j) return #s end, nfcnormalize = function(s) return s end, nfdnormalize = function(s) return s end, offset = function(s, n, i) return i end },
    task = { spawn = function(f, ...) f(...) end, defer = function(f, ...) f(...) end, delay = function(t, f, ...) f(...) end, wait = function(t) _fake_time = _fake_time + (t or 0) end, cancel = function() end, desynchronize = function(f) return f() end, synchronize = function(f) return f() end },
    wait = function(t) _fake_time = _fake_time + (t or 0); return t or 0 end,
    delay = function(t, f) f() end,
    spawn = function(f) f() end,
    tick = function() return _fake_time end,
    time = function() return _fake_time end,
    elapsedTime = function() return _fake_time end,
}

_safe_env._G = _safe_env
_safe_env._ENV = _safe_env
_safe_env.shared = _shared
_shared._G = _safe_env

local _env_mt = {
    __index = function(t, k)
        local v = _orig_rawget(_safe_env, k)
        if v ~= nil then return v end
        return _new_proxy()
    end,
    __newindex = function(t, k, v)
        _track_string(v)
        _orig_rawset(_safe_env, k, v)
    end,
}
local env = setmetatable({}, _env_mt)

local fh = _io.open(_inp, "rb")
if not fh then
    _write_file(_out .. "/error.txt", "cannot open input")
else
    local source = fh:read("*a")
    fh:close()
    if not source then
        _write_file(_out .. "/error.txt", "cannot read input")
    else
        local chunk, parse_err = _orig_loadstring(source, "@input")
        if not chunk then
            _write_file(_out .. "/error.txt", "parse error: " .. tostring(parse_err))
        else
            _orig_setfenv(chunk, env)
            local function error_handler(e)
                return _orig_debug_traceback(tostring(e), 2)
            end
            local ok, res = _orig_xpcall(chunk, error_handler)
            if not ok then
                _write_file(_out .. "/error.txt", tostring(res))
            end
        end
    end
end

local found_bytecode = {}
local visited = {}

local function _scan(t, depth)
    if depth > 6 then return end
    if visited[t] then return end
    visited[t] = true
    for k, v in pairs(t) do
        if _orig_type(v) == "string" and #v >= 12 and v:sub(1, 4) == "\27Lua" then
            found_bytecode[#found_bytecode + 1] = v
        elseif _orig_type(v) == "table" and not v.__is_proxy then
            _scan(v, depth + 1)
        end
    end
end

visited = {}
_scan(_safe_env, 0)
visited = {}
_scan(env, 0)
visited = {}
_scan(_shared, 0)
for _, obj in ipairs(_instances) do
    visited = {}
    _scan(obj, 0)
end

local out_parts = {}
out_parts[#out_parts + 1] = "SANDBOX_OUTPUT_START\n"
out_parts[#out_parts + 1] = "return {\n"
for i, bc in ipairs(found_bytecode) do
    local escaped = bc:gsub(".", function(c) return string.format("\\%03d", string.byte(c)) end)
    out_parts[#out_parts + 1] = '  ["bytecode_' .. i .. '"] = "' .. escaped .. '",\n'
end
out_parts[#out_parts + 1] = "}\n"
out_parts[#out_parts + 1] = "SANDBOX_OUTPUT_END\n"

_write_file(_out .. "/sandbox_output.lua", table.concat(out_parts))

for _, text in ipairs(_tracked) do
    _write_capture(text)
end

local df = _io.open(_out .. "/diag.txt", "w")
if df then
    df:write(table.concat(_log, "\n"))
    df:close()
end
