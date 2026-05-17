local _out = "OUTDIR_PLACEHOLDER"
local _inp = "INPATH_PLACEHOLDER"
local _log = {}
local _layer_count = 0
local _step_count = 0
local _tracked = {}
local _capture_count = 0
local _scheduled = {}
local _schedule_id = 0
local _fake_time = 0
local _running = true

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
local _orig_debug_getinfo = debug.getinfo
local _orig_debug_getregistry = debug.getregistry
local _orig_debug_getmetatable = debug.getmetatable
local _orig_debug_getupvalue = debug.getupvalue
local _orig_debug_setupvalue = debug.setupvalue
local _orig_debug_getlocal = debug.getlocal
local _orig_debug_setlocal = debug.setlocal
local _orig_debug_traceback = debug.traceback
local _orig_debug_sethook = debug.sethook
local _orig_coroutine_create = coroutine.create
local _orig_coroutine_resume = coroutine.resume
local _orig_coroutine_running = coroutine.running
local _orig_coroutine_status = coroutine.status
local _orig_coroutine_wrap = coroutine.wrap
local _orig_coroutine_yield = coroutine.yield

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

local _proxy_id_counter = 0
local _all_proxies = {}
local _proxy_mt = {}

_proxy_mt.__index = function(t, k)
    if k == "__proxy_id" then return _orig_rawget(t, "_pid") end
    if k == "__is_proxy" then return true end
    if k == "_pid" then return _orig_rawget(t, "_pid") end
    local v = _orig_rawget(t, k)
    if v ~= nil then return v end
    _proxy_id_counter = _proxy_id_counter + 1
    v = setmetatable({_pid = _proxy_id_counter}, _proxy_mt)
    _orig_rawset(t, k, v)
    _all_proxies[_proxy_id_counter] = v
    return v
end
_proxy_mt.__newindex = function(t, k, v) _orig_rawset(t, k, v) end
_proxy_mt.__call = function(t, ...)
    _proxy_id_counter = _proxy_id_counter + 1
    local v = setmetatable({_pid = _proxy_id_counter}, _proxy_mt)
    _all_proxies[_proxy_id_counter] = v
    return v
end
_proxy_mt.__gc = function() end
_proxy_mt.__tostring = function(t) return "Instance" end
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

local function _new_proxy(name)
    _proxy_id_counter = _proxy_id_counter + 1
    local v = setmetatable({_pid = _proxy_id_counter}, _proxy_mt)
    _all_proxies[_proxy_id_counter] = v
    return v
end

local _readonly_objects = setmetatable({}, {__mode = "k"})

local _Ray = {
    new = function(origin, direction)
        return {
            Origin = origin or _Vector3.new(),
            Direction = direction or _Vector3.new(0, 0, -1),
            Unit = direction and _Vector3.new(
                direction.x / (math.sqrt(direction.x^2 + direction.y^2 + direction.z^2) + 0.0001),
                direction.y / (math.sqrt(direction.x^2 + direction.y^2 + direction.z^2) + 0.0001),
                direction.z / (math.sqrt(direction.x^2 + direction.y^2 + direction.z^2) + 0.0001)
            ) or _Vector3.new(0, 0, -1)
        }
    end
}

local _Vector3 = {}
_Vector3.__index = _Vector3
_Vector3.__add = function(a, b) return _Vector3.new(a.x + b.x, a.y + b.y, a.z + b.z) end
_Vector3.__sub = function(a, b) return _Vector3.new(a.x - b.x, a.y - b.y, a.z - b.z) end
_Vector3.__mul = function(a, b)
    if type(a) == "number" then return _Vector3.new(a * b.x, a * b.y, a * b.z) end
    if type(b) == "number" then return _Vector3.new(a.x * b, a.y * b, a.z * b) end
    return _Vector3.new(a.x * b.x, a.y * b.y, a.z * b.z)
end
_Vector3.__div = function(a, b)
    if type(b) == "number" then return _Vector3.new(a.x / b, a.y / b, a.z / b) end
    return _Vector3.new(a.x / b.x, a.y / b.y, a.z / b.z)
end
_Vector3.__unm = function(a) return _Vector3.new(-a.x, -a.y, -a.z) end
_Vector3.__tostring = function(a) return a.x .. ", " .. a.y .. ", " .. a.z end
_Vector3.__eq = function(a, b) return a.x == b.x and a.y == b.y and a.z == b.z end
_Vector3.new = function(x, y, z)
    return setmetatable({
        X = x or 0, Y = y or 0, Z = z or 0,
        x = x or 0, y = y or 0, z = z or 0,
        Magnitude = math.sqrt((x or 0)^2 + (y or 0)^2 + (z or 0)^2),
        Unit = _Vector3.new(0, 0, 0),
    }, _Vector3)
end
_Vector3.zero = _Vector3.new(0, 0, 0)
_Vector3.one = _Vector3.new(1, 1, 1)
_Vector3.xAxis = _Vector3.new(1, 0, 0)
_Vector3.yAxis = _Vector3.new(0, 1, 0)
_Vector3.zAxis = _Vector3.new(0, 0, 1)
_Vector3.FromNormalId = function(id) return _Vector3.new(0, 1, 0) end
_Vector3.FromAxis = function(axis) return _Vector3.new(0, 1, 0) end
_Vector3.new = function(x, y, z)
    local v = {
        X = x or 0, Y = y or 0, Z = z or 0,
        x = x or 0, y = y or 0, z = z or 0,
    }
    v.Magnitude = math.sqrt(v.X^2 + v.Y^2 + v.Z^2)
    v.Unit = v.Magnitude > 0 and _Vector3.new(v.X/v.Magnitude, v.Y/v.Magnitude, v.Z/v.Magnitude) or _Vector3.new(0,0,0)
    return setmetatable(v, _Vector3)
end
_Vector3.Dot = function(a, b) return a.X * b.X + a.Y * b.Y + a.Z * b.Z end
_Vector3.Cross = function(a, b) return _Vector3.new(a.Y*b.Z - a.Z*b.Y, a.Z*b.X - a.X*b.Z, a.X*b.Y - a.Y*b.X) end
_Vector3.Lerp = function(a, b, t) return _Vector3.new(a.X+(b.X-a.X)*t, a.Y+(b.Y-a.Y)*t, a.Z+(b.Z-a.Z)*t) end
_Vector3.Min = function(a, b) return _Vector3.new(math.min(a.X,b.X), math.min(a.Y,b.Y), math.min(a.Z,b.Z)) end
_Vector3.Max = function(a, b) return _Vector3.new(math.max(a.X,b.X), math.max(a.Y,b.Y), math.max(a.Z,b.Z)) end
_Vector3.Angle = function(a, b) return math.acos((a.X*b.X+a.Y*b.Y+a.Z*b.Z)/(a.Magnitude*b.Magnitude+0.0001)) end

local _CFrame = {}
_CFrame.__index = _CFrame
_CFrame.__mul = function(a, b)
    return _CFrame.new(
        a:pointToWorldSpace(b.Position),
        b.XVector * a.XVector + b.YVector * a.YVector + b.ZVector * a.ZVector
    )
end
_CFrame.__tostring = function(a) return tostring(a.Position) end
_CFrame.new = function(...)
    local args = {...}
    if #args == 0 then
        return setmetatable({
            Position = _Vector3.new(),
            XVector = _Vector3.new(1,0,0),
            YVector = _Vector3.new(0,1,0),
            ZVector = _Vector3.new(0,0,1),
            LookVector = _Vector3.new(0,0,-1),
            RightVector = _Vector3.new(1,0,0),
            UpVector = _Vector3.new(0,1,0),
            p = _Vector3.new(),
            X = 1, Y = 0, Z = 0, R00 = 1, R01 = 0, R02 = 0,
            R10 = 0, R11 = 1, R12 = 0, R20 = 0, R21 = 0, R22 = 1,
        }, _CFrame)
    elseif #args == 1 and _orig_type(args[1]) == "table" then
        local cf = args[1]
        return setmetatable({
            Position = cf.Position or _Vector3.new(),
            XVector = cf.XVector or _Vector3.new(1,0,0),
            YVector = cf.YVector or _Vector3.new(0,1,0),
            ZVector = cf.ZVector or _Vector3.new(0,0,1),
            LookVector = cf.LookVector or _Vector3.new(0,0,-1),
            RightVector = cf.RightVector or _Vector3.new(1,0,0),
            UpVector = cf.UpVector or _Vector3.new(0,1,0),
            p = cf.Position or _Vector3.new(),
            X = cf.X or 1, Y = cf.Y or 0, Z = cf.Z or 0,
            R00 = cf.R00 or 1, R01 = cf.R01 or 0, R02 = cf.R02 or 0,
            R10 = cf.R10 or 0, R11 = cf.R11 or 1, R12 = cf.R12 or 0,
            R20 = cf.R20 or 0, R21 = cf.R21 or 0, R22 = cf.R22 or 1,
        }, _CFrame)
    elseif #args == 3 then
        local x, y, z = args[1], args[2], args[3]
        return setmetatable({
            Position = _Vector3.new(x, y, z),
            XVector = _Vector3.new(1,0,0),
            YVector = _Vector3.new(0,1,0),
            ZVector = _Vector3.new(0,0,1),
            LookVector = _Vector3.new(0,0,-1),
            RightVector = _Vector3.new(1,0,0),
            UpVector = _Vector3.new(0,1,0),
            p = _Vector3.new(x, y, z),
            X = x, Y = y, Z = z,
            R00 = 1, R01 = 0, R02 = 0,
            R10 = 0, R11 = 1, R12 = 0,
            R20 = 0, R21 = 0, R22 = 1,
        }, _CFrame)
    elseif #args == 7 then
        local px, py, pz, qx, qy, qz, qw = args[1], args[2], args[3], args[4], args[5], args[6], args[7]
        return setmetatable({
            Position = _Vector3.new(px, py, pz),
            XVector = _Vector3.new(1,0,0),
            YVector = _Vector3.new(0,1,0),
            ZVector = _Vector3.new(0,0,1),
            LookVector = _Vector3.new(0,0,-1),
            RightVector = _Vector3.new(1,0,0),
            UpVector = _Vector3.new(0,1,0),
            p = _Vector3.new(px, py, pz),
            X = px, Y = py, Z = pz,
            R00 = 1, R01 = 0, R02 = 0,
            R10 = 0, R11 = 1, R12 = 0,
            R20 = 0, R21 = 0, R22 = 1,
        }, _CFrame)
    elseif #args == 12 then
        local x, y, z, r00, r01, r02, r10, r11, r12, r20, r21, r22 = args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10], args[11], args[12]
        return setmetatable({
            Position = _Vector3.new(x, y, z),
            XVector = _Vector3.new(r00, r10, r20),
            YVector = _Vector3.new(r01, r11, r21),
            ZVector = _Vector3.new(r02, r12, r22),
            LookVector = _Vector3.new(-r02, -r12, -r22),
            RightVector = _Vector3.new(r00, r10, r20),
            UpVector = _Vector3.new(r01, r11, r21),
            p = _Vector3.new(x, y, z),
            X = x, Y = y, Z = z,
            R00 = r00, R01 = r01, R02 = r02,
            R10 = r10, R11 = r11, R12 = r12,
            R20 = r20, R21 = r21, R22 = r22,
        }, _CFrame)
    end
    return setmetatable({
        Position = _Vector3.new(),
        XVector = _Vector3.new(1,0,0),
        YVector = _Vector3.new(0,1,0),
        ZVector = _Vector3.new(0,0,1),
        LookVector = _Vector3.new(0,0,-1),
        RightVector = _Vector3.new(1,0,0),
        UpVector = _Vector3.new(0,1,0),
        p = _Vector3.new(),
        X = 1, Y = 0, Z = 0,
        R00 = 1, R01 = 0, R02 = 0,
        R10 = 0, R11 = 1, R12 = 0,
        R20 = 0, R21 = 0, R22 = 1,
    }, _CFrame)
end
_CFrame.Angles = function(rx, ry, rz) return _CFrame.new() end
_CFrame.fromOrientation = function(x, y, z, rx, ry, rz) return _CFrame.new(x, y, z) end
_CFrame.fromMatrix = function(x, y, z, r00, r01, r02, r10, r11, r12, r20, r21, r22) return _CFrame.new(x, y, z, r00, r01, r02, r10, r11, r12, r20, r21, r22) end
_CFrame.identity = _CFrame.new()
_CFrame.lookAt = function(pos, target) return _CFrame.new(pos.X, pos.Y, pos.Z) end
_CFrame.new = _CFrame.new
_CFrame.Angles = _CFrame.Angles
_CFrame.pointToWorldSpace = function(self, v) return _Vector3.new(v.X + self.X, v.Y + self.Y, v.Z + self.Z) end
_CFrame.pointToObjectSpace = function(self, v) return _Vector3.new(v.X - self.X, v.Y - self.Y, v.Z - self.Z) end
_CFrame.vectorToWorldSpace = function(self, v) return v end
_CFrame.vectorToObjectSpace = function(self, v) return v end
_CFrame.Inverse = function(self) return _CFrame.new(-self.X, -self.Y, -self.Z) end
_CFrame.Lerp = function(a, b, t) return _CFrame.new(a.X+(b.X-a.X)*t, a.Y+(b.Y-a.Y)*t, a.Z+(b.Z-a.Z)*t) end

local _Vector2 = {}
_Vector2.__index = _Vector2
_Vector2.__add = function(a, b) return _Vector2.new(a.X + b.X, a.Y + b.Y) end
_Vector2.__sub = function(a, b) return _Vector2.new(a.X - b.X, a.Y - b.Y) end
_Vector2.__mul = function(a, b)
    if type(a) == "number" then return _Vector2.new(a * b.X, a * b.Y) end
    if type(b) == "number" then return _Vector2.new(a.X * b, a.Y * b) end
    return _Vector2.new(a.X * b.X, a.Y * b.Y)
end
_Vector2.__div = function(a, b)
    if type(b) == "number" then return _Vector2.new(a.X / b, a.Y / b) end
    return _Vector2.new(a.X / b.X, a.Y / b.Y)
end
_Vector2.new = function(x, y) return setmetatable({X = x or 0, Y = y or 0, x = x or 0, y = y or 0}, _Vector2) end
_Vector2.zero = _Vector2.new(0, 0)
_Vector2.one = _Vector2.new(1, 1)

local _UDim = {}
_UDim.new = function(scale, offset) return {Scale = scale or 0, Offset = offset or 0} end

local _UDim2 = {}
_UDim2.new = function(xScale, xOffset, yScale, yOffset)
    return {
        X = _UDim.new(xScale, xOffset),
        Y = _UDim.new(yScale, yOffset),
        Width = _UDim.new(xScale, xOffset),
        Height = _UDim.new(yScale, yOffset),
    }
end

local _Color3 = {}
_Color3.new = function(r, g, b) return {R = r or 0, G = g or 0, B = b or 0, r = r or 0, g = g or 0, b = b or 0} end
_Color3.fromRGB = function(r, g, b) return _Color3.new(r, g, b) end
_Color3.fromHSV = function(h, s, v) return _Color3.new(255, 255, 255) end
_Color3.fromHex = function(hex) return _Color3.new(255, 255, 255) end
_Color3.toHSV = function(c) return 0, 0, 0 end

local _BrickColor = {}
_BrickColor.new = function(name) return {Name = name or "Medium stone grey", Color = _Color3.new(163, 162, 165)} end
_BrickColor.Random = function() return _BrickColor.new("Bright red") end
_BrickColor.palette = function(index) return _BrickColor.new("Medium stone grey") end
_BrickColor.White = function() return _BrickColor.new("White") end
_BrickColor.Gray = function() return _BrickColor.new("Medium stone grey") end
_BrickColor.DarkGray = function() return _BrickColor.new("Dark stone grey") end
_BrickColor.Black = function() return _BrickColor.new("Black") end
_BrickColor.Red = function() return _BrickColor.new("Bright red") end
_BrickColor.Yellow = function() return _BrickColor.new("Bright yellow") end
_BrickColor.Green = function() return _BrickColor.new("Bright green") end
_BrickColor.Blue = function() return _BrickColor.new("Bright blue") end

local _NumberRange = {}
_NumberRange.new = function(min, max) return {Min = min or 0, Max = max or 0} end

local _NumberSequenceKeypoint = {}
_NumberSequenceKeypoint.new = function(time, value, envelope) return {Time = time or 0, Value = value or 0, Envelope = envelope or 0} end

local _NumberSequence = {}
_NumberSequence.new = function(...) return {Keypoints = {...}} end

local _ColorSequenceKeypoint = {}
_ColorSequenceKeypoint.new = function(time, color) return {Time = time or 0, Value = color or _Color3.new()} end

local _ColorSequence = {}
_ColorSequence.new = function(...) return {Keypoints = {...}} end

local _Region3 = {}
_Region3.new = function(min, max) return {CFrame = _CFrame.new(), Size = _Vector3.new()} end

local _Region3int16 = {}
_Region3int16.new = function(min, max) return {} end

local _RaycastParams = {}
_RaycastParams.new = function() return {FilterDescendantsInstances = {}, FilterType = 0, IgnoreWater = false} end

local _RaycastResult = {}
_RaycastResult.new = function() return {Distance = 0, Instance = nil, Material = 0, Normal = _Vector3.new(), Position = _Vector3.new()} end

local _TweenInfo = {}
_TweenInfo.new = function(time, easingStyle, easingDirection, repeatCount, reverses, delayTime)
    return {
        Time = time or 1,
        EasingStyle = easingStyle or 0,
        EasingDirection = easingDirection or 0,
        RepeatCount = repeatCount or 0,
        Reverses = reverses or false,
        DelayTime = delayTime or 0,
    }
end

local _Faces = {}
_Faces.new = function(faces) return {Faces = faces or 0} end

local _Axes = {}
_Axes.new = function(axes) return {Axes = axes or 0} end

local _PhysicalProperties = {}
_PhysicalProperties.new = function(density, friction, elasticity, frictionWeight, elasticityWeight)
    return {
        Density = density or 0.7,
        Friction = friction or 0.3,
        Elasticity = elasticity or 0.5,
        FrictionWeight = frictionWeight or 100,
        ElasticityWeight = elasticityWeight or 100,
    }
end

local _DateTime = {}
_DateTime.now = function() return {UnixTimestamp = os.time()} end
_DateTime.fromUnixTimestamp = function(ts) return {UnixTimestamp = ts} end
_DateTime.fromUniversalTime = function(y, m, d, h, min, s) return {UnixTimestamp = os.time()} end
_DateTime.fromLocalTime = function(y, m, d, h, min, s) return {UnixTimestamp = os.time()} end

local _DockWidgetPluginGuiInfo = {}
_DockWidgetPluginGuiInfo.new = function(initDockState, initEnabled, initOverrideEnabledRestore, initFloatXSize, initFloatYSize, initMinWidth, initMinHeight)
    return {}
end

local _CatalogSearchParams = {}
_CatalogSearchParams.new = function() return {} end

local _PathWaypoint = {}
_PathWaypoint.new = function(position, action) return {Position = position, Action = action or 0} end

local _OverlapParams = {}
_OverlapParams.new = function() return {FilterDescendantsInstances = {}, FilterType = 0, MaxParts = 20} end

local _Random = {}
_Random.new = function(seed) return {NextNumber = function(self) return math.random() end, NextInteger = function(self, min, max) return math.random(min, max) end} end

local Enum = {
    Material = {Plastic = 256, Wood = 512, Slate = 768, Concrete = 1024, CorrodedMetal = 1280, DiamondPlate = 1536, Foil = 1792, Grass = 2048, Ice = 2304, Marble = 2560, Granite = 2816, Brick = 3072, Pebble = 3328, Sand = 3584, Fabric = 3840, SmoothPlastic = 4096, Metal = 4352, Neon = 4608, Glass = 4864, Asphalt = 5120, Basalt = 5376, CrackedLava = 5632, Cobblestone = 5888, Limestone = 6144, Mud = 6400, Pavement = 6656, Rock = 6912, Salt = 7168, Sandstone = 7424, Snow = 7680, WoodPlanks = 7936, Ground = 8192, Air = 256},
    Shape = {Ball = 0, Block = 1, Cylinder = 2},
    FormFactor = {Symmetric = 0, Brick = 1, Plate = 2, Custom = 3},
    SurfaceType = {Smooth = 0, Glue = 1, Weld = 2, Studs = 3, Inlet = 4, Universal = 5, Hinge = 6, Motor = 7, SteppingMotor = 8},
    NormalId = {Top = 0, Bottom = 1, Left = 2, Right = 3, Front = 4, Back = 5},
    HumanoidRigType = {R6 = 0, R15 = 1},
    HumanoidStateType = {RunningNoPhysics = 0, Running = 1, Climbing = 2, FallingDown = 3, Flying = 4, Freefall = 5, GettingUp = 6, Jumping = 7, Landed = 8, Physics = 9, PlatformStanding = 10, Ragdoll = 11, Seated = 12, StrafingNoPhysics = 13, Swimming = 14, Dead = 15},
    MembershipType = {None = 0, Premium = 4},
    EasingStyle = {Linear = 0, Sine = 1, Back = 2, Quad = 3, Quart = 4, Quint = 5, Bounce = 6, Elastic = 7, Exponential = 8, Circular = 9, Cubic = 10},
    EasingDirection = {In = 0, Out = 1, InOut = 2},
    Genre = {All = 0, Tutorial = 1, Adventure = 2, TownAndCity = 3, Military = 4, SciFi = 5, Fantasy = 6, FPS = 7, RPG = 8, Sports = 9, Comedy = 10, Horror = 11, Fighting = 12, Ninja = 13, Medieval = 14, Pirate = 15, Western = 16, Skater = 17},
    KeyCode = {A = 65, B = 66, C = 67, D = 68, E = 69, F = 70, G = 71, H = 72, I = 73, J = 74, K = 75, L = 76, M = 77, N = 78, O = 79, P = 80, Q = 81, R = 82, S = 83, T = 84, U = 85, V = 86, W = 87, X = 88, Y = 89, Z = 90, Space = 32, LeftShift = 304, RightShift = 303, LeftControl = 306, RightControl = 305, LeftAlt = 308, RightAlt = 307, MouseButton1 = 1, MouseButton2 = 2, MouseButton3 = 3, Unknown = 0},
    UserInputType = {MouseButton1 = 1, MouseButton2 = 2, MouseButton3 = 3, Keyboard = 4, Touch = 5, Gamepad1 = 6, Gamepad2 = 7, Gamepad3 = 8, Gamepad4 = 9, Unknown = 0},
    UserInputState = {Begin = 0, Change = 1, End = 2, Cancel = 3},
    Platform = {Windows = 0, OSX = 1, IOS = 2, Android = 3, XboxOne = 4, PS4 = 5, Unknown = 6},
    PoseEasingStyle = {Linear = 0, Constant = 1},
    PoseEasingDirection = {In = 0, Out = 1, InOut = 2},
    Font = {Legacy = 0, Arial = 1, ArialBold = 2, SourceSans = 3, SourceSansBold = 4, SourceSansLight = 5, SourceSansItalic = 6, Gotham = 7, GothamBold = 8, GothamBlack = 9, AmaticSC = 10, Creepster = 11, DenkOne = 12, Fondamento = 13, FredokaOne = 14, GrenzeGotisch = 15, IndieFlower = 16, JosefinSans = 17, Kalam = 18, LuckiestGuy = 19, Merriweather = 20, Michroma = 21, Nunito = 22, Oswald = 23, PatrickHand = 24, PermanentMarker = 25, Roboto = 26, RobotoCondensed = 27, RobotoMono = 28, Sarpanch = 29, Ubuntu = 30},
    SortOrder = {Name = 0, Size = 1, Custom = 2},
    FillDirection = {Horizontal = 0, Vertical = 1},
    TextXAlignment = {Left = 0, Center = 1, Right = 2},
    TextYAlignment = {Top = 0, Center = 1, Bottom = 2},
    ScaleType = {Stretch = 0, Slice = 1, Tile = 2, Fit = 3, Crop = 4},
    HorizontalAlignment = {Left = 0, Center = 1, Right = 2},
    VerticalAlignment = {Top = 0, Center = 1, Bottom = 2},
    AutocompleteMode = {Off = 0, Suggestions = 1, Complete = 2},
}

local _scheduler = {}
local _scheduled_tasks = {}
local _schedule_counter = 0
local _heartbeat_connections = {}
local _renderstepped_connections = {}

local function _schedule_task(delay_time, callback, repeating)
    _schedule_counter = _schedule_counter + 1
    local task = {
        id = _schedule_counter,
        time = _fake_time + (delay_time or 0),
        callback = callback,
        repeating = repeating or false,
        delay_time = delay_time or 0,
    }
    _scheduled_tasks[_schedule_counter] = task
    return task
end

local function _remove_task(task_id)
    _scheduled_tasks[task_id] = nil
end

local function _tick_scheduler()
    _fake_time = _fake_time + 0.03
    local to_run = {}
    for id, task in pairs(_scheduled_tasks) do
        if _fake_time >= task.time then
            to_run[#to_run + 1] = task
            if not task.repeating then
                _scheduled_tasks[id] = nil
            else
                task.time = _fake_time + task.delay_time
            end
        end
    end
    for _, task in ipairs(to_run) do
        local ok, err = pcall(task.callback)
        if not ok then _L("SCHEDULER_ERROR: " .. tostring(err)) end
    end
end

local _run_service = {
    Heartbeat = {
        Connect = function(self, callback)
            local conn = {Connected = true}
            conn.Disconnect = function() conn.Connected = false end
            _heartbeat_connections[#_heartbeat_connections + 1] = {conn = conn, callback = callback}
            return conn
        end,
    },
    RenderStepped = {
        Connect = function(self, callback)
            local conn = {Connected = true}
            conn.Disconnect = function() conn.Connected = false end
            _renderstepped_connections[#_renderstepped_connections + 1] = {conn = conn, callback = callback}
            return conn
        end,
    },
    Stepped = {
        Connect = function(self, callback)
            local conn = {Connected = true}
            conn.Disconnect = function() conn.Connected = false end
            return conn
        end,
    },
    IsRunning = function() return true end,
    IsClient = function() return true end,
    IsServer = function() return false end,
    IsStudio = function() return false end,
}

local _signal_class = {}
_signal_class.new = function()
    local connections = {}
    local signal = {}
    signal.Connect = function(self, callback)
        local conn = {Connected = true}
        conn.Disconnect = function() conn.Connected = false; connections[conn] = nil end
        connections[conn] = callback
        return conn
    end
    signal.Fire = function(self, ...)
        local args = {...}
        for conn, callback in pairs(connections) do
            if conn.Connected then
                pcall(callback, unpack(args))
            end
        end
    end
    signal.Wait = function(self)
        return nil
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
local _instance_count = 0

local function _create_instance(className)
    _instance_count = _instance_count + 1
    local obj = {}
    obj.className = className
    obj.Name = className
    obj.Parent = nil
    obj.Archivable = true
    obj.ClassName = className
    obj.DataCost = 0
    obj.RobloxLocked = false
    obj.instanceId = _instance_count
    obj.Changed = _signal_class.new()
    obj.AncestryChanged = _signal_class.new()
    obj.AttributeChanged = _signal_class.new()
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
            if inst == self then
                table.remove(_instances, i)
                break
            end
        end
    end
    obj.FindFirstChild = function(self, name, recursive)
        for _, child in ipairs(_instances) do
            if child.Parent == self and child.Name == name then return child end
        end
        return nil
    end
    obj.FindFirstChildOfClass = function(self, cn) return nil end
    obj.FindFirstChildWhichIsA = function(self, cn, recursive) return nil end
    obj.FindFirstAncestorWhichIsA = function(self, cn) return nil end
    obj.GetChildren = function(self)
        local children = {}
        for _, child in ipairs(_instances) do
            if child.Parent == self then children[#children+1] = child end
        end
        return children
    end
    obj.GetDescendants = function(self) return {} end
    obj.GetFullName = function(self)
        local name = self.Name
        local parent = self.Parent
        while parent do
            name = parent.Name .. "." .. name
            parent = parent.Parent
        end
        return name
    end
    obj.IsA = function(self, cn) return className == cn end
    obj.IsAncestorOf = function(self, descendant) return false end
    obj.IsDescendantOf = function(self, ancestor)
        local parent = self.Parent
        while parent do
            if parent == ancestor then return true end
            parent = parent.Parent
        end
        return false
    end
    obj.WaitForChild = function(self, name, timeout)
        return nil
    end

    if className == "Part" or className == "MeshPart" or className == "WedgePart" or className == "CornerWedgePart" then
        obj.Position = _Vector3.new()
        obj.Size = _Vector3.new(4, 1.2, 2)
        obj.Color = _Color3.new(163, 162, 165)
        obj.Material = Enum.Material.Plastic
        obj.Anchored = false
        obj.CanCollide = true
        obj.CanTouch = true
        obj.CanQuery = true
        obj.Transparency = 0
        obj.Reflectance = 0
        obj.Shape = Enum.Shape.Block
        obj.FormFactor = Enum.FormFactor.Symmetric
        obj.BrickColor = _BrickColor.new("Medium stone grey")
        obj.CFrame = _CFrame.new()
        obj.RotVelocity = _Vector3.new()
        obj.Velocity = _Vector3.new()
        obj.Mass = 1
        obj.Friction = 0.3
        obj.Elasticity = 0.5
        obj.CustomPhysicalProperties = _PhysicalProperties.new()
        obj.LocalTransparencyModifier = 0
        obj.Locked = false
        obj.CastShadow = true
        obj.ReceiveAge = 0
        obj.Touched = _signal_class.new()
        obj.TouchEnded = _signal_class.new()
        obj:MakeJoints = function() end
        obj:BreakJoints = function() end
        obj:GetConnectedParts = function() return {} end
        obj:GetJoints = function() return {} end
        obj:GetMass = function() return 1 end
        obj:GetNetworkOwner = function() return nil end
        obj:GetNetworkPing = function() return 0 end
        obj:Resize = function(normalId, deltaAmount) end
        obj:SetNetworkOwner = function(owner) end
        obj:ApplyAngularImpulse = function(impulse) end
        obj:ApplyImpulse = function(impulse) end
        obj:ApplyImpulseAtPosition = function(impulse, position) end
        obj:GetVelocityAtPosition = function(position) return _Vector3.new() end
        obj:CanSetNetworkOwnership = function() return true end
        obj:GetRootPart = function() return obj end
        obj:GetTouchingParts = function() return {} end
        obj:IsGrounded = function() return true end
        obj:PivotTo = function(cf) obj.CFrame = cf end
    elseif className == "Model" then
        obj.PrimaryPart = nil
        obj.WorldPivot = _CFrame.new()
        obj.ModelInPrimary = _signal_class.new()
        obj:GetPrimaryPartCFrame = function() return _CFrame.new() end
        obj:SetPrimaryPartCFrame = function(cf) end
        obj:MoveTo = function(pos) end
        obj:GetBoundingBox = function() return _CFrame.new(), _Vector3.new() end
        obj:GetExtentsSize = function() return _Vector3.new() end
        obj:BreakJoints = function() end
        obj:MakeJoints = function() end
        obj:TranslateBy = function(delta) end
    elseif className == "Humanoid" then
        obj.RigType = Enum.HumanoidRigType.R6
        obj.Health = 100
        obj.MaxHealth = 100
        obj.WalkSpeed = 16
        obj.JumpPower = 50
        obj.HipHeight = 2
        obj.AutoRotate = true
        obj.PlatformStand = false
        obj.Sit = false
        obj.TargetPoint = _Vector3.new()
        obj.WalkToPoint = _Vector3.new()
        obj.WalkToPart = nil
        obj.SeatPart = nil
        obj.MoveDirection = _Vector3.new()
        obj.Died = _signal_class.new()
        obj.Jumping = _signal_class.new()
        obj.FreeFalling = _signal_class.new()
        obj.FallingDown = _signal_class.new()
        obj.GettingUp = _signal_class.new()
        obj.Landed = _signal_class.new()
        obj.Running = _signal_class.new()
        obj.Seated = _signal_class.new()
        obj.StateChanged = _signal_class.new()
        obj.DisplayDistanceType = "None"
        obj.NameDisplayDistance = 0
        obj.HealthDisplayDistance = 0
        obj.HealthDisplayType = "AlwaysOn"
        obj:TakeDamage = function(amount) obj.Health = math.max(0, obj.Health - amount) end
        obj:LoadAnimation = function(anim) return {Play = function() end, Stop = function() end, Looped = false, Priority = 0, AnimationId = ""} end
        obj:Move = function(dir, relativeToCamera) end
        obj:MoveTo = function(location, part) end
        obj:ApplyDescription = function(desc) end
        obj:GetState = function() return Enum.HumanoidStateType.Running end
        obj:GetStateEnabled = function(state) return true end
        obj:SetStateEnabled = function(state, enabled) end
        obj:ChangeState = function(state) end
        obj:GetAccessories = function() return {} end
        obj:GetAppliedDescription = function() return {} end
        obj:AddAccessory = function(accessory) end
        obj:RemoveAccessories = function() end
        obj:ReplaceBodyPartR15 = function(part, replacement) end
        obj:GetBodyPartR15 = function(part) return nil end
    elseif className == "Animator" then
        obj:LoadAnimation = function(anim) return {Play = function() end, Stop = function() end} end
    elseif className == "ScreenGui" then
        obj.Enabled = true
        obj.IgnoreGuiInset = false
        obj.DisplayOrder = 0
        obj.ResetOnSpawn = true
        obj.ZIndexBehavior = 0
        obj.ScreenInsets = 0
    elseif className == "Frame" or className == "ScrollingFrame" then
        obj.BackgroundColor3 = _Color3.new(255, 255, 255)
        obj.BackgroundTransparency = 0
        obj.BorderColor3 = _Color3.new(0, 0, 0)
        obj.BorderSizePixel = 1
        obj.Position = _UDim2.new(0, 0, 0, 0)
        obj.Size = _UDim2.new(1, 0, 1, 0)
        obj.AnchorPoint = _Vector2.new()
        obj.Rotation = 0
        obj.Visible = true
        obj.Active = false
        obj.Selectable = false
        obj.SelectionOrder = 0
        obj.ZIndex = 1
        obj.LayoutOrder = 0
        obj.ClipsDescendants = false
    elseif className == "TextLabel" or className == "TextButton" or className == "TextBox" then
        obj.Text = ""
        obj.TextColor3 = _Color3.new(0, 0, 0)
        obj.TextTransparency = 0
        obj.TextSize = 14
        obj.Font = Enum.Font.SourceSans
        obj.TextScaled = false
        obj.TextWrapped = false
        obj.TextXAlignment = Enum.TextXAlignment.Left
        obj.TextYAlignment = Enum.TextYAlignment.Center
        obj.TextStrokeColor3 = _Color3.new(0, 0, 0)
        obj.TextStrokeTransparency = 1
        obj.BackgroundColor3 = _Color3.new(255, 255, 255)
        obj.BackgroundTransparency = 0
        obj.BorderColor3 = _Color3.new(0, 0, 0)
        obj.BorderSizePixel = 1
        obj.Position = _UDim2.new(0, 0, 0, 0)
        obj.Size = _UDim2.new(1, 0, 1, 0)
        obj.AnchorPoint = _Vector2.new()
        obj.Rotation = 0
        obj.Visible = true
        obj.Active = false
        obj.Selectable = false
        obj.SelectionOrder = 0
        obj.ZIndex = 1
        obj.LayoutOrder = 0
    elseif className == "ImageLabel" or className == "ImageButton" then
        obj.Image = ""
        obj.ImageColor3 = _Color3.new(255, 255, 255)
        obj.ImageTransparency = 0
        obj.ImageRectOffset = _Vector2.new()
        obj.ImageRectSize = _Vector2.new()
        obj.ScaleType = Enum.ScaleType.Stretch
        obj.SliceCenter = {X = 0, Y = 0, Width = 0, Height = 0}
        obj.TileSize = _UDim2.new(1, 0, 1, 0)
        obj.BackgroundColor3 = _Color3.new(255, 255, 255)
        obj.BackgroundTransparency = 0
        obj.BorderColor3 = _Color3.new(0, 0, 0)
        obj.BorderSizePixel = 1
        obj.Position = _UDim2.new(0, 0, 0, 0)
        obj.Size = _UDim2.new(1, 0, 1, 0)
        obj.AnchorPoint = _Vector2.new()
        obj.Rotation = 0
        obj.Visible = true
    elseif className == "Sound" or className == "SoundGroup" then
        obj.SoundId = ""
        obj.Volume = 0.5
        obj.PlaybackSpeed = 1
        obj.Looped = false
        obj.Playing = false
        obj.IsLoaded = false
        obj.TimePosition = 0
        obj.TimeLength = 0
        obj.PlaybackRegionsEnabled = false
        obj:Play = function() obj.Playing = true end
        obj:Stop = function() obj.Playing = false end
        obj:Pause = function() obj.Playing = false end
        obj:Resume = function() obj.Playing = true end
    elseif className == "RemoteEvent" then
        obj.OnClientEvent = _signal_class.new()
        obj.OnServerEvent = _signal_class.new()
        obj:FireClient = function(player, ...) end
        obj:FireServer = function(...) end
        obj:FireAllClients = function(...) end
    elseif className == "RemoteFunction" then
        obj.OnClientInvoke = function(...) return nil end
        obj.OnServerInvoke = function(...) return nil end
        obj:InvokeClient = function(player, ...) return nil end
        obj:InvokeServer = function(...) return nil end
    elseif className == "BindableEvent" then
        obj.Event = _signal_class.new()
        obj:Fire = function(...) obj.Event:Fire(...) end
    elseif className == "BindableFunction" then
        obj.OnInvoke = function(...) return nil end
        obj:Invoke = function(...) return nil end
    elseif className == "ProximityPrompt" then
        obj.Triggered = _signal_class.new()
        obj.TriggerEnded = _signal_class.new()
        obj.ActionText = ""
        obj.Enabled = true
        obj.HoldDuration = 0
        obj.KeyboardKeyCode = 0
        obj.GamepadKeyCode = 0
        obj.RequiresLineOfSight = true
        obj.MaxActivationDistance = 10
    elseif className == "Tool" then
        obj.Enabled = true
        obj.Grip = _CFrame.new()
        obj.GripForward = _Vector3.new(0, 0, -1)
        obj.GripRight = _Vector3.new(1, 0, 0)
        obj.GripUp = _Vector3.new(0, 1, 0)
        obj.CanBeDropped = true
        obj.ManualActivationOnly = false
        obj.Activated = _signal_class.new()
        obj.Deactivated = _signal_class.new()
        obj.Equipped = _signal_class.new()
        obj.Unequipped = _signal_class.new()
    elseif className == "HopperBin" then
        obj.BinType = 0
        obj.Active = false
        obj.Activated = _signal_class.new()
        obj.Deactivated = _signal_class.new()
        obj.Selected = _signal_class.new()
        obj.Deselected = _signal_class.new()
    elseif className == "Animation" then
        obj.AnimationId = ""
    elseif className == "Attachment" then
        obj.Position = _Vector3.new()
        obj.Rotation = _Vector3.new()
        obj.Axis = _Vector3.new(1, 0, 0)
        obj.SecondaryAxis = _Vector3.new(0, 1, 0)
        obj.WorldPosition = _Vector3.new()
        obj.WorldRotation = _Vector3.new()
        obj.CFrame = _CFrame.new()
        obj.WorldCFrame = _CFrame.new()
        obj.Visible = false
    elseif className == "Trail" then
        obj.Attachment0 = nil
        obj.Attachment1 = nil
        obj.Color = _ColorSequence.new(_ColorSequenceKeypoint.new(0, _Color3.new(255, 255, 255)))
        obj.Enabled = true
        obj.Lifetime = 2
        obj.MinLength = 0.1
        obj.MaxLength = 0.2
        obj.Texture = ""
        obj.Transparency = _NumberSequence.new(_NumberSequenceKeypoint.new(0, 1))
        obj.WidthScale = _NumberSequence.new(_NumberSequenceKeypoint.new(0, 1))
        obj.FaceCamera = false
    elseif className == "Beam" then
        obj.Attachment0 = nil
        obj.Attachment1 = nil
        obj.Color = _ColorSequence.new(_ColorSequenceKeypoint.new(0, _Color3.new(255, 255, 255)))
        obj.Enabled = true
        obj.FaceCamera = false
        obj.LightEmission = 0
        obj.LightInfluence = 0
        obj.Segments = 10
        obj.Texture = ""
        obj.TextureLength = 1
        obj.TextureMode = 0
        obj.Transparency = _NumberSequence.new(_NumberSequenceKeypoint.new(0, 0))
        obj.Width0 = 0.1
        obj.Width1 = 0.1
        obj.CurveSize0 = 0.1
        obj.CurveSize1 = 0.1
        obj.ZOffset = 0
    end

    _instances[#_instances + 1] = obj
    return obj
end

local _teams = {}
local _players_list = {}
local _local_player = {
    Name = "Player",
    DisplayName = "Player",
    UserId = 1,
    AccountAge = 365,
    MembershipType = Enum.MembershipType.Premium,
    Team = nil,
    TeamColor = _BrickColor.new("Medium stone grey"),
    Character = nil,
    Backpack = _create_instance("Tool"),
    PlayerGui = _create_instance("ScreenGui"),
    PlayerScripts = _create_instance("Script"),
    StarterGear = _create_instance("StarterGear"),
    leaderstats = {},
    DataReady = false,
    DataLoaded = _signal_class.new(),
    CharacterAdded = _signal_class.new(),
    CharacterRemoving = _signal_class.new(),
    Idled = _signal_class.new(),
    Chatted = _signal_class.new(),
    PlayerRemoving = _signal_class.new(),
    RespawnLocation = nil,
    Neutral = false,
    Respawned = _signal_class.new(),
    userId = 1,
    UserName = "Player",
    playerId = 1,
    PlayerScriptsLoaded = false,
    BanCount = 0,
    BanHistory = {},
    CameraMode = 0,
    DevCameraOcclusionMode = 0,
    DevEnableMouseLock = false,
    FollowUserId = 0,
    AutoJumpEnabled = true,
    CanLoadCharacterAppearance = true,
    CharacterAppearanceLoaded = function() end,
    CharacterAppearance = "",
    ChatMode = 0,
    GameplayPaused = false,
    HasCharacterAppearanceLoaded = false,
    HealthDisplayDistance = 100,
    LocaleId = "en-us",
    NameDisplayDistance = 100,
    ReplicationFocus = nil,
    Respawn = function() end,
    LoadCharacter = function() end,
    LoadCharacterWithHumanoidDescription = function() end,
    IsFriendsWith = function(id) return false end,
    IsInGroup = function(id) return false end,
    GetRoleInGroup = function(id) return "Guest" end,
    GetRankInGroup = function(id) return 0 end,
    GetFriendsOnline = function() return {} end,
    GetFriendsAsync = function() return {} end,
    GetGameSessionID = function() return "" end,
    Kick = function(msg) end,
    Move = function(pos) end,
    DistanceFromCharacter = function(pos) return 0 end,
    GetMouse = function() return _new_proxy("Mouse") end,
    GetUnder13 = function() return false end,
    ClearAllChildren = function() end,
    Destroy = function() end,
    FindFirstChild = function() return nil end,
    FindFirstChildOfClass = function() return nil end,
    FindFirstChildWhichIsA = function() return nil end,
    GetChildren = function() return {} end,
    GetDescendants = function() return {} end,
    GetFullName = function() return "Player" end,
    IsA = function(cn) return cn == "Player" end,
    IsAncestorOf = function() return false end,
    IsDescendantOf = function() return false end,
    WaitForChild = function() return nil end,
}

local Players = {
    LocalPlayer = _local_player,
    RespawnTime = 5,
    BubbleChat = true,
    CharacterAutoLoads = true,
    ClassicChat = true,
    MaxPlayers = 10,
    NumPlayers = 1,
    PreferredPlayers = 1,
    PlayerAdded = _signal_class.new(),
    PlayerRemoving = _signal_class.new(),
    GameStarted = _signal_class.new(),
    GetPlayers = function() return {_local_player} end,
    GetPlayerByUserId = function(id) return _local_player end,
    GetPlayerFromCharacter = function(char) return _local_player end,
    GetNameFromUserIdAsync = function(id) return "Player" end,
    GetUserIdFromNameAsync = function(name) return 1 end,
    CreateHumanoidModelFromUserId = function(id) return _create_instance("Model") end,
    CreateHumanoidModelFromDescription = function(desc) return _create_instance("Model") end,
    GetCharacterAppearanceInfoAsync = function(id) return {} end,
    GetCharacterAppearanceAsync = function(id) return "" end,
    GetFriendsAsync = function(id) return {} end,
    GetGroupsAsync = function(id) return {} end,
    GetHumanoidDescriptionFromOutfitId = function(id) return {} end,
    GetHumanoidDescriptionFromUserId = function(id) return {} end,
    GetOutfits = function(id) return {} end,
    GetUserInfosAsync = function(ids) return {} end,
    ReportAbuse = function(player, reason, message) end,
    GetCharacterAppearanceInfoById = function(id) return {} end,
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
    HttpService = {GetAsync = function(url) return "" end, PostAsync = function(url, data) return "" end, RequestAsync = function(opts) return {} end, GenerateGUID = function() return "00000000-0000-0000-0000-000000000000" end, JSONEncode = function(t) return "{}" end, JSONDecode = function(s) return {} end, UrlEncode = function(s) return s end},
    MarketplaceService = {PlayerOwnsAsset = function(p, id) return false end, PromptPurchase = function(p, id) end, PromptGamePassPurchase = function(p, id) end, PromptBundlePurchase = function(p, id) end, GetProductInfo = function(id) return {} end, UserOwnsGamePassAsync = function(id) return false end, PlayerHasPass = function(p, id) return false end},
    TeleportService = {Teleport = function(placeId, player) end, TeleportAsync = function(placeId, players) end, TeleportPartyAsync = function(placeId, players) end, GetLocalPlayerTeleportData = function() return {} end, SetTeleportData = function(data) end, SetTeleportSetting = function(setting, value) end, GetTeleportSetting = function(setting) return "" end, ReserveServer = function(placeId) return {} end},
    Chat = {Chat = function(part, message) end, InvokeChatCallback = function() end, RegisterChatCallback = function() end, FilterStringAsync = function(msg, from, to) return msg end, FilterStringForBroadcast = function(msg, from) return msg end, FilterStringForPlayerAsync = function(msg, player) return msg end, CanUsersChatAsync = function(u1, u2) return true end, CanUserChatAsync = function(u1) return true end},
    InsertService = {LoadAsset = function(id) return {} end, LoadAssetVersion = function(id, ver) return {} end, CreateMeshPartAsync = function(meshId, col, tex) return _create_instance("MeshPart") end, GetFreeDecals = function() return {} end, GetFreeModels = function() return {} end, GetUserCategories = function(id) return {} end, ApproveAssetVersion = function(id, ver) end, GetBaseCategories = function() return {} end, GetBaseSets = function() return {} end, GetCollection = function(id) return {} end},
    RunService = _run_service,
    LogService = {GetLogHistory = function() return {} end, ClearLog = function() end},
    AnalyticsService = {LogCustomEvent = function(name, data) end, LogEconomyEvent = function() end, LogFunnelStepEvent = function() end, LogProgressionEvent = function() end, LogProgressionCompleteEvent = function() end, FireEvent = function(name, data) end, FireInGameEconomyEvent = function() end, FireLogEvent = function() end},
    AssetService = {CreatePlaceAsync = function(name, template, desc) return 0 end, SavePlaceAsync = function() end, CreatePlaceInPlayerInventoryAsync = function(player, name, template, desc) return 0 end, GetBundleDetailsAsync = function(id) return {} end, GetGamePlacesAsync = function() return {} end, SearchAsync = function(query) return {} end, CreateEditableImageAsync = function() return {} end, CreateEditableMeshAsync = function() return {} end},
    BadgeService = {AwardBadge = function(player, id) return true end, UserHasBadge = function(player, id) return false end, UserHasBadgeAsync = function(player, id) return false end, GetBadgeInfoAsync = function(id) return {} end, IsBadgeDisabled = function(id) return false end, IsBadgeLegal = function(id) return true end},
    BrowserService = {OpenBrowserWindow = function(url) end, ReturnToJavaScript = function(data) end, ExecuteJavaScript = function(code) end, OpenNativeOverlay = function(opts) end, OpenScreenshots = function() end, CloseBrowserWindow = function() end, SetGlobalMetaTag = function(tag, content) end},
    ContextActionService = {BindAction = function(name, fn, touch, keys) end, UnbindAction = function(name) end, BindActionAtPriority = function(name, fn, touch, prio, keys) end, UnbindAllActions = function() end, GetCurrentLocalToolIcon = function() return "" end, GetAllBoundActionInfo = function() return {} end, GetBoundActionInfo = function(name) return nil end, SetImage = function(name, image) end, SetPosition = function(name, pos) end, SetTitle = function(name, title) end},
    CoreGui = _create_instance("ScreenGui"),
    CorePackages = _create_instance("Folder"),
    VRService = {GetDeviceInfo = function() return {} end, IsVRDeviceActive = function() return false end, VREnabled = false, VRDeviceActive = false},
    UserInputService = {InputBegan = _signal_class.new(), InputChanged = _signal_class.new(), InputEnded = _signal_class.new(), TouchStarted = _signal_class.new(), TouchMoved = _signal_class.new(), TouchEnded = _signal_class.new(), MouseBehavior = 0, MouseEnabled = true, TouchEnabled = true, GamepadEnabled = false, KeyboardEnabled = true, AccelerometerEnabled = false, GyroscopeEnabled = false, VREnabled = false, IsGamepadButtonDown = function() return false end, IsKeyDown = function() return false end, IsMouseButtonPressed = function() return false end, GetDeviceAcceleration = function() return _Vector3.new() end, GetDeviceGravity = function() return _Vector3.new() end, GetDeviceRotation = function() return _CFrame.new() end, GetGamepadState = function() return {} end, GetGamepadConnected = function() return false end, GetLastInputType = function() return 0 end, GetMouseDelta = function() return _Vector2.new() end, GetMouseLocation = function() return _Vector2.new() end, GetNavigationGamepads = function() return {} end, GetPlatform = function() return Enum.Platform.Windows end, GetSupportedGamepadKeyCodes = function() return {} end, IsNavigationBlocked = function() return false end, SetNavigationBlocked = function(b) end, GetConnectedGamepads = function() return {} end},
    ScriptContext = _create_instance("ScriptContext"),
    GuiService = {GetGuiInset = function() return _Vector2.new() end, AddSelectionParent = function() end, RemoveSelectionParent = function() end, Select = function() end, Deselect = function() end, CloseInspectMenu = function() end, GetEmotesMenuOpen = function() return false end, GetErrorType = function() return 0 end, GetInspectMenuEnabled = function() return false end, IsModal = function() return false end, IsTenFootInterface = function() return false end, SetEmotesMenuOpen = function() end, SetInspectMenuEnabled = function() end, AutoSelectGuiEnabled = true, CoreGuiNavigationEnabled = true, SelectedCoreObject = nil, SelectedObject = nil, TopbarInset = _Vector2.new(), MenuIsOpen = false},
    SocialService = {CanSendGameInviteAsync = function(player) return true end, PromptGameInvite = function(player) end, GetFriendsInfo = function() return {} end, GetUnreadFriendRequestCount = function() return 0 end, PromptPhoneBook = function() end, PromptPhoneNumber = function() end, PromptFriendRequest = function() end},
    GameSettings = _create_instance("GameSettings"),
    PhysicsService = {CreateCollisionGroup = function(name) return 0 end, CollisionGroupContainsPart = function(group, part) return false end, CollisionGroupSetCollidable = function(group1, group2, collidable) end, GetCollisionGroups = function() return {} end, GetCollisionGroupId = function(name) return 0 end, GetCollisionGroupName = function(id) return "" end, GetMaxCollisionGroups = function() return 64 end, GetRegisteredCollisionGroups = function() return {} end, RegisterCollisionGroup = function(name) end, RemoveCollisionGroup = function(id) end, SetPartCollisionGroup = function(part, group) end},
    Selection = _create_instance("Selection"),
    StudioService = _create_instance("StudioService"),
    TextService = {GetTextSize = function(text, size, font, frameSize) return _Vector2.new() end, FilterStringAsync = function(text, from) return text end, FilterStringForBroadcast = function(text, from) return text end, FilterStringForPlayerAsync = function(text, player) return text end},
    TweenService = {Create = function(obj, info, props) return {Play = function() end, Pause = function() end, Cancel = function() end, PlaybackState = 0} end},
    CollectionService = {GetInstanceAddedSignal = function(tag) return _signal_class.new() end, GetInstanceRemovedSignal = function(tag) return _signal_class.new() end, GetTagged = function(tag) return {} end, HasTag = function(inst, tag) return false end, AddTag = function(inst, tag) end, RemoveTag = function(inst, tag) end, GetAllTags = function() return {} end, GetTags = function(inst) return {} end},
    Debris = {AddItem = function(item, lifetime) _schedule_task(lifetime, function() if item.Destroy then item:Destroy() end end) end},
    PathfindingService = {CreatePath = function(opts) return {ComputeAsync = function(start, finish) return 0 end, GetWaypoints = function() return {} end} end},
    ProximityPromptService = _create_instance("ProximityPromptService"),
    GroupService = {GetGroupInfoAsync = function(id) return {} end, GetGroupsAsync = function(id) return {} end, GetAlliesAsync = function(id) return {} end, GetEnemiesAsync = function(id) return {} end, IsInGroup = function(id, groupId) return false end, GetGroupRolesInfoAsync = function(id) return {} end, GetPrimaryGroupInfoAsync = function(id) return {} end},
    LocalizationService = {GetTranslatorForPlayerAsync = function(player) return {FormatByKey = function(key, args) return key end} end},
    MessagingService = {PublishAsync = function(topic, message) end, SubscribeAsync = function(topic, callback) return {Disconnect = function() end} end},
    MemoryStoreService = {GetHashMap = function(name) return {GetAsync = function(key) return nil end, SetAsync = function(key, value, expiration) end} end},
    AvatarEditorService = {PromptCreateOutfit = function(humanoidDescription, rig) end, PromptSaveAvatar = function(humanoidDescription, rig) end, SearchCatalog = function(params) return {} end},
    DataStoreService = {GetDataStore = function(name, scope, opts) return {GetAsync = function(key) return nil end, SetAsync = function(key, value) end, UpdateAsync = function(key, callback) return nil end, RemoveAsync = function(key) end, IncrementAsync = function(key, delta) return 0 end, ListKeysAsync = function(prefix) return {} end, ListVersionsAsync = function(key) return {} end, GetVersionAsync = function(key, version) return nil end} end},
}

local _game = setmetatable({
    PlaceId = 12345678,
    PlaceVersion = 1,
    JobId = "00000000-0000-0000-0000-000000000000",
    CreatorId = 1,
    CreatorType = 0,
    VIPServerId = "",
    VIPServerOwnerId = 0,
    Workspace = _services.Workspace,
    Players = _services.Players,
    Lighting = _services.Lighting,
    ReplicatedStorage = _services.ReplicatedStorage,
    ServerStorage = _services.ServerStorage,
    ServerScriptService = _services.ServerScriptService,
    StarterGui = _services.StarterGui,
    StarterPack = _services.StarterPack,
    StarterPlayer = _services.StarterPlayer,
    SoundService = _services.SoundService,
    GetService = function(self, name)
        local svc = _services[name]
        if svc then return svc end
        local new_svc = _create_instance(name)
        _services[name] = new_svc
        return new_svc
    end,
    IsLoaded = function() return true end,
    IsGravityWell = function() return false end,
    GetObjects = function(assetId) return {_create_instance("Model")} end,
    GetObjectsAsync = function(assetId) return {_create_instance("Model")} end,
    InsertObjectsAndJoinIfLegacyAsync = function(assetId) return {_create_instance("Model")} end,
    HttpGet = function(url) return "" end,
    HttpGetAsync = function(url) return "" end,
    HttpPostAsync = function(url, data) return "" end,
    DefineFastFlag = function(name, default) return default end,
    DefineFastInt = function(name, default) return default end,
    DefineFastString = function(name, default) return default end,
    GetFastFlag = function(name) return false end,
    GetFastInt = function(name) return 0 end,
    GetFastString = function(name) return "" end,
    GetEngineFeature = function(name) return false end,
    SetFastFlagForTesting = function(name, value) end,
    ReportInGoogleAnalytics = function(category, action, label, value) end,
    IsGreyListed = function() return false end,
}, _proxy_mt)

local _shared = {}
local _plugin_globals = {}

local _script_obj = _create_instance("Script")
_script_obj.Source = ""
_script_obj.Disabled = false
_script_obj.LinkedSource = ""
_script_obj.CurrentEditor = nil
_script_obj.Enabled = true
_script_obj:GetHash = function() return "" end
_script_obj:GetScriptOptions = function() return {} end
_script_obj:SetScriptOptions = function() end

local _debug_lib = {
    getinfo = _orig_debug_getinfo,
    getregistry = function() return _safe_env end,
    getmetatable = _orig_debug_getmetatable,
    getupvalue = _orig_debug_getupvalue,
    setupvalue = _orig_debug_setupvalue,
    getlocal = _orig_debug_getlocal,
    setlocal = _orig_debug_setlocal,
    traceback = _orig_debug_traceback,
    sethook = _orig_debug_sethook,
    setmetatable = setmetatable,
    getupvalues = function(f) return {} end,
    setupvalues = function(f, t) end,
    getconstants = function(f) return {} end,
    setconstant = function(f, idx, val) end,
    getproto = function(f, idx) return nil end,
    getprotos = function(f) return {} end,
    setproto = function(f, idx, proto) end,
    getstack = function(th, level) return {} end,
    setstack = function(th, level, info) end,
    info = function(th, what) return {} end,
    profilebegin = function() end,
    profileend = function() end,
    getmemory = function() return 0 end,
}

local _safe_env = {
    _G = nil,
    _ENV = nil,
    _VERSION = "Luau",
    assert = assert,
    error = function(msg, level)
        if msg == "detected by LeakD" then return nil end
        error(msg, level or 0)
    end,
    ipairs = ipairs,
    next = next,
    pairs = pairs,
    pcall = _orig_pcall,
    rawequal = _orig_rawequal,
    rawget = rawget,
    rawlen = rawlen,
    rawset = rawset,
    select = _orig_select,
    setmetatable = setmetatable,
    getmetatable = getmetatable,
    tonumber = tonumber,
    tostring = tostring,
    type = type,
    typeof = function(v)
        if _orig_type(v) == "table" and v.__is_proxy then return "Instance" end
        return _orig_type(v)
    end,
    xpcall = _orig_xpcall,
    unpack = _orig_unpack or table.unpack,
    getfenv = _orig_getfenv,
    setfenv = _orig_setfenv,
    loadstring = loadstring,
    load = load,
    newproxy = function(add)
        local u = _orig_newproxy(add)
        if add then
            local mt = getmetatable(u)
            if mt then mt.__gc = function() end end
        end
        return u
    end,
    string = {
        byte = string.byte, char = string.char, find = string.find,
        format = string.format, gmatch = string.gmatch, gsub = string.gsub,
        len = string.len, lower = string.lower, match = string.match,
        rep = string.rep, reverse = string.reverse, sub = string.sub,
        upper = string.upper, dump = string.dump, pack = string.pack or function() return "" end,
        unpack = string.unpack or function() return 0, 1 end, split = function(s, sep) return {} end,
    },
    math = {
        abs = math.abs, acos = math.acos, asin = math.asin, atan = math.atan,
        atan2 = math.atan2, ceil = math.ceil, cos = math.cos, cosh = math.cosh,
        deg = math.deg, exp = math.exp, floor = math.floor, fmod = math.fmod,
        frexp = math.frexp, huge = math.huge, ldexp = math.ldexp, log = math.log,
        log10 = math.log10, max = math.max, min = math.min, modf = math.modf,
        pi = math.pi, pow = math.pow, rad = math.rad, random = math.random,
        randomseed = math.randomseed, sin = math.sin, sinh = math.sinh,
        sqrt = math.sqrt, tan = math.tan, tanh = math.tanh, clamp = function(v, mn, mx) return math.max(mn, math.min(mx, v)) end,
        sign = function(v) return v > 0 and 1 or (v < 0 and -1 or 0) end,
        noise = function(x, y, z) return 0 end,
        round = function(v) return math.floor(v + 0.5) end,
        ldexp = math.ldexp or function() return 0 end,
    },
    table = {
        concat = table.concat, insert = table.insert,
        maxn = function(t) local n = 0; for k in pairs(t) do if type(k) == "number" and k > n then n = k end end; return n end,
        remove = table.remove, sort = table.sort,
        unpack = _orig_unpack or table.unpack, clear = function(t) for k in pairs(t) do t[k] = nil end end,
        create = function(count, value) local t = {}; for i = 1, count do t[i] = value end; return t end,
        find = function(t, value) for i, v in ipairs(t) do if v == value then return i end end; return nil end,
        move = function(src, srcStart, srcEnd, destStart, dest) for i = srcStart, srcEnd do dest[destStart + i - srcStart] = src[i] end; return dest end,
        pack = function(...) return {n = select("#", ...), ...} end,
        isfrozen = function() return false end,
        freeze = function() end,
        clone = function(t) local r = {}; for k, v in pairs(t) do r[k] = v end; return r end,
        keys = function(t) local r = {}; for k in pairs(t) do r[#r+1] = k end; return r end,
        values = function(t) local r = {}; for _, v in pairs(t) do r[#r+1] = v end; return r end,
        flatten = function(t) local r = {}; for _, v in ipairs(t) do if type(v) == "table" then for _, v2 in ipairs(v) do r[#r+1] = v2 end else r[#r+1] = v end end; return r end,
    },
    os = {
        clock = os.clock, date = os.date, difftime = os.difftime,
        time = os.time, exit = function() end, execute = function() return 0 end,
        getenv = function() return "" end, remove = function() end, rename = function() end,
        setlocale = function() return "" end, tmpname = function() return "" end,
    },
    coroutine = {
        create = function(f)
            local co = _orig_coroutine_create(f)
            return co
        end,
        resume = function(co, ...)
            local results = {_orig_coroutine_resume(co, ...)}
            return unpack(results)
        end,
        running = _orig_coroutine_running,
        status = _orig_coroutine_status,
        wrap = function(f)
            local co = _orig_coroutine_create(f)
            return function(...)
                local results = {_orig_coroutine_resume(co, ...)}
                if results[1] then
                    return select(2, unpack(results))
                else
                    error(results[2], 0)
                end
            end
        end,
        yield = function(...) return _orig_coroutine_yield(...) end,
        close = function() return true end,
        isyieldable = function() return false end,
    },
    print = function(...) end,
    warn = function(...) end,
    game = _game,
    Game = _game,
    workspace = _services.Workspace,
    Workspace = _services.Workspace,
    script = _script_obj,
    Script = _script_obj,
    shared = _shared,
    plugin = _new_proxy("plugin"),
    debug = _debug_lib,
    Enum = Enum,
    Instance = {
        new = function(className)
            return _create_instance(className or "Part")
        end,
        FromExisting = function(obj) return obj end,
    },
    Vector3 = _Vector3,
    Vector2 = _Vector2,
    CFrame = _CFrame,
    Color3 = _Color3,
    BrickColor = _BrickColor,
    UDim = _UDim,
    UDim2 = _UDim2,
    Ray = _Ray,
    Region3 = _Region3,
    Region3int16 = _Region3int16,
    NumberRange = _NumberRange,
    NumberSequence = _NumberSequence,
    NumberSequenceKeypoint = _NumberSequenceKeypoint,
    ColorSequence = _ColorSequence,
    ColorSequenceKeypoint = _ColorSequenceKeypoint,
    TweenInfo = _TweenInfo,
    Faces = _Faces,
    Axes = _Axes,
    PhysicalProperties = _PhysicalProperties,
    DateTime = _DateTime,
    RaycastParams = _RaycastParams,
    RaycastResult = _RaycastResult,
    DockWidgetPluginGuiInfo = _DockWidgetPluginGuiInfo,
    CatalogSearchParams = _CatalogSearchParams,
    PathWaypoint = _PathWaypoint,
    OverlapParams = _OverlapParams,
    Random = _Random,
    bit32 = bit32 or {
        bxor = function(a, b) return a ~ b end,
        band = function(a, b) return a & b end,
        bor = function(a, b) return a | b end,
        bnot = function(a) return ~a end,
        lshift = function(a, b) return a << b end,
        rshift = function(a, b) return a >> b end,
        arshift = function(a, b) return a >> b end,
        btst = function(a, b) return (a & (1 << b)) ~= 0 end,
        bset = function(a, b) return a | (1 << b) end,
        bclear = function(a, b) return a & ~(1 << b) end,
        extract = function(a, field, width) return (a >> field) & ((1 << width) - 1) end,
        replace = function(a, v, field, width) return a & ~(((1 << width) - 1) << field) | (v << field) end,
    },
    utf8 = utf8 or {
        char = function(...) return string.char(...) end,
        codes = function(s) return function() return 0 end end,
        codepoint = function(s, i, j) return nil end,
        graphemes = function(s) return function() return "" end end,
        len = function(s, i, j) return #s end,
        nfcnormalize = function(s) return s end,
        nfdnormalize = function(s) return s end,
        offset = function(s, n, i) return i end,
    },
    task = {
        spawn = function(f, ...) _schedule_task(0, function() f(...) end) end,
        defer = function(f, ...) _schedule_task(0, function() f(...) end) end,
        delay = function(t, f, ...) _schedule_task(t, function() f(...) end) end,
        wait = function(t) _fake_time = _fake_time + (t or 0); _tick_scheduler() end,
        cancel = function(id) _remove_task(id) end,
        desynchronize = function(f) return f() end,
        synchronize = function(f) return f() end,
    },
    wait = function(t) _fake_time = _fake_time + (t or 0); _tick_scheduler() return t or 0 end,
    delay = function(t, f) _schedule_task(t, function() f() end) end,
    spawn = function(f) _schedule_task(0, function() f() end) end,
    tick = function() return _fake_time end,
    time = function() return _fake_time end,
    elapsedTime = function() return _fake_time end,
    _G = nil,
    _ENV = nil,
}

_safe_env._G = _safe_env
_safe_env._ENV = _safe_env
_safe_env.shared = _shared
_safe_env.Shared = _shared
_shared._G = _safe_env

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

local function _state_scan()
    local results = {}
    local visited = {}

    local function _serialize_table(t, depth)
        if depth > 8 then return "{...}" end
        if visited[t] then return "(visited)" end
        visited[t] = true
        local parts = {}
        parts[#parts+1] = "{"
        local count = 0
        for k, v in pairs(t) do
            if count < 200 then
                local ks = _orig_type(k) == "string" and string.format("%q", k) or tostring(k)
                local vs = _orig_type(v) == "table" and _serialize_table(v, depth + 1) or
                           _orig_type(v) == "string" and string.format("%q", v) or tostring(v)
                parts[#parts+1] = "  [" .. ks .. "] = " .. vs .. ","
                count = count + 1
            end
        end
        parts[#parts+1] = "}"
        return table.concat(parts, "\n")
    end

    local function _is_base64_map(t)
        if _orig_type(t) ~= "table" then return false end
        local count = 0
        local has_correct_values = true
        for k, v in pairs(t) do
            count = count + 1
            if _orig_type(v) ~= "number" or v < 0 or v > 63 then
                has_correct_values = false
            end
        end
        return count >= 60 and has_correct_values
    end

    local function _find_suspect_tables(t, depth, path)
        if depth > 6 then return end
        if visited[t] then return end
        visited[t] = true
        if _is_base64_map(t) then
            results["base64_table_" .. path] = _serialize_table(t, 0)
        end
        for k, v in pairs(t) do
            if _orig_type(v) == "table" and not v.__is_proxy then
                _find_suspect_tables(v, depth + 1, path .. "." .. tostring(k))
            end
        end
    end

    local function _find_bytecode(t, depth, path)
        if depth > 6 then return end
        if visited[t] then return end
        visited[t] = true
        for k, v in pairs(t) do
            if _orig_type(v) == "string" and #v >= 12 and v:sub(1, 4) == "\27Lua" then
                results["bytecode_" .. path .. "." .. tostring(k)] = v
            elseif _orig_type(v) == "table" and not v.__is_proxy then
                _find_bytecode(v, depth + 1, path .. "." .. tostring(k))
            end
        end
    end

    visited = {}
    _find_suspect_tables(_safe_env, 0, "_G")
    visited = {}
    _find_bytecode(_safe_env, 0, "_G")
    visited = {}
    _find_suspect_tables(_shared, 0, "shared")
    visited = {}
    _find_bytecode(_shared, 0, "shared")

    for _, obj in ipairs(_instances) do
        visited = {}
        _find_suspect_tables(obj, 0, obj.className)
        visited = {}
        _find_bytecode(obj, 0, obj.className)
    end

    return results
end

local _env_mt = {
    __index = function(t, k)
        local v = _orig_rawget(_safe_env, k)
        if v ~= nil then return v end
        return _new_proxy(tostring(k))
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

_fake_time = _fake_time + 5
_tick_scheduler()

local scan_results = _state_scan()

local _output_parts = {}
_output_parts[#_output_parts + 1] = "SANDBOX_OUTPUT_START\n"
_output_parts[#_output_parts + 1] = "return {\n"

for k, v in pairs(scan_results) do
    if _orig_type(v) == "string" and #v > 5 then
        _track_string(v)
    end
    _output_parts[#_output_parts + 1] = "  [" .. string.format("%q", k) .. "] = "
    if _orig_type(v) == "string" then
        _output_parts[#_output_parts + 1] = string.format("%q", v)
    else
        _output_parts[#_output_parts + 1] = tostring(v)
    end
    _output_parts[#_output_parts + 1] = ",\n"
end

_output_parts[#_output_parts + 1] = "}\n"
_output_parts[#_output_parts + 1] = "SANDBOX_OUTPUT_END\n"

local full_output = table.concat(_output_parts)
local of = _io.open(_out .. "/sandbox_output.lua", "w")
if of then
    of:write(full_output)
    of:close()
end

for _, text in ipairs(_tracked) do
    _write_capture(text)
end

local df = _io.open(_out .. "/diag.txt", "w")
if df then
    df:write(table.concat(_log, "\n"))
    df:close()
end
