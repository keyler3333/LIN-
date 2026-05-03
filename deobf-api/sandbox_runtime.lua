local _out = "OUTDIR_PLACEHOLDER"
local _inp = "INPATH_PLACEHOLDER"
local _dumped = {}

local function _save(tag, data)
    if _dumped[tag] then return end
    _dumped[tag] = true
    local f = io.open(_out .. "/cap.txt", "a")
    if f then
        f:write("--- " .. tag .. " ---\n")
        f:write(data)
        f:write("\n---SEP---\n")
        f:close()
    end
end

local _orig_loadstring = loadstring
local function _hook_loadstring(src)
    if type(src) == "string" then
        _save("LOADSTRING_PAYLOAD", src)
    end
    return _orig_loadstring(src)
end
loadstring = _hook_loadstring
_G.loadstring = _hook_loadstring

local _orig_concat = table.concat
table.concat = function(t, sep)
    local r = _orig_concat(t, sep)
    if type(r) == "string" and #r > 50 then
        _save("CONCAT_RESULT", r)
    end
    return r
end

if not bit then
    bit = {
        bxor = function(a,b) local r,p=0,1 while a>0 or b>0 do if a%2~=b%2 then r=r+p end a=math.floor(a/2) b=math.floor(b/2) p=p*2 end return r end,
        band = function(a,b) local r,p=0,1 while a>0 and b>0 do if a%2==1 and b%2==1 then r=r+p end a=math.floor(a/2) b=math.floor(b/2) p=p*2 end return r end,
        bor = function(a,b) local r,p=0,1 while a>0 or b>0 do if a%2==1 or b%2==1 then r=r+p end a=math.floor(a/2) b=math.floor(b/2) p=p*2 end return r end,
        bnot = function(a) return -a-1 end,
        rshift = function(a,b) return math.floor(a/(2^b)) end,
        lshift = function(a,b) return math.floor(a*(2^b)) end,
        arshift = function(a,b) return math.floor(a/(2^b)) end,
        btest = function(a,b) return bit.band(a,b)~=0 end,
        tobit = function(a) return a end,
    }
end

local function _noop() end
local function _dummy(name)
    local d = {}
    setmetatable(d, {
        __index = function(_, k) local child = _dummy(name.."."..tostring(k)) rawset(d,k,child) return child end,
        __call = function() return _dummy(name.."()") end,
        __newindex = function() end,
    })
    return d
end

local _game = _dummy("game")
_game.GetService = function(_,s) return _dummy(s) end
_game.HttpService = { Base64Decode = function(_,s) return s end }

local _env = {
    _G = _G,
    game = _game,
    workspace = _game,
    script = _dummy("script"),
    Player = _dummy("Player"),
    Players = _dummy("Players"),
    RunService = _dummy("RunService"),
    UserInputService = _dummy("UserInputService"),
    TweenService = _dummy("TweenService"),
    HttpService = _game.HttpService,
    Instance = { new = function(_,n) return _dummy(n) end },
    Vector3 = { new = function() return _dummy("Vector3") end },
    Vector2 = { new = function() return _dummy("Vector2") end },
    CFrame = { new = function() return _dummy("CFrame") end, Angles = function() return _dummy("CFrame") end },
    Color3 = { new = function() return _dummy("Color3") end, fromRGB = function() return _dummy("Color3") end },
    UDim2 = { new = function() return _dummy("UDim2") end },
    Enum = setmetatable({}, {__index = function(_,k) return k end}),
    newproxy = function() return {} end,
    tick = function() return 0 end,
    time = function() return 0 end,
    wait = function() end,
    spawn = function(f) if type(f)=="function" then pcall(f) end end,
    delay = function(t,f) if type(f)=="function" then pcall(f) end end,
    print = function() end,
    warn = function() end,
    os = { time = function() return 1000000 end, clock = function() return 0 end, date = function() return "2024-01-01" end },
    math = math,
    string = string,
    table = table,
    coroutine = coroutine,
    bit = bit,
    bit32 = bit,
    pcall = pcall,
    xpcall = xpcall,
    error = error,
    assert = assert,
    select = select,
    unpack = unpack or table.unpack,
    setmetatable = setmetatable,
    getmetatable = getmetatable,
    rawget = rawget,
    rawset = rawset,
    loadstring = _hook_loadstring,
    load = _hook_loadstring,
}

setmetatable(_env, {__index = _G})

local f = io.open(_inp, "r")
if f then
    local src = f:read("*a")
    f:close()
    local fn, err = _orig_loadstring(src, "@input")
    if fn then
        setfenv(fn, _env)
        pcall(fn)
    end
end
