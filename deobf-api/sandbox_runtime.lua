local _out = "OUTDIR_PLACEHOLDER"
local _inp = "INPATH_PLACEHOLDER"
local _cap, _log, _step = {}, {}, 0

local function _L(s)
    _log[#_log+1] = s
end

local _orig_debug = debug

debug.sethook(function()
    _step = _step + 1000
    if _step > 50000000 then
        _L("STEP_LIMIT")
        error("__LIMIT__")
    end
end, "", 1000)

local _captured = {}
local function _capture(v)
    if type(v) == "string" and #v > 1 and not _captured[v] then
        _captured[v] = true
        _cap[#_cap+1] = v
        _L("CAPTURED " .. #v .. " bytes: " .. string.sub(v, 1, 80):gsub("%c","."))
    end
end

local _orig_loadstring   = loadstring
local _orig_pcall        = pcall
local _orig_xpcall       = xpcall
local _orig_rawset       = rawset
local _orig_table_concat = table.concat
local _orig_string_char  = string.char

local _proxy = require("proxy")
local _proxy_meta = require("proxy_meta")
local _scope = require("scope")
local _identity = require("identity")

local _global_scope = _scope.new(_L)

rawset = function(t, k, v)
    if type(v) == "string" and #v > 1 then
        _capture(v)
    end
    if type(v) == "table" then
        v = _proxy(v, "N[" .. tostring(k) .. "]", _L)
    end
    return _orig_rawset(t, k, v)
end

table.concat = function(t, sep, i, j)
    local r = _orig_table_concat(t, sep, i, j)
    if type(r) == "string" and #r > 1 then
        _capture(r)
    end
    return r
end

string.char = function(...)
    local r = _orig_string_char(...)
    if #r > 1 then
        _capture(r)
    end
    return r
end

local function _safe_library(lib)
    local t = {}
    for k, v in pairs(lib) do
        t[k] = v
    end
    return t
end

local _MembershipType = { None = 0, Premium = 4, Name = "MembershipType" }
local _EnumItem = { EnumType = _MembershipType, Value = 0, Name = "None" }

local _known = {
    assert           = function(v) return v end,
    error            = function(msg, level)
        if msg == "detected by LeakD" then
            return nil
        end
        error(msg, level)
    end,
    ipairs           = ipairs,
    next             = next,
    pairs            = pairs,
    pcall            = pcall,
    rawequal         = rawequal,
    rawget           = rawget,
    rawlen           = rawlen,
    rawset           = rawset,
    select           = select,
    setmetatable     = setmetatable,
    getmetatable     = getmetatable,
    tonumber         = tonumber,
    tostring         = tostring,
    type             = type,
    typeof           = function(v)
        if type(v) == "table" and rawget(v, "EnumType") ~= nil then
            return "EnumItem"
        end
        return type(v)
    end,
    xpcall           = xpcall,
    string           = _safe_library(string),
    math             = _safe_library(math),
    table            = _safe_library(table),
    os               = _safe_library(os),
    coroutine        = _safe_library(coroutine),
    debug            = debug,
    _G               = nil,
    _VERSION         = "Luau",
    getfenv          = function() return _known end,
    setfenv          = function(fn, e) return fn end,
    print            = function(...)
        local args = {...}
        local msg = table.concat(args, "\t")
        _L("PRINT: " .. tostring(msg))
    end,
    warn             = function() end,
    newproxy         = function(add)
        local u = {}
        if add then setmetatable(u, {}) end
        return u
    end,
    loadstring       = function(code, name)
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
        if type(code) == "string" and #code > 1 then
            _capture(code)
            local f = io.open(_out .. "/layer_1.lua", "w")
            if f then f:write(code) f:close() end
            _L("LOADSTRING " .. #code .. " bytes")
        end
        return _orig_loadstring(code, name)
    end,
    load             = nil,

    game             = {
        PlaceId       = 12345678,
        JobId         = "test-job-id",
        GetService    = function(self, name)
            if name == "Players" then
                return {
                    LocalPlayer = {
                        Name = "Player",
                        UserId = 1,
                        MembershipType = _EnumItem,
                        Character = {},
                        PlayerGui = {},
                        Backpack = {},
                    },
                    GetPlayers = function() return {} end,
                }
            elseif name == "MarketplaceService" then
                return {
                    PromptPremiumPurchase = function() end,
                    PlayerOwnsAsset = function() return false end,
                }
            end
            return {}
        end,
    },
    workspace        = {},
    Players          = {
        LocalPlayer = {
            Name = "Player",
            UserId = 1,
            MembershipType = _EnumItem,
            Character = {},
            PlayerGui = {},
            Backpack = {},
        },
        GetPlayers = function() return {} end,
    },
    MarketplaceService = {
        PromptPremiumPurchase = function() end,
        PlayerOwnsAsset = function() return false end,
    },
    Enum             = {
        MembershipType = _MembershipType,
    },
}

_known._G  = _known
_known.load = _known.loadstring

for name, value in pairs(_known) do
    _global_scope:set(name, value)
end

local _env_mt = {
    __index = function(_, k)
        local v = rawget(_known, k)
        if v ~= nil then
            return v
        end
        local wrapped = _proxy({}, k, _L)
        rawset(_known, k, wrapped)
        _global_scope:set(k, wrapped)
        return wrapped
    end,
    __newindex = function(_, k, v)
        rawset(_known, k, v)
        _global_scope:set(k, v)
    end,
}

local env = setmetatable({}, _env_mt)

local fh = io.open(_inp, "r")
if not fh then
    _L("cannot open input")
    local ef = io.open(_out .. "/error.txt", "w")
    if ef then ef:write("cannot open input") ef:close() end
else
    local source = fh:read("*a")
    fh:close()

    local chunk, err = _orig_loadstring(source, "@input")
    if not chunk then
        _L("PARSE ERROR: " .. tostring(err))
        local ef = io.open(_out .. "/error.txt", "w")
        if ef then ef:write("parse error: " .. tostring(err)) ef:close() end
    else
        setfenv(chunk, env)
        local function error_handler(e)
            return _orig_debug.traceback(tostring(e), 2)
        end
        local ok, res = _orig_xpcall(chunk, error_handler)
        if not ok then
            _L("RUNTIME ERROR: " .. tostring(res))
        else
            _L("MAIN RETURNED: type=" .. type(res) .. " value=" .. tostring(res):sub(1, 200))
            if type(res) == "string" and #res > 1 then
                _capture(res)
            elseif type(res) == "function" then
                _L("FUNCTION IDENTITY: " .. _identity.get_signature(res))
                local ok2, bc = _orig_pcall(string.dump, res)
                if ok2 then
                    local df = io.open(_out .. "/dump.bin", "wb")
                    if df then df:write(bc) df:close() end
                    _L("DUMPED " .. #bc .. " bytes")
                else
                    _L("DUMP FAILED: " .. tostring(bc))
                end
            end
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
