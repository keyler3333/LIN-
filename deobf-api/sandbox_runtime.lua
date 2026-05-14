package.path = package.path .. ";" .. (os.getenv("APP_DIR") or ".") .. "/?.lua"

local _out = "OUTDIR_PLACEHOLDER"
local _inp = "INPATH_PLACEHOLDER"
local _log = {}

local function _L(s)
    _log[#_log+1] = s
end

local StringUtils = require("string_utils")
local FunctionTracer = require("function_tracer")
local OutputWriter = require("output_writer")

local _orig_loadstring = loadstring
local _orig_pcall = pcall
local _orig_xpcall = xpcall

local function _repair_malformed(code)
    return (tostring(code or "")):gsub("(%d)([a-zA-Z_])", "%1 %2")
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
        _L("LOADSTRING captured " .. #code .. " bytes")
        local f = io.open(_out .. "/layer_1.lua", "w")
        if f then f:write(code) f:close() end
    end
    return _orig_loadstring(code, name)
end

loadstring = _hooked_loadstring
load = _hooked_loadstring

local function _safe_library(lib)
    local t = {}
    for k, v in pairs(lib) do
        t[k] = v
    end
    return t
end

local env = {
    _G = nil,
    _VERSION = "Luau",
    assert = function(v) return v end,
    error = function() end,
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
    getmetatable = function(obj)
        if type(obj) == "string" then return nil end
        return getmetatable(obj)
    end,
    tonumber = tonumber,
    tostring = tostring,
    type = type,
    typeof = function(v)
        if type(v) == "table" and rawget(v, "EnumType") ~= nil then
            return "EnumItem"
        end
        return type(v)
    end,
    xpcall = xpcall,
    string = _safe_library(string),
    math = _safe_library(math),
    table = _safe_library(table),
    os = _safe_library(os),
    coroutine = _safe_library(coroutine),
    debug = debug,
    getfenv = function() return env end,
    setfenv = function(fn, e) return fn end,
    print = function(...) _L("PRINT: " .. table.concat({...}, "\t")) end,
    warn = function() end,
    newproxy = function(add)
        local u = {}
        if add then setmetatable(u, {}) end
        return u
    end,
    loadstring = loadstring,
    load = load,
    game = {
        PlaceId = 12345678,
        JobId = "test-job-id",
        GetService = function(self, name)
            _L("GetService: " .. tostring(name))
            return {}
        end,
    },
    workspace = {},
    Players = { LocalPlayer = { Name = "Player", UserId = 1 }, GetPlayers = function() return {} end },
    MarketplaceService = { PromptPremiumPurchase = function() end },
    Enum = { MembershipType = { None = 0, Premium = 4 } },
}

env._G = env

local fh = io.open(_inp, "r")
if not fh then
    _L("cannot open input")
    OutputWriter.emit_comment("ERROR: cannot open input file")
else
    local source = fh:read("*a")
    fh:close()

    source = _repair_malformed(source)

    local chunk, err = _orig_loadstring(source, "@input")
    if not chunk then
        _L("PARSE ERROR: " .. tostring(err))
        OutputWriter.emit_comment("PARSE ERROR: " .. tostring(err))
    else
        setfenv(chunk, env)
        local ok, res = _orig_pcall(chunk)
        if not ok then
            _L("RUNTIME ERROR: " .. tostring(res))
            OutputWriter.emit_comment("RUNTIME ERROR: " .. tostring(res))
        else
            _L("SCRIPT COMPLETED")
            OutputWriter.emit_comment("Deobfuscated output follows")
            OutputWriter.emit_blank()

            if res and type(res) == "function" then
                local ok2, bc = pcall(string.dump, res)
                if ok2 then
                    local df = io.open(_out .. "/dump.bin", "wb")
                    if df then df:write(bc) df:close() end
                    _L("DUMPED " .. #bc .. " bytes")
                    OutputWriter.emit_comment("Bytecode dumped to dump.bin (" .. #bc .. " bytes)")
                end
            end

            OutputWriter.emit_blank()
            OutputWriter.emit_comment("Traced functions:")
            for key, info in pairs(FunctionTracer.captured_sources) do
                OutputWriter.emit_comment(string.format("  %s from %s line %d", info.name, info.source, info.linedefined))
            end
            OutputWriter.emit_comment("Total functions traced: " .. tostring(FunctionTracer.captured_count))
        end
    end
end

local output_path = _out .. "/output.lua"
OutputWriter.save_to_file(output_path)

local sf = io.open(_out .. "/cap.txt", "w")
if sf then
    sf:write(OutputWriter.get_output())
    sf:close()
end

local df = io.open(_out .. "/diag.txt", "w")
if df then
    df:write(table.concat(_log, "\n"))
    df:close()
end
