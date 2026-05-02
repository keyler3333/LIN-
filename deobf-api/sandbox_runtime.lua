local _out = "OUTDIR_PLACEHOLDER"
local _inp = "INPATH_PLACEHOLDER"
local _layer = 0
local _cap, _log, _step = {}, {}, 0

local function _L(s) _log[#_log+1] = s end

debug.sethook(function()
    _step = _step + 5000
    if _step > 2000000 then
        _L("STEP_LIMIT")
        error("__LIMIT__")
    end
end, "", 5000)

local function _capture(v)
    if type(v) == "string" and #v > 3 then
        _cap[#_cap+1] = v
    end
end

local _orig_rawget = rawget
rawget = function(t, k)
    local v = _orig_rawget(t, k)
    if type(v) == "string" and #v > 3 then _capture(v) end
    return v
end
_G.rawget = rawget

local _orig_string_char = string.char
string.char = function(...)
    local r = _orig_string_char(...)
    _capture(r)
    return r
end

local _orig_table_concat = table.concat
table.concat = function(t, sep, i, j)
    local r = _orig_table_concat(t, sep, i, j)
    if #r > 3 then _capture(r) end
    return r
end

local _orig_loadstring = loadstring

local function _hooked_load(code, name)
    if type(code) == "function" then
        local parts = {}
        while true do
            local p = code()
            if not p then break end
            if type(p) == "string" then parts[#parts+1] = p end
            if #parts > 5000 then break end
        end
        code = _orig_table_concat(parts)
    end
    if type(code) == "string" and #code > 5 then
        _capture(code)
        _layer = _layer + 1
        local f = io.open(_out .. "/layer_" .. _layer .. ".lua", "w")
        if f then f:write(code); f:close() end
        _L("layer " .. _layer .. " captured (" .. #code .. " bytes)")
    end
    return _orig_loadstring(code, name)
end

_G.loadstring = _hooked_load
_G.load       = _hooked_load

local fh = io.open(_inp, "r")
if not fh then
    local ef = io.open(_out .. "/error.txt", "w")
    if ef then ef:write("cannot open input: " .. _inp); ef:close() end
    return
end
local source_code = fh:read("*a")
fh:close()

local chunk, err = _orig_loadstring(source_code, "@input")
if not chunk then
    local ef = io.open(_out .. "/error.txt", "w")
    if ef then ef:write("parse error: " .. tostring(err)); ef:close() end
else
    local env = setmetatable({}, {__index = _G})
    rawset(env, "loadstring", _hooked_load)
    rawset(env, "load",       _hooked_load)
    local ok, res = pcall(setfenv(chunk, env))
    if not ok then _L("runtime error: " .. tostring(res)) end
    if ok and type(res) == "function" then
        local ok2, bc = pcall(string.dump, res)
        if ok2 then
            local df = io.open(_out .. "/dump.bin", "wb")
            if df then df:write(bc); df:close() end
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
    df:write(_orig_table_concat(_log, "\n"))
    df:close()
end
