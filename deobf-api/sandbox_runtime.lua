local _out = "OUTDIR_PLACEHOLDER"
local _inp = "INPATH_PLACEHOLDER"
local _layer = 0
local _cap = {}

local function _capture(v)
    if type(v) == "string" and #v > 5 then
        _cap[#_cap+1] = v
    end
end

local _orig_loadstring = loadstring

loadstring = function(code, name)
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
    end
    return _orig_loadstring(code, name)
end
load = loadstring

newproxy = function(add)
    local u = {}
    if add then
        setmetatable(u, {})
    end
    return u
end

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
    setfenv(chunk, _G)
    local ok, res = pcall(chunk)
    if ok then
        if type(res) == "string" then _capture(res) end
        if type(res) == "function" then
            local ok2, bc = pcall(string.dump, res)
            if ok2 then
                local df = io.open(_out .. "/dump.bin", "wb")
                if df then df:write(bc) df:close() end
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
    df:write("done")
    df:close()
end
