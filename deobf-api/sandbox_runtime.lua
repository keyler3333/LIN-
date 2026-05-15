local _out = "OUTDIR_PLACEHOLDER"
local _inp = "INPATH_PLACEHOLDER"
local _log = {}

local function _L(s)
    _log[#_log+1] = s
end

local function _repair_malformed(code)
    return (tostring(code or "")):gsub("(%d)([a-zA-Z_])", "%1 %2")
end

local _orig_loadstring = loadstring
local _orig_pcall = pcall

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
        _L("LOADSTRING captured " .. #code .. " bytes: " .. string.sub(code, 1, 80))
        local f = io.open(_out .. "/layer_1.lua", "w")
        if f then f:write(code) f:close() end
    end
    return _orig_loadstring(code, name)
end

loadstring = _hooked_loadstring
load = _hooked_loadstring

local fh = io.open(_inp, "r")
if not fh then
    _L("cannot open input")
else
    local source = fh:read("*a")
    fh:close()

    source = _repair_malformed(source)

    local chunk, err = _orig_loadstring(source, "@input")
    if not chunk then
        _L("PARSE ERROR: " .. tostring(err))
    else
        local ok, res = _orig_pcall(chunk)
        if not ok then
            _L("RUNTIME ERROR: " .. tostring(res))
        else
            _L("SCRIPT COMPLETED. Return type: " .. type(res))
            if res and type(res) == "function" then
                local ok2, bc = pcall(string.dump, res)
                if ok2 then
                    local df = io.open(_out .. "/dump.bin", "wb")
                    if df then df:write(bc) df:close() end
                    _L("DUMPED " .. #bc .. " bytes")
                else
                    _L("DUMP FAILED: " .. tostring(bc))
                end
            elseif res and type(res) == "string" and #res > 5 then
                local f = io.open(_out .. "/layer_1.lua", "w")
                if f then f:write(res) f:close() end
                _L("RETURNED STRING: " .. #res .. " bytes")
            end
        end
    end
end

local df = io.open(_out .. "/diag.txt", "w")
if df then
    df:write(table.concat(_log, "\n"))
    df:close()
end
