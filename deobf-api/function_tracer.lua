local StringUtils = require("string_utils")

local FunctionTracer = {}
FunctionTracer.captured_sources = {}
FunctionTracer.captured_count = 0

function FunctionTracer.wrap(fn, name_hint, log_func)
    if type(fn) ~= "function" then
        return fn
    end

    local info = debug.getinfo(fn, "S")
    local source = "unknown"
    local linedefined = -1

    if info then
        source = info.short_src or "unknown"
        linedefined = info.linedefined or -1
    end

    local capture_key = source .. ":" .. tostring(linedefined)
    if not FunctionTracer.captured_sources[capture_key] then
        FunctionTracer.captured_count = FunctionTracer.captured_count + 1
        local source_lines = {}
        if info and info.linedefined and info.lastlinedefined then
            for line = info.linedefined, info.lastlinedefined do
                table.insert(source_lines, "line " .. tostring(line))
            end
        end
        FunctionTracer.captured_sources[capture_key] = {
            name = name_hint or ("func_" .. tostring(FunctionTracer.captured_count)),
            source = source,
            linedefined = linedefined,
            line_count = info and (info.lastlinedefined or 0) - (info.linedefined or 0) + 1 or 0
        }
        if log_func then
            log_func("TRACED: " .. name_hint .. " from " .. source)
        end
    end

    return function(...)
        if log_func then
            log_func("CALL: " .. (name_hint or "anon") .. "(" .. tostring(select("#", ...)) .. " args)")
        end
        local results = {pcall(fn, ...)}
        if results[1] then
            local rets = {}
            for i = 2, #results do
                rets[i-1] = results[i]
            end
            return table.unpack(rets)
        end
        return nil
    end
end

return FunctionTracer
