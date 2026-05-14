local Identity = {}

function Identity.get_signature(fn)
    if type(fn) ~= "function" then
        return "not_a_function"
    end
    local info = debug.getinfo(fn, "nS")
    if not info then
        return "unknown"
    end
    local parts = {}
    if info.name then
        table.insert(parts, info.name)
    end
    if info.what == "C" then
        table.insert(parts, "[C]")
    end
    if info.short_src then
        table.insert(parts, "(" .. info.short_src .. ")")
    end
    return table.concat(parts, " ")
end

function Identity.get_source(fn)
    if type(fn) ~= "function" then
        return "not_a_function"
    end
    local info = debug.getinfo(fn, "S")
    if not info then
        return "no_info"
    end
    return info.short_src or "unknown"
end

return Identity
