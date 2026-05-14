local StringUtils = {}

function StringUtils.quote(value)
    if type(value) ~= "string" then
        return tostring(value)
    end
    local parts = {'"'}
    for i = 1, #value do
        local b = string.byte(value, i)
        if b == 34 then
            table.insert(parts, '\\"')
        elseif b == 92 then
            table.insert(parts, "\\\\")
        elseif b == 10 then
            table.insert(parts, "\\n")
        elseif b == 13 then
            table.insert(parts, "\\r")
        elseif b == 9 then
            table.insert(parts, "\\t")
        elseif b < 32 or b > 126 then
            table.insert(parts, string.format("\\%03d", b))
        else
            table.insert(parts, string.char(b))
        end
    end
    table.insert(parts, '"')
    return table.concat(parts)
end

function StringUtils.trim(s)
    return (tostring(s or "")):gsub("^%s+", ""):gsub("%s+$", "")
end

return StringUtils
