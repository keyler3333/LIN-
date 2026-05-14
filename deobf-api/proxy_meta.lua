local proxy = require("proxy")

local function proxy_meta(value, name, log_func)
    if type(value) == "table" then
        return proxy(value, name, log_func)
    end
    return value
end

return proxy_meta
