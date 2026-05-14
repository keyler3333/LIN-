local proxy_meta = require("proxy_meta")

local Scope = {}
Scope.__index = Scope

function Scope.new(log_func)
    local self = setmetatable({}, Scope)
    self._variables = {}
    self._log = log_func or function() end
    return self
end

function Scope:set(name, value)
    self._variables[name] = value
    self._log(string.format("SCOPE SET %s = %s", name, tostring(value):sub(1, 40)))
end

function Scope:get(name)
    local value = self._variables[name]
    if value == nil then
        self._log(string.format("SCOPE MISS %s", name))
        return proxy_meta({}, name, self._log)
    end
    return value
end

function Scope:wrap_table(t, name)
    return proxy_meta(t, name, self._log)
end

return Scope
