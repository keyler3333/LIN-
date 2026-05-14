local function proxy(value, name, log_func)
    local _value = value
    local _name  = name or "anon"
    local _log   = log_func or function(msg) end

    local function _trace(operation, ...)
        local args = {...}
        local arg_strs = {}
        for _, v in ipairs(args) do
            table.insert(arg_strs, tostring(v):sub(1, 40))
        end
        _log(string.format("PROXY [%s] %s(%s)", _name, operation, table.concat(arg_strs, ", ")))
    end

    if type(value) == "table" then
        local mt = getmetatable(value) or {}
        local proxy_mt = {}
        for k, v in pairs(mt) do
            proxy_mt[k] = v
        end
        proxy_mt.__index = function(t, k)
            _trace("INDEX", k)
            local result = _value[k]
            if result == nil and rawget(_value, k) == nil then
                local child = proxy({}, _name .. "." .. tostring(k), _log)
                rawset(_value, k, child)
                return child
            end
            if type(result) == "table" then
                return proxy(result, _name .. "." .. tostring(k), _log)
            end
            return result
        end
        proxy_mt.__newindex = function(t, k, v)
            _trace("NEWINDEX", k, v)
            rawset(_value, k, v)
        end
        proxy_mt.__call = function(t, ...)
            _trace("CALL", ...)
            local func_type = type(_value)
            if func_type == "function" then
                local results = {pcall(_value, ...)}
                if results[1] then
                    local rets = {}
                    for i = 2, #results do
                        rets[i-1] = results[i]
                    end
                    return table.unpack(rets)
                end
            end
            return proxy({}, _name .. "_result", _log)
        end
        proxy_mt.__add = function(a, b)
            _trace("ADD", b)
            return proxy({}, _name .. "_add", _log)
        end
        proxy_mt.__sub = function(a, b)
            _trace("SUB", b)
            return proxy({}, _name .. "_sub", _log)
        end
        proxy_mt.__mul = function(a, b)
            _trace("MUL", b)
            return proxy({}, _name .. "_mul", _log)
        end
        proxy_mt.__div = function(a, b)
            _trace("DIV", b)
            return proxy({}, _name .. "_div", _log)
        end
        proxy_mt.__eq  = function(a, b)
            _trace("EQ", b)
            return false
        end
        proxy_mt.__lt  = function(a, b)
            _trace("LT", b)
            return false
        end
        proxy_mt.__le  = function(a, b)
            _trace("LE", b)
            return true
        end
        proxy_mt.__tostring = function()
            _trace("TOSTRING")
            return _name
        end
        return setmetatable({}, proxy_mt)
    elseif type(value) == "function" then
        return function(...)
            _trace("CALL", ...)
            local results = {pcall(value, ...)}
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
    return value
end

return proxy
