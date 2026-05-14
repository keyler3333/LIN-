local StringUtils = require("string_utils")

local OutputWriter = {}
OutputWriter.lines = {}
OutputWriter.indent_level = 0

function OutputWriter.emit(text)
    local indent = string.rep("    ", OutputWriter.indent_level)
    table.insert(OutputWriter.lines, indent .. tostring(text))
end

function OutputWriter.emit_comment(text)
    table.insert(OutputWriter.lines, "-- " .. tostring(text))
end

function OutputWriter.emit_blank()
    table.insert(OutputWriter.lines, "")
end

function OutputWriter.emit_function_header(name, params)
    local param_str = table.concat(params or {}, ", ")
    OutputWriter.emit("function " .. name .. "(" .. param_str .. ")")
    OutputWriter.indent_level = OutputWriter.indent_level + 1
end

function OutputWriter.emit_function_footer()
    OutputWriter.indent_level = math.max(0, OutputWriter.indent_level - 1)
    OutputWriter.emit("end")
end

function OutputWriter.emit_assignment(name, value)
    if type(value) == "string" then
        OutputWriter.emit(name .. " = " .. StringUtils.quote(value))
    else
        OutputWriter.emit(name .. " = " .. tostring(value))
    end
end

function OutputWriter.emit_call(target, method, args)
    local arg_str = table.concat(args or {}, ", ")
    OutputWriter.emit(target .. ":" .. method .. "(" .. arg_str .. ")")
end

function OutputWriter.get_output()
    return table.concat(OutputWriter.lines, "\n")
end

function OutputWriter.save_to_file(path)
    local f = io.open(path, "w")
    if f then
        f:write(OutputWriter.get_output())
        f:close()
        return true
    end
    return false
end

return OutputWriter
