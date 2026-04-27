def apply_anti_analysis(sandbox_lua):
    patches = """
    local _orig_os_clock = os.clock
    os.clock = function() return 0 end
    local _orig_os_time = os.time
    os.time = function() return 1000000 end
    local _orig_debug_sethook = debug.sethook
    debug.sethook = function() end
    local _orig_debug_getinfo = debug.getinfo
    debug.getinfo = function() return {short_src="script.lua", currentline=0, what="Lua"} end
    """
    return sandbox_lua + '\n' + patches
