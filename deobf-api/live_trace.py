import re
import os
import subprocess
import tempfile
from pathlib import Path

_mock_env_cache = None

def _load_mock_env():
    global _mock_env_cache
    if _mock_env_cache is not None:
        return _mock_env_cache
    with open(os.path.join(os.path.dirname(__file__), 'mock_env.lua'), 'r', encoding='utf-8') as f:
        _mock_env_cache = f.read()
    return _mock_env_cache

def _run_trace(source, lua_bin="lua5.1", timeout=20):
    mock_env = _load_mock_env()
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        src_file = tmp / "input.lua"
        src_file.write_text(source, encoding='utf-8')
        driver = (
            mock_env +
            "\n" +
            r"""
            local function deobfuscate_script()
                local f = io.open("""" + src_file.as_posix().replace("\\","\\\\") + """", "r")
                if not f then
                    io.stderr:write("CANNOT_OPEN_INPUT\n")
                    return
                end
                local code = f:read("*a")
                f:close()
                local var_match = code:match("local ([a-zA-Z0-9_]+)={%s*\"")
                if var_match then
                    local dumped = false
                    code = code:gsub("(local " .. var_match .. "%s*=%s*{[^}]*})", function(match)
                        dumped = true
                        return match .. [[

                        print("--- CONSTANTS START ---")
                        if ]] .. var_match .. [[ then
                            local sorted_keys = {}
                            for k in pairs(]] .. var_match .. [[) do table.insert(sorted_keys, k) end
                            table.sort(sorted_keys)
                            local out = "local Constants = {"
                            for i, k in ipairs(sorted_keys) do
                                local v = ]] .. var_match .. [[[k]
                                local v_str = escape_lua_string(v)
                                out = out .. " [" .. k .. "] = " .. v_str .. ","
                            end
                            out = out .. " }"
                            print(out)
                        end
                        print("--- CONSTANTS END ---")
                        ]]
                    end, 1)
                end
                if code:find("getfenv and getfenv%(%)or _ENV") then
                    code = code:gsub("getfenv and getfenv%(%)or _ENV", "MockEnv")
                else
                    code = code:gsub("getfenv%s*%(%s*%)", "MockEnv")
                end
                local chunk, err = loadstring(code)
                if not chunk then
                    io.stderr:write("COMPILE_ERROR: " .. tostring(err) .. "\n")
                    return
                end
                setfenv(chunk, MockEnv)
                local ok, err = pcall(chunk)
                if not ok then
                    io.stderr:write("RUNTIME_ERROR: " .. tostring(err) .. "\n")
                end
            end
            deobfuscate_script()
            """
        )
        driver_path = tmp / "driver.lua"
        driver_path.write_text(driver, encoding='utf-8')
        cmd = [lua_bin, str(driver_path)]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=tmpdir)
        except subprocess.TimeoutExpired:
            raise RuntimeError("Trace execution timed out")
        stderr = proc.stderr.strip()
        if stderr and ("CANNOT_OPEN" in stderr or "COMPILE_ERROR" in stderr or "RUNTIME_ERROR" in stderr):
            raise RuntimeError(f"Lua error: {stderr[:500]}")
        return proc.stdout

def trace_deobfuscate(source, lua_bin="lua5.1"):
    stdout = _run_trace(source, lua_bin)
    trace_lines = []
    constants_str = ""
    in_constants = False
    for line in stdout.splitlines():
        ln = line.strip()
        if ln == "--- CONSTANTS START ---":
            in_constants = True
            continue
        if ln == "--- CONSTANTS END ---":
            in_constants = False
            continue
        if in_constants:
            constants_str += ln + "\n"
        elif any(ln.startswith(p) for p in ("ACCESSED", "CALL_RESULT", "URL DETECTED",
                                              "SET GLOBAL", "UNPACK CALLED",
                                              "LOADSTRING", "TRACE_PRINT", "CAPTURED")):
            trace_lines.append(ln)
    report_text = "--- DEOBFUSCATION REPORT ---\n"
    report_text += "--- TRACE ---\n" + "\n".join(trace_lines) + "\n"
    report_text += "\n--- CONSTANTS ---\n" + constants_str
    import trace_to_lua
    return trace_to_lua.parse_trace_string(report_text)
