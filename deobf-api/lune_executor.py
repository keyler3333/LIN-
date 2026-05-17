import asyncio
import os
import tempfile
import hashlib

EXECUTION_TIMEOUT = 10
LUNE_BIN = os.environ.get("LUNE_BIN", "lune")

SHIM_TEMPLATE = """
game = {{
    GetService = function(self, name) return {{}} end,
    Players = {{ LocalPlayer = {{ UserId = 1, Name = "Player" }} }},
    HttpGet = function(self, url) return "" end,
}}
workspace = {{}}
script = {{ Parent = game }}
shared = {{}}
_G = {{}}

local _captured = false
local _outpath = {outpath!r}

local _orig_loadstring = loadstring
loadstring = function(chunk, chunkname)
    if not _captured then
        _captured = true
        local f = io.open(_outpath, "wb")
        if f then
            f:write(chunk)
            f:close()
        end
    end
    return function() end
end

load = loadstring

do
{indented_user_script}
end
"""

async def execute_and_capture(lua_source: str):
    with tempfile.TemporaryDirectory() as tmpdir:
        tag = hashlib.md5(lua_source.encode()).hexdigest()[:8]
        script_path = os.path.join(tmpdir, f"input_{tag}.luau")
        output_path = os.path.join(tmpdir, f"captured_{tag}.luac")

        indented = "\n".join("    " + line for line in lua_source.splitlines())

        shim = SHIM_TEMPLATE.format(
            outpath=output_path,
            indented_user_script=indented,
        )

        with open(script_path, "w", encoding="utf-8") as f:
            f.write(shim)

        try:
            proc = await asyncio.create_subprocess_exec(
                LUNE_BIN, "run", script_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                await asyncio.wait_for(proc.communicate(), timeout=EXECUTION_TIMEOUT)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                return None
        except FileNotFoundError:
            raise RuntimeError(
                f"Lune binary not found at '{LUNE_BIN}'. "
                "Install it with: cargo install lune  or set LUNE_BIN env var."
            )

        if os.path.isfile(output_path):
            with open(output_path, "rb") as f:
                data = f.read()
            return data if data else None

        return None
