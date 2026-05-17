import os
import re
import subprocess
import tempfile
import shutil
import traceback

LUA_BIN = shutil.which('lua5.1') or shutil.which('lua51') or shutil.which('lua') or 'lua'
RUNTIME_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sandbox_runtime.lua')
APP_DIR = os.path.dirname(os.path.abspath(__file__))


def _lua_str(path):
    return '"' + path.replace('\\', '\\\\').replace('"', '\\"') + '"'


def execute_sandbox(source, use_emulator=False, timeout=90):
    if not os.path.isfile(RUNTIME_PATH):
        raise RuntimeError(f'sandbox_runtime.lua not found at {RUNTIME_PATH!r}')

    error_log = []
    layers = []
    caps = []
    diag = ""

    try:
        temp_dir = tempfile.mkdtemp()
    except Exception as e:
        return [], [], f"TEMP_DIR_ERROR: {e}"

    try:
        inp = os.path.join(temp_dir, 'input.lua')
        drv = os.path.join(temp_dir, 'driver.lua')

        try:
            if isinstance(source, bytes):
                raw_bytes = source
            else:
                raw_bytes = source.encode('utf-8', errors='replace')
            with open(inp, 'wb') as f:
                f.write(raw_bytes)
        except Exception as e:
            error_log.append(f"WRITE_INPUT_ERROR: {e}")
            shutil.rmtree(temp_dir, ignore_errors=True)
            return [], [], f"WRITE_INPUT_ERROR: {e}"

        try:
            with open(RUNTIME_PATH, 'r', encoding='utf-8') as f:
                runtime = f.read()
        except Exception as e:
            error_log.append(f"READ_RUNTIME_ERROR: {e}")
            shutil.rmtree(temp_dir, ignore_errors=True)
            return [], [], f"READ_RUNTIME_ERROR: {e}"

        out_dir  = temp_dir.replace('\\', '/')
        inp_path = inp.replace('\\', '/')

        driver = (runtime
                  .replace('"OUTDIR_PLACEHOLDER"', _lua_str(out_dir))
                  .replace('"INPATH_PLACEHOLDER"', _lua_str(inp_path)))

        try:
            with open(drv, 'w', encoding='utf-8') as f:
                f.write(driver)
        except Exception as e:
            error_log.append(f"WRITE_DRIVER_ERROR: {e}")
            shutil.rmtree(temp_dir, ignore_errors=True)
            return [], [], f"WRITE_DRIVER_ERROR: {e}"

        env = os.environ.copy()
        current_lua_path = env.get('LUA_PATH', '')
        app_lua_path = os.path.join(APP_DIR, '?.lua')
        if app_lua_path not in current_lua_path:
            env['LUA_PATH'] = app_lua_path + ';' + current_lua_path

        proc_error = ""
        try:
            result = subprocess.run(
                [LUA_BIN, drv],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=temp_dir,
                env=env,
            )
            if result.returncode != 0:
                proc_error = f"LUA_EXIT_CODE_{result.returncode}"
                if result.stderr:
                    proc_error += f": {result.stderr[:500]}"
        except subprocess.TimeoutExpired:
            proc_error = "TIMEOUT_EXPIRED"
        except FileNotFoundError:
            proc_error = f"LUA_NOT_FOUND: {LUA_BIN}"
        except Exception as e:
            proc_error = f"SUBPROCESS_ERROR: {e}"

        if proc_error:
            error_log.append(proc_error)

        i = 1
        while True:
            p = os.path.join(temp_dir, f'layer_{i}.lua')
            if not os.path.exists(p):
                break
            try:
                with open(p, encoding='utf-8', errors='replace') as f:
                    data = f.read()
                if data:
                    layers.append(data)
            except Exception as e:
                error_log.append(f"READ_LAYER_{i}_ERROR: {e}")
            i += 1

        dump = os.path.join(temp_dir, 'dump.bin')
        if os.path.exists(dump):
            try:
                with open(dump, 'rb') as f:
                    bc = f.read()
                if bc and bc[:4] == b'\x1bLua':
                    layers.append(bc)
                elif bc:
                    error_log.append(f"DUMP_NOT_BYTECODE: {len(bc)} bytes, header: {bc[:4].hex()}")
            except Exception as e:
                error_log.append(f"READ_DUMP_ERROR: {e}")

        capf = os.path.join(temp_dir, 'cap.txt')
        if os.path.exists(capf):
            try:
                with open(capf, encoding='utf-8', errors='replace') as f:
                    data = f.read()
                if data:
                    for part in data.split('---SEP---'):
                        s = part.strip()
                        if len(s) > 5:
                            caps.append(s)
            except Exception as e:
                error_log.append(f"READ_CAP_ERROR: {e}")

        memf = os.path.join(temp_dir, 'memory.txt')
        if os.path.exists(memf):
            try:
                with open(memf, encoding='utf-8', errors='replace') as f:
                    data = f.read()
                if data:
                    for part in data.split('---MEMSEP---'):
                        s = part.strip()
                        if len(s) > 10:
                            caps.append(s)
            except Exception as e:
                error_log.append(f"READ_MEM_ERROR: {e}")

        diagf = os.path.join(temp_dir, 'diag.txt')
        if os.path.exists(diagf):
            try:
                with open(diagf, encoding='utf-8', errors='replace') as f:
                    data = f.read()
                if data:
                    diag = data
            except Exception as e:
                error_log.append(f"READ_DIAG_ERROR: {e}")

        errf = os.path.join(temp_dir, 'error.txt')
        if os.path.exists(errf):
            try:
                with open(errf, encoding='utf-8', errors='replace') as f:
                    data = f.read()
                if data:
                    diag = data + "\n---\n" + diag if diag else data
            except Exception as e:
                error_log.append(f"READ_ERROR_FILE_ERROR: {e}")

        if error_log:
            err_summary = "\n".join(error_log)
            diag = err_summary + "\n---\n" + diag if diag else err_summary

        if not layers and not caps and not diag:
            diag = "NO_OUTPUT: Sandbox produced no output files"

    except Exception as e:
        diag = f"SANDBOX_FATAL: {e}\n{traceback.format_exc()}"
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    return layers, caps, diag
