import os
import re
import subprocess
import tempfile
import shutil
import traceback
import sys

LUA_BIN = shutil.which('lua5.1') or shutil.which('lua51') or shutil.which('lua') or 'lua'
RUNTIME_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sandbox_runtime.lua')
APP_DIR = os.path.dirname(os.path.abspath(__file__))


def _lua_str(path):
    return '"' + path.replace('\\', '\\\\').replace('"', '\\"') + '"'


def _escape_to_byte(match):
    try:
        val = int(match.group(1))
        if val < 256:
            return chr(val)
        return match.group(0)
    except (ValueError, OverflowError):
        return match.group(0)


def _hex_to_byte(match):
    try:
        return chr(int(match.group(1), 16))
    except (ValueError, OverflowError):
        return match.group(0)


def _fix_lua_source(source):
    try:
        source = re.sub(r'\\x([0-9a-fA-F]{2})', _hex_to_byte, source)
        source = re.sub(r'\\(\d{1,3})', _escape_to_byte, source)
        return source
    except Exception:
        return source


def _repair_malformed(source):
    try:
        return re.sub(r'(\d)([a-zA-Z_])', r'\1 \2', source)
    except Exception:
        return source


def _write_file_safe(path, data, mode='w'):
    try:
        with open(path, mode, encoding='utf-8' if 'b' not in mode else None) as f:
            f.write(data)
        return True
    except Exception:
        return False


def _read_file_safe(path, mode='r'):
    try:
        with open(path, mode, encoding='utf-8' if 'b' not in mode else None, errors='replace') as f:
            return f.read(), None
    except Exception as e:
        return None, str(e)


def execute_sandbox(source, use_emulator=False, timeout=90):
    if not os.path.isfile(RUNTIME_PATH):
        raise RuntimeError(f'sandbox_runtime.lua not found at {RUNTIME_PATH!r}')

    error_log = []
    layers = []
    caps = []
    diag = ""

    try:
        source = _fix_lua_source(source)
    except Exception as e:
        error_log.append(f"SOURCE_FIX_ERROR: {e}")
    
    try:
        source = _repair_malformed(source)
    except Exception as e:
        error_log.append(f"REPAIR_ERROR: {e}")

    try:
        temp_dir = tempfile.mkdtemp()
    except Exception as e:
        return [], [], f"TEMP_DIR_ERROR: {e}"

    try:
        inp = os.path.join(temp_dir, 'input.lua')
        drv = os.path.join(temp_dir, 'driver.lua')

        try:
            with open(inp, 'wb') as f:
                f.write(source.encode('latin-1'))
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

        out_dir = temp_dir.replace('\\', '/')
        inp_path = inp.replace('\\', '/')
        
        driver = (runtime
                  .replace('"OUTDIR_PLACEHOLDER"', _lua_str(out_dir))
                  .replace('"INPATH_PLACEHOLDER"', _lua_str(inp_path)))

        if not _write_file_safe(drv, driver, 'w'):
            error_log.append("WRITE_DRIVER_ERROR")
            shutil.rmtree(temp_dir, ignore_errors=True)
            return [], [], "WRITE_DRIVER_ERROR: Could not write driver.lua"

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
            data, err = _read_file_safe(p)
            if err:
                error_log.append(f"READ_LAYER_{i}_ERROR: {err}")
            elif data:
                layers.append(data)
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
            data, err = _read_file_safe(capf)
            if err:
                error_log.append(f"READ_CAP_ERROR: {err}")
            elif data:
                for part in data.split('---SEP---'):
                    s = part.strip()
                    if len(s) > 20:
                        caps.append(s)

        diagf = os.path.join(temp_dir, 'diag.txt')
        if os.path.exists(diagf):
            data, err = _read_file_safe(diagf)
            if err:
                error_log.append(f"READ_DIAG_ERROR: {err}")
            elif data:
                diag = data

        errf = os.path.join(temp_dir, 'error.txt')
        if os.path.exists(errf):
            data, err = _read_file_safe(errf)
            if err:
                error_log.append(f"READ_ERROR_FILE_ERROR: {err}")
            elif data:
                if diag:
                    diag = data + "\n---\n" + diag
                else:
                    diag = data

        if error_log:
            err_summary = "\n".join(error_log)
            if diag:
                diag = err_summary + "\n---\n" + diag
            else:
                diag = err_summary

        if not layers and not caps and not diag:
            diag = "NO_OUTPUT: Sandbox produced no output files"

    except Exception as e:
        diag = f"SANDBOX_FATAL: {e}\n{traceback.format_exc()}"
    finally:
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass

    return layers, caps, diag
