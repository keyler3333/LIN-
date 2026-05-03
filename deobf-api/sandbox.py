import os
import subprocess
import tempfile
import shutil

LUA_BIN = (
    shutil.which('lua5.1') or
    shutil.which('lua51')  or
    shutil.which('lua')    or
    'lua'
)
RUNTIME_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sandbox_runtime.lua')


def _lua_str(path):
    return '"' + path.replace('\\', '\\\\').replace('"', '\\"') + '"'


def execute_sandbox(source, use_emulator=False, timeout=35):
    if not os.path.isfile(RUNTIME_PATH):
        raise RuntimeError(f'sandbox_runtime.lua not found at {RUNTIME_PATH!r}')

    with tempfile.TemporaryDirectory() as d:
        inp = os.path.join(d, 'input.lua')
        drv = os.path.join(d, 'driver.lua')

        with open(inp, 'w', encoding='utf-8') as f:
            f.write(source)

        with open(RUNTIME_PATH, 'r', encoding='utf-8') as f:
            runtime = f.read()

        driver = (runtime
            .replace('"OUTDIR_PLACEHOLDER"', _lua_str(d.replace('\\', '/')))
            .replace('"INPATH_PLACEHOLDER"', _lua_str(inp.replace('\\', '/'))))

        with open(drv, 'w', encoding='utf-8') as f:
            f.write(driver)

        proc = None
        try:
            proc = subprocess.run(
                [LUA_BIN, drv],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=d,
            )
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

        layers = []
        i = 1
        while True:
            p = os.path.join(d, f'layer_{i}.lua')
            if not os.path.exists(p):
                break
            with open(p, encoding='utf-8', errors='replace') as f:
                layers.append(f.read())
            i += 1

        dump = os.path.join(d, 'dump.bin')
        if os.path.exists(dump):
            with open(dump, 'rb') as f:
                bc = f.read()
            if bc[:4] == b'\x1bLua':
                layers.append(bc)

        caps = []
        capf = os.path.join(d, 'cap.txt')
        if os.path.exists(capf):
            with open(capf, encoding='utf-8', errors='replace') as f:
                for part in f.read().split('---SEP---'):
                    s = part.strip()
                    if len(s) > 20:
                        caps.append(s)

        errf = os.path.join(d, 'error.txt')
        if os.path.exists(errf):
            with open(errf, encoding='utf-8', errors='replace') as f:
                err_text = f.read().strip()
            if err_text:
                caps.append(f'__SANDBOX_ERROR__: {err_text}')

        diagf = os.path.join(d, 'diag.txt')
        if os.path.exists(diagf):
            with open(diagf, encoding='utf-8', errors='replace') as f:
                diag_text = f.read().strip()
            if diag_text:
                caps.append(f'__SANDBOX_DIAG__: {diag_text}')

        if proc and proc.stderr and proc.stderr.strip():
            caps.append(f'__LUA_STDERR__: {proc.stderr.strip()[:500]}')

        return layers, caps
