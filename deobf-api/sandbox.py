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
    escaped = path.replace('\\', '\\\\').replace('"', '\\"')
    return f'"{escaped}"'


def execute_sandbox(source, use_emulator=False, timeout=25):
    if not os.path.isfile(RUNTIME_PATH):
        raise RuntimeError(
            f'sandbox_runtime.lua not found at {RUNTIME_PATH!r}. '
            'Place it in the same directory as sandbox.py.'
        )

    with tempfile.TemporaryDirectory() as tmp_dir:
        inp_path = os.path.join(tmp_dir, 'input.lua')
        drv_path = os.path.join(tmp_dir, 'driver.lua')

        with open(inp_path, 'w', encoding='utf-8') as fh:
            fh.write(source)

        with open(RUNTIME_PATH, 'r', encoding='utf-8') as fh:
            template = fh.read()

        driver = template \
            .replace('"OUTDIR_PLACEHOLDER"', _lua_str(tmp_dir.replace('\\', '/'))) \
            .replace('"INPATH_PLACEHOLDER"', _lua_str(inp_path.replace('\\', '/')))

        with open(drv_path, 'w', encoding='utf-8') as fh:
            fh.write(driver)

        try:
            subprocess.run(
                [LUA_BIN, drv_path],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=tmp_dir,
                env=os.environ.copy(),
            )
        except Exception:
            pass

        layers = []
        idx = 1
        while True:
            lpath = os.path.join(tmp_dir, f'layer_{idx}.lua')
            if not os.path.exists(lpath):
                break
            with open(lpath, encoding='utf-8', errors='replace') as fh:
                layers.append(fh.read())
            idx += 1

        captures = []
        cap_path = os.path.join(tmp_dir, 'cap.txt')
        if os.path.exists(cap_path):
            with open(cap_path, encoding='utf-8', errors='replace') as fh:
                for part in fh.read().split('---SEP---'):
                    stripped = part.strip()
                    if len(stripped) > 20:
                        captures.append(stripped)

        return layers, captures
