import os, subprocess, tempfile, shutil

LUA_BIN = shutil.which('lua5.1') or shutil.which('lua51') or 'lua'
RUNTIME_PATH = os.path.join(os.path.dirname(__file__), 'sandbox_runtime.lua')

def execute_sandbox(source, use_emulator=False, timeout=25):
    with tempfile.TemporaryDirectory() as d:
        inp = os.path.join(d, 'input.lua')
        drv = os.path.join(d, 'driver.lua')
        with open(inp, 'w', encoding='utf-8') as f:
            f.write(source)
        with open(RUNTIME_PATH, 'r', encoding='utf-8') as f:
            runtime = f.read()
        driver = runtime.replace('OUTDIR_PLACEHOLDER', d.replace('\\', '/')).replace('INPATH_PLACEHOLDER', inp.replace('\\', '/'))
        with open(drv, 'w', encoding='utf-8') as f:
            f.write(driver)
        try:
            subprocess.run([LUA_BIN, drv], capture_output=True, text=True, timeout=timeout, cwd=d)
        except:
            pass
        layers, caps = [], []
        i = 1
        while True:
            p = os.path.join(d, f'layer_{i}.lua')
            if not os.path.exists(p): break
            with open(p, encoding='utf-8', errors='replace') as f:
                layers.append(f.read())
            i += 1
        dump = os.path.join(d, 'dump.bin')
        if os.path.exists(dump):
            with open(dump, 'rb') as f:
                bc = f.read()
            if bc.startswith(b'\x1bLua'):
                layers.append(bc)
        capf = os.path.join(d, 'cap.txt')
        if os.path.exists(capf):
            with open(capf, encoding='utf-8', errors='replace') as f:
                for part in f.read().split('---SEP---'):
                    if len(part.strip()) > 20:
                        caps.append(part.strip())
        return layers, caps
