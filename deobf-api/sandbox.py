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
        driver = runtime.replace('OUTDIR_PLACEHOLDER', d.replace('\\', '/'))\
                        .replace('INPATH_PLACEHOLDER', inp.replace('\\', '/'))
        with open(drv, 'w', encoding='utf-8') as f:
            f.write(driver)
        try:
            env = os.environ.copy()
            subprocess.run([LUA_BIN, drv], capture_output=True, text=True,
                           timeout=timeout, cwd=d, env=env)
        except:
            pass
        layers, captures = [], []
        i = 1
        while os.path.exists(os.path.join(d, f'layer_{i}.lua')):
            with open(os.path.join(d, f'layer_{i}.lua'), encoding='utf-8', errors='replace') as f:
                layers.append(f.read())
            i += 1
        cap_path = os.path.join(d, 'cap.txt')
        if os.path.exists(cap_path):
            with open(cap_path, encoding='utf-8', errors='replace') as f:
                for part in f.read().split('---SEP---'):
                    if len(part.strip()) > 20:
                        captures.append(part.strip())
        return layers, captures
