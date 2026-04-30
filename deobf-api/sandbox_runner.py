import os
import subprocess
import tempfile

def run_sandbox(source, timeout=15):
    script_dir = os.path.dirname(__file__)
    runtime_path = os.path.join(script_dir, 'sandbox_runtime.lua')
    with tempfile.TemporaryDirectory() as d:
        inp = os.path.join(d, 'input.lua')
        with open(inp, 'w', encoding='utf-8') as f:
            f.write(source)
        with open(runtime_path, 'r', encoding='utf-8') as f:
            runtime = f.read()
        driver = runtime.replace('OUTDIR_PLACEHOLDER', d).replace('INPATH_PLACEHOLDER', inp)
        drv = os.path.join(d, 'driver.lua')
        with open(drv, 'w', encoding='utf-8') as f:
            f.write(driver)
        try:
            proc = subprocess.run(['lua5.1', drv], capture_output=True, text=True, timeout=timeout, cwd=d)
            stdout = proc.stdout.strip()
            stderr = proc.stderr.strip()
        except Exception as e:
            return [], str(e)
        layers = []
        i = 1
        while True:
            p = os.path.join(d, f'layer_{i}.lua')
            if not os.path.exists(p):
                break
            with open(p, encoding='utf-8', errors='replace') as f:
                layers.append(f.read())
            i += 1
        dump_path = os.path.join(d, 'dump.bin')
        if os.path.exists(dump_path):
            with open(dump_path, 'rb') as f:
                bc = f.read()
            if bc.startswith(b'\x1bLua'):
                layers.append(bc)
        return layers, stderr if not layers else ''
