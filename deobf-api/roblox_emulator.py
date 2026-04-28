import os, subprocess, tempfile

EMULATOR_BIN     = os.environ.get('LUNE_BIN', 'lune')
ROBLOX_ENV_PATH  = os.path.join(os.path.dirname(__file__), 'roblox_env.lua')

def run_emulator(source, timeout=30):
    with tempfile.TemporaryDirectory() as d:
        in_path  = os.path.join(d, 'input.lua')
        env_path = ROBLOX_ENV_PATH.replace('\\', '/')
        inp_path = in_path.replace('\\', '/')
        out_path = d.replace('\\', '/')

        with open(in_path, 'w', encoding='utf-8') as f:
            f.write(source)

        driver = f'''
local env_chunk = loadfile("{env_path}")
if not env_chunk then
    print("ERROR: cannot load roblox_env.lua")
    return
end
env_chunk()
local f = io.open("{inp_path}", "r")
if not f then print("ERROR: cannot open input") return end
local code = f:read("*a")
f:close()
os.setenv("OUTDIR", "{out_path}")
_run(code)
'''
        drv_path = os.path.join(d, 'driver.lua')
        with open(drv_path, 'w', encoding='utf-8') as f:
            f.write(driver)

        try:
            env = os.environ.copy()
            env['OUTDIR'] = out_path
            proc = subprocess.run(
                [EMULATOR_BIN, 'run', drv_path],
                capture_output=True, text=True,
                timeout=timeout, cwd=d, env=env
            )
            stdout = proc.stdout.strip()
            stderr = proc.stderr.strip()
        except subprocess.TimeoutExpired:
            return [], 'timeout', '', ''
        except FileNotFoundError:
            return [], 'lune_not_installed', '', ''
        except Exception as e:
            return [], str(e), '', ''

        layers = []
        i = 1
        while True:
            p = os.path.join(d, f'layer_{i}.lua')
            if not os.path.exists(p):
                break
            with open(p, encoding='utf-8', errors='replace') as f:
                data = f.read()
            if data.strip():
                layers.append(data)
            i += 1

        return layers, '', stdout, stderr
