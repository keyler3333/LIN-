import os, subprocess, tempfile, concurrent.futures, hashlib
from collections import Counter
import math

LUA_BIN      = os.environ.get('LUA_BIN', 'lua5.1')
RUNTIME_PATH = os.path.join(os.path.dirname(__file__), 'sandbox', 'runtime.lua')

def _entropy(s):
    if not s: return 0
    c  = Counter(s)
    ln = len(s)
    return -sum((v/ln) * math.log2(v/ln) for v in c.values())

def _score_layer(code, trace_text=''):
    score = (
        code.count('function'),
        code.count('local'),
        code.count('end'),
        -_entropy(code),
        len(code),
    )
    if trace_text and ('loadstring' in trace_text or 'decode' in trace_text):
        return (score[0] + 10,) + score[1:]
    return score

def _run_single(source, timeout, env_patch=''):
    try:
        with open(RUNTIME_PATH, encoding='utf-8') as f:
            sandbox = f.read()
    except Exception:
        return [], ''
    if env_patch:
        sandbox = sandbox + '\n' + env_patch
    with tempfile.TemporaryDirectory() as d:
        in_path = os.path.join(d, 'input.lua')
        with open(in_path, 'w', encoding='utf-8') as f:
            f.write(source)
        esc_dir    = d.replace('\\', '\\\\').replace('"', '\\"')
        esc_input  = in_path.replace('\\', '\\\\').replace('"', '\\"')
        driver = sandbox + f'\nlocal _outdir = "{esc_dir}"\n' + f"""
local _f = io.open("{esc_input}", "r")
if not _f then return end
local _code = _f:read("*a")
_f:close()
local _chunk, _err = _orig_loadstring(_code)
if _chunk then
    setfenv(_chunk, _env)
    _running = true
    pcall(_chunk)
    _running = false
end
if _char_buffer and #_char_buffer > 0 then
    capture_string(_char_buffer)
    _char_buffer = ""
end
_dump_trace()
"""
        drv_path = os.path.join(d, 'driver.lua')
        with open(drv_path, 'w', encoding='utf-8') as f:
            f.write(driver)
        try:
            subprocess.run(
                [LUA_BIN, drv_path],
                timeout=timeout,
                capture_output=True,
                cwd=d
            )
        except (subprocess.TimeoutExpired, Exception):
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
        trace_text = ''
        trace_path = os.path.join(d, 'trace.json')
        if os.path.exists(trace_path):
            with open(trace_path, encoding='utf-8', errors='replace') as f:
                trace_text = f.read()
        return layers, trace_text

def run_parallel(source, timeouts=None, env_patches=None):
    if timeouts is None:
        timeouts = [5, 8, 12]
    if env_patches is None:
        env_patches = [''] * len(timeouts)
    n           = min(len(timeouts), len(env_patches))
    timeouts    = timeouts[:n]
    env_patches = env_patches[:n]
    results = []
    max_timeout = max(timeouts) + 3
    with concurrent.futures.ProcessPoolExecutor(max_workers=n) as executor:
        futures = {
            executor.submit(_run_single, source, t, e): t
            for t, e in zip(timeouts, env_patches)
        }
        for future in concurrent.futures.as_completed(futures, timeout=max_timeout):
            try:
                results.append(future.result())
            except Exception:
                pass
    all_layers = []
    all_traces = []
    for layers, trace in results:
        all_layers.extend(layers)
        if trace:
            all_traces.append(trace)
    seen   = set()
    unique = []
    for l in all_layers:
        h = hashlib.md5(l.encode(errors='replace')).hexdigest()
        if h not in seen:
            seen.add(h)
            unique.append(l)
    if unique:
        combined_trace = all_traces[0] if all_traces else ''
        best = max(unique, key=lambda x: _score_layer(x, combined_trace))
        return best, all_traces
    return None, []
