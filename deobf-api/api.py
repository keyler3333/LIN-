import os, re, subprocess, tempfile, shutil
from flask import Flask, request, jsonify

app = Flask(__name__)

def find_lua():
    for b in ['lua5.1','lua51','lua']:
        path = shutil.which(b)
        if path:
            try:
                r = subprocess.run([path,'-v'],capture_output=True,timeout=2)
                out = (r.stderr+r.stdout).decode(errors='replace')
                if '5.1' in out: return path
            except: pass
    return 'lua5.1'

LUA_BIN = os.environ.get('LUA_BIN') or find_lua()
RUNTIME_PATH = os.path.join(os.path.dirname(__file__),'sandbox_runtime.lua')

def run_sandbox(source,timeout=25):
    with tempfile.TemporaryDirectory() as d:
        inp = os.path.join(d,'input.lua')
        with open(inp,'w',encoding='utf-8') as f: f.write(source)
        with open(RUNTIME_PATH,'r',encoding='utf-8') as f: runtime = f.read()
        esc_d = d.replace('\\','\\\\').replace('"','\\"')
        esc_i = inp.replace('\\','\\\\').replace('"','\\"')
        driver = runtime.replace('OUTDIR_PLACEHOLDER',esc_d).replace('INPATH_PLACEHOLDER',esc_i)
        drv = os.path.join(d,'driver.lua')
        with open(drv,'w',encoding='utf-8') as f: f.write(driver)
        try:
            proc = subprocess.run([LUA_BIN,drv],capture_output=True,text=True,timeout=timeout,cwd=d)
            stdout = proc.stdout.strip()
            stderr = proc.stderr.strip()
        except subprocess.TimeoutExpired:
            stdout,stderr = '','timeout'
        except Exception as e: return [],[],str(e),'',''
        layers = []
        i = 1
        while True:
            p = os.path.join(d,f'layer_{i}.lua')
            if not os.path.exists(p): break
            with open(p,encoding='utf-8',errors='replace') as f: layers.append(f.read())
            i += 1
        cap = []
        cp = os.path.join(d,'cap.txt')
        if os.path.exists(cp):
            with open(cp,encoding='utf-8',errors='replace') as f:
                raw = f.read()
                for part in raw.split('---SEP---'):
                    s = part.strip().replace('\\n','\n')
                    if len(s) > 20: cap.append(s)
        diag = ''
        dp = os.path.join(d,'diag.txt')
        if os.path.exists(dp):
            with open(dp,encoding='utf-8',errors='replace') as f: diag = f.read()
        return layers,cap,diag,stdout,stderr

import roblox_emulator
from normalizer import normalize_source
import wearedevs_lifter

def detect_obfuscator(text):
    patterns = {
        'luraph':    [r'loadstring\s*\(\s*\(function',r'bytecode\s*=\s*["\'][A-Za-z0-9+/=]{50,}',r'Luraph'],
        'ironbrew2': [r'while\s+true\s+do\s+local\s+\w+\s*=\s*\w+\[\w+\]',r'local\s+\w+,\s*\w+,\s*\w+\s*=\s*\w+\s*&'],
        'ironbrew1': [r'bit\.bxor',r'getfenv\s*\(\s*\)\s*\[',r'IronBrew'],
        'moonsec':   [r'local\s+\w+\s*=\s*\{[\d\s,]{20,}\}',r'_moon\s*=\s*function',r'MoonSec'],
        'wearedevs': [r'show_\w+\s*=\s*function',r'getfenv\s*\(\s*\)',r'string\.reverse'],
        'prometheus':[r'Prometheus',r'number_to_bytes'],
        'hercules':  [r'Hercules',r'Str\s*=\s*string\.sub'],
        'generic_vm':[r'mkexec',r'constTags',r'protoFormats'],
    }
    scores = {}
    for name,pats in patterns.items():
        s = sum(1 for p in pats if re.search(p,text,re.IGNORECASE))
        if s: scores[name] = s
    if not scores: return 'generic','normalize'
    best = max(scores,key=lambda k:scores[k])
    if best in ('luraph','ironbrew2','generic_vm'): return best,'ast_vm_lift'
    return best,'normalize'

def static_decode(code):
    code = re.sub(r'\\x([0-9a-fA-F]{2})',lambda m:chr(int(m.group(1),16)),code)
    code = re.sub(r'\\(\d{1,3})',lambda m:chr(int(m.group(1))) if int(m.group(1))<256 else m.group(0),code)
    def sc(m):
        nums = re.findall(r'\d+',m.group(1))
        try: return '"'+''.join(chr(int(n)) for n in nums if int(n)<256)+'"'
        except: return m.group(0)
    code = re.sub(r'string\.char\s*\(\s*([\d,\s]+)\s*\)',sc,code)
    return code

def beautify(code):
    out,indent = [],0
    dedent_pat = r'^(end\b|else\b|elseif\b|until\b|\})'
    indent_pat = r'^(if\b|for\b|while\b|repeat\b|do\b|else\b|elseif\b|local\s+function\b|function\b)'
    for line in code.split('\n'):
        line = line.strip()
        if not line:
            out.append('')
            continue
        if re.match(dedent_pat,line): indent = max(0,indent-1)
        out.append('    '*indent+line)
        if re.match(indent_pat,line) and not (line.endswith('end') or line.endswith('}')): indent += 1
    return '\n'.join(out)

def lupa_sandbox(source,timeout=15):
    captured = []
    try:
        import lupa
        lua = lupa.LuaRuntime(unpack_returned_tuples=True)
        for name in ['io','os','require','dofile','loadfile','package','collectgarbage','newproxy','module']:
            try: lua.execute(f"{name}=nil")
            except: pass
        lua.execute("game=setmetatable({},{__index=function()return function()end end});workspace=game;script={}")
        lua.execute("Players={LocalPlayer={Name='Player',UserId=1}}")
        lua.execute("RunService={Heartbeat={Connect=function()end}}")
        lua.execute("tick=function()return 0 end;time=function()return 0 end;wait=function(n)return n or 0 end")
        lua.execute("spawn=function(f)if type(f)=='function'then pcall(f)end end")
        lua.execute("print=function()end;warn=function()end")
        lua.execute("if not bit then bit={bxor=function(a,b)local r,p=0,1 while a>0 or b>0 do if a%2~=b%2 then r=r+p end a=math.floor(a/2)b=math.floor(b/2)p=p*2 end return r end,band=function(a,b)local r,p=0,1 while a>0 and b>0 do if a%2==1 and b%2==1 then r=r+p end a=math.floor(a/2)b=math.floor(b/2)p=p*2 end return r end,bor=function(a,b)local r,p=0,1 while a>0 or b>0 do if a%2==1 or b%2==1 then r=r+p end a=math.floor(a/2)b=math.floor(b/2)p=p*2 end return r end,bnot=function(a)return -a-1 end,rshift=function(a,b)return math.floor(a/(2^b))end,lshift=function(a,b)return math.floor(a*(2^b))end,bit32=bit}end")
        lua.execute("table.pack=table.pack or function(...)return{n=select('#',...),...}end;table.unpack=table.unpack or unpack")
        def safe_ls(code,*args):
            if callable(code):
                chunks = []
                try:
                    while True:
                        c = code()
                        if not c:break
                        chunks.append(str(c))
                except: pass
                code = ''.join(chunks)
            s = str(code) if code else ''
            if len(s.strip())>5: captured.append(s)
            return lua.eval("function(...)end")
        lua.globals()['loadstring'] = safe_ls
        lua.globals()['load'] = safe_ls
        try: lua.execute(source)
        except: pass
        return captured
    except ImportError: return []

def deobfuscate(source):
    obf_type,method = detect_obfuscator(source)
    diag = ''
    if obf_type == 'wearedevs':
        try:
            lifted = wearedevs_lifter.lift_wearedevs(source)
            if lifted:
                lifted = static_decode(lifted)
                lifted = beautify(lifted)
                return lifted,obf_type,0,'wearedevs_vm_lift','WeAreDevs VM lifted with register inlining'
        except Exception as e: diag = f'WeAreDevs lifter error: {e}'
    if method == 'normalize':
        try:
            result = normalize_source(source)
            if result:
                result = static_decode(result)
                result = beautify(result)
                return result,obf_type,0,'ast_normalize','AST normalization + de-aliasing applied'
        except Exception as e: diag = f'AST normalizer error: {e}'
    if method == 'ast_vm_lift':
        result,layers,previews,diag2 = run_sandbox(source)
        if layers>0:
            result = static_decode(result)
            result = beautify(result)
            return result,obf_type,layers,'sandbox',diag2
    if method == 'roblox_emulator':
        emu_layers,emu_err,emu_stdout,emu_stderr = roblox_emulator.run_emulator(source)
        if emu_layers:
            result = max(emu_layers,key=len)
            result = static_decode(result)
            result = beautify(result)
            return result,obf_type,1,'roblox_emulator','Emulator captured payload'
        diag = f'Emulator failed: {emu_err}\n{emu_stdout}\n{emu_stderr}'
    result,layers,previews,diag2 = run_sandbox(source)
    diag = diag or diag2
    if layers>0:
        result = static_decode(result)
        result = beautify(result)
        return result,obf_type,layers,'sandbox',diag
    captured = lupa_sandbox(source)
    if captured:
        best = max(captured,key=len)
        if len(best.strip())>20 and best!=source:
            best = static_decode(best)
            best = beautify(best)
            return best,obf_type,1,'lupa_sandbox','lupa captured payload'
    result = static_decode(source)
    result = beautify(result)
    if obf_type in ('ironbrew2','luraph'):
        diag += ' This obfuscator requires specialized per-version deobfuscation for full reversal.'
    return result,obf_type,0,'static',diag

@app.route('/health')
def health():
    lua_ok,active = False,LUA_BIN
    for b in [LUA_BIN,'lua5.1','lua51','lua']:
        try:
            r = subprocess.run([b,'-v'],capture_output=True,timeout=2)
            out = (r.stderr+r.stdout).decode(errors='replace')
            if '5.1' in out: lua_ok = True; active = b; break
        except: pass
    return jsonify({'ok':True,'lua':lua_ok,'lua_bin':active})

@app.route('/deobf',methods=['POST'])
def deobf():
    data = request.get_json(force=True)
    source = data.get('source','')
    if not source.strip(): return jsonify({'error':'no source'}),400
    result,obf_type,layers,method,diag = deobfuscate(source)
    return jsonify({
        'result':result,
        'layers':layers,
        'method':method,
        'detected':obf_type,
        'diagnostic':diag[:1000] if diag else '',
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0',port=int(os.environ.get('PORT',5000)))
