import os, re, shutil, subprocess, tempfile, base64, urllib.request, ast
from transformers import WeAreDevsLifter
from sandbox import execute_sandbox

UNLUAC_JAR_URL = "https://github.com/scratchminer/unluac/releases/download/v2023.03.22/unluac.jar"
UNLUAC_LOCAL_PATH = os.environ.get('UNLUAC_PATH') or os.path.join(os.path.dirname(os.path.abspath(__file__)), 'unluac.jar')

class DeobfEngine:
    def __init__(self):
        self.lifter = WeAreDevsLifter()
        self.unluac_path = UNLUAC_LOCAL_PATH

    def process(self, source):
        layers, caps, diag = execute_sandbox(source, timeout=120)
        sandbox_dump = self._find_sandbox_dump(layers, caps)
        if sandbox_dump:
            cmap = self._extract_base64_map_from_dump(sandbox_dump)
            if cmap and len(cmap) >= 60:
                bc = self._extract_bytecode_from_dump(sandbox_dump, cmap)
                if bc:
                    decompiled, err = self._run_unluac(bc)
                    if decompiled and self._is_valid_lua(decompiled):
                        return self._beautify(decompiled), 'unluac', 'Decompiled from sandbox dump'
                    b64 = base64.b64encode(bc).decode('ascii')
                    return b64, 'bytecode', f'Bytecode extracted from sandbox ({len(bc)} bytes). unluac: {err or "unknown"}'

        bc, bc_diag = self._extract_bytecode_from_lifter(source)
        if bc:
            decompiled, err = self._run_unluac(bc)
            if decompiled and self._is_valid_lua(decompiled):
                return self._beautify(decompiled), 'unluac', 'Decompiled by static lifter'
            b64 = base64.b64encode(bc).decode('ascii')
            return b64, 'bytecode', f'Bytecode extracted ({len(bc)} bytes). unluac: {err or "unknown"}'

        return '', 'unable', bc_diag or 'No readable Lua could be extracted.'

    def _find_sandbox_dump(self, layers, caps):
        for item in layers + caps:
            if isinstance(item, str) and 'SANDBOX_OUTPUT_START' in item:
                return item
        return None

    def _extract_base64_map_from_dump(self, dump):
        m = re.search(r'SANDBOX_OUTPUT_START\s*(return\s*\{.*?\})\s*SANDBOX_OUTPUT_END', dump, re.DOTALL)
        if not m:
            return None
        try:
            data = ast.literal_eval(m.group(1).strip().replace('return ', ''))
        except Exception:
            return None
        for key, val in data.items():
            if 'base64' in key.lower() and isinstance(val, str):
                cmap = {}
                for match in re.finditer(r'\[(\d+)\]\s*=\s*(\d+)', val):
                    cmap[chr(int(match.group(1)))] = int(match.group(2))
                if len(cmap) >= 60:
                    return cmap
        return None

    def _extract_bytecode_from_dump(self, dump, cmap):
        m = re.search(r'SANDBOX_OUTPUT_START\s*(return\s*\{.*?\})\s*SANDBOX_OUTPUT_END', dump, re.DOTALL)
        if not m:
            return None
        try:
            data = ast.literal_eval(m.group(1).strip().replace('return ', ''))
        except Exception:
            return None
        for key, val in data.items():
            if 'bytecode' in key.lower() and isinstance(val, str):
                if val[:4] == '\x1bLua' or val[:12] == '\x1bLua':
                    return val.encode('latin-1') if isinstance(val, str) else val
        return None

    def _extract_bytecode_from_lifter(self, source):
        cmap = self.lifter._build_char_map(source)
        if not cmap or len(cmap) < 16:
            return None, f"Base64 map too small ({len(cmap) if cmap else 0} entries)"
        strings = self.lifter._extract_n_strings(source)
        if not strings or len(strings) == 0:
            return None, f"String table not found (map: {len(cmap)})"
        pairs = self.lifter._extract_shuffle_pairs(source)
        working = list(strings)
        if pairs:
            for a, b in pairs:
                lo, hi = a-1, b-1
                if 0 <= lo < len(working) and 0 <= hi < len(working) and lo < hi:
                    working[lo:hi+1] = working[lo:hi+1][::-1]
        decoded = []
        for s in working:
            buf = self.lifter._decode_b64(s, cmap)
            if buf:
                decoded.append(buf)
        if not decoded:
            return None, "No strings decoded"
        for chunk in decoded:
            if len(chunk) >= 12 and chunk[:4] == b'\x1bLua' and chunk[4] == 0x51:
                return chunk, None
        full = b''.join(decoded)
        idx = full.find(b'\x1bLua')
        if idx != -1 and idx+5 <= len(full) and full[idx+4] == 0x51:
            return full[idx:], None
        return None, f"Bytecode not found in {len(decoded)} chunks ({len(full)} bytes)"

    def _run_unluac(self, bytecode):
        if not os.path.isfile(self.unluac_path):
            self._ensure_unluac_jar()
        if not os.path.isfile(self.unluac_path):
            return None, "unluac.jar not found"
        java_bin = shutil.which('java')
        if not java_bin:
            return None, "java not found"
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix='.luac', delete=False) as tmp:
                tmp.write(bytecode)
                tmp_path = tmp.name
            result = subprocess.run(
                [java_bin, '-jar', self.unluac_path, tmp_path],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout, None
            return None, result.stderr[:300]
        except subprocess.TimeoutExpired:
            return None, "timeout"
        except Exception as e:
            return None, str(e)
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try: os.unlink(tmp_path)
                except OSError: pass

    def _ensure_unluac_jar(self):
        try:
            jar_dir = os.path.dirname(self.unluac_path)
            if jar_dir: os.makedirs(jar_dir, exist_ok=True)
            urllib.request.urlretrieve(UNLUAC_JAR_URL, self.unluac_path)
        except Exception: pass

    @staticmethod
    def _is_valid_lua(code):
        if not code or len(code) < 20:
            return False
        try:
            import luaparser
            luaparser.ast.parse(code)
            return True
        except Exception:
            pass
        lua_keywords = {'function','local','end','return','if','then','else','elseif','for','while','do','repeat','until','not','and','or','nil','true','false','in','break'}
        words = set(re.findall(r'\b\w+\b', code))
        keyword_hits = len(words & lua_keywords)
        printable = sum(1 for c in code if c.isprintable() or c in '\n\r\t')
        return keyword_hits >= 3 and (printable / max(len(code), 1)) > 0.75

    def _beautify(self, code):
        try:
            from luaparser import ast as lua_ast
            return lua_ast.to_lua_source(lua_ast.parse(code))
        except Exception:
            out, ind = [], 0
            openers = ('if ','if(','for ','for(','while ','while(','function ','local function ','do','repeat')
            closers = ('end','else','elseif','until','}',')')
            for raw in code.split('\n'):
                line = raw.strip()
                if not line: out.append(''); continue
                if any(line.startswith(w) for w in closers): ind = max(0, ind-1)
                out.append('    '*ind + line)
                if any(line.startswith(w) for w in openers) and not line.endswith('end'): ind += 1
            return '\n'.join(out)
