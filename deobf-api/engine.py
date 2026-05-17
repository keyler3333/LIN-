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
        bc = self._extract_bytecode_from_sandbox(layers)
        if bc:
            dc, err = self._run_unluac(bc)
            if dc and self._is_valid_lua(dc):
                return self._beautify(dc), 'unluac', 'Decompiled from sandbox state scan'
            return base64.b64encode(bc).decode(), 'bytecode', f'Sandbox bytecode ({len(bc)} bytes). unluac: {err}'

        for item in layers:
            if isinstance(item, bytes):
                if len(item) >= 12 and item[:4] == b'\x1bLua' and item[4] == 0x51:
                    dc, err = self._run_unluac(item)
                    if dc and self._is_valid_lua(dc):
                        return self._beautify(dc), 'sandbox_unluac', 'Decompiled from sandbox bytecode dump'
            elif isinstance(item, str):
                if len(item) > 100 and self._is_valid_lua(item):
                    return self._beautify(item), 'sandbox_capture', 'Readable source captured by sandbox'

        all_text = [c for c in caps if isinstance(c, str) and len(c) > 20]
        if all_text:
            combined = '\n'.join(all_text)
            if len(combined) > 200 and self._is_valid_lua(combined):
                return self._beautify(combined), 'sandbox_string', 'Readable strings captured by sandbox'

        bc, lifter_diag = self._extract_bytecode_from_lifter(source)
        if bc:
            dc, err = self._run_unluac(bc)
            if dc and self._is_valid_lua(dc):
                return self._beautify(dc), 'unluac', 'Decompiled from static lifter'
            return base64.b64encode(bc).decode(), 'bytecode', f'Static lifter bytecode ({len(bc)} bytes). unluac: {err}'

        return '', 'unable', lifter_diag or diag or 'No readable Lua could be extracted'

    def _extract_bytecode_from_sandbox(self, layers):
        for item in layers:
            if not isinstance(item, str):
                continue
            if 'SANDBOX_OUTPUT_START' not in item:
                continue
            m = re.search(r'SANDBOX_OUTPUT_START\s*(return\s*\{.*?\})\s*SANDBOX_OUTPUT_END', item, re.DOTALL)
            if not m:
                continue
            try:
                data = ast.literal_eval(m.group(1).strip().replace('return ', ''))
            except Exception:
                continue
            for key, val in data.items():
                if isinstance(val, str) and len(val) >= 12:
                    decoded = self._decode_lua_string(val)
                    if isinstance(decoded, bytes) and len(decoded) >= 12 and decoded[:4] == b'\x1bLua' and decoded[4] == 0x51:
                        return decoded
                    if isinstance(decoded, str) and len(decoded) >= 12 and decoded[:4] == '\x1bLua' and decoded[4] == '\x51':
                        return decoded.encode('latin-1')
        return None

    @staticmethod
    def _decode_lua_string(s):
        try:
            result = bytearray()
            i = 0
            while i < len(s):
                if s[i] == '\\' and i + 1 < len(s):
                    if s[i+1] == '\\':
                        result.append(ord('\\'))
                        i += 2
                    elif s[i+1].isdigit():
                        j = i + 1
                        while j < len(s) and s[j].isdigit() and j - i < 4:
                            j += 1
                        val = int(s[i+1:j])
                        if val < 256:
                            result.append(val)
                        else:
                            result.append(ord(s[i]))
                            i += 1
                            continue
                        i = j
                    else:
                        result.append(ord(s[i]))
                        i += 1
                else:
                    result.append(ord(s[i]))
                    i += 1
            return bytes(result)
        except Exception:
            return s

    def _extract_bytecode_from_lifter(self, source):
        cmap = self.lifter._build_char_map(source)
        map_size = len(cmap) if cmap else 0
        if not cmap or map_size < 16:
            return None, f"Base64 table too small ({map_size} entries)"
        strings = self.lifter._extract_n_strings(source)
        str_count = len(strings) if strings else 0
        if not strings or str_count == 0:
            return None, f"String table not found (map: {map_size})"
        pairs = self.lifter._extract_shuffle_pairs(source)
        working = list(strings)
        if pairs:
            for a, b in pairs:
                lo, hi = a - 1, b - 1
                if 0 <= lo < len(working) and 0 <= hi < len(working) and lo < hi:
                    working[lo:hi + 1] = working[lo:hi + 1][::-1]
        decoded = []
        for s in working:
            buf = self.lifter._decode_b64(s, cmap)
            if buf:
                decoded.append(buf)
        if not decoded:
            return None, f"No strings decoded (map: {map_size}, strings: {str_count})"
        for chunk in decoded:
            if len(chunk) >= 12 and chunk[:4] == b'\x1bLua' and chunk[4] == 0x51:
                return chunk, None
        full = b''.join(decoded)
        idx = full.find(b'\x1bLua')
        if idx != -1 and idx + 5 <= len(full) and full[idx + 4] == 0x51:
            return full[idx:], None
        return None, f"Bytecode not found in {len(decoded)} decoded chunks ({len(full)} bytes total, map: {map_size}, strings: {str_count})"

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
            from luaparser import ast as lua_ast
            lua_ast.parse(code)
            return True
        except Exception:
            pass
        lua_keywords = {'function','local','end','return','if','then','else','elseif','for','while','do','repeat','until','not','and','or','nil','true','false','in','break'}
        words = set(re.findall(r'\b\w+\b', code))
        if len(words & lua_keywords) < 2:
            return False
        printable = sum(1 for c in code if c.isprintable() or c in '\n\r\t')
        return (printable / max(len(code), 1)) >= 0.60

    def _beautify(self, code):
        try:
            from luaparser import ast as lua_ast
            return lua_ast.to_lua_source(lua_ast.parse(code))
        except Exception:
            out, ind = [], 0
            openers = ('if ', 'if(', 'for ', 'for(', 'while ', 'while(', 'function ', 'local function ', 'do', 'repeat')
            closers = ('end', 'else', 'elseif', 'until', '}', ')')
            for raw in code.split('\n'):
                line = raw.strip()
                if not line: out.append(''); continue
                if any(line.startswith(w) for w in closers): ind = max(0, ind - 1)
                out.append('    ' * ind + line)
                if any(line.startswith(w) for w in openers) and not line.endswith('end'): ind += 1
            return '\n'.join(out)
