import os
import shutil
import subprocess
import tempfile
import base64
import urllib.request
from transformers import WeAreDevsLifter
from sandbox import execute_sandbox

UNLUAC_JAR_URL = "https://github.com/scratchminer/unluac/releases/download/v2023.03.22/unluac.jar"
UNLUAC_LOCAL_PATH = os.environ.get('UNLUAC_PATH') or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'unluac.jar'
)

class DeobfEngine:
    def __init__(self):
        self.lifter = WeAreDevsLifter()
        self.unluac_path = UNLUAC_LOCAL_PATH

    def process(self, source):
        bc = self._extract_bytecode(source)
        if bc:
            decompiled, err = self._run_unluac(bc)
            if decompiled and self._is_valid_lua(decompiled):
                return self._beautify(decompiled), 'unluac', 'Decompiled by unluac'
            b64 = base64.b64encode(bc).decode('ascii')
            return b64, 'bytecode', f'Bytecode extracted ({len(bc)} bytes). unluac: {err or "unknown"}'

        layers, caps, diag = execute_sandbox(source, timeout=90)
        all_text = [t for t in caps + layers if isinstance(t, str) and len(t) > 20]
        combined = '\n'.join(all_text)
        if len(combined) > 200 and self._is_valid_lua(combined):
            return self._beautify(combined), 'sandbox_capture', 'Readable source captured by sandbox'

        return '', 'unable', 'No readable Lua could be extracted. The script may use an unsupported obfuscator.'

    def _extract_bytecode(self, source):
        cmap = self.lifter._build_char_map(source)
        if not cmap or len(cmap) < 16:
            return None
        strings = self.lifter._extract_n_strings(source)
        if not strings:
            return None
        pairs = self.lifter._extract_shuffle_pairs(source)
        working = list(strings)
        if pairs:
            for a, b in pairs:
                lo, hi = a - 1, b - 1
                if 0 <= lo < len(working) and 0 <= hi < len(working) and lo < hi:
                    working[lo:hi + 1] = working[lo:hi + 1][::-1]
        decoded = [buf for s in working if (buf := self.lifter._decode_b64(s, cmap))]
        if not decoded:
            return None
        for chunk in decoded:
            if len(chunk) >= 12 and chunk[:4] == b'\x1bLua' and chunk[4] == 0x51:
                return chunk
        full = b''.join(decoded)
        idx = full.find(b'\x1bLua')
        if idx != -1 and idx + 5 <= len(full) and full[idx + 4] == 0x51:
            return full[idx:]
        return None

    def _run_unluac(self, bytecode):
        if not os.path.isfile(self.unluac_path):
            self._ensure_unluac_jar()
        if not os.path.isfile(self.unluac_path):
            return None, "unluac.jar not found"
        java_bin = shutil.which('java')
        if not java_bin:
            return None, "java not found"
        try:
            with tempfile.NamedTemporaryFile(suffix='.luac', delete=False) as tmp:
                tmp.write(bytecode)
                tmp_path = tmp.name
            result = subprocess.run(
                [java_bin, '-jar', self.unluac_path, tmp_path],
                capture_output=True, text=True, timeout=30
            )
            os.unlink(tmp_path)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout, None
            return None, result.stderr[:300]
        except subprocess.TimeoutExpired:
            return None, "timeout"
        except Exception as e:
            return None, str(e)

    def _ensure_unluac_jar(self):
        try:
            os.makedirs(os.path.dirname(self.unluac_path), exist_ok=True)
            urllib.request.urlretrieve(UNLUAC_JAR_URL, self.unluac_path)
        except Exception:
            pass

    @staticmethod
    def _is_valid_lua(code):
        if not code or len(code) < 20:
            return False
        try:
            from luaparser import ast
            ast.parse(code)
            return True
        except Exception:
            return False

    def _beautify(self, code):
        try:
            from luaparser import ast as lua_ast
            return lua_ast.to_lua_source(lua_ast.parse(code))
        except Exception:
            out, ind = [], 0
            openers = ('if ', 'if(', 'for ', 'for(', 'while ', 'while(',
                       'function ', 'local function ', 'do', 'repeat')
            closers = ('end', 'else', 'elseif', 'until', '}', ')')
            for raw in code.split('\n'):
                line = raw.strip()
                if not line:
                    out.append('')
                    continue
                if any(line.startswith(w) for w in closers):
                    ind = max(0, ind - 1)
                out.append('    ' * ind + line)
                if any(line.startswith(w) for w in openers) and not line.endswith('end'):
                    ind += 1
            return '\n'.join(out)
