import os
import shutil
import subprocess
import tempfile
import base64
import urllib.request
import asyncio
from transformers import WeAreDevsLifter
from sandbox import execute_sandbox
from lune_executor import execute_and_capture

UNLUAC_JAR_URL = "https://github.com/scratchminer/unluac/releases/download/v2023.03.22/unluac.jar"
UNLUAC_LOCAL_PATH = os.environ.get('UNLUAC_PATH') or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'unluac.jar'
)

class DeobfEngine:
    def __init__(self):
        self.lifter = WeAreDevsLifter()
        self.unluac_path = UNLUAC_LOCAL_PATH

    def process(self, source):
        lifted = self.lifter.transform(source)
        if lifted and lifted != source and self._looks_decoded(lifted):
            return self._beautify(lifted), 'static_lift', 'Deobfuscated by static lifter'

        lifter_diag = self.lifter.diagnostic or ''

        decoded_chunks = self._run_decode_pipeline(source)
        extracted_bc = None
        if decoded_chunks:
            extracted_bc = next((c for c in decoded_chunks if self._is_lua51_bytecode(c)), None)
            if not extracted_bc:
                full = b''.join(decoded_chunks)
                idx = full.find(b'\x1bLua')
                if idx != -1 and idx + 5 <= len(full) and full[idx+4] == 0x51:
                    extracted_bc = full[idx:]

        raw_bytes = source.encode('latin-1')
        if not extracted_bc and raw_bytes[:4] == b'\x1bLua':
            extracted_bc = raw_bytes

        if extracted_bc:
            decompiled, decompile_err = self._run_unluac(extracted_bc)
            if decompiled and self._looks_decoded(decompiled):
                return self._beautify(decompiled), 'unluac', 'Decompiled by unluac'
            bc_b64 = base64.b64encode(extracted_bc).decode('ascii')
            hint = "Bytecode extracted but unluac failed."
            return bc_b64, 'bytecode', hint

        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        captured, info = loop.run_until_complete(execute_and_capture(source))

        if captured:
            if self._is_lua51_bytecode(captured):
                decompiled, decompile_err = self._run_unluac(captured)
                if decompiled and self._looks_decoded(decompiled):
                    return self._beautify(decompiled), 'lune_unluac', 'Captured and decompiled via Lune'
                bc_b64 = base64.b64encode(captured).decode('ascii')
                hint = "Bytecode captured via Lune but decompilation failed."
                return bc_b64, 'bytecode', hint

            try:
                text = captured.decode('utf-8', errors='replace')
                if self._looks_decoded(text):
                    return self._beautify(text), 'lune_capture', 'Readable source captured via Lune'
                if len(text) > 100:
                    return text, 'lune_string', 'String captured via Lune'
            except:
                pass

        layers, caps, diag = execute_sandbox(source, timeout=90)

        all_text = []
        for cap in caps:
            if isinstance(cap, str) and len(cap) > 20:
                all_text.append(cap)
        for layer in layers:
            if isinstance(layer, str) and len(layer) > 20:
                all_text.append(layer)

        all_text.sort(key=len, reverse=True)

        best = ''
        for text in all_text:
            if len(text) > len(best) and ('function' in text or 'local' in text or 'print' in text or 'end' in text):
                best = text
        if best:
            return self._beautify(best), 'sandbox_capture', 'Readable source captured'

        if all_text and len(all_text[0]) > 200:
            return all_text[0], 'memory_dump', 'Largest captured string'

        reason = lifter_diag or diag or 'No readable content decoded.'
        return source, 'unable', reason

    def _run_decode_pipeline(self, source):
        cmap = self.lifter._build_char_map(source)
        if not cmap or len(cmap) < 60:
            return []
        strings = self.lifter._extract_n_strings(source)
        if not strings:
            return []
        pairs = self.lifter._extract_shuffle_pairs(source)
        working = list(strings)
        if pairs and len(pairs) == 3:
            for a, b in pairs:
                lo, hi = a - 1, b - 1
                if 0 <= lo < len(working) and 0 <= hi < len(working) and lo < hi:
                    working[lo:hi+1] = working[lo:hi+1][::-1]
        decoded = []
        for s in working:
            buf = self.lifter._decode_b64(s, cmap)
            if buf:
                decoded.append(buf)
        return decoded

    @staticmethod
    def _is_lua51_bytecode(data):
        return len(data) >= 12 and data[:4] == b'\x1bLua' and data[4] == 0x51

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
            return None, result.stderr
        except subprocess.TimeoutExpired:
            return None, "unluac timed out"
        except Exception as e:
            return None, str(e)

    def _ensure_unluac_jar(self):
        try:
            os.makedirs(os.path.dirname(self.unluac_path), exist_ok=True)
            urllib.request.urlretrieve(UNLUAC_JAR_URL, self.unluac_path)
        except:
            pass

    @staticmethod
    def _looks_decoded(code):
        if not code or len(code) < 50:
            return False
        lines = code.split('\n')
        if max((len(l) for l in lines), default=0) > 500:
            return False
        keywords = ['function', 'local', 'end', 'if', 'then', 'else', 'for', 'while', 'do', 'return', 'print']
        kw_count = sum(1 for kw in keywords if kw in code)
        if kw_count < 3:
            return False
        alpha = sum(1 for ch in code if ch.isalpha() or ch in ' \t\n_.,;(){}[]=')
        return (alpha / max(len(code), 1)) > 0.2

    def _beautify(self, code):
        try:
            from luaparser import ast as lua_ast
            return lua_ast.to_lua_source(lua_ast.parse(code))
        except:
            out, ind = [], 0
            for raw in code.split('\n'):
                line = raw.strip()
                if not line:
                    continue
                if any(line.startswith(w) for w in ('end', 'else', 'elseif', 'until', '}', ')')):
                    ind = max(0, ind - 1)
                if any(line.startswith(w) for w in ('repeat', 'do')):
                    ind += 1
                out.append('    ' * ind + line)
                if any(line.startswith(w) for w in ('if ', 'for ', 'while ', 'function ', 'local function ')) and not line.endswith('end'):
                    ind += 1
            return '\n'.join(out)
