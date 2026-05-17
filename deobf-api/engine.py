import os
import shutil
import subprocess
import tempfile
import base64
import urllib.request
import asyncio

from transformers import (
    WeAreDevsLifter,
    EscapeSequenceTransformer,
    MathTransformer,
    HexNameRenamer,
    NumberArrayDecoder,
    Base64StdDecoder,
)
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
        self.pre_transformers = [
            EscapeSequenceTransformer(),
            MathTransformer(),
            HexNameRenamer(),
        ]
        self.static_decoders = [
            NumberArrayDecoder(),
            Base64StdDecoder(),
        ]

    def process(self, source):
        cleaned = source
        for t in self.pre_transformers:
            try:
                cleaned = t.transform(cleaned) or cleaned
            except Exception:
                pass

        lifted = self.lifter.transform(cleaned)
        if lifted and lifted != cleaned and self._looks_decoded(lifted):
            return self._beautify(lifted), 'static_lift', 'WeAreDev static lifter'

        lifter_diag = self.lifter.diagnostic or ''

        for decoder in self.static_decoders:
            try:
                result = decoder.transform(cleaned)
                if result and result != cleaned and self._looks_decoded(result):
                    return self._beautify(result), 'static_decode', decoder.__class__.__name__
            except Exception:
                pass

        extracted_bc = self._extract_bytecode(cleaned)
        raw_bytes = cleaned.encode('latin-1')
        if not extracted_bc and raw_bytes[:4] == b'\x1bLua':
            extracted_bc = raw_bytes

        if extracted_bc:
            decompiled, err = self._run_unluac(extracted_bc)
            if decompiled and self._looks_decoded(decompiled):
                return self._beautify(decompiled), 'unluac', 'Bytecode decompiled by unluac'
            bc_b64 = base64.b64encode(extracted_bc).decode('ascii')
            hint   = f"Bytecode extracted but unluac failed ({err or 'unknown reason'})"
            return bc_b64, 'bytecode', hint

        captured, lune_info = self._run_lune(cleaned)
        if captured:
            if self._is_lua51_bytecode(captured):
                decompiled, err = self._run_unluac(captured)
                if decompiled and self._looks_decoded(decompiled):
                    return self._beautify(decompiled), 'lune_unluac', 'Lune captured bytecode, decompiled by unluac'
                bc_b64 = base64.b64encode(captured).decode('ascii')
                return bc_b64, 'bytecode', 'Lune captured bytecode; unluac unavailable/failed'
            try:
                text = captured.decode('utf-8', errors='replace')
                if self._looks_decoded(text):
                    return self._beautify(text), 'lune_capture', 'Source captured by Lune dynamic execution'
                if len(text) > 100:
                    return text, 'lune_string', 'String captured by Lune'
            except Exception:
                pass

        layers, caps, sandbox_diag = execute_sandbox(cleaned, timeout=90)

        all_text = []
        for item in caps + layers:
            if isinstance(item, str) and len(item) > 20:
                all_text.append(item)
        all_text.sort(key=len, reverse=True)

        for text in all_text:
            if self._looks_decoded(text):
                return self._beautify(text), 'sandbox_capture', 'Readable source captured by sandbox'

        for item in layers:
            if isinstance(item, bytes) and self._is_lua51_bytecode(item):
                decompiled, _ = self._run_unluac(item)
                if decompiled and self._looks_decoded(decompiled):
                    return self._beautify(decompiled), 'sandbox_unluac', 'Sandbox bytecode decompiled by unluac'

        if all_text and len(all_text[0]) > 200:
            return all_text[0], 'memory_dump', 'Largest captured string from sandbox memory'

        reason = lifter_diag or sandbox_diag or 'No readable content extracted'
        return source, 'unable', reason

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
            if self._is_lua51_bytecode(chunk):
                return chunk
        full = b''.join(decoded)
        idx  = full.find(b'\x1bLua')
        if idx != -1 and idx + 5 <= len(full) and full[idx + 4] == 0x51:
            return full[idx:]
        return None

    def _run_lune(self, source):
        try:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_closed():
                    raise RuntimeError
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            return loop.run_until_complete(execute_and_capture(source))
        except Exception as e:
            return None, {'error': str(e)}

    @staticmethod
    def _is_lua51_bytecode(data):
        if isinstance(data, str):
            data = data.encode('latin-1')
        return len(data) >= 12 and data[:4] == b'\x1bLua' and data[4] == 0x51

    def _run_unluac(self, bytecode):
        if not os.path.isfile(self.unluac_path):
            self._ensure_unluac_jar()
        if not os.path.isfile(self.unluac_path):
            return None, "unluac.jar not found"
        java_bin = shutil.which('java')
        if not java_bin:
            return None, "java not found in PATH"
        try:
            with tempfile.NamedTemporaryFile(suffix='.luac', delete=False) as tmp:
                tmp.write(bytecode)
                tmp_path = tmp.name
            result = subprocess.run(
                [java_bin, '-jar', self.unluac_path, tmp_path],
                capture_output=True, text=True, timeout=30,
            )
            os.unlink(tmp_path)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout, None
            return None, result.stderr[:300]
        except subprocess.TimeoutExpired:
            return None, "unluac timed out after 30 s"
        except Exception as e:
            return None, str(e)

    def _ensure_unluac_jar(self):
        try:
            dir_ = os.path.dirname(self.unluac_path)
            if dir_:
                os.makedirs(dir_, exist_ok=True)
            urllib.request.urlretrieve(UNLUAC_JAR_URL, self.unluac_path)
        except Exception:
            pass

    @staticmethod
    def _looks_decoded(code):
        if not code or len(code) < 30:
            return False
        lines = code.split('\n')
        if max((len(l) for l in lines), default=0) > 4000:
            return False
        keywords = [
            'function', 'local', 'end', 'if', 'then', 'else',
            'for', 'while', 'do', 'return', 'print', 'require',
        ]
        kw_count = sum(1 for kw in keywords if kw in code)
        if kw_count < 2:
            return False
        alpha = sum(1 for ch in code if ch.isalpha() or ch in ' \t\n_.,;(){}[]=')
        return (alpha / max(len(code), 1)) > 0.15

    def _beautify(self, code):
        try:
            from luaparser import ast as lua_ast
            return lua_ast.to_lua_source(lua_ast.parse(code))
        except Exception:
            pass
        out = []
        ind = 0
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
