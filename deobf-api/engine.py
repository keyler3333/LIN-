import os, re, shutil, subprocess, tempfile, base64, urllib.request, asyncio

from transformers import (
    WeAreDevsLifter,
    EscapeSequenceTransformer,
    MathTransformer,
    NumberArrayDecoder,
    Base64StdDecoder,
    XorStringDecoder,
)
from sandbox import execute_sandbox
from lune_executor import execute_and_capture

UNLUAC_JAR_URL = "https://github.com/scratchminer/unluac/releases/download/v2023.03.22/unluac.jar"
UNLUAC_LOCAL_PATH = os.environ.get('UNLUAC_PATH') or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'unluac.jar'
)

LUA_KEYWORDS = {
    'function', 'local', 'end', 'return', 'if', 'then', 'else', 'elseif',
    'for', 'while', 'do', 'repeat', 'until', 'not', 'and', 'or',
    'nil', 'true', 'false', 'in', 'break', 'print', 'require',
    'pcall', 'xpcall', 'loadstring', 'load', 'pairs', 'ipairs',
    'setmetatable', 'getmetatable', 'rawset', 'rawget', 'tostring', 'tonumber',
}


class DeobfEngine:
    def __init__(self):
        self.lifter   = WeAreDevsLifter()
        self.unluac_path = UNLUAC_LOCAL_PATH
        self.pre_xforms = [EscapeSequenceTransformer(), MathTransformer()]
        self.static_decoders = [NumberArrayDecoder(), Base64StdDecoder(), XorStringDecoder()]

    def process(self, source: str):
        cleaned = source
        for t in self.pre_xforms:
            try:
                cleaned = t.transform(cleaned) or cleaned
            except Exception:
                pass
        if cleaned != source and self._looks_decoded(cleaned):
            return self._beautify(cleaned), 'pre_transform', 'Decoded by pre-transformers'

        raw = cleaned.encode('latin-1', errors='replace')
        if self._is_bc(raw):
            dc, err = self._run_unluac(raw)
            if dc and self._looks_decoded(dc):
                return self._beautify(dc), 'unluac_raw', 'Raw Lua 5.1 bytecode decompiled'
            return base64.b64encode(raw).decode(), 'bytecode', f'Raw bytecode; unluac: {err}'

        for d in self.static_decoders:
            try:
                r = d.transform(cleaned)
                if r and r != cleaned and self._looks_decoded(r):
                    return self._beautify(r), 'static', d.__class__.__name__
            except Exception:
                pass

        try:
            lifted = self.lifter.transform(cleaned)
            if lifted and lifted != cleaned and self._looks_decoded(lifted):
                return self._beautify(lifted), 'static_lift', 'WeAreDev static lifter'
        except Exception:
            pass
        lifter_diag = self.lifter.diagnostic or ''

        bc = self._wad_bc(cleaned)
        if bc:
            dc, err = self._run_unluac(bc)
            if dc and self._looks_decoded(dc):
                return self._beautify(dc), 'unluac', 'WeAreDev bytecode + unluac'
            return base64.b64encode(bc).decode(), 'bytecode', f'WeAreDev bytecode; unluac: {err}'

        lune_data, _ = self._run_lune(cleaned)
        if lune_data:
            if self._is_bc(lune_data):
                dc, err = self._run_unluac(lune_data)
                if dc and self._looks_decoded(dc):
                    return self._beautify(dc), 'lune_unluac', 'Lune capture + unluac'
                return base64.b64encode(lune_data).decode(), 'bytecode', f'Lune bytecode; unluac: {err}'
            try:
                text = lune_data.decode('utf-8', errors='replace')
                if self._looks_decoded(text):
                    return self._beautify(text), 'lune_capture', 'Source captured via Lune'
                if len(text) > 100:
                    return text, 'lune_raw', 'Raw string captured via Lune'
            except Exception:
                pass

        layers, caps, sb_diag = execute_sandbox(cleaned, timeout=120)

        for item in layers:
            if isinstance(item, bytes):
                if self._is_bc(item):
                    dc, err = self._run_unluac(item)
                    if dc and self._looks_decoded(dc):
                        return self._beautify(dc), 'sandbox_unluac', 'Sandbox bytecode + unluac'
                    return base64.b64encode(item).decode(), 'bytecode', f'Sandbox bytecode; unluac: {err}'
                continue
            if not isinstance(item, str):
                continue
            if 'SANDBOX_OUTPUT_START' in item:
                for hex_m in re.finditer(r'"(\\[0-9]{1,3}(?:\\[0-9]{1,3}){11,})"', item):
                    candidate = self._decode_lua_escape(hex_m.group(1))
                    if candidate and self._is_bc(candidate):
                        dc, err = self._run_unluac(candidate)
                        if dc and self._looks_decoded(dc):
                            return self._beautify(dc), 'sandbox_state_bc', 'State-scan bytecode + unluac'
                continue
            raw_layer = item.encode('latin-1', errors='replace')
            if self._is_bc(raw_layer):
                dc, err = self._run_unluac(raw_layer)
                if dc and self._looks_decoded(dc):
                    return self._beautify(dc), 'sandbox_bc_layer', 'Sandbox layer bytecode + unluac'
                return base64.b64encode(raw_layer).decode(), 'bytecode', f'Sandbox layer bytecode; unluac: {err}'
            if self._looks_decoded(item):
                return self._beautify(item), 'sandbox_capture', 'Source captured via sandbox'

        str_caps = sorted([c for c in caps if isinstance(c, str) and len(c) > 30], key=len, reverse=True)
        for cap in str_caps:
            raw_cap = cap.encode('latin-1', errors='replace')
            if self._is_bc(raw_cap):
                dc, err = self._run_unluac(raw_cap)
                if dc and self._looks_decoded(dc):
                    return self._beautify(dc), 'sandbox_cap_bc', 'Cap bytecode + unluac'
            if self._looks_decoded(cap):
                return self._beautify(cap), 'sandbox_string', 'String captured by sandbox'

        if str_caps and len(str_caps[0]) > 200:
            return str_caps[0], 'memory_dump', 'Largest string from sandbox memory scan'

        reason = lifter_diag or sb_diag or 'No readable content decoded'
        return source, 'unable', reason

    def _wad_bc(self, source: str):
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
            if self._is_bc(chunk):
                return chunk
        full = b''.join(decoded)
        idx  = full.find(b'\x1bLua')
        if idx != -1 and idx + 5 <= len(full) and full[idx + 4] == 0x51:
            return full[idx:]
        return None

    @staticmethod
    def _decode_lua_escape(s: str) -> bytes | None:
        try:
            result = bytearray()
            i = 0
            while i < len(s):
                if s[i] == '\\' and i + 1 < len(s):
                    j = i + 1
                    while j < len(s) and s[j].isdigit() and j - i < 4:
                        j += 1
                    result.append(int(s[i + 1:j]))
                    i = j
                else:
                    result.append(ord(s[i]))
                    i += 1
            return bytes(result)
        except Exception:
            return None

    def _run_lune(self, source: str):
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
    def _is_bc(data: bytes) -> bool:
        return (isinstance(data, bytes) and len(data) >= 12
                and data[:4] == b'\x1bLua' and data[4] == 0x51)

    def _run_unluac(self, bytecode: bytes):
        if not os.path.isfile(self.unluac_path):
            self._ensure_unluac_jar()
        if not os.path.isfile(self.unluac_path):
            return None, 'unluac.jar not found'
        java_bin = shutil.which('java')
        if not java_bin:
            return None, 'java not in PATH'
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix='.luac', delete=False) as tmp:
                tmp.write(bytecode)
                tmp_path = tmp.name
            result = subprocess.run(
                [java_bin, '-jar', self.unluac_path, tmp_path],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout, None
            return None, result.stderr[:300]
        except subprocess.TimeoutExpired:
            return None, 'timeout (30s)'
        except Exception as e:
            return None, str(e)
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try: os.unlink(tmp_path)
                except OSError: pass

    def _ensure_unluac_jar(self):
        try:
            jar_dir = os.path.dirname(self.unluac_path)
            if jar_dir:
                os.makedirs(jar_dir, exist_ok=True)
            urllib.request.urlretrieve(UNLUAC_JAR_URL, self.unluac_path)
        except Exception:
            pass

    def _looks_decoded(self, code: str) -> bool:
        if not code or len(code) < 20:
            return False
        if any(len(l) > 8000 for l in code.split('\n')):
            return False
        words = set(re.findall(r'\b\w+\b', code[:10000]))
        if len(words & LUA_KEYWORDS) < 2:
            return False
        printable = sum(1 for c in code if c.isprintable() or c in '\n\r\t')
        return (printable / max(len(code), 1)) >= 0.60

    def _beautify(self, code: str) -> str:
        try:
            from luaparser import ast as lua_ast
            return lua_ast.to_lua_source(lua_ast.parse(code))
        except Exception:
            pass
        out, ind = [], 0
        openers = ('if ', 'if(', 'for ', 'for(', 'while ', 'while(',
                   'function ', 'local function ', 'do', 'repeat')
        closers = ('end', 'else', 'elseif', 'until', '})')
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
