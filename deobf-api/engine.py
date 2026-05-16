import os
import shutil
import subprocess
import tempfile
import base64
import urllib.request
from transformers import WeAreDevsLifter
from sandbox import execute_sandbox

UNLUAC_JAR_URL = "https://github.com/HansWessels/unluac/releases/download/v2023.10.24/unluac.jar"
UNLUAC_LOCAL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "unluac.jar")


class DeobfEngine:
    def __init__(self):
        self.lifter = WeAreDevsLifter()

    def process(self, source, depth=0):
        if depth > 5:
            return source, 'max_depth', 'Max recursion depth reached'

        lifted = self.lifter.transform(source)
        if lifted and lifted != source and self._looks_decoded(lifted):
            return self._beautify(lifted), 'static_lift', 'Deobfuscated by static lifter'

        lifter_diag = self.lifter.diagnostic if self.lifter.diagnostic else ''

        extracted_bc = self._extract_bytecode_from_lifter(source)
        if extracted_bc:
            unluac_result = self._try_unluac(extracted_bc)
            if unluac_result and self._looks_decoded(unluac_result):
                return self._beautify(unluac_result), 'unluac', 'Decompiled by unluac'

            java_installed = shutil.which('java') is not None
            if not java_installed:
                hint = (
                    "Lua 5.1 bytecode successfully extracted but Java is not installed.\n"
                    "Run this single command and re-upload the file:\n"
                    "sudo apt update && sudo apt install default-jre -y"
                )
            else:
                hint = (
                    "Bytecode extracted but unluac decompilation failed.\n"
                    "The bytecode is valid Lua 5.1 – try decompiling manually with:\n"
                    "java -jar unluac.jar extracted_bytecode.luac"
                )
            bc_b64 = base64.b64encode(extracted_bc).decode('ascii')
            return bc_b64, 'bytecode', hint

        best_decoded = self._get_best_decoded_text(source)
        if best_decoded and len(best_decoded) > 200:
            return best_decoded, 'static_decode', 'Best decoded strings from static lifter'

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

        if all_text:
            biggest = max(all_text, key=len)
            if len(biggest) > 200:
                return biggest, 'memory_dump', 'Largest captured string'

        reason = diag if diag else lifter_diag
        if not reason:
            reason = 'VM obfuscator – no readable source captured'
        return source, 'unable', reason

    def _get_best_decoded_text(self, source):
        try:
            cmap = self.lifter._build_char_map(source)
            if not cmap or len(cmap) < 60:
                return None
            strings = self.lifter._extract_n_strings(source)
            if not strings:
                return None
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
            if not decoded:
                return None
            best = ""
            for chunk in decoded:
                try:
                    text = chunk.decode('utf-8', errors='replace')
                    printable = sum(1 for c in text if c.isprintable() or c in '\n\r\t ')
                    if len(text) > 20 and printable / max(len(text), 1) > 0.5:
                        if len(text) > len(best):
                            best = text
                except:
                    pass
            return best if best else None
        except:
            return None

    def _ensure_unluac_jar(self):
        if os.path.isfile(UNLUAC_LOCAL_PATH):
            return UNLUAC_LOCAL_PATH
        try:
            os.makedirs(os.path.dirname(UNLUAC_LOCAL_PATH), exist_ok=True)
            urllib.request.urlretrieve(UNLUAC_JAR_URL, UNLUAC_LOCAL_PATH)
            return UNLUAC_LOCAL_PATH
        except Exception:
            return None

    def _extract_bytecode_from_lifter(self, source):
        try:
            cmap = self.lifter._build_char_map(source)
            if not cmap or len(cmap) < 60:
                return None
            strings = self.lifter._extract_n_strings(source)
            if not strings:
                return None
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
            if not decoded:
                return None
            for chunk in decoded:
                if len(chunk) >= 12 and chunk[:4] == b'\x1bLua' and chunk[4] == 0x51:
                    return chunk
            full = b''.join(decoded)
            idx = full.find(b'\x1bLua')
            if idx != -1 and idx + 5 <= len(full) and full[idx+4] == 0x51:
                return full[idx:]
            return None
        except:
            return None

    def _try_unluac(self, bytecode):
        jar_path = self._ensure_unluac_jar()
        if not jar_path:
            return None
        java_bin = shutil.which('java')
        if not java_bin:
            return None
        try:
            with tempfile.NamedTemporaryFile(suffix='.luac', delete=False) as tmp:
                tmp.write(bytecode)
                tmp_path = tmp.name
            result = subprocess.run(
                [java_bin, '-jar', jar_path, tmp_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            os.unlink(tmp_path)
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout
            return None
        except:
            return None

    @staticmethod
    def _looks_decoded(code):
        if not code or len(code) < 50:
            return False
        lines = code.split('\n')
        if max((len(l) for l in lines), default=0) > 500:
            return False
        keywords = ['function', 'local', 'end', 'if', 'then', 'else', 'for', 'while', 'do', 'return', 'print']
        kw_count = sum(1 for kw in keywords if kw in code)
        if kw_count < 2:
            return False
        alpha = sum(1 for ch in code if ch.isalpha() or ch in ' \t\n_.,;(){}[]=')
        return (alpha / max(len(code), 1)) > 0.2

    def _beautify(self, code):
        try:
            from luaparser import ast as lua_ast
            return lua_ast.to_lua_source(lua_ast.parse(code))
        except Exception:
            out, ind = [], 0
            for raw in code.split('\n'):
                line = raw.strip()
                if not line:
                    continue
                if any(line.startswith(w) for w in ('end', 'else', 'elseif', 'until', '}', ')')):
                    ind = max(0, ind - 1)
                out.append('    ' * ind + line)
                if any(line.startswith(w) for w in ('if ', 'for ', 'while ', 'repeat', 'function ', 'local function ')) and not line.endswith('end'):
                    ind += 1
            return '\n'.join(out)
