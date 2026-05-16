import os
import shutil
import subprocess
import tempfile
import base64
from transformers import WeAreDevsLifter, Lua51Parser, Lua51Decompiler
from sandbox import execute_sandbox

GROQ_KEY = os.environ.get('GROQ_API_KEY', '')
GROQ_AVAILABLE = False
if GROQ_KEY:
    try:
        from groq import Groq
        GROQ_AVAILABLE = True
    except ImportError:
        pass

class DeobfEngine:
    def __init__(self):
        self.lifter = WeAreDevsLifter()

    def process(self, source, depth=0):
        if depth > 5:
            return source, 'max_depth', 'Max recursion depth reached'

        # 1) Static lifter
        lifted = self.lifter.transform(source)
        if lifted and lifted != source and self._looks_decoded(lifted):
            return self._beautify(lifted), 'static_lift', 'Deobfuscated by static lifter'

        lifter_diag = self.lifter.diagnostic if self.lifter.diagnostic else ''

        # 2) Extract bytecode from the lifter and try unluac
        extracted_bc = self._extract_bytecode_from_lifter(source)
        if extracted_bc:
            unluac_result = self._try_unluac(extracted_bc)
            if unluac_result and self._looks_decoded(unluac_result):
                return self._beautify(unluac_result), 'unluac', 'Decompiled by unluac'
            bc_b64 = base64.b64encode(extracted_bc).decode('ascii')
            hint = (
                "Lua 5.1 bytecode extracted but unluac is not available.\n"
                "Install Java (apt install default-jre) and download unluac.jar, then run:\n"
                "java -jar unluac.jar extracted_bytecode.luac"
            )
            return bc_b64, 'bytecode', hint

        # 3) Sandbox (best‑effort string capture)
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

        # 4) Fallback reason
        reason = diag if diag else lifter_diag
        if not reason:
            reason = 'VM obfuscator – bytecode saved for external decompilation'
        if GROQ_AVAILABLE and GROQ_KEY:
            try:
                client = Groq(api_key=GROQ_KEY)
                resp = client.chat.completions.create(
                    model="llama-3.3-70b-versatile",
                    messages=[{"role": "user", "content": f"Deobfuscation failed: {reason}. Suggest fix."}],
                    max_tokens=300,
                    temperature=0.2
                )
                reason += "\n\n--- AI Analysis ---\n" + resp.choices[0].message.content.strip()
            except:
                pass
        return source, 'unable', reason

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
        unluac_path = os.environ.get('UNLUAC_PATH', 'unluac.jar')
        if not os.path.isfile(unluac_path):
            return None
        java_bin = shutil.which('java')
        if not java_bin:
            return None
        try:
            with tempfile.NamedTemporaryFile(suffix='.luac', delete=False) as tmp:
                tmp.write(bytecode)
                tmp_path = tmp.name
            result = subprocess.run(
                [java_bin, '-jar', unluac_path, tmp_path],
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

    def _lift_bc(self, bc):
        try:
            parser = Lua51Parser(bc)
            func = parser.parse_function()
            return Lua51Decompiler(func).decompile()
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
