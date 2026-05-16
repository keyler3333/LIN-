import os
from transformers import (
    WeAreDevsLifter,
    EscapeSequenceTransformer,
    MathTransformer,
    HexNameRenamer,
    Lua51Parser,
    Lua51Decompiler,
)
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
        self.cleaners = [
            EscapeSequenceTransformer(),
            MathTransformer(),
            HexNameRenamer(),
        ]

    def process(self, source, depth=0):
        if depth > 5:
            return source, 'max_depth', 'Max recursion depth reached'

        lifted = self.lifter.transform(source)
        if lifted and lifted != source and self._looks_decoded(lifted):
            return self._beautify(lifted), 'static_lift', 'Static lifter extracted readable source'

        lifter_diag = self.lifter.diagnostic if self.lifter.diagnostic else ''

        layers, caps, diag = execute_sandbox(source, timeout=90)

        for cap in caps:
            for offset in range(len(cap)):
                if cap[offset:offset+4] == '\x1bLua':
                    if offset + 5 <= len(cap) and ord(cap[offset+4]) == 0x51:
                        bc = cap[offset:].encode('latin-1')
                        lifted_bc = self._lift_bc(bc)
                        if lifted_bc:
                            return self._beautify(lifted_bc), 'sandbox_bytecode', 'Bytecode captured via sandbox'

        for item in layers:
            if isinstance(item, bytes) and item.startswith(b'\x1bLua'):
                lifted_bc = self._lift_bc(item)
                if lifted_bc:
                    return self._beautify(lifted_bc), 'sandbox_dump', 'Decompiled from bytecode dump'

        all_captured = caps + layers
        best = ''
        for item in all_captured:
            s = item if isinstance(item, str) else (item.decode('utf-8', errors='replace') if isinstance(item, bytes) else str(item))
            if len(s) > len(best):
                score = self._readability_score(s)
                if score > 0.1 and len(s) > len(best):
                    best = s

        if best and ('function' in best or 'local' in best or 'print' in best or 'end' in best):
            return self._beautify(best), 'sandbox_capture', 'Readable source captured from sandbox'

        if lifted and len(lifted) > 50 and lifted != source:
            return self._beautify(lifted), 'static_lift_fallback', 'Static lifter produced output'

        if best and len(best) > 200:
            return best, 'memory_dump', 'Recovered from sandbox memory dump'

        reason = diag if diag else lifter_diag
        if not reason:
            reason = 'All deobfuscation methods exhausted. The script uses VM-based obfuscation that does not call loadstring.'
        if GROQ_AVAILABLE and GROQ_KEY:
            ai_note = self._ai_analysis(source, reason)
            if ai_note:
                reason = f"{reason}\n\n--- AI Analysis ---\n{ai_note}"
        return source, 'unable', reason

    def _lift_bc(self, bc):
        try:
            parser = Lua51Parser(bc)
            func = parser.parse_function()
            return Lua51Decompiler(func).decompile()
        except Exception:
            return None

    @staticmethod
    def _looks_decoded(code):
        return DeobfEngine._readability_score(code) > 0.15

    @staticmethod
    def _readability_score(code):
        if not code or len(code) < 20:
            return 0.0
        lines = code.split('\n')
        if max((len(l) for l in lines), default=0) > 500:
            return 0.0
        alpha = sum(1 for ch in code if ch.isalpha() or ch in ' \t\n_.,;(){}[]=')
        keywords = ['function', 'local', 'end', 'if', 'then', 'else', 'for', 'while', 'do', 'return', 'print']
        kw_score = sum(1 for kw in keywords if kw in code) / len(keywords)
        return (alpha / max(len(code), 1)) * 0.7 + kw_score * 0.3

    def _ai_analysis(self, source, diag):
        try:
            client = Groq(api_key=GROQ_KEY)
            prompt = (
                "A Lua obfuscation deobfuscator failed to lift a WeAreDevs script. "
                "The obfuscator uses a custom Base64 table, a shuffled string constant table, "
                "and a VM-based executor that never calls loadstring.\n\n"
                f"Diagnostic: {diag}\n\n"
                "Source (first 4000 chars):\n```lua\n" +
                source[:4000] +
                "\n```\n\n"
                "Explain why the deobfuscation likely failed and what specific fix should be applied."
            )
            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=800,
                temperature=0.2,
            )
            return response.choices[0].message.content.strip()
        except Exception:
            return None

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
