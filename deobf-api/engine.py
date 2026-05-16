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
        # Cleaners used ONLY for static lifting
        self.cleaners = [
            EscapeSequenceTransformer(),
            MathTransformer(),
            self.lifter,
            HexNameRenamer(),
        ]

    def process(self, source, depth=0):
        if depth > 5:
            return source, 'max_depth', 'Max recursion depth reached'

        # ---- Static lift attempt ----
        current = source
        for t in self.cleaners:
            try:
                current = t.transform(current)
            except:
                pass

        if current != source and self._looks_decoded(current):
            return self._beautify(current), 'static_lift', 'Successfully deobfuscated'

        # ---- Sandbox with ORIGINAL source ----
        layers, caps, diag = execute_sandbox(source, timeout=90)

        # ... rest of the handling (bytecode / captured strings) is identical ...
        for cap in caps:
            for offset in range(len(cap)):
                if cap[offset:offset+4] == '\x1bLua':
                    if offset + 5 <= len(cap) and ord(cap[offset+4]) == 0x51:
                        bc = cap[offset:].encode('latin-1')
                        lifted = self._lift_bc(bc)
                        if lifted:
                            return self._beautify(lifted), 'sandbox_bytecode', 'Bytecode captured via sandbox'

        for item in layers:
            if isinstance(item, bytes) and item.startswith(b'\x1bLua'):
                lifted = self._lift_bc(item)
                if lifted:
                    return self._beautify(lifted), 'sandbox_dump', 'Decompiled from bytecode dump'

        best = ''
        for cap in caps:
            if len(cap) > len(best) and ('function' in cap or 'local' in cap or 'print' in cap):
                best = cap

        if best:
            return self._beautify(best), 'sandbox_capture', 'Readable source captured'

        for layer in layers:
            if isinstance(layer, str) and len(layer) > 50:
                if 'function' in layer or 'local' in layer or 'print' in layer:
                    return self._beautify(layer), 'sandbox_layer', 'Layer captured'

        reason = diag if diag else 'Sandbox produced no output and no errors were logged.'
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
        if not code or len(code) < 20:
            return False
        lines = code.split('\n')
        if max((len(l) for l in lines), default=0) > 500:
            return False
        alpha = sum(1 for ch in code if ch.isalpha() or ch in ' \t\n_.,;(){}[]=')
        return (alpha / max(len(code), 1)) > 0.25

    def _ai_analysis(self, source, diag):
        try:
            client = Groq(api_key=GROQ_KEY)
            prompt = (
                "A Lua obfuscation deobfuscator failed to lift a WeAreDevs script. "
                "The obfuscator uses a custom Base64 table, a shuffled string constant table, "
                "and then the original Lua source is hidden among the decoded strings.\n\n"
                f"Lifter diagnostic: {diag}\n\n"
                "Source code (first 4000 chars):\n```lua\n" +
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
