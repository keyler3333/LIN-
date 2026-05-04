import os
from transformers import Lua51Parser, Lua51Decompiler, EscapeSequenceTransformer, MathTransformer, HexNameRenamer
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
        self.cleaners = [
            EscapeSequenceTransformer(),
            MathTransformer(),
            HexNameRenamer(),
        ]
        self.max_depth = 5

    def process(self, source, depth=0):
        if depth >= self.max_depth:
            return source, 'max_depth', 'Max recursion depth reached'

        current = source
        for t in self.cleaners:
            try:
                current = t.transform(current)
            except:
                pass

        layers, captures, diag = execute_sandbox(current, timeout=90)

        for cap in captures:
            for offset in range(len(cap)):
                if cap[offset:offset+4] == '\x1bLua':
                    if offset + 5 <= len(cap) and ord(cap[offset+4]) == 0x51:
                        bc = cap[offset:].encode('latin-1')
                        lifted = self._lift_bc(bc)
                        if lifted:
                            return self._beautify(lifted), 'table_concat_bytecode', 'Bytecode captured via table.concat / string.char'

        for item in layers:
            if isinstance(item, bytes) and item.startswith(b'\x1bLua'):
                lifted = self._lift_bc(item)
                if lifted:
                    return self._beautify(lifted), 'sandbox_bytecode', 'Decompiled from bytecode dump'

        best = ''
        for cap in captures:
            if len(cap) > len(best) and ('function' in cap or 'local' in cap or 'print' in cap):
                best = cap

        if best:
            return self._beautify(best), 'table_concat_source', 'Readable source captured via table.concat / string.char'

        for layer in layers:
            if isinstance(layer, str) and len(layer) > 50:
                if 'function' in layer or 'local' in layer or 'print' in layer:
                    return self._beautify(layer), 'sandbox_layer', 'Layer captured'

        reason = diag if diag else 'Sandbox executed but no bytecode or source was captured.'
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

    def _ai_analysis(self, source, diag):
        try:
            client = Groq(api_key=GROQ_KEY)
            prompt = (
                "A Lua obfuscation deobfuscator failed to capture any decrypted payload from a WeAreDevs script. "
                "The script uses a custom Base64 decoder, a shuffled string table, and a VM‑based executor. "
                "The sandbox executed without errors but produced no captured bytecode or readable source.\n\n"
                f"Sandbox diagnostic: {diag}\n\n"
                "Source code (first 4000 chars):\n```lua\n" +
                source[:4000] +
                "\n```\n\n"
                "Explain the most likely reason for the failure and suggest exactly what to change in the sandbox or engine to capture the payload. "
                "Be concise and technical."
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
