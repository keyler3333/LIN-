import os
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

        lifted = self.lifter.transform(source)
        if lifted and lifted != source and self._looks_decoded(lifted):
            return self._beautify(lifted), 'static_lift', 'Static lifter extracted readable source'

        lifter_diag = self.lifter.diagnostic if self.lifter.diagnostic else ''

        layers, caps, diag = execute_sandbox(source, timeout=90)

        for cap in caps:
            for offset in range(len(cap)):
                if cap[offset:offset+4] == '\x1bLua' and offset + 5 <= len(cap) and ord(cap[offset+4]) == 0x51:
                    bc = cap[offset:].encode('latin-1')
                    lifted_bc = self._lift_bc(bc)
                    if lifted_bc:
                        return self._beautify(lifted_bc), 'sandbox_bytecode', 'Bytecode captured'

        for item in layers:
            if isinstance(item, bytes) and item.startswith(b'\x1bLua') and item[4] == 0x51:
                lifted_bc = self._lift_bc(item)
                if lifted_bc:
                    return self._beautify(lifted_bc), 'sandbox_dump', 'Bytecode from dump'

        all_text = []
        for cap in caps:
            if isinstance(cap, str) and len(cap) > 20:
                all_text.append(cap)
        for layer in layers:
            if isinstance(layer, str) and len(layer) > 20:
                all_text.append(layer)

        best = ''
        for text in all_text:
            if len(text) > len(best) and ('function' in text or 'local' in text or 'print' in text or 'end' in text):
                best = text

        if best:
            return self._beautify(best), 'sandbox_capture', 'Readable source captured'

        if lifted and len(lifted) > 50 and lifted != source:
            return self._beautify(lifted), 'static_lift_fallback', 'Static lifter output'

        if all_text:
            best_overall = max(all_text, key=len)
            if len(best_overall) > 200:
                return best_overall, 'memory_dump', 'Recovered from sandbox memory'

        reason = diag if diag else lifter_diag
        if not reason:
            reason = 'VM-based obfuscator – no loadstring call. The hidden source is inside the VM bytecode and requires a dedicated Lua 5.1 decompiler (e.g. unluac) to recover.'
        if GROQ_AVAILABLE and GROQ_KEY:
            try:
                client = Groq(api_key=GROQ_KEY)
                prompt = (
                    "Deobfuscation failed for a WeAreDevs VM obfuscator.\n"
                    f"Diagnostic: {reason}\n"
                    "Suggest a concrete fix."
                )
                response = client.chat.completions.create(
                    model="llama-3.3-70b-versatile",
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=300,
                    temperature=0.2,
                )
                ai_note = response.choices[0].message.content.strip()
                reason = f"{reason}\n\n--- AI Analysis ---\n{ai_note}"
            except:
                pass
        return source, 'unable', reason

    def _lift_bc(self, bc):
        try:
            parser = Lua51Parser(bc)
            func = parser.parse_function()
            return Lua51Decompiler(func).decompile()
        except:
            return None

    @staticmethod
    def _looks_decoded(code):
        if not code or len(code) < 20:
            return False
        lines = code.split('\n')
        if max((len(l) for l in lines), default=0) > 500:
            return False
        alpha = sum(1 for ch in code if ch.isalpha() or ch in ' \t\n_.,;(){}[]=')
        return (alpha / max(len(code), 1)) > 0.15

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
