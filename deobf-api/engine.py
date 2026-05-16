import os
from transformers import WeAreDevsLifter, Lua51Parser, Lua51Decompiler
from sandbox import execute_sandbox

GROQ_KEY = os.environ.get('GROQ_API_KEY', '')
GROQ_AVAILABLE = False
if GROQ_KEY:
    try: from groq import Groq; GROQ_AVAILABLE = True
    except: pass

class DeobfEngine:
    def __init__(self):
        self.lifter = WeAreDevsLifter()

    def process(self, source, depth=0):
        if depth > 5: return source, 'max_depth', 'Max recursion depth'

        lifted = self.lifter.transform(source)
        if lifted and lifted != source and self._looks_decoded(lifted):
            return self._beautify(lifted), 'static_lift', 'Deobfuscated by static lifter'

        lifter_diag = self.lifter.diagnostic or ''

        layers, caps, diag = execute_sandbox(source, timeout=90)

        for cap in caps:
            for offset in range(len(cap)):
                if cap[offset:offset+4] == '\x1bLua' and offset+5 <= len(cap) and ord(cap[offset+4]) == 0x51:
                    bc = cap[offset:].encode('latin-1')
                    lifted_bc = self._lift_bc(bc)
                    if lifted_bc: return self._beautify(lifted_bc), 'sandbox_bytecode', 'Bytecode captured'

        for item in layers:
            if isinstance(item, bytes) and item.startswith(b'\x1bLua') and item[4] == 0x51:
                lifted_bc = self._lift_bc(item)
                if lifted_bc: return self._beautify(lifted_bc), 'sandbox_dump', 'Bytecode from dump'

        best = ''
        for cap in caps:
            if isinstance(cap, str) and len(cap) > 20 and ('function' in cap or 'local' in cap):
                if len(cap) > len(best): best = cap
        for layer in layers:
            if isinstance(layer, str) and len(layer) > 20 and ('function' in layer or 'local' in layer):
                if len(layer) > len(best): best = layer

        if best: return self._beautify(best), 'sandbox_capture', 'Readable source captured'

        if lifted and len(lifted) > 50 and lifted != source:
            return self._beautify(lifted), 'static_lift_fallback', 'Lifter output (heuristic)'

        all_text = [c for c in caps if isinstance(c, str)] + [l for l in layers if isinstance(l, str)]
        if all_text:
            biggest = max(all_text, key=len)
            if len(biggest) > 200: return biggest, 'memory_dump', 'Largest captured string'

        reason = diag or lifter_diag
        if not reason: reason = 'VM obfuscator – the hidden code is inside the decoded bytecode.'

        if GROQ_AVAILABLE and GROQ_KEY:
            try:
                client = Groq(api_key=GROQ_KEY)
                resp = client.chat.completions.create(
                    model="llama-3.3-70b-versatile",
                    messages=[{"role":"user","content":f"Deobfuscation failed: {reason}. Suggest a fix."}],
                    max_tokens=300,temperature=0.2)
                reason += "\n\n--- AI Analysis ---\n" + resp.choices[0].message.content.strip()
            except: pass
        return source, 'unable', reason

    def _lift_bc(self, bc):
        try:
            parser = Lua51Parser(bc)
            func = parser.parse_function()
            return Lua51Decompiler(func).decompile()
        except: return None

    @staticmethod
    def _looks_decoded(code):
        if not code or len(code) < 20: return False
        lines = code.split('\n')
        if max((len(l) for l in lines), default=0) > 500: return False
        alpha = sum(1 for ch in code if ch.isalpha() or ch in ' \t\n_.,;(){}[]=')
        return (alpha / max(len(code),1)) > 0.15

    def _beautify(self, code):
        try:
            from luaparser import ast as lua_ast
            return lua_ast.to_lua_source(lua_ast.parse(code))
        except:
            out, ind = [], 0
            for raw in code.split('\n'):
                line = raw.strip()
                if not line: continue
                if any(line.startswith(w) for w in ('end','else','elseif','until','}',')')): ind = max(0, ind-1)
                out.append('    '*ind + line)
                if any(line.startswith(w) for w in ('if ','for ','while ','repeat','function ','local function ')) and not line.endswith('end'): ind += 1
            return '\n'.join(out)
