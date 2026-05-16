import os
from transformers import WeAreDevsLifter
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
            return source, 'max_depth', 'Max recursion depth'

        lifted = self.lifter.transform(source)
        if lifted and lifted != source and self._looks_decoded(lifted):
            return self._beautify(lifted), 'static_lift', 'Deobfuscated by static lifter'

        lifter_diag = self.lifter.diagnostic or ''

        layers, caps, diag = execute_sandbox(source, timeout=90)

        all_str = []
        for c in caps:
            if isinstance(c, str) and len(c) > 10:
                all_str.append(c)
        for l in layers:
            if isinstance(l, str) and len(l) > 10:
                all_str.append(l)

        all_str.sort(key=len, reverse=True)

        best_combo = '\n'.join(all_str[:30])
        if len(best_combo) > 50 and self._looks_decoded(best_combo):
            return self._beautify(best_combo), 'sandbox_capture', 'Combined readable source from sandbox'

        if lifted and len(lifted) > 50 and lifted != source:
            return self._beautify(lifted), 'static_lift_fallback', 'Lifter produced output'

        reason = diag if diag else lifter_diag
        if not reason:
            reason = 'VM obfuscator – the hidden source must be extracted with an external Lua decompiler (e.g., unluac)'
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
