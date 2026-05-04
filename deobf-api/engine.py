import os
from transformers import (
    WeAreDevsLifter,
    EscapeSequenceTransformer,
    MathTransformer,
    HexNameRenamer,
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
            self.lifter,
            HexNameRenamer(),
        ]
        self.max_depth = 5

    def process(self, source, depth=0):
        if depth >= self.max_depth:
            return self._beautify(source), 'max_depth', 'Max recursion depth reached'

        current = source
        for t in self.cleaners:
            try:
                current = t.transform(current)
            except:
                pass

        if isinstance(current, str) and current != source and self._looks_decoded(current):
            return self._beautify(current), 'static_lift', 'Static lift succeeded'

        diag = self.lifter.diagnostic or 'Could not identify or decode the constant table.'

        if GROQ_AVAILABLE and GROQ_KEY:
            ai_note = self._ai_analysis(source, diag)
            if ai_note:
                diag = f"{diag}\n\n--- AI Analysis ---\n{ai_note}"

        return self._beautify(current), 'unable', diag

    def _ai_analysis(self, source, diag):
        try:
            client = Groq(api_key=GROQ_KEY)
            prompt = (
                "A Lua obfuscation deobfuscator failed to lift a WeAreDevs script. "
                "The obfuscator works by decoding a custom Base64 table, unshuffling a string constant table, "
                "and then decompiling the recovered Lua 5.1 bytecode.\n\n"
                f"Lifter diagnostic: {diag}\n\n"
                "Source code (first 4000 chars):\n```lua\n" +
                source[:4000] +
                "\n```\n\n"
                "Explain why the deobfuscation likely failed and what specific improvements would help. "
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

    @staticmethod
    def _looks_decoded(code):
        if not isinstance(code, str) or not code or len(code) < 20:
            return False
        lines = code.split('\n')
        if max((len(l) for l in lines), default=0) > 500:
            return False
        alpha = sum(1 for ch in code if ch.isalpha() or ch in ' \t\n_.,;(){}[]=')
        return (alpha / max(len(code), 1)) > 0.25

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
