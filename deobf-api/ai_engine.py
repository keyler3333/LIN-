import os
import json
import re

GROQ_AVAILABLE = False
try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    pass

from scanner import ObfuscationScanner
from transformers import (
    EscapeSequenceTransformer,
    MathTransformer,
    WeAreDevsLifter,
    HexNameRenamer,
)
from sandbox import execute_sandbox

SYSTEM_PROMPT = """You are a Lua reverse-engineering AI with full control over a modular deobfuscation pipeline.
You can:
- analyze the code to detect the obfuscator
- apply static transformers (escape, math, cipher, hexrename, or custom variable renaming)
- run the sandbox to peel VM layers or capture payloads
- rename identifiers intelligently based on their usage patterns

Use these tools iteratively until the script is readable. When done, call finalize with the clean code and a detailed summary."""

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "analyze",
            "description": "Return detected obfuscator type and recommended method.",
            "parameters": {
                "type": "object",
                "properties": {"code": {"type": "string"}},
                "required": ["code"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "apply_transformers",
            "description": "Apply one or more static transformers. Available: escape, math, wearedevs, hexrename.",
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {"type": "string"},
                    "transformers": {
                        "type": "array",
                        "items": {"type": "string", "enum": ["escape", "math", "wearedevs", "hexrename"]},
                    },
                },
                "required": ["code", "transformers"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "smart_rename",
            "description": "Replace old variable/field names with meaningful new ones.",
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {"type": "string"},
                    "mapping": {"type": "object", "description": "Dict mapping old names to new names."},
                },
                "required": ["code", "mapping"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_sandbox",
            "description": "Execute the code in the Lua sandbox.",
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {"type": "string"},
                    "use_emulator": {"type": "boolean"},
                },
                "required": ["code", "use_emulator"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "finalize",
            "description": "Finish and return the final code plus summary.",
            "parameters": {
                "type": "object",
                "properties": {
                    "final_code": {"type": "string"},
                    "summary": {"type": "string"},
                },
                "required": ["final_code", "summary"],
            },
        },
    },
]


def _beautify(code):
    try:
        from luaparser import ast
        return ast.to_lua_source(ast.parse(code))
    except Exception:
        out, ind = [], 0
        for line in code.split('\n'):
            line = line.strip()
            if not line:
                continue
            if line.startswith(('end', 'else', 'elseif', 'until', '}', ')')):
                ind = max(0, ind - 1)
            out.append('    ' * ind + line)
            if line.startswith(('if', 'for', 'while', 'repeat', 'function', 'local function')) \
               and not line.endswith('end'):
                ind += 1
            elif line.startswith(('else', 'elseif')):
                ind += 1
        return '\n'.join(out)


class _DictRenamer:
    def __init__(self, mapping):
        self._mapping = mapping

    def transform(self, code):
        for old, new in self._mapping.items():
            code = re.sub(r'\b' + re.escape(old) + r'\b', new, code)
        return code


class AIEngine:
    def __init__(self, api_key, model="llama-3.3-70b-versatile"):
        self.api_key = api_key
        self.model   = model
        self.client  = None
        if GROQ_AVAILABLE and api_key:
            self.client = Groq(api_key=api_key)
        self.scanner = ObfuscationScanner()
        self.transformers = {
            'escape':    EscapeSequenceTransformer(),
            'math':      MathTransformer(),
            'wearedevs': WeAreDevsLifter(),
            'hexrename': HexNameRenamer(),
        }
        self.max_iterations = 12

    def _call_ai(self, messages):
        if not self.client:
            return None
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            tools=TOOLS,
            tool_choice="auto",
            temperature=0.1,
        )
        return response.choices[0].message

    def process(self, original_source):
        if not self.client:
            current_code = original_source
            for t in self.transformers.values():
                current_code = t.transform(current_code)
            obf_type, method = self.scanner.analyze(current_code)
            layers, captures = execute_sandbox(current_code, use_emulator=(method == 'dynamic'))
            if layers:
                payload = max((l for l in layers if isinstance(l, str)), key=len, default=None)
                if payload:
                    current_code = payload
            elif captures:
                for cap in captures:
                    if isinstance(cap, str) and len(cap) > len(current_code) * 0.4 and 'function' in cap:
                        current_code = cap
                        break
            return {
                'result':       _beautify(current_code),
                'detected':     obf_type,
                'diagnostic':   'Non-AI fallback pipeline used (groq not configured).',
                'ai_feedback':  'AI not available - used static transformers + sandbox fallback.',
            }

        messages = [
            {'role': 'system', 'content': SYSTEM_PROMPT},
            {'role': 'user',   'content': f'Deobfuscate this Lua script:\n```lua\n{original_source}\n```'},
        ]
        current_code = original_source
        iteration = 0
        while iteration < self.max_iterations:
            iteration += 1
            msg = self._call_ai(messages)
            if msg is None:
                break
            messages.append(msg)
            if not msg.tool_calls:
                break
            for tool_call in msg.tool_calls:
                func_name = tool_call.function.name
                args      = json.loads(tool_call.function.arguments)
                result_text = 'Unknown function.'

                if func_name == 'finalize':
                    return {
                        'result':      args['final_code'],
                        'detected':    'ai_driven',
                        'diagnostic':  args['summary'],
                        'ai_feedback': args['summary'],
                    }

                elif func_name == 'analyze':
                    obf_type, method = self.scanner.analyze(current_code)
                    result_text = f'Detected: {obf_type}, method: {method}'

                elif func_name == 'apply_transformers':
                    applied = []
                    for tname in args['transformers']:
                        if tname in self.transformers:
                            current_code = self.transformers[tname].transform(current_code)
                            applied.append(tname)
                    result_text = f'Applied: {", ".join(applied)}. Length: {len(current_code)}.'

                elif func_name == 'smart_rename':
                    current_code = _DictRenamer(args['mapping']).transform(current_code)
                    result_text  = f'Renamed {len(args["mapping"])} identifiers.'

                elif func_name == 'run_sandbox':
                    layers, captures = execute_sandbox(
                        current_code, use_emulator=args['use_emulator']
                    )
                    if layers:
                        str_layers = [l for l in layers if isinstance(l, str)]
                        if str_layers:
                            current_code = max(str_layers, key=len)
                            result_text  = f'Sandbox peeled layer of size {len(current_code)}.'
                        else:
                            result_text = 'Sandbox gave only bytecode layers.'
                    elif captures:
                        useful = [c for c in captures if isinstance(c, str)
                                  and not c.startswith('__')
                                  and len(c) > len(current_code) * 0.4
                                  and 'function' in c]
                        if useful:
                            current_code = useful[0]
                            result_text  = 'Sandbox recovered payload.'
                        else:
                            result_text = 'Sandbox gave nothing useful.'
                    else:
                        result_text = 'No sandbox output.'

                messages.append({
                    'role': 'tool',
                    'tool_call_id': tool_call.id,
                    'content': result_text,
                })

        return {
            'result':      _beautify(current_code),
            'detected':    'ai_driven',
            'diagnostic':  'AI did not finalize within iteration limit.',
            'ai_feedback': 'AI did not call finalize.',
        }
