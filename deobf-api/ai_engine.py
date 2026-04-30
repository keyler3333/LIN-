import os
import json
import time
from datetime import datetime

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
    CipherMapTransformer,
    HexNameRenamer,
    DictRenamer
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
                "properties": {
                    "code": {"type": "string"}
                },
                "required": ["code"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "apply_transformers",
            "description": "Apply one or more static transformers. Available: escape, math, cipher, hexrename.",
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {"type": "string"},
                    "transformers": {"type": "array", "items": {"type": "string", "enum": ["escape", "math", "cipher", "hexrename"]}}
                },
                "required": ["code", "transformers"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "smart_rename",
            "description": "Replace old variable/field names with meaningful new ones based on analysis.",
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {"type": "string"},
                    "mapping": {"type": "object", "description": "Dictionary mapping old names to new names."}
                },
                "required": ["code", "mapping"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_sandbox",
            "description": "Execute the code in the Lua sandbox. use_emulator=True for heavy VM obfuscators.",
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {"type": "string"},
                    "use_emulator": {"type": "boolean"}
                },
                "required": ["code", "use_emulator"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "finalize",
            "description": "Finish the deobfuscation and return the final code and a detailed summary.",
            "parameters": {
                "type": "object",
                "properties": {
                    "final_code": {"type": "string"},
                    "summary": {"type": "string"}
                },
                "required": ["final_code", "summary"]
            }
        }
    }
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
            if line.startswith(('if', 'for', 'while', 'repeat', 'function', 'local function')) and not line.endswith('end'):
                ind += 1
        return '\n'.join(out)

class AIEngine:
    def __init__(self, api_key, model="llama-3.3-70b-versatile"):
        self.api_key = api_key
        self.model = model
        self.client = None
        if GROQ_AVAILABLE and api_key:
            self.client = Groq(api_key=api_key)
        self.scanner = ObfuscationScanner()
        self.transformers = {
            'escape': EscapeSequenceTransformer(),
            'math': MathTransformer(),
            'cipher': CipherMapTransformer(),
            'hexrename': HexNameRenamer()
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
            temperature=0.1
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
                payload = max(layers, key=len)
                current_code = payload
            elif captures:
                for cap in captures:
                    if len(cap) > len(current_code)*0.4 and "function" in cap:
                        current_code = cap
                        break
            final_code = _beautify(current_code)
            return {
                "result": final_code,
                "detected": obf_type,
                "diagnostic": "Non-AI fallback pipeline used (groq not configured).",
                "ai_feedback": "AI not available – used static transformers + sandbox fallback."
            }

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Deobfuscate this Lua script:\n```lua\n{original_source}\n```"}
        ]
        current_code = original_source
        iteration = 0
        while iteration < self.max_iterations:
            iteration += 1
            msg = self._call_ai(messages)
            if msg is None:
                break
            messages.append(msg)
            if msg.tool_calls:
                for tool_call in msg.tool_calls:
                    func_name = tool_call.function.name
                    args = json.loads(tool_call.function.arguments)
                    if func_name == "finalize":
                        final_code = args["final_code"]
                        summary = args["summary"]
                        return {
                            "result": final_code,
                            "detected": "ai_driven",
                            "diagnostic": summary,
                            "ai_feedback": summary
                        }
                    elif func_name == "analyze":
                        obf_type, method = self.scanner.analyze(current_code)
                        messages.append({"role": "tool", "tool_call_id": tool_call.id, "content": f"Detected: {obf_type}, method: {method}"})
                    elif func_name == "apply_transformers":
                        code = current_code
                        applied = []
                        for tname in args["transformers"]:
                            if tname in self.transformers:
                                code = self.transformers[tname].transform(code)
                                applied.append(tname)
                        current_code = code
                        messages.append({"role": "tool", "tool_call_id": tool_call.id, "content": f"Applied: {', '.join(applied)}. Length: {len(current_code)}."})
                    elif func_name == "smart_rename":
                        mapping = args["mapping"]
                        code = DictRenamer(mapping).transform(current_code)
                        current_code = code
                        messages.append({"role": "tool", "tool_call_id": tool_call.id, "content": f"Renamed {len(mapping)} identifiers."})
                    elif func_name == "run_sandbox":
                        use_emu = args["use_emulator"]
                        layers, captures = execute_sandbox(current_code, use_emulator=use_emu)
                        if layers:
                            payload = max(layers, key=len)
                            current_code = payload
                            messages.append({"role": "tool", "tool_call_id": tool_call.id, "content": f"Sandbox peeled layer of size {len(payload)}."})
                        elif captures:
                            for cap in captures:
                                if cap.startswith('\x1bLua'):
                                    messages.append({"role": "tool", "tool_call_id": tool_call.id, "content": "Sandbox captured bytecode."})
                                    break
                                if len(cap) > len(current_code)*0.4 and "function" in cap:
                                    current_code = cap
                                    messages.append({"role": "tool", "tool_call_id": tool_call.id, "content": "Sandbox recovered payload."})
                                    break
                            else:
                                messages.append({"role": "tool", "tool_call_id": tool_call.id, "content": "Sandbox gave nothing useful."})
                        else:
                            messages.append({"role": "tool", "tool_call_id": tool_call.id, "content": "No sandbox output."})
                    else:
                        messages.append({"role": "tool", "tool_call_id": tool_call.id, "content": "Unknown function."})
            else:
                break
        final_code = _beautify(current_code)
        return {
            "result": final_code,
            "detected": "ai_driven",
            "diagnostic": "AI did not finalize within iteration limit.",
            "ai_feedback": "AI did not call finalize."
        }
