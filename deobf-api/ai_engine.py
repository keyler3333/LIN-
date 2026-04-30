import os
import json
import time
import io
from datetime import datetime

GROQ_AVAILABLE = False
try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    pass

from scanner import ObfuscationScanner
from transformers import EscapeSequenceTransformer, MathTransformer, CipherMapTransformer, HexNameRenamer
from sandbox import execute_sandbox

SYSTEM_PROMPT = """You are a Lua reverse-engineering AI. You have full control over a deobfuscation pipeline that includes static code transformations and a dynamic sandbox. Your job is to deobfuscate a given Lua script until the result is clean, readable code. You may call the available functions to analyze, transform, run sandbox, or finish when the job is done.

Always explain your reasoning briefly before calling a function. When you believe the code is fully deobfuscated, call `finish` with the final code and a summary of all methods you used and what worked.

You must record everything you do in the final summary."""

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "analyze",
            "description": "Return obfuscator type and recommended method (static_peel or dynamic).",
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "Current Lua source code"}
                },
                "required": ["code"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "apply_transformers",
            "description": "Apply one or more static transformers to the code. Available transformers: escape (decode \\x, \\ddd sequences), math (fold constant arithmetic like (number+number)), cipher (decode MoonSec/IronBrew custom base64 constant tables), hexrename (rename _0x prefixed identifiers to readable names).",
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "Current Lua source code"},
                    "transformers": {"type": "array", "items": {"type": "string", "enum": ["escape", "math", "cipher", "hexrename"]}, "description": "Which transformers to apply, in order."}
                },
                "required": ["code", "transformers"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_sandbox",
            "description": "Execute the code in the Lua sandbox (or Lune emulator if dynamic) and return any peeled layers or captured strings/bytecode.",
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "Current Lua source code"},
                    "use_emulator": {"type": "boolean", "description": "Set true for Luraph/IronBrew2/MoonSec VM style obfuscators that need a full environment."}
                },
                "required": ["code", "use_emulator"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "finalize",
            "description": "Finish the deobfuscation with the final code and a detailed summary of everything you did.",
            "parameters": {
                "type": "object",
                "properties": {
                    "final_code": {"type": "string", "description": "The completely deobfuscated Lua code."},
                    "summary": {"type": "string", "description": "Detailed summary of steps taken, methods used, what worked, and any issues."}
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
                        result_text = f"Detected obfuscator: {obf_type}, recommended method: {method}"
                        messages.append({"role": "tool", "tool_call_id": tool_call.id, "content": result_text})
                    elif func_name == "apply_transformers":
                        code = current_code
                        applied = []
                        for tname in args["transformers"]:
                            if tname in self.transformers:
                                code = self.transformers[tname].transform(code)
                                applied.append(tname)
                        current_code = code
                        messages.append({"role": "tool", "tool_call_id": tool_call.id, "content": f"Applied transformers: {', '.join(applied)}. Code length now: {len(current_code)}."})
                    elif func_name == "run_sandbox":
                        use_emu = args["use_emulator"]
                        layers, captures = execute_sandbox(current_code, use_emulator=use_emu)
                        if layers:
                            payload = max(layers, key=len)
                            current_code = payload
                            messages.append({"role": "tool", "tool_call_id": tool_call.id, "content": f"Sandbox peeled a layer of size {len(payload)} bytes."})
                        elif captures:
                            for cap in captures:
                                if cap.startswith('\x1bLua'):
                                    messages.append({"role": "tool", "tool_call_id": tool_call.id, "content": "Sandbox captured Lua 5.1 bytecode. This needs bytecode lifting."})
                                    break
                                if len(cap) > len(current_code)*0.4 and "function" in cap:
                                    current_code = cap
                                    messages.append({"role": "tool", "tool_call_id": tool_call.id, "content": "Sandbox recovered a large payload."})
                                    break
                            else:
                                messages.append({"role": "tool", "tool_call_id": tool_call.id, "content": "Sandbox produced no usable output."})
                        else:
                            messages.append({"role": "tool", "tool_call_id": tool_call.id, "content": "Sandbox produced no layers or captures."})
                    else:
                        messages.append({"role": "tool", "tool_call_id": tool_call.id, "content": "Unknown function."})
            else:
                break
        final_code = _beautify(current_code)
        return {
            "result": final_code,
            "detected": "ai_driven",
            "diagnostic": "AI reached iteration limit without finalizing.",
            "ai_feedback": "AI did not call finalize."
        }
