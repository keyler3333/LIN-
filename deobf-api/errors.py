import traceback
import logging
import asyncio
import functools
import time
from enum import Enum
from dataclasses import dataclass, field
from typing import Callable

import logging.handlers

logger = logging.getLogger("deobf")
logger.setLevel(logging.DEBUG)

_console = logging.StreamHandler()
_console.setLevel(logging.INFO)
_console.setFormatter(logging.Formatter(
    "[%(asctime)s] %(levelname)s  %(message)s",
    datefmt="%H:%M:%S"
))

_file = logging.handlers.RotatingFileHandler(
    "deobf.log", maxBytes=5 * 1024 * 1024, backupCount=3
)
_file.setLevel(logging.DEBUG)
_file.setFormatter(logging.Formatter(
    "[%(asctime)s] %(levelname)s [%(funcName)s:%(lineno)d]  %(message)s"
))

logger.addHandler(_console)
logger.addHandler(_file)

class DeobfError(Exception):
    pass

class InputError(DeobfError):
    pass

class UnsupportedObfuscatorError(DeobfError):
    def __init__(self, obf_name: str):
        self.obf_name = obf_name
        super().__init__(f"Unsupported obfuscator: {obf_name}")

class StaticLiftError(DeobfError):
    pass

class SandboxError(DeobfError):
    pass

class SandboxTimeoutError(SandboxError):
    pass

class CaptureError(DeobfError):
    pass

class DecompileError(DeobfError):
    def __init__(self, tool: str, stderr: str = ""):
        self.tool = tool
        self.stderr = stderr
        super().__init__(f"{tool} failed: {stderr[:200]}")

class LuneNotInstalledError(SandboxError):
    pass

class UnluacNotFoundError(DecompileError):
    def __init__(self):
        super().__init__("unluac", "jar not found or java missing")

class Stage(Enum):
    STATIC_LIFT   = "static_lift"
    BYTECODE_PASS = "bytecode_pass"
    DYNAMIC_EXEC  = "dynamic_exec"
    DECOMPILE     = "decompile"
    FALLBACK      = "fallback"

@dataclass
class StageResult:
    stage: Stage
    success: bool
    output: str | bytes | None = None
    error: Exception | None = None
    duration_ms: float = 0.0
    note: str = ""

@dataclass
class PipelineResult:
    success: bool
    output: str | None = None
    raw_bytecode: bytes | None = None
    stages: list = field(default_factory=list)
    error: DeobfError | None = None

    def summary(self):
        lines = []
        for s in self.stages:
            icon = "[OK]" if s.success else "[FAIL]"
            line = f"{icon} {s.stage.value} ({s.duration_ms:.0f}ms)"
            if s.note:
                line += f" - {s.note}"
            lines.append(line)
        return "\n".join(lines) if lines else "No stages ran."

MAX_INPUT_BYTES = 5 * 1024 * 1024

def validate_input(source):
    if not source:
        raise InputError("File is empty.")
    raw_len = len(source) if isinstance(source, bytes) else len(source.encode("utf-8", errors="replace"))
    if raw_len > MAX_INPUT_BYTES:
        raise InputError(f"File is {raw_len // 1024}KB, exceeds {MAX_INPUT_BYTES // 1024}KB limit.")
    if isinstance(source, bytes):
        try:
            source = source.decode("utf-8")
        except UnicodeDecodeError:
            source = source.decode("latin-1")
            logger.debug("Input decoded as latin-1")
    if not source.strip():
        raise InputError("File contains only whitespace.")
    return source

def format_error_for_discord(exc):
    logger.error("Unhandled exception:\n" + traceback.format_exc())
    if isinstance(exc, InputError):
        return f"Bad input: {exc}"
    if isinstance(exc, UnsupportedObfuscatorError):
        return f"Unsupported obfuscator: {exc.obf_name}"
    if isinstance(exc, LuneNotInstalledError):
        return "Internal error: Lune runtime not installed."
    if isinstance(exc, SandboxTimeoutError):
        return "Timeout: script took too long to decode."
    if isinstance(exc, CaptureError):
        return "Capture failed: script ran but never called loadstring."
    if isinstance(exc, DecompileError):
        return f"Decompile failed ({exc.tool}). Raw .luac attached."
    if isinstance(exc, DeobfError):
        return f"Deobfuscation failed: {exc}"
    return "Unexpected error. Owner has been notified."

class timer:
    def __enter__(self):
        self._start = time.perf_counter()
        return self
    def __exit__(self, *_):
        self.ms = (time.perf_counter() - self._start) * 1000
    async def __aenter__(self):
        self._start = time.perf_counter()
        return self
    async def __aexit__(self, *_):
        self.ms = (time.perf_counter() - self._start) * 1000
