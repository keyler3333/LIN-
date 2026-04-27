from .base import BaseStrategy
import re

class LuraphStrategy(BaseStrategy):
    name = "luraph"
    def detect(self, source):
        return bool(re.search(r'loadstring\s*\(\s*\(function', source))
    def deobfuscate(self, source, pipeline):
        from pipeline import deep_deobfuscate
        return deep_deobfuscate(source, force_vm_lift=True)
