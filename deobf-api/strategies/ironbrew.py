from .base import BaseStrategy
import re

class IronBrewStrategy(BaseStrategy):
    name = "ironbrew"
    def detect(self, source):
        return bool(re.search(r'bit\.bxor', source))
    def deobfuscate(self, source, pipeline):
        from pipeline import deep_deobfuscate
        return deep_deobfuscate(source, force_sandbox=True)
