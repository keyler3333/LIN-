class BaseStrategy:
    name = "base"
    def detect(self, source):
        return False
    def deobfuscate(self, source, pipeline):
        return source
