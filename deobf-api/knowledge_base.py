import json, os, hashlib

class KnowledgeBase:
    def __init__(self, path):
        self.path = path
        self.data = {}
        if os.path.exists(path):
            with open(path) as f:
                self.data = json.load(f)

    def save(self):
        with open(self.path, 'w') as f:
            json.dump(self.data, f, indent=2)

    def add_result(self, source_hash, result_code, strategy_used):
        self.data[source_hash] = {
            'result': result_code,
            'strategy': strategy_used
        }
        self.save()

    def get_result(self, source_hash):
        return self.data.get(source_hash)

def hash_source(source):
    return hashlib.sha256(source.encode('utf-8')).hexdigest()
