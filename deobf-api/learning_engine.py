import json, os, hashlib
from collections import defaultdict

class LearningEngine:
    def __init__(self, path):
        self.path = path
        self.data = defaultdict(lambda: {'success': 0, 'fail': 0, 'strategies': {}})
        if os.path.exists(path):
            with open(path) as f:
                loaded = json.load(f)
                for k,v in loaded.items():
                    self.data[k] = v

    def save(self):
        with open(self.path, 'w') as f:
            json.dump(dict(self.data), f, indent=2)

    def record_result(self, source_hash, strategy_name, success):
        entry = self.data[source_hash]
        if success:
            entry['success'] += 1
        else:
            entry['fail'] += 1
        entry['strategies'][strategy_name] = entry['strategies'].get(strategy_name, 0) + 1
        self.save()

    def best_strategy(self, source_hash):
        entry = self.data.get(source_hash)
        if entry and entry['strategies']:
            return max(entry['strategies'], key=entry['strategies'].get)
        return None

    def generalize(self):
        success_count = {}
        for h, entry in self.data.items():
            if entry['success'] > entry['fail']:
                for strat, count in entry['strategies'].items():
                    success_count[strat] = success_count.get(strat, 0) + 1
        return max(success_count, key=success_count.get) if success_count else None
