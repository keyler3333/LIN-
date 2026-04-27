import json, os, threading
from collections import defaultdict

_lock = threading.Lock()

class LearningEngine:
    def __init__(self, path):
        self.path = path
        self.data = defaultdict(lambda: {'success': 0, 'fail': 0, 'strategies': {}})
        if os.path.exists(path):
            try:
                with open(path) as f:
                    loaded = json.load(f)
                for k, v in loaded.items():
                    self.data[k] = v
            except Exception:
                pass

    def _save(self):
        tmp = self.path + '.tmp'
        try:
            with open(tmp, 'w') as f:
                json.dump(dict(self.data), f, indent=2)
            os.replace(tmp, self.path)
        except Exception:
            pass

    def record_result(self, source_hash, strategy_name, success):
        with _lock:
            entry = self.data[source_hash]
            if success:
                entry['success'] += 1
            else:
                entry['fail'] += 1
            entry['strategies'][strategy_name] = \
                entry['strategies'].get(strategy_name, 0) + 1
            self._save()

    def best_strategy(self, source_hash):
        with _lock:
            entry = self.data.get(source_hash)
            if entry and entry['strategies']:
                return max(entry['strategies'], key=entry['strategies'].get)
            return None
