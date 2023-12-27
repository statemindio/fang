class FuncTracker:
    def __init__(self):
        self._id = -1
        self._functions = []

    def register_function(self, name):
        self._functions.append(name)
        self._id = len(self._functions) - 1

    @property
    def current_id(self):
        return self._id

    @property
    def next_id(self):
        return self._id + 1
