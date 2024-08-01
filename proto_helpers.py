class ConvertFromTypeMessageHelper:
    def __init__(self, message):
        self._message = message

    def __getattr__(self, item):
        return getattr(self._message, item)

    def HasField(self, field):
        return hasattr(self._message, field)
