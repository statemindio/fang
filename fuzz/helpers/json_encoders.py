import json
from decimal import Decimal

class ExtendedEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return {
                "_type": "Decimal",
                "value": str(obj)
            }
        if isinstance(obj, bytes):
            return {
                "_type": "bytes",
                "value": obj.hex()
            }
        return super().default(obj)


class ExtendedDecoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        super().__init__(object_hook=self.object_hook, *args, **kwargs)

    def object_hook(self, obj):
        if '_type' not in obj:
            return obj
        if obj['_type'] == 'Decimal':
            return Decimal(obj['value'])
        if obj['_type'] == 'bytes':
            return bytes.fromhex(obj["value"])
        return obj