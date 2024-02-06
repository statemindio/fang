from collections import defaultdict
from google._upb._message import RepeatedCompositeContainer

class FunctionConverter:
    def __init__(self):
        self._call_tree = defaultdict(list)

    def _find_func_call(self, i, statement):
        fields = statement.ListFields()
        if len(fields) == 0:
            return
        field = fields[0]
        if isinstance(field, RepeatedCompositeContainer):
            for f in field:
                self._find_func_call(i, f)
        if field.name == "func_call":
            self._call_tree[i].append(statement.func_call.func_num)
        else:
            self._find_func_call(i, field)

    def setup_order(self, functions):
        for i, function in enumerate(functions):
            for statement in function.block.statements:
                self._find_func_call(i, statement)
