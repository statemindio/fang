from collections import defaultdict
from google._upb._message import RepeatedCompositeContainer


class FunctionConverter:
    def __init__(self):
        self._call_tree = defaultdict(list)

    def _find_func_call(self, i, statement):
        if isinstance(statement, (int, bool, str)):
            return
        fields = statement.ListFields()
        if len(fields) == 0:
            return
        for field in fields:
            # TODO: this test can be replaced with checking `field[0].label == field[0].LABEL_REPEATED`
            if isinstance(field[1], RepeatedCompositeContainer):
                for f in field[1]:
                    self._find_func_call(i, f)
                continue
            if field[0].name == "func_call":
                self._call_tree[i].append(statement.func_call.func_num)
            else:
                self._find_func_call(i, field[1])

    def setup_order(self, functions):
        for i, function in enumerate(functions):
            for statement in function.block.statements:
                self._find_func_call(i, statement)
