import copy
from collections import defaultdict

from proto_loader import import_proto
proto = import_proto()

class FunctionConverter:
    def __init__(self, func_tracker):
        self._call_tree = defaultdict(list)
        self._sanitized_tree = defaultdict(list)
        self._func_amount = 0
        self._func_tracker = func_tracker

    @property
    def call_tree(self):
        return self._call_tree

    def _find_func_call(self, i, statement):
        if isinstance(statement, (int, bool, str, bytes)):
            return
        fields = statement.ListFields()
        if len(fields) == 0:
            return
        for field in fields:
            if field[0].label == field[0].LABEL_REPEATED:
                for f in field[1]:
                    self._find_func_call(i, f)
                continue
            if field[0].name == "func_call":
                func_index = statement.func_call.func_num % self._func_amount
                if (func_index not in self._call_tree[i] and
                        self._func_tracker[func_index].visibility != proto.Func.Visibility.EXTERNAL):
                    self._call_tree[i].append(func_index)
            else:
                self._find_func_call(i, field[1])

    def _resolve_cyclic_dependencies(self):
        def _find_cyclic_calls(_id, call_stack):
            for called_id in self._call_tree[_id]:
                if called_id in call_stack:
                    self._sanitized_tree[_id].remove(called_id)
                    continue
                call_stack.append(called_id)
                _find_cyclic_calls(called_id, copy.copy(call_stack))

        self._sanitized_tree = copy.deepcopy(self._call_tree)
        for func in self._func_tracker:
            _find_cyclic_calls(func.id, [func.id])
            self._call_tree = copy.deepcopy(self._sanitized_tree)

    def _define_order(self):
        order = []

        def _find_next_id(_id):
            for called_id in self._call_tree[_id]:
                _find_next_id(called_id)
            if _id not in order:
                order.append(_id)

        for func in self._func_tracker:
            _find_next_id(func.id)
        return order

    def setup_order(self, functions):
        self._func_amount = len(self._func_tracker)

        for i, function in zip(range(self._func_amount), functions):
            for statement in function.block.statements:
                self._find_func_call(i, statement)
        self._resolve_cyclic_dependencies()
        return self._define_order()

    def _generate_function_name(self):
        _id = self._func_tracker.next_id
        return f"func_{_id}"
