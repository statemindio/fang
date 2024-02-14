import copy
from collections import defaultdict

from config import MAX_FUNCTIONS, MAX_FUNCTION_INPUT, MAX_FUNCTION_OUTPUT
from vyperProtoNew_pb2 import Func


class ParametersConverter:
    def __init__(self, var_tracker, types_provider):
        self._var_tracker = var_tracker
        self._types_provider = types_provider

    def visit_input_parameters(self, input_params):
        result = ""
        input_types = []
        names = []
        for i, input_param in enumerate(input_params):
            param_type = self._types_provider(input_param)
            input_types.append(param_type)
            idx = self._var_tracker.next_id(param_type)
            name = f"x_{param_type.name}_{idx}"
            names.append(name)

            self._var_tracker.register_function_variable(name, 1, param_type, False)

            if i > 0:
                result = f"{result}, "
            result = f"{result}{name}: {param_type.vyper_type}"

            if i + 1 == MAX_FUNCTION_INPUT:
                break

        return result, input_types, names

    def visit_output_parameters(self, output_params):
        output_types = []
        for i, output_param in enumerate(output_params):
            param_type = self._types_provider(output_param)
            output_types.append(param_type)

            if i + 1 == MAX_FUNCTION_OUTPUT:
                break
        return output_types


class FunctionConverter:
    def __init__(self, func_tracker, params_converter):
        self._call_tree = defaultdict(list)
        self._sanitized_tree = defaultdict(list)
        self._func_amount = 0
        self._func_tracker = func_tracker
        self._params_converter = params_converter

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
                if (func_index not in self._call_tree[i] or
                        self._func_tracker[func_index].visibility == Func.Visibility.EXTERNAL):
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
        self._func_amount = len(functions)
        input_names = []
        for i, function in enumerate(functions):
            if i >= MAX_FUNCTIONS:
                break

            function_name = self._generate_function_name()
            input_params, input_types, names = self._params_converter.visit_input_parameters(function.input_params)
            input_names.append(names)
            output_types = self._params_converter.visit_output_parameters(function.output_params)
            self._func_tracker.register_function(function_name, function.mut, function.vis, input_types, output_types)

            for statement in function.block.statements:
                self._find_func_call(i, statement)
        self._resolve_cyclic_dependencies()
        return self._define_order()

    def _generate_function_name(self):
        _id = self._func_tracker.next_id
        return f"func_{_id}"
