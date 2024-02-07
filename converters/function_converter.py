from collections import defaultdict

from google._upb._message import RepeatedCompositeContainer

from config import MAX_FUNCTIONS, MAX_FUNCTION_INPUT, MAX_FUNCTION_OUTPUT


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
        self._func_amount = 0
        self._func_tracker = func_tracker
        self._params_converter = params_converter

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
                self._call_tree[i].append(statement.func_call.func_num % self._func_amount)
            else:
                self._find_func_call(i, field[1])

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

    def _generate_function_name(self):
        _id = self._func_tracker.next_id
        return f"func_{_id}"
