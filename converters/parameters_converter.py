from .utils import extract_type
from config import MAX_FUNCTION_INPUT, MAX_FUNCTION_OUTPUT

from proto_loader import import_proto
proto = import_proto()

class ParametersConverter:
    def __init__(self, var_tracker):
        self._var_tracker = var_tracker
        self._types_provider = extract_type

    def visit_input_parameters(self, input_params):
        result = ""
        input_types = []
        names = []
        for i, input_param in enumerate(input_params):
            param_type = self._types_provider(input_param)
            input_types.append(param_type)

            name = self._var_tracker.create_and_register_variable(param_type, 1, proto.VarDecl.Mutability.IMMUTABLE)
            names.append(name)

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