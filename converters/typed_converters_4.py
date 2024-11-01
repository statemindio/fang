from .typed_converters import TypedConverter


class NaginiConverter(TypedConverter):
    # https://github.com/vyperlang/vyper/pull/2937
    INT_BIN_OP_MAP = {
        0: "+",
        1: "-",
        2: "*",
        3: "//",
        4: "%",
        5: "**",
        6: "&",
        7: "|",
        8: "^",
        9: "<<",
        10: ">>"
    }

    DECIMAL_BIN_OP_MAP = {
        0: "+",
        1: "-",
        2: "*",
        3: "/",
        4: "%"
    }

    def visit_init(self, init):
        self._mutability_level = 0

        # init keyword
        visibility = "@deploy"

        input_params, input_types, _ = self._visit_input_parameters(init.input_params)
        function_name = "__init__"
        if len(input_types) > 0:
            self.function_inputs[function_name] = input_types

        self._block_level_count = 1
        block = self._visit_init_immutables()
        block += self._visit_block(init.block)
        self._var_tracker.remove_function_level(self._block_level_count, True)
        self._var_tracker.remove_function_level(self._block_level_count, False)
        self._block_level_count = 0

        mutability = "@payable\n" if init.mut else ""

        result = f"{visibility}\n{mutability}def {function_name}({input_params}):\n{block}"

        return result

    # https://github.com/vyperlang/vyper/pull/3769
    def _visit_reentrancy(self, ret):
        return "@nonreentrant\n"

    @classmethod
    def _format_for_statement(cls, var_name, ivar_type, start, end=None, length=None):
        if length is None:
            return f"for {var_name}: {ivar_type.vyper_type} in range({start}, {end}):"
        if end is None:
            return f"for {var_name}: {ivar_type.vyper_type} in range({length}):"
        return f"for {var_name}: {ivar_type.vyper_type} in range({start}, {end}+{length}):"
