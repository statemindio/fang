from .typed_converters import TypedConverter, get_bin_op
from types_d import Bool, Decimal, BytesM, Address, Bytes, Int, String, FixedList, DynArray

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


    # https://github.com/vyperlang/vyper/pull/3596
    def _visit_for_stmt_ranged(self, for_stmt_ranged):
        start, stop = (
            for_stmt_ranged.start, for_stmt_ranged.stop) if for_stmt_ranged.start < for_stmt_ranged.stop else (
            for_stmt_ranged.stop, for_stmt_ranged.start
        )
        if stop == start:
            stop += 1
        ivar_type = Int()
        idx = self._var_tracker.next_id(ivar_type)
        var_name = f"i_{idx}"
        self._var_tracker.register_function_variable(var_name, self._block_level_count + 1, ivar_type, False)
        result = f"for {var_name}: {ivar_type.vyper_type}  in range({start}, {stop}):"
        return result

    def _visit_for_stmt_variable(self, for_stmt_variable):
        variable = None
        ivar_type = Int()
        if for_stmt_variable.HasField("ref_id"):
            self.type_stack.append(ivar_type)
            variable = self._visit_var_ref(for_stmt_variable.ref_id, self._block_level_count)
            self.type_stack.pop()
        length = for_stmt_variable.length
        if length == 0:
            length = 1
        idx = self._var_tracker.next_id(ivar_type)
        var_name = f"i_{idx}"
        self._var_tracker.register_function_variable(var_name, self._block_level_count + 1, ivar_type, False)
        if variable is None:
            result = f"for {var_name}: {ivar_type.vyper_type} in range({length}):"
            return result
        result = f"for {var_name}: {ivar_type.vyper_type}  in range({variable}, {variable}+{length}):"
        return result
