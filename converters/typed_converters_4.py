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
