import random

from config import MAX_STORAGE_VARIABLES, MAX_FUNCTIONS
from types_d import Bool, Decimal, BytesM, Address, Bytes, Int, String
from var_tracker import VarTracker

BIN_OP_MAP = {

}

BIN_OP_BOOL_MAP = {

}

INT_BIN_OP_BOOL_MAP = {

}

LITERAL_ATTR_MAP = {
    "BOOL": "boolval",
    "DECIMAL": "decimalval",
    "BYTESM": "bMval",
    "STRING": "strval",
    "ADDRESS": "addval",
    "BYTES": "barrval",
    "INT": "intval"
}


def get_bin_op(op, op_set):
    return op_set[op]


class TypedConverter:
    def __init__(self, msg):
        self.contract = msg
        self.type_stack = []
        self._expression_handlers = {
            "INT": self._visit_int_expression,
            "BYTESM": self._visit_bytes_m_expression,
            "BOOL": self._visit_bool_expression,
            "BYTES": self._visit_bytes_expression,
            "DECIMAL": self._visit_decimal_expression,
            "STRING": self._visit_string_expression,
            "ADDRESS": self.visit_address_expression
        }
        self.result = ""
        self._var_tracker = VarTracker()
        self._block_level_count = 0

    def visit(self):
        for i, var in enumerate(self.contract.decl):
            if i >= MAX_STORAGE_VARIABLES:
                break
            self.result += self.visit_var_decl(var, True)

        for i, func in enumerate(self.contract.functions):
            if i >= MAX_FUNCTIONS:
                break
            # TODO: handle a function

    def visit_type(self, instance):
        if instance.HasField("b"):
            current_type = Bool()
        elif instance.HasField("d"):
            current_type = Decimal
        elif instance.HasField("bM"):
            current_type = BytesM(instance.bM)
        elif instance.HasField("s"):
            current_type = String(instance.s)
        elif instance.HasField("adr"):
            current_type = Address()
        elif instance.HasField("barr"):
            current_type = Bytes(instance.barr.max_len)
        else:
            current_type = Int(instance.i)

        return current_type

    def _visit_var_ref(self, expr, level=None):
        current_type = self.type_stack[len(self.type_stack) - 1]
        allowed_vars = self._var_tracker.get_global_vars(
            current_type
        ) if level is None else self._var_tracker.get_all_allowed_vars(level, current_type)

        return None if len(allowed_vars) == 0 else random.choice(allowed_vars)

    def visit_typed_expression(self, expr, current_type):
        return self._expression_handlers[current_type.name](expr)

    def visit_var_decl(self, variable, is_global=False):
        current_type = self.visit_type(variable)
        self.type_stack.append(current_type)

        idx = self._var_tracker.next_id

        var_name = f"x_{current_type.name}_{str(idx)}"
        result = var_name + " : " + current_type.vyper_type
        if is_global:
            self._var_tracker.register_global_variable(var_name, current_type)
        else:
            self._var_tracker.register_function_variable(var_name, self._block_level_count, current_type)
            value = self.visit_typed_expression(variable.expr)
            result += f"{result} = {value}"
        self.type_stack.pop()
        return result

    def visit_func(self, function):
        # TODO: implement
        pass

    def visit_address_expression(self, expr):
        if expr.HasField("cmp"):
            return self.visit_create_min_proxy(expr.cmp)
        if expr.HasField("cfb"):
            return self.visit_create_from_blueprint(expr.cfb)
        if expr.HasField("varRef"):
            # TODO: it has to be decided how exactly to track a current block level or if it has to be passed
            result = self._visit_var_ref(expr.varRef, self._block_level_count)
            if result is not None:
                return result
        return self.create_literal(expr.lit)

    def visit_create_min_proxy(self, cmp):
        target = self.visit_address_expression(cmp.target)
        result = f"create_minimal_proxy_to({target}"
        if cmp.HasField("value"):
            self.type_stack.append(Int(256))
            value = self._visit_int_expression(cmp.value)
            result = f"{result}, value = {value}"
            self.type_stack.pop()
        if cmp.HasField("salt"):
            self.type_stack.append(Bytes(32))
            salt = self._visit_bytes_m_expression(cmp.salt)
            result = f"{result}, salt = {salt}"
            self.type_stack.pop()
        result = f"{result})"

        return result

    def visit_create_from_blueprint(self, cfb):
        target = self.visit_address_expression(cfb.target)
        result = f"create_from_blueprint({target}"

        # TODO: args parameter is not handled yet

        if cfb.HasField("rawArgs"):
            self.type_stack.append(Bool())
            raw_args = self._visit_bool_expression(cfb.rawArgs)
            result = f"{result}, raw_args = {raw_args}"
            self.type_stack.pop()
        if cfb.HasField("value"):
            self.type_stack.append(Int(256))
            value = self._visit_int_expression(cfb.value)
            result = f"{result}, value = {value}"
            self.type_stack.pop()
        if cfb.HasField("code_offset"):
            self.type_stack.append(Int(256))
            offset = self._visit_int_expression(cfb.code_offset)
            result = f"{result}, code_offset = {offset}"
            self.type_stack.pop()
        if cfb.HasField("salt"):
            self.type_stack.append(Int(256))
            salt = self._visit_bytes_m_expression(cfb.salt)
            result = f"{result}, salt = {salt}"
            self.type_stack.pop()
        result = f"{result})"

        return result

    def create_literal(self, lit):
        current_type = self.type_stack[len(self.type_stack) - 1]
        return current_type.generate_literal(getattr(lit, LITERAL_ATTR_MAP[current_type.name]))

    def _visit_bool_expression(self, expr):
        if expr.HasField("boolBinOp"):
            left = self._visit_bool_expression(expr.boolBinOp.left)
            right = self._visit_bool_expression(expr.boolBinOp.right)
            bin_op = get_bin_op(expr.boolBinOp.op, BIN_OP_BOOL_MAP)
            result = f"{left} {bin_op} {right}"
            return result
        if expr.HasField("boolUnOp"):
            operand = self._visit_bool_expression(expr.boolUnOp.expr)
            result = f"not {operand}"
            return result
        if expr.HasField("intBoolBinOp"):
            # TODO: here probably must be different kinds of Int
            self.type_stack.append(Int(256))
            left = self._visit_int_expression(expr.intBoolBinOp.left)
            right = self._visit_int_expression(expr.intBoolBinOp.right)
            bin_op = get_bin_op(expr.intBoolBinOp.op, INT_BIN_OP_BOOL_MAP)
            result = f"{left} {bin_op} {right}"
            self.type_stack.pop()
            return result
        if expr.HasField("decBoolBinOp"):
            self.type_stack.append(Decimal())
            left = self._visit_decimal_expression(expr.decBoolBinOp.left)
            right = self._visit_decimal_expression(expr.decBoolBinOp.right)
            bin_op = get_bin_op(expr.intBoolBinOp.op, INT_BIN_OP_BOOL_MAP)
            result = f"{left} {bin_op} {right}"
            self.type_stack.pop()
            return result
        if expr.HasField("varRef"):
            # TODO: it has to be decided how exactly to track a current block level or if it has to be passed
            result = self._visit_var_ref(expr.varRef, self._block_level_count)
            if result is not None:
                return result
        return self.create_literal(expr.lit)

    def _visit_int_expression(self, expr):
        if expr.HasField("binOp"):
            left = self._visit_int_expression(expr.binOp.left)
            right = self._visit_int_expression(expr.binOp.right)
            bin_op = get_bin_op(expr.binOp.op, BIN_OP_MAP)
            result = f"{left} {bin_op} {right}"
            return result
        if expr.HasField("unOp"):
            result = self._visit_int_expression(expr.unOp.expr)
            # TODO: implement a stack for arithmetic operations to avoin redundant brackets
            result = f"(-({result}))"
            return result
        if expr.HasField("varRef"):
            # TODO: it has to be decided how exactly to track a current block level or if it has to be passed
            result = self._visit_var_ref(expr.varRef, self._block_level_count)
            if result is not None:
                return result
        return self.create_literal(expr.lit)

    def _visit_bytes_m_expression(self, expr):
        if expr.HasField("sha"):
            # FIXME: length of current BytesM might me less than 32, If so, the result of `sha256` must be converted
            return self._visit_sha256(expr.sha)
        if expr.HasField("varRef"):
            # TODO: it has to be decided how exactly to track a current block level or if it has to be passed
            result = self._visit_var_ref(expr.varRef, self._block_level_count)
            if result is not None:
                return result
        return self.create_literal(expr.lit)

    def _visit_sha256(self, expr):
        result = "sha256("
        if expr.HasField("strVal"):
            self.type_stack.append(String(100))
            value = self._visit_string_expression(expr.strVal)
            self.type_stack.pop()
            return f"{result}{value})"
        if expr.HasField("bVal"):
            self.type_stack.append(Bytes(100))
            value = self._visit_bytes_expression(expr.bVal)
            self.type_stack.pop()
            return f"{result}{value})"
        self.type_stack.append(BytesM(32))
        value = self._visit_bytes_m_expression(expr.bmVal)
        self.type_stack.pop()
        return f"{result}{value})"

    def _visit_decimal_expression(self, expr):
        if expr.HasField("binOp"):
            left = self._visit_decimal_expression(expr.binOp.left)
            right = self._visit_decimal_expression(expr.binOp.right)
            bin_op = get_bin_op(expr.binOp.op, BIN_OP_MAP)
            result = f"{left} {bin_op} {right}"
            return result
        if expr.HasField("unOp"):
            result = self._visit_decimal_expression(expr.unOp.expr)
            # TODO: implement a stack for arithmetic operations to avoin redundant brackets
            result = f"(-({result}))"
            return result
        if expr.HasField("varRef"):
            # TODO: it has to be decided how exactly to track a current block level or if it has to be passed
            result = self._visit_var_ref(expr.varRef, self._block_level_count)
            if result is not None:
                return result
        return self.create_literal(expr.lit)

    def _visit_bytes_expression(self, expr):
        if expr.HasField("varRef"):
            # TODO: it has to be decided how exactly to track a current block level or if it has to be passed
            result = self._visit_var_ref(expr.varRef, self._block_level_count)
            if result is not None:
                return result
        return self.create_literal(expr.lit)

    def _visit_string_expression(self, expr):
        if expr.HasField("varRef"):
            # TODO: it has to be decided how exactly to track a current block level or if it has to be passed
            result = self._visit_var_ref(expr.varRef, self._block_level_count)
            if result is not None:
                return result
        return self.create_literal(expr.lit)
