from config import MAX_STORAGE_VARIABLES, MAX_FUNCTIONS
from types_d import Bool, Decimal, BytesM, Address, Bytes, Int, String

BIN_OP_MAP = {

}


def get_bin_op(op, op_set):
    return op_set[op]


class TypedConverter:
    def __init__(self, msg):
        self.contract = msg
        self.type_stack = []
        self._expression_handlers = {
            "INT": self._visit_int_expression
        }  # TODO: define expression handlers
        self._available_vars = {}
        self.result = ""

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

    def visit_typed_expression(self, expr, current_type):
        return self._expression_handlers[current_type.name](expr, current_type)

    def visit_var_decl(self, variable, is_global=False):
        current_type = self.visit_type(variable)
        self.type_stack.append(current_type)

        idx = self._available_vars.get(current_type.name, 0)
        self._available_vars[current_type.name] = idx + 1

        result = f"x_{current_type.name}_" + str(idx) + " : " + current_type.vyper_type
        if is_global:
            value = self.visit_typed_expression(variable.expr, current_type)
            result += f"{result} = {value}"
        return result

    def visit_func(self, function):
        # TODO: implement
        pass

    def visit_address_expression(self, expr, current_type):
        if expr.HasField("cmp"):
            return self.visit_create_min_proxy(expr.cmp, current_type)
        if expr.HasField("cfb"):
            return self.visit_create_from_blueprint(expr.cfb, current_type)
        return self.create_literal(expr.lit, current_type)

    def visit_create_min_proxy(self, cmp, current_type):
        target = self.visit_address_expression(cmp.target, current_type)
        result = f"create_minimal_proxy_to({target}"
        if cmp.HasField("value"):
            value = self._visit_int_expression(cmp.value, Int(256))
            result = f"{result}, value = {value}"
        if cmp.HasField("salt"):
            salt = self._visit_bytes_m_expression(cmp.salt, BytesM(32))
            result = f"{result}, salt = {salt}"
        result = f"{result})"

        return result

    def visit_create_from_blueprint(self, cfb, current_type):
        target = self.visit_address_expression(cfb.target, current_type)
        result = f"create_from_blueprint({target}"

        # TODO: args parameter is not handled yet

        if cfb.HasField("rawArgs"):
            raw_args = self._visit_bool_expression(cfb.rawArgs)
            result = f"{result}, raw_args = {raw_args}"
        if cfb.HasField("value"):
            value = self._visit_int_expression(cfb.value, Int(256))
            result = f"{result}, value = {value}"
        if cfb.HasField("code_offset"):
            offset = self._visit_int_expression(cfb.code_offset, Int(256))
            result = f"{result}, code_offset = {offset}"
        if cfb.HasField("salt"):
            salt = self._visit_bytes_m_expression(cfb.salt, BytesM(32))
            result = f"{result}, salt = {salt}"
        result = f"{result})"

        return result

    def create_literal(self, lit, current_type):
        # TODO: implement
        pass

    def _visit_bool_expression(self, expr):
        # TODO: implement
        pass

    def _visit_int_expression(self, expr, current_type):
        if expr.HasField("binOp"):
            left = self._visit_int_expression(expr.binOp.left, current_type)
            right = self._visit_int_expression(expr.binOp.right, current_type)
            bin_op = get_bin_op(expr.binOp.op, BIN_OP_MAP)
            result = f"{left} {bin_op} {right}"
            return result
        return self.create_literal(expr.lit, current_type)

    def _visit_bytes_m_expression(self, expr, current_type):
        # TODO: implement
        pass
