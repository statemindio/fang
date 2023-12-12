from config import MAX_STORAGE_VARIABLES, MAX_FUNCTIONS
from types_d import Bool, Decimal, BytesM, Address, Bytes, Int, String


class TypedConverter:
    def __init__(self, msg):
        self.contract = msg
        self.type_stack = []
        self._expression_handlers = {}  # TODO: define expression handlers
        self._available_vars = {}

    def visit(self):
        for i, var in enumerate(self.contract.decl):
            if i >= MAX_STORAGE_VARIABLES:
                break
            # TODO: handle a storage variable

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
