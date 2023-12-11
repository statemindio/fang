from config import MAX_STORAGE_VARIABLES, MAX_FUNCTIONS


class TypedConverter:
    def __init__(self, msg):
        self.contract = msg

    def visit(self):
        for i, var in enumerate(self.contract.decl):
            if i >= MAX_STORAGE_VARIABLES:
                break
            # TODO: handle a storage variable

        for i, func in enumerate(self.contract.functions):
            if i >= MAX_FUNCTIONS:
                break
            # TODO: handle a function

    def visit_var_decl(self, variable):
        # TODO: implement
        pass

    def visit_func(self, function):
        # TODO: implement
        pass
