from types_d.base import BaseType


class VarTracker:
    GLOBAL_KEY = "__global__"
    FUNCTION_KEY = "__function__"

    def __init__(self):
        self._var_id = -1
        self._var_id_map = {}
        self._vars = {
            self.GLOBAL_KEY: {},
            self.FUNCTION_KEY: {}
        }

    def next_id(self, var_type) -> int:
        return self.current_id(var_type) + 1

    def current_id(self, var_type) -> int:
        if var_type.name not in self._var_id_map:
            self._var_id_map[var_type.name] = -1
        return self._var_id_map[var_type.name]

    def register_function_variable(self, name, level, var_type: BaseType):
        if var_type.vyper_type not in self._vars[self.FUNCTION_KEY]:
            self._vars[self.FUNCTION_KEY][var_type.vyper_type] = {
                level: []
            }
        if level not in self._vars[self.FUNCTION_KEY][var_type.vyper_type]:
            self._vars[self.FUNCTION_KEY][var_type.vyper_type][level] = []

        # TODO: check if a variable already exist
        self._vars[var_type.vyper_type][self.FUNCTION_KEY][level].append(name)
        self._var_id += 1
        self._var_id_map[var_type.name] = self.next_id(var_type)

    def register_global_variable(self, name, var_type: BaseType):
        if var_type.vyper_type not in self._vars[self.GLOBAL_KEY]:
            self._vars[self.GLOBAL_KEY][var_type.vyper_type] = []
        # TODO: check if a variable already exist
        self._vars[self.GLOBAL_KEY][var_type.vyper_type].append(name)
        self._var_id += 1
        self._var_id_map[var_type.name] = self.next_id(var_type)

    def remove_function_level(self, level: int):
        for vyper_type in self._vars[self.FUNCTION_KEY]:
            if level not in self._vars[self.GLOBAL_KEY][vyper_type]:
                continue
            self._var_id -= len(self._vars[self.GLOBAL_KEY][level])
            self._vars[self.GLOBAL_KEY][level] = []

    def get_all_allowed_vars(self, level: int, var_type: BaseType):
        allowed_vars = self.get_global_vars(var_type)
        for i in range(level):
            allowed_vars.extend(self._vars[self.FUNCTION_KEY].get(var_type.vyper_type, {}).get(i, []))
        return allowed_vars

    def get_global_vars(self, var_type: BaseType):
        allowed_vars = [f"self.{v}" for v in self._vars[self.GLOBAL_KEY].get(var_type.vyper_type, [])]
        return allowed_vars
