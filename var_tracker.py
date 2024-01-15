from types_d.base import BaseType


class VarTracker:
    """
    Manages variables, tracks its ID and provides access to variables up to a certain level of block.
    """

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
        """

        :param var_type: type instance
        :type var_type: BaseType
        :return: the next ID for a certain `var_type`
        """
        return self.current_id(var_type) + 1

    def current_id(self, var_type) -> int:
        """
        Checks if the current ID exists for a certain `var_type` and returns the ID if it exists
        :param var_type: type instance
        :type var_type: BaseType
        :return: the current ID for a certain `var_type`. If it doesn't exist, returns -1
        """
        if var_type.name not in self._var_id_map:
            self._var_id_map[var_type.name] = -1
        return self._var_id_map[var_type.name]

    def register_function_variable(self, name, level, var_type: BaseType):
        """
        Sets a new variable to the passed `level`
        :param name: name of the new variable
        :param level:
        :param var_type:
        """
        if var_type.vyper_type not in self._vars[self.FUNCTION_KEY]:
            self._vars[self.FUNCTION_KEY][var_type.vyper_type] = {
                level: []
            }
        if level not in self._vars[self.FUNCTION_KEY][var_type.vyper_type]:
            self._vars[self.FUNCTION_KEY][var_type.vyper_type][level] = []

        # TODO: check if a variable already exist
        self._vars[self.FUNCTION_KEY][var_type.vyper_type][level].append(name)
        self._var_id += 1
        self._var_id_map[var_type.name] = self.next_id(var_type)

    def register_global_variable(self, name, var_type: BaseType):
        """
        Sets a new global variable
        :param name: name of the new variable
        :param var_type:
        """
        if var_type.vyper_type not in self._vars[self.GLOBAL_KEY]:
            self._vars[self.GLOBAL_KEY][var_type.vyper_type] = []
        # TODO: check if a variable already exist
        self._vars[self.GLOBAL_KEY][var_type.vyper_type].append(name)
        self._var_id += 1
        self._var_id_map[var_type.name] = self.next_id(var_type)

    def remove_function_level(self, level: int):
        """
        Removes the specified level's variables
        :param level:
        """
        for vyper_type in self._vars[self.FUNCTION_KEY]:
            if level not in self._vars[self.FUNCTION_KEY][vyper_type]:
                continue
            self._var_id -= len(self._vars[self.FUNCTION_KEY][vyper_type][level])
            self._vars[self.FUNCTION_KEY][vyper_type][level] = []

    def get_all_allowed_vars(self, level: int, var_type: BaseType):
        """

        :param level:
        :param var_type:
        :return: list of allowed variables. It's a united of the global variables and function variables
        allowed on the given level
        """
        allowed_vars = self.get_global_vars(var_type)
        for i in range(level + 1):
            allowed_vars.extend(self._vars[self.FUNCTION_KEY].get(var_type.vyper_type, {}).get(i, []))
        return allowed_vars

    def get_global_vars(self, var_type: BaseType):
        """

        :param var_type:
        :return: list of allowed global variables
        """
        allowed_vars = [f"self.{v}" for v in self._vars[self.GLOBAL_KEY].get(var_type.vyper_type, [])]
        return allowed_vars
