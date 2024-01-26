from types_d.base import BaseType
from types_d.types import FixedList


class VarTracker:
    """
    Manages variables, tracks its ID and provides access to variables up to a certain level of block.
    """
    GLOBAL_KEY = "__global__"
    FUNCTION_KEY = "__function__"
    READONLY_KEY = "__readonly__"

    def __init__(self):
        self._var_id = -1
        self._var_id_map = {}
        self._vars = {
            self.GLOBAL_KEY: {},
            self.FUNCTION_KEY: {},
            self.READONLY_KEY: {}
        }
        self._lists = {
            self.GLOBAL_KEY: {},
            self.FUNCTION_KEY: {},
            self.READONLY_KEY: {}
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

    def register_function_variable(self, name, level, var_type: BaseType, mutable: bool):
        """
        Sets a new variable to the passed `level`
        :param name: name of the new variable
        :param level:
        :param var_type:
        :param mutable:
        """
        key = self.FUNCTION_KEY if mutable else self.READONLY_KEY

        if var_type.vyper_type not in self._vars[key]:
            self._vars[key][var_type.vyper_type] = {
                level: []
            }
        if level not in self._vars[key][var_type.vyper_type]:
            self._vars[key][var_type.vyper_type][level] = []

        # TODO: check if a variable already exist
        self._vars[key][var_type.vyper_type][level].append(name)
        self._var_id += 1
        self._var_id_map[var_type.name] = self.next_id(var_type)

        if isinstance(var_type, FixedList):
            self._register_list_items(name, level, var_type, mutable)

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

        if isinstance(var_type, FixedList):
            self._register_global_list(name, var_type)

    def _register_list_items(self, name, level, var_type: FixedList, mutable: bool):
        """
        Saves list data of a new variable to the passed `level`
        :param name: name of the new variable
        :param level:
        :param var_type:
        :param mutable:
        """
        base_type = var_type.base_type
        key = self.FUNCTION_KEY if mutable else self.READONLY_KEY

        if base_type.vyper_type not in self._lists[key]:
            self._lists[key][base_type.vyper_type] = {
                level: []
            }
        if level not in self._lists[key][base_type.vyper_type]:
            self._lists[key][base_type.vyper_type][level] = []

        self._lists[key][base_type.vyper_type][level].append((name, var_type.size))

    def _get_list_items(self, level: int, var_type: BaseType, mutable: bool):
        """
        Returns list elements according to saved data upto `level`
        :param name: name of the new variable
        :param level:
        :param var_type:
        :param mutable:
        """
        key = self.FUNCTION_KEY if mutable else self.READONLY_KEY
        allowed_lists = []
        for i in range(level + 1):
            allowed_lists.extend(self._lists[key].get(var_type.vyper_type, {}).get(i, []))

        # TODO: optimize
        allowed_vars = []
        for l, s in allowed_lists:
            allowed_vars.extend([f"{l}[{i}]" for i in range(s)])

        return allowed_vars

    def _register_global_list(self, name, var_type: FixedList):
        """
        Saves list data of a new global variable
        :param name: name of the new variable
        :param var_type:
        """
        base_type = var_type.base_type
        if base_type.vyper_type not in self._lists[self.GLOBAL_KEY]:
            self._lists[self.GLOBAL_KEY][base_type.vyper_type] = []

        self._lists[self.GLOBAL_KEY][base_type.vyper_type].append((name, var_type.size))

    def _get_global_list_items(self, var_type: BaseType):
        """
        :param var_type list's base type:
        :return: list of allowed global list variables
        """
        allowed_vars = []
        for v, s in self._lists[self.GLOBAL_KEY].get(var_type.vyper_type, []):
            allowed_vars.extend([f"self.{v}[{i}]" for i in range(s)])
        return allowed_vars

    def _remove_list_items(self, level: int, mutable: bool):
        """
        Removes the specified level's list data
        :param level:
        :param mutable:
        """
        key = self.FUNCTION_KEY if mutable else self.READONLY_KEY

        for vyper_type in self._lists[key]:
            if level not in self._lists[key][vyper_type]:
                continue
            self._var_id -= len(self._lists[key][vyper_type][level])
            self._lists[key][vyper_type][level] = []

    def remove_function_level(self, level: int, mutable: bool):
        """
        Removes the specified level's variables
        :param level:
        :param mutable:
        """
        key = self.FUNCTION_KEY if mutable else self.READONLY_KEY

        for vyper_type in self._vars[key]:
            if level not in self._vars[key][vyper_type]:
                continue
            self._var_id -= len(self._vars[key][vyper_type][level])
            self._vars[key][vyper_type][level] = []

        self._remove_list_items(level, mutable)

    def get_readonly_variables(self, level: int, var_type: BaseType):
        """
        Returns read-only variables upto `level`
        :param level:
        :param var_type:
        :return: list of allowed readonly variables
        """
        allowed_vars = []
        allowed_vars.extend(self._get_list_items(level, var_type, False))
        for i in range(level + 1):
            allowed_vars.extend(self._vars[self.READONLY_KEY].get(var_type.vyper_type, {}).get(i, []))
        return allowed_vars

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

        allowed_vars.extend(self._get_list_items(level, var_type, True))

        return allowed_vars

    def get_global_vars(self, var_type: BaseType):
        """

        :param var_type:
        :return: list of allowed global variables
        """
        allowed_vars = [f"self.{v}" for v in self._vars[self.GLOBAL_KEY].get(var_type.vyper_type, [])]
        allowed_vars.extend(self._get_global_list_items(var_type))
        return allowed_vars
