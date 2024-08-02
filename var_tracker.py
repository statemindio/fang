import copy

from types_d.base import BaseType
from types_d.types import FixedList, DynArray
from vyperProtoNew_pb2 import VarDecl


class VarTracker:
    """
    Manages variables, tracks its ID and provides access to variables up to a certain level of block.
    """
    FUNCTION_KEY = "__function__"
    READONLY_KEY = "__readonly__"

    def __init__(self):
        self._var_id_map = {}
        self._global_var_id_map = {}
        self._vars = {
            self.FUNCTION_KEY: {},
            self.READONLY_KEY: {}
        }
        self._lists = {
            self.FUNCTION_KEY: {},
            self.READONLY_KEY: {}
        }
        # scope -> base_type -> level -> size
        self._dyns = {
            self.FUNCTION_KEY: {},
            self.READONLY_KEY: {}
        }

    def _register_function_dyn_array(self, name, level, var_type: DynArray, mutable: bool):
        """
        Sets a new variable to the passed `level`
        :param name: name of the new variable
        :param level:
        :param var_type:
        :param mutable:
        """
        key = self.FUNCTION_KEY if mutable else self.READONLY_KEY

        if var_type.base_type not in self._dyns[key]:
            self._dyns[key][var_type.base_type] = {
                level: {}
            }
        if level not in self._dyns[key][var_type.base_type]:
            self._dyns[key][var_type.base_type][level] = {
                var_type.size: []
            }

        if var_type.size not in self._dyns[key][var_type.base_type][level]:
            self._dyns[key][var_type.base_type][level][var_type.size] = []

        # TODO: check if a variable already exist
        self._dyns[key][var_type.base_type][level][var_type.size].append(name)
        self._var_id_map[var_type.name] = self.next_id(var_type)

        if isinstance(var_type.base_type, FixedList):
            for i in range(var_type.current_size):
                self._register_list_items(f"{name}[{i}]", level, var_type.base_type, key)

    def _remove_function_dyn_array_level(self, level: int, key):
        """
        Removes the specified level's variables
        :param level:
        :param mutable:
        """

        for vyper_type in self._dyns[key]:
            if level not in self._dyns[key][vyper_type]:
                continue
            self._dyns[key][vyper_type][level] = {}

    # TODO: must handle size changes somehow (pop, append)
    def _register_global_dyn_array(self, name, var_type: DynArray):
        """
        Sets a new global variable
        :param name: name of the new variable
        :param var_type:
        """
        self._register_function_dyn_array(name, 0, var_type, True)

    def _get_global_dyn_arrays(self, var_type: DynArray, assignee=False):
        """

        :param var_type:
        :return: list of allowed global variables
        """

        allowed_vars = self._get_function_dyn_arrays(0, var_type, True, assignee)
        allowed_vars = [f"self.{v}" for v in allowed_vars]

        return allowed_vars

    def _get_function_dyn_arrays(self, level: int, var_type: DynArray, mutable: bool, assignee=False):
        """

        :param level:
        :param var_type:
        :return: list of allowed variables. It's a united of the global variables and function variables
        allowed on the given level
        """
        key = self.FUNCTION_KEY if mutable else self.READONLY_KEY

        types = [var_type.base_type]
        if var_type.base_type is None:
            types = list(self._dyns[key].keys())

        allowed_vars = []
        for t in types:
            for l in self._dyns[key].get(t, {}):
                # level
                if (level > 0 and l == 0) or l > level:
                    continue
                for s in self._dyns[key][t][l]:
                    # size
                    if (s <= var_type.size and not assignee) or (s >= var_type.size and assignee):
                        allowed_vars.extend(self._dyns[key][t][l][s])

        return allowed_vars

    # can use set as container?
    def get_dyn_array_base_type(self, name, level: int, mutable: bool):
        key = self.FUNCTION_KEY if mutable else self.READONLY_KEY

        if name[:5] == "self.":
            name = name[5:]
            level = 0

        for t in self._dyns[key]:
            for l in self._dyns[key][t]:
                if l > level:
                    continue
                for s in self._dyns[key][t][l]:
                    if name in self._dyns[key][t][l][s]:
                        return t

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

    @classmethod
    def _init_var_list(cls, var_type, _vars, key, level):
        if var_type.vyper_type not in _vars[key]:
            _vars[key][var_type.vyper_type] = {
                level: []
            }

        if level not in _vars[key][var_type.vyper_type]:
            _vars[key][var_type.vyper_type][level] = []

    def register_function_variable(self, name, level, var_type: BaseType, mutable: bool):
        """
        Sets a new variable to the passed `level`
        :param name: name of the new variable
        :param level:
        :param var_type:
        :param mutable:
        """
        key = self.FUNCTION_KEY if mutable else self.READONLY_KEY

        if isinstance(var_type, FixedList):
            self._register_list_items(name, level, var_type, key)

        if isinstance(var_type, DynArray):
            self._register_function_dyn_array(name, level, var_type, mutable)
            return

        self._init_var_list(var_type, self._vars, key, level)

        # TODO: check if a variable already exist
        self._vars[key][var_type.vyper_type][level].append(name)
        self._var_id_map[var_type.name] = self.next_id(var_type)
        if not mutable and level == 0:
            self._global_var_id_map[var_type.name] = self._var_id_map[var_type.name]

    def create_and_register_variable(
            self, var_type: BaseType,
            level: int = 0,
            mutability: VarDecl.Mutability = VarDecl.Mutability.REGULAR
    ) -> str:
        prefixes = {
            0: "x",
            1: "C",
            2: "IM"
        }
        idx = self.next_id(var_type)
        pre = prefixes[0] if level > 0 else prefixes[mutability]
        name = f"{pre}_{var_type.name}_{str(idx)}"
        if level == 0 and mutability == VarDecl.Mutability.REGULAR:
            self.register_global_variable(name, var_type)
        else:
            self.register_function_variable(name, level, var_type, mutability == VarDecl.Mutability.REGULAR)

        return name

    def register_global_variable(self, name, var_type: BaseType):
        """
        Sets a new global variable
        :param name: name of the new variable
        :param var_type:
        """
        if isinstance(var_type, FixedList):
            self._register_global_list(name, var_type)

        if isinstance(var_type, DynArray):
            self._register_global_dyn_array(name, var_type)
            return

        # TODO: check if a variable already exist
        if not isinstance(var_type, FixedList):
            self.register_function_variable(name, 0, var_type, True)
        else:
            self._var_id_map[var_type.name] = self.next_id(var_type)
        self._global_var_id_map[var_type.name] = self._var_id_map[var_type.name]

    def _register_list_items(self, name, level, var_type: FixedList, key):
        """
        Saves list data of a new variable to the passed `level`
        :param name: name of the new variable
        :param level:
        :param var_type:
        :param mutable:
        """
        base_type = var_type.base_type

        self._init_var_list(base_type, self._lists, key, level)

        self._lists[key][base_type.vyper_type][level].append((name, var_type.size))

    # TODO: dynArray must include .pop as list item
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
        start_range = 0 if level == 0 else 1
        for i in range(start_range, level + 1):
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

        self._register_list_items(name, 0, var_type, self.FUNCTION_KEY)

    def _get_global_list_items(self, var_type: BaseType):
        """
        :param var_type list's base type:
        :return: list of allowed global list variables
        """

        return [f"self.{v}" for v in self._get_list_items(0, var_type, True)]

    def _remove_list_items(self, level: int, key):
        """
        Removes the specified level's list data
        :param level:
        :param mutable:
        """
        for vyper_type in self._lists[key]:
            if level not in self._lists[key][vyper_type]:
                continue
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
            self._vars[key][vyper_type][level] = []

        self._remove_function_dyn_array_level(level, key)
        self._remove_list_items(level, key)

    def reset_function_variables(self):
        for key in (self.READONLY_KEY, self.FUNCTION_KEY):
            for _vars in (self._vars, self._lists):
                for vyper_type, level_vars in _vars[key].items():
                    for level, variables in level_vars.items():
                        if level == 0:
                            continue
                        _vars[key][vyper_type][level] = []

        self._var_id_map = copy.copy(self._global_var_id_map)

    def get_readonly_variables(self, level: int, var_type: BaseType):
        """
        Returns read-only variables upto `level`
        :param level:
        :param var_type:
        :return: list of allowed readonly variables
        """
        allowed_vars = []

        if isinstance(var_type, DynArray):
            allowed_vars = self._get_function_dyn_arrays(level, var_type, False)
            return allowed_vars

        allowed_vars.extend(self._get_list_items(level, var_type, False))
        for i in range(level + 1):
            allowed_vars.extend(self._vars[self.READONLY_KEY].get(var_type.vyper_type, {}).get(i, []))
        return allowed_vars

    def get_all_allowed_vars(self, level: int, var_type: BaseType, **kwargs):
        """

        :param level:
        :param var_type:
        :return: list of allowed variables. It's a united of the global variables and function variables
        allowed on the given level
        """
        allowed_vars = self.get_global_vars(var_type)

        if isinstance(var_type, DynArray):
            allowed_vars.extend(self._get_function_dyn_arrays(level, var_type, True, kwargs.get("assignee", False)))
            return allowed_vars

        for i in range(1, level + 1):
            allowed_vars.extend(self._vars[self.FUNCTION_KEY].get(var_type.vyper_type, {}).get(i, []))

        allowed_vars.extend(self._get_list_items(level, var_type, True))

        return allowed_vars

    def get_global_vars(self, var_type: BaseType, **kwargs):
        """

        :param var_type:
        :return: list of allowed global variables
        """
        if isinstance(var_type, DynArray):
            allowed_vars = self._get_global_dyn_arrays(var_type, kwargs.get("assignee", False))
            return allowed_vars

        allowed_vars = [f"self.{v}" for v in self._vars[self.FUNCTION_KEY].get(var_type.vyper_type, {}).get(0, [])]
        allowed_vars.extend(self._get_global_list_items(var_type))
        return allowed_vars
