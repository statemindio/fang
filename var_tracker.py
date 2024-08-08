import copy

from types_d.base import BaseType
from types_d.types import FixedList, DynArray, Bytes, String
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
        # should extend to bytes and strings
        # scope -> base_type -> level -> size
        self._dyns = {
            self.FUNCTION_KEY: {},
            self.READONLY_KEY: {}
        }
        self._bytes = {
            self.FUNCTION_KEY: {},
            self.READONLY_KEY: {}
        }

    def _register_dyn_array(self, name, level, var_type: DynArray, mutable: bool):
        """
        Sets a new variable to the passed `level`
        :param name: name of the new variable
        :param level:
        :param var_type:
        :param mutable:
        """
        key = self.FUNCTION_KEY if mutable else self.READONLY_KEY

        index_type = var_type.base_type
        type_size = var_type.size
        self._register_dyns(self._dyns, index_type, type_size, name, level, var_type, key)

        if isinstance(var_type.base_type, FixedList):
            for i in range(var_type.current_size):
                self._register_list_items(
                    f"{name}[{i}]", level, var_type.base_type, key)

    def _register_bytes_or_string(self, name, level, var_type: DynArray, mutable: bool):
        key = self.FUNCTION_KEY if mutable else self.READONLY_KEY

        index_type = type(var_type)
        type_size = var_type.m
        self._register_dyns(self._bytes, index_type, type_size, name, level, var_type, key)

    def _register_dyns(self, _dict, index_type, var_size, name, level, var_type: DynArray, key):
        if index_type not in _dict[key]:
            _dict[key][index_type] = {
                level: {}
            }
        if level not in _dict[key][index_type]:
            _dict[key][index_type][level] = {
                var_size: []
            }

        if var_size not in _dict[key][index_type][level]:
            _dict[key][index_type][level][var_size] = []

        # TODO: check if a variable already exist
        _dict[key][index_type][level][var_size].append(name)

    def _remove_dyns_level(self, level: int, key):
        """
        Removes the specified level's variables
        :param level:
        :param mutable:
        """
        for _dict in (self._dyns, self._bytes):
            for vyper_type in _dict[key]:
                if level not in _dict[key][vyper_type]:
                    continue
                _dict[key][vyper_type][level] = {}

    def _get_dyn_arrays(self, level: int, var_type: DynArray, mutable: bool, assignee=False):
        """

        :param level:
        :param var_type:
        :return: list of allowed variables. It's a united of the global variables and function variables
        allowed on the given level
        """
        key = self.FUNCTION_KEY if mutable else self.READONLY_KEY
        types = [var_type.base_type]
        # get all DynArrays to append() or pop()
        if var_type.base_type is None:
            types = list(self._dyns[key].keys())
        size = var_type.size

        return self._get_dyns(self._dyns, level, types, size, key, assignee=assignee)

    def _get_bytes_or_string(self, level: int, var_type: DynArray, mutable: bool, assignee=False):
        key = self.FUNCTION_KEY if mutable else self.READONLY_KEY
        types = [type(var_type)]
        size = var_type.m
        return self._get_dyns(self._bytes, level, types, size, key, assignee=assignee)

    def _get_dyns(self, _dict: dict, level: int, types, size, key, assignee=False):
        allowed_vars = []

        for t in types:
            for l in _dict[key].get(t, {}):
                # level
                if l > level:
                    continue
                for s in _dict[key][t][l]:
                    # size
                    if (s <= size and not assignee) or (s >= size and assignee):
                        allowed_vars.extend(_dict[key][t][l][s])
        return allowed_vars

    # get DynArray by name for append statement
    def get_dyn_array_base_type(self, name, mutable: bool):
        key = self.FUNCTION_KEY if mutable else self.READONLY_KEY

        for t in self._dyns[key]:
            for l in self._dyns[key][t]:
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
        self._var_id_map[var_type.name] = self.next_id(var_type)
        # Doesnt do this line if Bytes, String or DynArray
        if level == 0:
            self._global_var_id_map[var_type.name] = self._var_id_map[var_type.name]

        key = self.FUNCTION_KEY if mutable else self.READONLY_KEY

        if level == 0 and mutable:
            name = f"self.{name}"

        if isinstance(var_type, FixedList):
            self._register_list_items(name, level, var_type, key)

        if isinstance(var_type, DynArray):
            self._register_dyn_array(name, level, var_type, mutable)
            return

        if type(var_type) == Bytes or type(var_type) == String:
            self._register_bytes_or_string(name, level, var_type, mutable)
            return

        self._init_var_list(var_type, self._vars, key, level)

        # TODO: check if a variable already exist
        self._vars[key][var_type.vyper_type][level].append(name)

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
            self.register_function_variable(
                name, level, var_type, mutability == VarDecl.Mutability.REGULAR)

        return name

    def register_global_variable(self, name, var_type: BaseType):
        """
        Sets a new global variable
        :param name: name of the new variable
        :param var_type:
        """
        self.register_function_variable(name, 0, var_type, True)

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

        self._lists[key][base_type.vyper_type][level].append(
            (name, var_type.size))

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

        for i in range(0, level + 1):
            allowed_lists.extend(self._lists[key].get(
                var_type.vyper_type, {}).get(i, []))

        # TODO: optimize
        allowed_vars = []
        for l, s in allowed_lists:
            allowed_vars.extend([f"{l}[{i}]" for i in range(s)])

        return allowed_vars

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

        self._remove_dyns_level(level, key)
        self._remove_list_items(level, key)

    def reset_function_variables(self):
        for key in (self.READONLY_KEY, self.FUNCTION_KEY):
            for _vars in (self._vars, self._lists):
                for vyper_type, level_vars in _vars[key].items():
                    for level, variables in level_vars.items():
                        if level == 0:
                            continue
                        _vars[key][vyper_type][level] = []
            for _vars in (self._dyns, self._bytes):
                for vyper_type, level_vars in _vars[key].items():
                    for level, variables in level_vars.items():
                        if level == 0:
                            continue
                        _vars[key][vyper_type][level] = {}

        self._var_id_map = copy.copy(self._global_var_id_map)

    def get_readonly_variables(self, level: int, var_type: BaseType):
        """
        Returns read-only variables upto `level`
        :param level:
        :param var_type:
        :return: list of allowed readonly variables
        """
        return self._get_vars(var_type, level, False)

    def get_mutable_variables(self, level: int, var_type: BaseType, **kwargs):
        """

        :param level:
        :param var_type:
        :return: list of allowed variables. It's a united of the global variables and function variables
        allowed on the given level
        """
        return self._get_vars(var_type, level, True, **kwargs)

    def get_global_vars(self, var_type: BaseType, **kwargs):
        """

        :param var_type:
        :return: list of allowed global variables
        """
        return self._get_vars(var_type, 0, True, **kwargs)

    def _get_vars(self, var_type: BaseType, level: int, mutable, **kwargs):
        key = self.FUNCTION_KEY if mutable else self.READONLY_KEY
        allowed_vars = []

        if isinstance(var_type, DynArray):
            allowed_vars.extend(self._get_dyn_arrays(
                level, var_type, mutable, kwargs.get("assignee", False)))
            return allowed_vars

        if type(var_type) == Bytes or type(var_type) == String:
            allowed_vars.extend(self._get_bytes_or_string(
                level, var_type, mutable, kwargs.get("assignee", False)))
            return allowed_vars

        for i in range(0, level + 1):
            allowed_vars.extend(self._vars[key].get(
                var_type.vyper_type, {}).get(i, []))

        allowed_vars.extend(self._get_list_items(level, var_type, mutable))

        return allowed_vars
