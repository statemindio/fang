from dataclasses import dataclass
from typing import List

from types_d.base import BaseType


@dataclass
class Function:
    name: str
    mutability: int
    visibility: str
    input_parameters: List[BaseType]
    output_parameters: List[BaseType]


class FuncTracker:
    def __init__(self):
        self._id = -1
        self._functions = []

    def __getitem__(self, item):
        return self._functions[item]

    def register_function(
            self,
            name,
            mutability,
            visibility,
            input_parameters,
            output_parameters
    ):
        # TODO: add `self.` the prefix to the name if `visibility` is `external`
        func = Function(name, mutability, visibility, input_parameters, output_parameters)
        self._functions.append(func)
        self._id = len(self._functions) - 1

    def find_functions_by_output(self, output_parameter: BaseType):
        functions = []
        for func in self._functions:
            if output_parameter in func.output_parameters:
                functions.append((func, func.output_parameters.index(output_parameter)))
        return functions

    @property
    def current_id(self):
        return self._id

    @property
    def next_id(self):
        return self._id + 1
