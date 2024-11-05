from typing import Sequence

from fuzz.types_d.base import BaseType

import fuzz.helpers.proto_loader as proto

class Function:
    MUTABILITY_MAPPING = (
        "@pure",
        "@view",
        "@nonpayable",
        "@payable"
    )

    def __init__(
            self,
            _id: int,
            name: str,
            mutability: int,
            visibility: str,
            input_parameters: Sequence[BaseType],
            output_parameters: Sequence[BaseType]
    ):
        self.id = _id
        self._name = name
        self.mutability = mutability
        self.visibility = visibility
        self.input_parameters = input_parameters
        self.output_parameters = output_parameters
        self.body = ""
        self.reentrancy = ""
        self._function_calls = []

    @property
    def name(self) -> str:
        return f"self.{self._name}"

    def render_call(self, input_parameters: Sequence[str]):
        return f"{self.name}({', '.join(input_parameters)})"

    def render_signature(self, input_parameters: Sequence[str]):
        if len(input_parameters) != len(self.input_parameters):
            raise ValueError(
                f"parameter length {len(input_parameters)} does not match signature length {len(self.input_parameters)}"
            )
        output = ""
        if len(self.output_parameters) > 0:
            output = ", ".join(o.vyper_type for o in self.output_parameters)
            if len(self.output_parameters) > 1:
                output = f" -> ({output})"
            else:
                output = f" -> {output}"
        signature = f"def {self._name}({', '.join(f'{n}: {t}' for n, t in zip(input_parameters, self.input_parameters))}){output}"
        return signature

    def render_definition(self, input_parameters: Sequence[str]):
        mutability = self.MUTABILITY_MAPPING[self.mutability]
        signature = self.render_signature(input_parameters)
        body = self.body
        if self.visibility == proto.Func.Visibility.EXTERNAL:
            visibility = "@external"
        else:
            visibility = "@internal"
        definition = f"{visibility}\n{self.reentrancy}{mutability}\n{signature}:\n{body}"
        return definition


class FuncTracker:
    def __init__(self, max_functions):
        self._id = -1
        self._functions = []
        self._max_functions = max_functions

    def __getitem__(self, item):
        return self._functions[item]

    def __iter__(self):
        return iter(self._functions)

    def __len__(self):
        return len(self._functions)

    def _generate_function_name(self):
        _id = self.next_id
        return f"func_{_id}"

    def register_functions(self, functions):
        for func in functions:
            if len(self._functions) >= self._max_functions:
                break
            name = self._generate_function_name()
            self._register_function(name, func.mut, func.vis, [], [])

    def _register_function(
            self,
            name,
            mutability,
            visibility,
            input_parameters,
            output_parameters
    ):
        self._id += 1
        func = Function(self._id, name, mutability, visibility, input_parameters, output_parameters)
        self._functions.append(func)

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
