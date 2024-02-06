import random
from collections import defaultdict

from config import MAX_STORAGE_VARIABLES, MAX_FUNCTIONS, MAX_FUNCTION_INPUT, MAX_FUNCTION_OUTPUT, MAX_LIST_SIZE
from func_tracker import FuncTracker
from types_d import Bool, Decimal, BytesM, Address, Bytes, Int, String, FixedList, DynArray
from types_d.base import BaseType
from utils import get_nearest_multiple, VALID_CHARS
from var_tracker import VarTracker
from vyperProtoNew_pb2 import Func

PURE = 0
VIEW = 1
NON_PAYABLE = 2
PAYABLE = 3

BIN_OP_MAP = {
    0: "+",
    1: "-",
    2: "*",
    3: "/",
    4: "%",
    5: "**",
    6: "&",
    7: "|",
    8: "^",
    9: "<<",
    10: ">>"
}

BIN_OP_BOOL_MAP = {
    0: "and",
    1: "or",
    2: "==",
    3: "!="
}

INT_BIN_OP_BOOL_MAP = {
    0: "==",
    1: "!=",
    2: "<",
    3: "<=",
    4: ">",
    5: ">="
}

LITERAL_ATTR_MAP = {
    "BOOL": "boolval",
    "DECIMAL": "decimalval",
    "BYTESM": "bMval",
    "STRING": "strval",
    "ADDRESS": "addval",
    "BYTES": "barrval",
    "INT": "intval"
}


def get_bin_op(op, op_set):
    return op_set[op]


def _has_field(instance, field):
    try:
        return instance.HasField(field)
    except ValueError:
        return False


class TypedConverter:
    """
    The Converter class to convert Protobuf messages `Contract` into Vyper source code
    :param msg: `Contract` message
    :type msg: Contract
    :ivar contract: Stores the original Contract message
    :ivar type_stack: Stores types used to pass ones between sub-messages of the Contract
    :vartype type_stack: list of `BaseType`
    :ivar result: Contains the result of the conversion of the original message
    :vartype result: str
    """

    TAB = "    "
    MUTABILITY_MAPPING = (
        "@pure",
        "@view",
        "@nonpayable",
        "@payable"
    )

    def __init__(self, msg):
        self.contract = msg
        self.type_stack = []
        self.op_stack = []
        self._expression_handlers = {
            "INT": (self._visit_int_expression, "intExp"),
            "BYTESM": (self._visit_bytes_m_expression, "bmExp"),
            "BOOL": (self._visit_bool_expression, "boolExp"),
            "BYTES": (self._visit_bytes_expression, "bExp"),
            "DECIMAL": (self._visit_decimal_expression, "decExpression"),
            "STRING": (self._visit_string_expression, "strExp"),
            "ADDRESS": (self.visit_address_expression, "addrExp"),
            "FL_INT": (self._visit_list_expression, "intList"),
            "FL_BYTESM": (self._visit_list_expression, "bmList"),
            "FL_BOOL": (self._visit_list_expression, "boolList"),
            "FL_DECIMAL": (self._visit_list_expression, "decList"),
            "FL_ADDRESS": (self._visit_list_expression, "addrList"),
            "DA_INT": (self._visit_list_expression, "intDyn"),
            "DA_BYTESM": (self._visit_list_expression, "bmDyn"),
            "DA_BOOL": (self._visit_list_expression, "boolDyn"),
            "DA_DECIMAL": (self._visit_list_expression, "decDyn"),
            "DA_ADDRESS": (self._visit_list_expression, "addrDyn"),
            "DA_BYTES": (self._visit_list_expression, "bytesDyn"),
            "DA_STRING": (self._visit_list_expression, "strDyn"),
            "DA_FL_INT": (self._visit_list_expression, "lintDyn"),
            "DA_FL_BYTESM": (self._visit_list_expression, "lbmDyn"),
            "DA_FL_BOOL": (self._visit_list_expression, "lboolByn"),
            "DA_FL_DECIMAL": (self._visit_list_expression, "ldecDyn"),
            "DA_FL_ADDRESS": (self._visit_list_expression, "ladrDyn"),
        }
        self.result = ""
        self._var_tracker = VarTracker()
        self._func_tracker = FuncTracker()
        self._block_level_count = 0
        self._mutability_level = 0
        self._function_output = []
        self._for_block_count = 0
        self._immutable_exp = []
        self._function_call_map = defaultdict(list)
        self._excluded_call_map = defaultdict(list)
        self._current_func = None
        self._root_func_id = None
        self.func_handled = []
        self.func_flag = True

    def visit(self):
        """
        Runs the conversion of the message and stores the result in the result variable
        """
        for i, var in enumerate(self.contract.decls):
            if i >= MAX_STORAGE_VARIABLES:
                break
            self.result += self.__var_decl_global(var)
            self.result += "\n"

        if self.result != "":
            self.result += "\n"

        # TODO: if immutable must be init
        if self.contract.init.flag or len(self._immutable_exp):
            self.result += self.visit_init(self.contract.init)
            self.result += "\n"

        input_names = []
        for i, func in enumerate(self.contract.functions):
            if i >= MAX_FUNCTIONS:
                break
            function_name = self._generate_function_name()
            input_params, input_types, names = self._visit_input_parameters(func.input_params)
            input_names.append(names)
            output_types = self._visit_output_parameters(func.output_params)
            self._func_tracker.register_function(function_name, func.mut, func.vis, input_types, output_types)

        for func_obj, func in zip(self._func_tracker, self.contract.functions):
            self.visit_func(func_obj, func)

        self.func_flag = False

        def __convert_func(_func_id, function_def):
            if len(self._function_call_map[_func_id]) == 0:
                self.func_handled.append(_func_id)
                _func_obj = self._func_tracker[_func_id]
                self.visit_func(_func_obj, function_def)
            else:
                for func_id_internal in self._function_call_map[_func_id]:
                    if (func_id_internal == self._root_func_id or
                            self._func_tracker[func_id_internal].visibility == Func.Visibility.EXTERNAL):
                        self._excluded_call_map[_func_id].append(func_id_internal)
                        self._function_call_map[_func_id].remove(func_id_internal)
                        __convert_func(_func_id, function_def)
                    if func_id_internal not in self.func_handled:
                        __convert_func(func_id_internal, self.contract.functions[func_id_internal])
                    if self._func_tracker[_func_id].mutability < self._func_tracker[func_id_internal].mutability:
                        self._func_tracker[_func_id].mutability = self._func_tracker[func_id_internal].mutability

        self._var_tracker.reset_function_variables()
        for func_obj, func in zip(self._func_tracker, self.contract.functions):
            input_params, input_types, names = self._visit_input_parameters(func.input_params)
            self._root_func_id = func_obj.id
            __convert_func(func_obj.id, func)

        for func_obj, names in zip(self._func_tracker, input_names):
            self.result += func_obj.render_definition(names)
            self.result += "\n"

        if self.contract.HasField("def_func"):
            self.result += self.visit_default_func(self.contract.def_func)
            self.result += "\n"

    def visit_type(self, instance):
        if instance.HasField("b"):
            current_type = Bool()
        elif instance.HasField("d"):
            current_type = Decimal()
        elif instance.HasField("bM"):
            m = instance.bM.m % 32 + 1
            current_type = BytesM(m)
        elif _has_field(instance, "s"):
            max_len = 1 if instance.s.max_len == 0 else instance.s.max_len
            current_type = String(max_len)
        elif instance.HasField("adr"):
            current_type = Address()
        elif _has_field(instance, "barr"):
            max_len = 1 if instance.barr.max_len == 0 else instance.barr.max_len
            current_type = Bytes(max_len)
        elif _has_field(instance, "list"):
            # TODO: handle size in class?
            list_len = 1 if instance.list.n == 0 else instance.list.n
            list_len = list_len if instance.list.n < MAX_LIST_SIZE else MAX_LIST_SIZE

            current_type = self.visit_type(instance.list)
            current_type = FixedList(list_len, current_type)
        elif _has_field(instance, "dyn"):
            list_len = 1 if instance.dyn.n == 0 else instance.dyn.n
            list_len = list_len if instance.dyn.n < MAX_LIST_SIZE else MAX_LIST_SIZE
            current_type = self.visit_type(instance.dyn)
            current_type = DynArray(list_len, current_type)
        else:
            n = instance.i.n % 256 + 1
            n = get_nearest_multiple(n, 8)
            current_type = Int(n, instance.i.sign)

        return current_type

    def _visit_list_expression(self, list):

        if list.HasField("varRef"):
            result = self._visit_var_ref(list.varRef, self._block_level_count)
            if result is not None:
                return result

        current_type = current_type = self.type_stack[len(self.type_stack) - 1]
        base_type = current_type.base_type

        handler, _ = self._expression_handlers[base_type.name]
        list_size = 1

        self.type_stack.append(base_type)
        value = handler(list.rexp)

        for i, expr in enumerate(list.exp):
            expr_val = handler(expr)

            list_size += 1
            value += f", {expr_val}"
            # TODO: move size handling to type class
            if list_size == MAX_LIST_SIZE or \
                    (isinstance(current_type, DynArray) and list_size == current_type.size):
                break
        self.type_stack.pop()

        if list_size < current_type.size and not isinstance(base_type, FixedList):
            for i in range(current_type.size - list_size):
                expr_val = base_type.generate()
                value += f", {expr_val}"

        # current_type.adjust_size(list_size)

        return f"[{value}]"

    def _visit_var_ref(self, expr, level=None, assignment=False):
        current_type = self.type_stack[len(self.type_stack) - 1]
        allowed_vars = self._var_tracker.get_global_vars(
            current_type
        ) if level is None else self._var_tracker.get_all_allowed_vars(level, current_type)

        if not assignment and level is not None:
            read_only_vars = self._var_tracker.get_readonly_variables(level, current_type)
            allowed_vars.extend(read_only_vars)

        if len(allowed_vars) == 0:
            return None

        variable = random.choice(allowed_vars)
        global_vars = self._var_tracker.get_global_vars(current_type)

        if variable in global_vars and self._mutability_level < NON_PAYABLE and assignment:
            self._mutability_level = NON_PAYABLE

        if variable in global_vars and self._mutability_level < VIEW:
            self._mutability_level = VIEW

        return variable

    def visit_typed_expression(self, expr, current_type):
        handler, attr = self._expression_handlers[current_type.name]
        # let handler adjust list size
        # if isinstance(current_type, FixedList):
        #    return handler(getattr(expr, attr), current_type)
        return handler(getattr(expr, attr))

    def __var_decl(self, expr, current_type):
        self.type_stack.append(current_type)

        idx = self._var_tracker.next_id(current_type)

        value = self.visit_typed_expression(expr, current_type)

        var_name = f"x_{current_type.name}_{str(idx)}"
        result = var_name + " : " + current_type.vyper_type

        self._var_tracker.register_function_variable(var_name, self._block_level_count, current_type, True)
        result = f"{result} = {value}"

        self.type_stack.pop()
        result = f"{self.code_offset}{result}"
        return result

    def __var_decl_global(self, variable):
        current_type = self.visit_type(variable)
        self.type_stack.append(current_type)
        idx = self._var_tracker.next_id(current_type)

        prefixes = {
            0: "x",
            1: "C",
            2: "IM"
        }

        var_name = f"{prefixes[variable.mut]}_{current_type.name}_{str(idx)}"
        result = var_name + " : "

        # TODO: somehow must change size, if has been written to afterwards
        if variable.mut == 0:
            result += current_type.vyper_type
            self._var_tracker.register_global_variable(var_name, current_type)
        else:
            value = self.visit_typed_expression(variable.expr, current_type)
            self._var_tracker.register_function_variable(var_name, 0, current_type, False)

            if variable.mut == 1:
                result += f"constant({current_type.vyper_type})"
                result = f"{result} = {value}"
            else:
                result += f"immutable({current_type.vyper_type})"
                self._immutable_exp.append((var_name, value))

        self.type_stack.pop()
        return result

    def visit_var_decl(self, variable):
        current_type = self.visit_type(variable)
        return self.__var_decl(variable.expr, current_type)

    def _visit_input_parameters(self, input_params):
        result = ""
        input_types = []
        names = []
        for i, input_param in enumerate(input_params):
            param_type = self.visit_type(input_param)
            input_types.append(param_type)
            idx = self._var_tracker.next_id(param_type)
            name = f"x_{param_type.name}_{idx}"
            names.append(name)

            # self._var_tracker.register_function_variable(name, self._block_level_count, param_type)
            self._var_tracker.register_function_variable(name, 1, param_type, False)

            if i > 0:
                result = f"{result}, "
            result = f"{result}{name}: {param_type.vyper_type}"

            if i + 1 == MAX_FUNCTION_INPUT:
                break

        return result, input_types, names

    def _visit_output_parameters(self, output_params) -> [BaseType]:
        output_types = []
        for i, output_param in enumerate(output_params):
            param_type = self.visit_type(output_param)
            output_types.append(param_type)

            if i + 1 == MAX_FUNCTION_OUTPUT:
                break
        return output_types

    def _generate_function_name(self):
        _id = self._func_tracker.next_id
        return f"func_{_id}"

    def _visit_reentrancy(self, ret):
        # https://github.com/vyperlang/vyper/blob/55e18f6d128b2da8986adbbcccf1cd59a4b9ad6f/vyper/ast/nodes.py#L878
        # https://github.com/vyperlang/vyper/blob/55e18f6d128b2da8986adbbcccf1cd59a4b9ad6f/vyper/ast/identifiers.py#L8
        result = ""
        for c in ret.key:
            if c not in VALID_CHARS:
                continue
            result += c

        return f'@nonreentrant("{result}")\n' if result else ""

    def __get_mutability(self, mut):
        return self.MUTABILITY_MAPPING[max(self._mutability_level, mut)]

    def visit_func(self, function_obj, function):
        self._mutability_level = 0
        self._current_func = function_obj

        # FIXME: have to leave it to keep `return` statement properly
        self._function_output = self._visit_output_parameters(function.output_params)

        self._block_level_count = 1
        block = self._visit_block(function.block)
        self._var_tracker.remove_function_level(self._block_level_count, True)
        self._var_tracker.remove_function_level(self._block_level_count, False)
        self._block_level_count = 0
        self._var_tracker.remove_function_level(self._block_level_count, True)

        reentrancy = ""
        if function.HasField("ret") and self._mutability_level > PURE:
            reentrancy = self._visit_reentrancy(function.ret)
        function_obj.mutability = max(self._mutability_level, function.mut)
        function_obj.body = block
        function_obj.reentrancy = reentrancy
        function_obj.output_parameters = self._function_output

    def visit_init(self, init):
        self._mutability_level = 0

        visibility = "@external"

        input_params, _, _ = self._visit_input_parameters(init.input_params)

        function_name = "__init__"
        # self._func_tracker.register_function(function_name)

        self._block_level_count = 1
        block = self._visit_init_immutables()
        block += self._visit_block(init.block)
        self._var_tracker.remove_function_level(self._block_level_count, True)
        self._var_tracker.remove_function_level(self._block_level_count, False)
        self._block_level_count = 0
        self._var_tracker.remove_function_level(self._block_level_count, True)

        mutability = "@payable\n" if init.mut else ""

        result = f"{visibility}\n{mutability}def {function_name}({input_params}):\n{block}"

        return result

    def visit_default_func(self, function):
        self._mutability_level = 0
        visibility = "@external"

        self._function_output = self._visit_output_parameters(function.output_params)
        function_name = "__default__"

        self._block_level_count = 1
        block = self._visit_block(function.block)
        self._var_tracker.remove_function_level(self._block_level_count, True)
        self._var_tracker.remove_function_level(self._block_level_count, False)
        self._block_level_count = 0
        self._var_tracker.remove_function_level(self._block_level_count, True)

        output_str = ", ".join(o_type.vyper_type for o_type in self._function_output)
        if len(self._function_output) > 1:
            output_str = f"({output_str})"
        if len(self._function_output) > 0:
            output_str = f" -> {output_str}"

        reentrancy = ""
        if function.HasField("ret") and self._mutability_level > PURE:
            reentrancy = self._visit_reentrancy(function.ret)
        mutability = self.__get_mutability(function.mut)

        result = f"{visibility}\n{reentrancy}{mutability}\ndef {function_name}(){output_str}:\n{block}"

        return result

    def _visit_init_immutables(self):
        result = ""
        for var, expr in self._immutable_exp:
            result += f"{self.TAB}{var} = {expr}\n"
        return result

    def _visit_for_stmt_ranged(self, for_stmt_ranged):
        start, stop = (
            for_stmt_ranged.start, for_stmt_ranged.stop) if for_stmt_ranged.start < for_stmt_ranged.stop else (
            for_stmt_ranged.stop, for_stmt_ranged.start
        )
        if stop == start:
            stop += 1
        ivar_type = Int()
        idx = self._var_tracker.next_id(ivar_type)
        var_name = f"i_{idx}"
        self._var_tracker.register_function_variable(var_name, self._block_level_count + 1, ivar_type, False)
        result = f"for {var_name} in range({start}, {stop}):"
        return result

    def _visit_for_stmt_variable(self, for_stmt_variable):
        variable = None
        ivar_type = Int()
        if for_stmt_variable.HasField("ref_id"):
            self.type_stack.append(ivar_type)
            variable = self._visit_var_ref(for_stmt_variable.ref_id, self._block_level_count)
            self.type_stack.pop()
        length = for_stmt_variable.length
        if length == 0:
            length += 1
        idx = self._var_tracker.next_id(ivar_type)
        var_name = f"i_{idx}"
        self._var_tracker.register_function_variable(var_name, self._block_level_count + 1, ivar_type, False)
        if variable is None:
            result = f"for {var_name} in range({length}):"
            return result
        result = f"for {var_name} in range({variable}, {variable}+{length}):"
        return result

    def _visit_for_stmt(self, for_stmt):
        if for_stmt.HasField("variable"):
            for_statement = self.code_offset + self._visit_for_stmt_variable(for_stmt.variable)
        else:
            for_statement = self.code_offset + self._visit_for_stmt_ranged(for_stmt.ranged)

        self._for_block_count += 1
        self._block_level_count += 1
        body = self._visit_block(for_stmt.body)
        self._var_tracker.remove_function_level(self._block_level_count, True)
        self._var_tracker.remove_function_level(self._block_level_count, False)
        self._block_level_count -= 1
        self._for_block_count -= 1

        result = f"{for_statement}\n{body}"

        return result

    def _visit_if_cases(self, expr):
        result = f"{self.code_offset}if"
        if len(expr) == 0:
            result = f"{result} False:\n{self.TAB * (self._block_level_count + 1)}pass"
            return result
        for i, case in enumerate(expr):
            prefix = "" if i == 0 else f"{self.code_offset}elif"
            self.type_stack.append(Bool())
            condition = self._visit_bool_expression(case.cond)
            self.type_stack.pop()
            self._block_level_count += 1
            body = self._visit_block(case.if_body)
            self._var_tracker.remove_function_level(self._block_level_count, True)
            self._block_level_count -= 1
            result = f"{result}{prefix} {condition}:\n{body}\n"

        return result

    def _visit_else_case(self, expr):
        result = f"{self.code_offset}else:"
        self._block_level_count += 1
        else_block = self._visit_block(expr)
        self._var_tracker.remove_function_level(self._block_level_count, True)
        self._block_level_count -= 1
        result = f"{result}\n{else_block}"
        return result

    def _visit_if_stmt(self, if_stmt):
        result = self._visit_if_cases(if_stmt.cases)
        if if_stmt.HasField('else_case'):
            else_case = self._visit_else_case(if_stmt.else_case)
            result = f"{result}\n{else_case}"
        return result

    def _visit_selfd(self, selfd):
        if self._mutability_level < NON_PAYABLE:
            self._mutability_level = NON_PAYABLE

        self.type_stack.append(Address())
        to_parameter = self.visit_address_expression(selfd.to)
        self.type_stack.pop()
        return f"{self.code_offset}selfdestruct({to_parameter})"

    def _visit_raise_statement(self, expr):
        self.type_stack.append(String(100))
        error_value = self._visit_string_expression(expr.errval)
        self.type_stack.pop()

        result = f"{self.code_offset}raise"
        if len(error_value) > 2:
            result = f"{result} {error_value}"
        return result

    def _visit_assignment(self, assignment):
        current_type = self.visit_type(assignment.ref_id)
        self.type_stack.append(current_type)
        result = self._visit_var_ref(assignment.ref_id, self._block_level_count, True)
        if result is None:
            result = self.__var_decl(assignment.expr, current_type)
            return result
        expression_result = self.visit_typed_expression(assignment.expr, current_type)
        result = f"{self.code_offset}{result} = {expression_result}"
        self.type_stack.pop()
        return result

    def _visit_statement(self, statement):
        # if not in `for` theres always assignment; probs need another default value
        if self._for_block_count > 0:
            if statement.HasField("cont_stmt"):
                return self._visit_continue_statement()
            if statement.HasField("break_stmt"):
                return self._visit_break_statement()
        if statement.HasField("decl"):
            return self.visit_var_decl(statement.decl)
        if statement.HasField("for_stmt"):
            return self._visit_for_stmt(statement.for_stmt)
        if statement.HasField("if_stmt"):
            return self._visit_if_stmt(statement.if_stmt)
        if statement.HasField("assert_stmt"):
            return self._visit_assert_stmt(statement.assert_stmt)
        if statement.HasField("func_call"):
            func_num = statement.func_call.func_num % len(self._func_tracker)
            if self.func_flag or func_num not in self._excluded_call_map[self._current_func.id]:
                return self._visit_func_call(statement.func_call)
        if statement.HasField("append_stmt"):
            append_st = self._visit_append_stmt(statement.append_stmt)
            if append_st is not None:
                return append_st
        if statement.HasField("pop_stmt"):
            pop_st = self._visit_pop_stmt(statement.pop_stmt)
            if pop_st is not None:
                return pop_st
        return self._visit_assignment(statement.assignment)

    def _visit_func_call(self, func_call):
        def __create_variable(var_type):
            idx = self._var_tracker.next_id(var_type)
            name = f"x_{var_type.name}_{idx}"
            self._var_tracker.register_function_variable(name, self._block_level_count, var_type, True)
            return name

        def __find_function(_func_num):
            if self._func_tracker[func_num].id == self._current_func.id:
                _func_num = (_func_num + 1) % len(self._func_tracker)
            if self.func_flag:
                self._function_call_map[self._current_func.id].append(self._func_tracker[_func_num].id)
            return self._func_tracker[_func_num]

        func_num = func_call.func_num % len(self._func_tracker)
        func_obj = __find_function(func_num)

        output_vars = []
        result = ""
        for t in func_obj.output_parameters:
            allowed_vars = self._var_tracker.get_all_allowed_vars(self._block_level_count, t)
            if len(allowed_vars) > 0:
                variable = random.choice(allowed_vars)
            else:
                variable = __create_variable(t)
                result = f"{result}{self.code_offset}{variable} : {t.vyper_type} = empty({t.vyper_type})\n"
            output_vars.append(variable)
        result += f"{self.code_offset}"
        if len(output_vars) > 0:
            result += f'{", ".join(output_vars)} = '

        params_attrs = ("one", "two", "three", "four", "five")
        input_values = []
        for input_type, attr in zip(func_obj.input_parameters, params_attrs):
            self.type_stack.append(input_type)
            input_values.append(self.visit_typed_expression(getattr(func_call.params, attr), input_type))
            self.type_stack.pop()

        result = f"{result}{func_obj.render_call(input_values)}"

        return result

    def _visit_block(self, block):
        result = ""
        for statement in block.statements:
            statement_result = self._visit_statement(statement)
            result = f"{result}{statement_result}\n"

        if (self._block_level_count == 1 or block.exit_d.flag or len(block.statements) == 0):
            exit_result = ""
            # can omit return statement if no outputs
            if block.exit_d.HasField("selfd"):
                exit_result = self._visit_selfd(block.exit_d.selfd)
            elif block.exit_d.HasField("raise_st"):
                exit_result = self._visit_raise_statement(block.exit_d.raise_st)
            elif len(self._function_output) > 0 or block.exit_d.flag or len(block.statements) == 0:
                exit_result = self._visit_return_payload(block.exit_d.payload)

            result = f"{result}{exit_result}\n"

        return result

    def _visit_return_payload(self, return_p):
        # if len(self._function_output) == 0:
        #   return ""

        # TODO: dunno how to enumerate non repeated message
        iter_map = {
            0: return_p.one,
            1: return_p.two,
            2: return_p.three,
            3: return_p.four,
            4: return_p.five
        }

        result = "return "
        # must be len(ReturnPayload) >= len(output_params)
        for i in range(len(self._function_output)):
            # TODO: probably this should be done somewhere else
            self.type_stack.append(self._function_output[i])
            expression_result = self.visit_typed_expression(iter_map[i], self._function_output[i])
            self.type_stack.pop()
            result += f"{expression_result},"

        result = f"{self.code_offset}{result[:-1]}"

        return result

    def visit_address_expression(self, expr):
        # if expr.HasField("convert"):
        #     result = self._visit_convert(expr.convert)
        #     return result
        if expr.HasField("cmp"):
            return self.visit_create_min_proxy(expr.cmp)
        if expr.HasField("cfb"):
            return self.visit_create_from_blueprint(expr.cfb)
        if expr.HasField("varRef"):
            # TODO: it has to be decided how exactly to track a current block level or if it has to be passed
            result = self._visit_var_ref(expr.varRef, self._block_level_count)
            if result is not None:
                return result
        return self.create_literal(expr.lit)

    def visit_create_min_proxy(self, cmp):
        if self._mutability_level < NON_PAYABLE:
            self._mutability_level = NON_PAYABLE

        target = self.visit_address_expression(cmp.target)
        result = f"create_minimal_proxy_to({target}"
        if cmp.HasField("value"):
            self.type_stack.append(Int(256))
            value = self._visit_int_expression(cmp.value)
            result = f"{result}, value = {value}"
            self.type_stack.pop()
        if cmp.HasField("salt"):
            self.type_stack.append(BytesM(32))
            salt = self._visit_bytes_m_expression(cmp.salt)
            result = f"{result}, salt = {salt}"
            self.type_stack.pop()
        result = f"{result})"

        return result

    def visit_create_from_blueprint(self, cfb):
        if self._mutability_level < NON_PAYABLE:
            self._mutability_level = NON_PAYABLE

        target = self.visit_address_expression(cfb.target)
        result = f"create_from_blueprint({target}"

        # TODO: args parameter is not handled yet

        if cfb.HasField("rawArgs"):
            self.type_stack.append(Bool())
            raw_args = self._visit_bool_expression(cfb.rawArgs)
            result = f"{result}, raw_args = {raw_args}"
            self.type_stack.pop()
        if cfb.HasField("value"):
            self.type_stack.append(Int(256))
            value = self._visit_int_expression(cfb.value)
            result = f"{result}, value = {value}"
            self.type_stack.pop()
        if cfb.HasField("code_offset"):
            self.type_stack.append(Int(256))
            offset = self._visit_int_expression(cfb.code_offset)
            result = f"{result}, code_offset = {offset}"
            self.type_stack.pop()
        if cfb.HasField("salt"):
            self.type_stack.append(BytesM(32))
            salt = self._visit_bytes_m_expression(cfb.salt)
            result = f"{result}, salt = {salt}"
            self.type_stack.pop()
        result = f"{result})"

        return result

    def create_literal(self, lit):
        current_type = self.type_stack[len(self.type_stack) - 1]
        return current_type.generate_literal(getattr(lit, LITERAL_ATTR_MAP[current_type.name]))

    # @classmethod
    # def _get_from_type(cls, conv_expr):
    #     # TODO: implement
    #     pass

    # def _visit_convert(self, conv_expr):
    #     # TODO: the conversion path is supposed to go through more difficult way
    #     current_type = self.type_stack[len(self.type_stack) - 1]
    #     source_type = self._get_from_type(conv_expr)
    #     value = self.visit_typed_expression(conv_expr.value, source_type)
    #     result = f"convert({value}, {current_type.vyper_type})"
    #     return result

    def _visit_bool_expression(self, expr):
        # if expr.HasField("convert"):
        #     result = self._visit_convert(expr.convert)
        #     return result
        if expr.HasField("boolBinOp"):
            left = self._visit_bool_expression(expr.boolBinOp.left)
            right = self._visit_bool_expression(expr.boolBinOp.right)
            bin_op = get_bin_op(expr.boolBinOp.op, BIN_OP_BOOL_MAP)
            result = f"{left} {bin_op} {right}"
            return result
        if expr.HasField("boolUnOp"):
            operand = self._visit_bool_expression(expr.boolUnOp.expr)
            result = f"not {operand}"
            return result
        if expr.HasField("intBoolBinOp"):
            # TODO: here probably must be different kinds of Int
            self.type_stack.append(Int(256))
            left = self._visit_int_expression(expr.intBoolBinOp.left)
            right = self._visit_int_expression(expr.intBoolBinOp.right)
            bin_op = get_bin_op(expr.intBoolBinOp.op, INT_BIN_OP_BOOL_MAP)
            result = f"{left} {bin_op} {right}"
            self.type_stack.pop()
            return result
        if expr.HasField("decBoolBinOp"):
            self.type_stack.append(Decimal())
            left = self._visit_decimal_expression(expr.decBoolBinOp.left)
            right = self._visit_decimal_expression(expr.decBoolBinOp.right)
            bin_op = get_bin_op(expr.decBoolBinOp.op, INT_BIN_OP_BOOL_MAP)
            result = f"{left} {bin_op} {right}"
            self.type_stack.pop()
            return result
        if expr.HasField("varRef"):
            # TODO: it has to be decided how exactly to track a current block level or if it has to be passed
            result = self._visit_var_ref(expr.varRef, self._block_level_count)
            if result is not None:
                return result
        return self.create_literal(expr.lit)

    def _visit_int_expression(self, expr):
        # if expr.HasField("convert"):
        #     result = self._visit_convert(expr.convert)
        #     return result
        if expr.HasField("binOp"):
            bin_op = get_bin_op(expr.binOp.op, BIN_OP_MAP)
            self.op_stack.append(bin_op)
            left = self._visit_int_expression(expr.binOp.left)
            right = self._visit_int_expression(expr.binOp.right)
            result = f"{left} {bin_op} {right}"
            self.op_stack.pop()
            if len(self.op_stack) > 0:
                result = f"({result})"
            return result
        if expr.HasField("unOp"):
            self.op_stack.append("unMinus")
            result = self._visit_int_expression(expr.unOp.expr)
            result = f"-{result}"
            self.op_stack.pop()
            if len(self.op_stack) > 0:
                result = f"({result})"
            return result
        if expr.HasField("varRef"):
            # TODO: it has to be decided how exactly to track a current block level or if it has to be passed
            result = self._visit_var_ref(expr.varRef, self._block_level_count)
            if result is not None:
                return result
        return self.create_literal(expr.lit)

    def _visit_bytes_m_expression(self, expr):
        # if expr.HasField("convert"):
        #     result = self._visit_convert(expr.convert)
        #     return result
        if expr.HasField("sha"):
            # FIXME: length of current BytesM might me less than 32, If so, the result of `sha256` must be converted
            return self._visit_sha256(expr.sha)
        if expr.HasField("varRef"):
            # TODO: it has to be decided how exactly to track a current block level or if it has to be passed
            result = self._visit_var_ref(expr.varRef, self._block_level_count)
            if result is not None:
                return result
        return self.create_literal(expr.lit)

    def _visit_sha256(self, expr):
        result = "sha256("
        if expr.HasField("strVal"):
            self.type_stack.append(String(100))
            value = self._visit_string_expression(expr.strVal)
            self.type_stack.pop()
            return f"{result}{value})"
        if expr.HasField("bVal"):
            self.type_stack.append(Bytes(100))
            value = self._visit_bytes_expression(expr.bVal)
            self.type_stack.pop()
            return f"{result}{value})"
        self.type_stack.append(BytesM(32))
        value = self._visit_bytes_m_expression(expr.bmVal)
        self.type_stack.pop()
        return f"{result}{value})"

    def _visit_decimal_expression(self, expr):
        # if expr.HasField("convert"):
        #     result = self._visit_convert(expr.convert)
        #     return result
        if expr.HasField("binOp"):
            bin_op = get_bin_op(expr.binOp.op, BIN_OP_MAP)
            self.op_stack.append(bin_op)
            left = self._visit_decimal_expression(expr.binOp.left)
            right = self._visit_decimal_expression(expr.binOp.right)
            result = f"{left} {bin_op} {right}"
            self.op_stack.pop()
            if len(self.op_stack) > 0:
                result = f"({result})"
            return result
        if expr.HasField("unOp"):
            self.op_stack.append("unMinus")
            result = self._visit_decimal_expression(expr.unOp.expr)
            result = f"-{result}"
            self.op_stack.pop()
            if len(self.op_stack) > 0:
                result = f"({result})"
            return result
        if expr.HasField("varRef"):
            # TODO: it has to be decided how exactly to track a current block level or if it has to be passed
            result = self._visit_var_ref(expr.varRef, self._block_level_count)
            if result is not None:
                return result
        return self.create_literal(expr.lit)

    def _visit_bytes_expression(self, expr):
        # if expr.HasField("convert"):
        #     result = self._visit_convert(expr.convert)
        #     return result
        if expr.HasField("varRef"):
            # TODO: it has to be decided how exactly to track a current block level or if it has to be passed
            result = self._visit_var_ref(expr.varRef, self._block_level_count)
            if result is not None:
                return result
        return self.create_literal(expr.lit)

    def _visit_string_expression(self, expr):
        # if expr.HasField("convert"):
        #     result = self._visit_convert(expr.convert)
        #     return result
        if expr.HasField("varRef"):
            # TODO: it has to be decided how exactly to track a current block level or if it has to be passed
            result = self._visit_var_ref(expr.varRef, self._block_level_count)
            if result is not None:
                return result
        return f"\"{self.create_literal(expr.lit)}\""

    def _visit_continue_statement(self):
        return f"{self.code_offset}continue"

    def _visit_break_statement(self):
        return f"{self.code_offset}break"

    def _visit_assert_stmt(self, assert_stmt):
        result = f"{self.code_offset}assert"

        self.type_stack.append(Bool())  # not sure
        condition = self._visit_bool_expression(assert_stmt.cond)
        result = f"{result} {condition}"
        self.type_stack.pop()

        self.type_stack.append(String(100))
        value = self._visit_string_expression(assert_stmt.reason)
        self.type_stack.pop()

        if len(value) > 2:
            result = f"{result}, {value}"

        return result

    # FIXME: will adjust sizes in list expressions -> generates wrong expression
    def _visit_append_stmt(self, stmt):
        # None type as key for all available dynamic arrays
        current_type = DynArray(MAX_LIST_SIZE, None)

        self.type_stack.append(current_type)
        variable_name = self._visit_var_ref(stmt.varRef, self._block_level_count, True)
        self.type_stack.pop()

        if variable_name is None:
            return

        variable_type = self._var_tracker.get_dyn_array_base_type(variable_name, self._block_level_count, True)
        self.type_stack.append(variable_type)
        expression_result = self.visit_typed_expression(stmt.expr, variable_type)
        self.type_stack.pop()

        return f"{self.TAB * self._block_level_count}{variable_name}.append({expression_result})"

    def _visit_pop_stmt(self, stmt):
        current_type = DynArray(MAX_LIST_SIZE, None)
        self.type_stack.append(current_type)

        result = self._visit_var_ref(stmt.varRef, self._block_level_count, True)
        if result is None:
            return
        self.type_stack.pop()

        result = f"{self.TAB * self._block_level_count}{result}.pop()"

        return result

    @property
    def code_offset(self):
        return self.TAB * self._block_level_count
