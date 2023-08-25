from enum import Enum

from utils import get_spaces, get_nearest_multiple

from config import MAX_NESTING_LEVEL, MAX_EXPRESSION_LEVEL, MAX_FUNCTION_INPUT, MAX_FUNCTIONS
from config import MAX_FUNCTION_OUTPUT, MAX_STORAGE_VARIABLES, MAX_LOCAL_VARIABLES


from vyperProto_pb2 import Contract, Func, FuncParam, Reentrancy,  Block, Statement
from vyperProto_pb2 import VarDecl, AssignmentStatement, Expression, Int, Bool
from vyperProto_pb2 import VarRef, Literal, BinaryOp, UnaryOp
from vyperProto_pb2 import IfStmtCase, IfStmt, ForStmtRanged, ForStmtVariable, ForStmt


class Type(Enum):
    INT = 0
    BOOL = 1


class Converter:

    def __init__(self) -> None:
        self.result = ""

    def visit(self):
        pass


class ProtoConverter(Converter):

    def __init__(self, contract: Contract):
        super().__init__()

        self.contract = contract

        self.func_count = 0

        self.global_vars = {}  # dict type => number of variables
        # Based on nesting_level we will calculate tabulations
        self.nesting_level = 0  # In other instances this should be limited by config

    def get_func_idx(self):
        return self.func_count

    def visit(self):

        variable_counter = 0
        for variable in self.contract.decls:
            if variable_counter == MAX_STORAGE_VARIABLES:
                break
            variable_counter += 1
            # passing empty func_params
            variable_converter = self.visit_var_decl(variable,
                                                     self.global_vars.copy(),
                                                     {}, is_global=True)
            self.result += variable_converter + '\n\n'

        function_counter = 0
        for function in self.contract.functions:
            if function_counter == MAX_FUNCTIONS:
                break
            function_counter += 1

            function_converter = self.visit_func(
                function, self.nesting_level + 1)
            self.result += function_converter + '\n\n'

            self.func_count += 1

    def visit_int(self, int):

        result = 0
        if int.sign:
            result = "int"
        else:
            result = "uint"

        n = int.n % 256 + 1
        n = get_nearest_multiple(n, 8)

        result += str(n)

        return result

    def visit_bool(self):
        result = "bool"
        return result

    def visit_reentrancy(self, ret):
        result = "@nonreentrant(\"" + ret.key + "\")"
        return result

    def visit_var_decl(self, variable, available_vars, func_params, is_global=False):
        vyper_type = ""
        idx = 0

        current_type = None

        if variable.HasField("i"):

            vyper_type = self.visit_int(variable.i)
            current_type = Type.INT
        else:
            vyper_type += self.visit_bool()
            current_type = Type.BOOL

        if current_type not in available_vars:
            available_vars[current_type] = 1
        else:
            idx = available_vars[current_type]
            available_vars[current_type] += 1

        result = 'x_' + current_type.name + "_" + str(idx) + " : " + vyper_type

        if not is_global:
            result += " = "

            result += self.visit_expression(variable.expr,
                                            available_vars, func_params, 1)

        return result

    def visit_expression(self, expr, available_vars, func_params, expr_level) -> str:

        result = ''
        if expr_level == MAX_EXPRESSION_LEVEL:
            # has to be right literal?
            result = "True"
        elif expr.HasField("varref"):

            result = self.visit_var_ref(
                expr.varref, available_vars, func_params)
        elif expr.HasField("binop"):

            result = self.visit_bin_op(expr.binop, func_params, 1)
        elif expr.HasField("unop"):

            result = self.visit_unary_op(
                expr.unop, available_vars, func_params, expr_level)
        else:  # cons, had to remove else cuz of oneof
            # i think this might lead to something like `literal` = ...
            result = self.visit_literal(expr.cons)

        return result

    def visit_var_ref(self, var_ref, available_vars, func_params, is_assign=False):

        current_type = None
        result = ''

        if var_ref.HasField('i'):
            current_type = Type.INT
        else:
            current_type = Type.BOOL

        global_vars_type_max_idx = -1
        if current_type in self.global_vars:
            global_vars_type_max_idx = self.global_vars[current_type] - 1

        available_vars_type_max_idx = -1
        if current_type in available_vars:
            available_vars_type_max_idx = available_vars[current_type] - 1

        func_param_type_max_idx = -1
        if current_type in func_params:
            func_param_type_max_idx = func_params[current_type] - 1

        idx = -1

        if available_vars_type_max_idx >= 0:
            idx = var_ref.varnum % (available_vars_type_max_idx + 1)
        else:
            # has to return some typed literal
            if current_type == Type.INT:
                result = "1"
            else:
                result = "True"

            return result

        if not is_assign:  # REFACTOR THIS IF STATEMENT AND CHECK WHAT TO DO IF WE DON'T HAVE ANY FREE VARIABLES
            if idx <= global_vars_type_max_idx:
                result = "self.x_"
            else:
                result = "x_"
        else:
            if idx <= global_vars_type_max_idx:
                result = "self.x_"
            elif idx <= func_param_type_max_idx:

                if available_vars_type_max_idx > func_param_type_max_idx:
                    idx = func_param_type_max_idx + 1
                    result = "x_"
            else:
                result = "x_"

        result += current_type.name + "_" + str(idx)

        return result

    def visit_bin_op(self, binop, func_params, expr_level):
        return ""

    def visit_unary_op(self, unop, available_vars, func_params, expr_level: int):

        result = ''
        if unop.op == UnaryOp.UOp.NOT:
            result = "not "
        elif unop.op == UnaryOp.UOp.MINUS:
            result = "-"
        elif unop.op == UnaryOp.UOp.BIT_NOT:
            result = "~"

        result += self.visit_expression(unop.expr, available_vars,
                                        func_params, expr_level + 1)

        return result

    def visit_literal(self, literal):
        result = ''
        if literal.HasField("intval"):
            result = str(literal.intval)
        elif literal.HasField("strval"):
            result = literal.strval
        elif literal.HasField("boolval"):
            # TO-DO check format of str(bool), uppercase
            result = str(literal.boolval)

        return result

    def visit_func(self, function, nesting_level):

        idx = self.get_func_idx()
        available_vars = self.global_vars.copy()
        func_params = {}

        result = "@"

        if function.vis == Func.Visibility.EXTERNAL:
            result += "external"
        elif function.vis == Func.Visibility.INTERNAL:
            result += "internal"

        result += "\n"

        if function.mut != Func.Mutability.NONPAYABLE:
            result += "@"

            if function.mut == Func.Mutability.PURE:
                result += "pure"
            elif function.mut == Func.Mutability.VIEW:
                result += "view"
            elif function.mut == Func.Mutability.PAYABLE:
                result += "payable"

            result += "\n"

        if function.HasField("ret"):
            result += self.visit_reentrancy(function.ret)

            result += '\n'

        result += "def func_" + str(idx) + "("

        # here can be set input length
        # does not add to local vars
        input_counter = 0
        for input_param in function.input_params:
            if input_counter == MAX_FUNCTION_INPUT:
                break
            input_counter += 1

            param_converter = self.visit_func_input(
                input_param, available_vars, func_params)

            result += param_converter + ", "

        if input_counter != 0:
            result = result[:-2]

        result += ")"

        if len(function.output_params) != 0:

            result += " -> ("

            # can move to utility to not replicate code
            output_counter = 0
            for output_param in function.output_params:
                if output_counter == MAX_FUNCTION_OUTPUT:
                    break
                output_counter += 1

                param_converter = self.visit_func_output(output_param)

                result += param_converter + ", "

            result = result[:-2] + ')'

        result += ":" + "\n"

        result += self.visit_block(function.block,
                                   available_vars, func_params, nesting_level)

        return result

    def visit_func_input(self, param, available_vars, func_params):
        # refactor to avoid code duplication with VarDecl
        vyper_type = ""
        idx = 0
        current_type = None

        if param.HasField("i"):

            vyper_type += self.visit_int(param.i)
            current_type = Type.INT

        else:

            vyper_type += self.visit_bool()
            current_type = Type.BOOL

        if current_type not in available_vars:
            available_vars[current_type] = 1
            # self.func_params[self.type] = 1
        else:
            idx = available_vars[current_type]
            available_vars[current_type] += 1

        # CHECK IF THIS HOLDS IN EVERY CASE
        func_params[current_type] = available_vars[current_type]

        result = 'x_' + current_type.name + "_" + str(idx)
        result += " : " + vyper_type

        # if self.param.HasField('loc'):
        #     if self.param.loc == FuncParam.MEMORY:
        #         self.result += "memory"
        #     elif self.param.loc == FuncParam.CALLDATA:
        #         self.result += "calldata"

        #     self.result += " "

        return result

    def visit_func_output(self, param):
        vyper_type = ""
        current_type = None

        if param.HasField("i"):

            vyper_type += self.visit_int(param.i)
            current_type = Type.INT

        else:

            vyper_type += self.visit_bool()
            current_type = Type.BOOL

        return vyper_type

    def visit_block(self, block, available_vars, func_params, nesting_level):

        result = ''
        for statement in block.statements:
            statement_converter = self.visit_statement(
                statement, available_vars, func_params, nesting_level)

            result += get_spaces(nesting_level) + statement_converter

        if len(block.statements) == 0:
            result += get_spaces(nesting_level) + "pass"

        return result

    def visit_statement(self, statement, available_vars, func_params, nesting_level):

        result = ''
        if statement.HasField('decl'):

            result += self.visit_var_decl(statement.decl,
                                          available_vars, func_params)
        # can be NoneType
        elif statement.HasField('assignment'):

            result += self.visit_assignment_statement(
                statement.assignment, available_vars, func_params)
        elif statement.HasField('for_stmt'):

            result += self.visit_for_stmt(statement.for_stmt,
                                          available_vars, func_params, nesting_level)
        elif statement.HasField('if_stmt'):

            result += self.visit_if_stmt(statement.if_stmt,
                                         available_vars, func_params, nesting_level)

        return result

    def visit_assignment_statement(self, assign, available_vars, func_params):
        var_ref_converter = self.visit_var_ref(
            assign.ref_id, available_vars, func_params, is_assign=True)

        result = var_ref_converter + " = "

        result += self.visit_expression(assign.expr,
                                        available_vars, func_params, 1)

        return result

    def visit_if_stmt_case(self, ifstmtcase, available_vars, func_params, nesting_level):

        result = self.visit_expression(
            ifstmtcase.cond, available_vars, func_params, 1)
        result += ":\n"
        result += self.visit_block(ifstmtcase.if_body,
                                   available_vars, func_params, nesting_level + 1)

        return result

    def visit_if_stmt(self, ifstmt, available_vars, func_params, nesting_level):
        result = "if "
        branches = len(ifstmt.cases)
        # add tabbing
        if branches == 0:
            result += "False:\n"
            result += get_spaces(nesting_level) + "    pass\n"
        else:
            result += self.visit_if_stmt_case(
                ifstmt.cases[0], available_vars, func_params, nesting_level)

        for case_num in range(1, branches):
            result += get_spaces(nesting_level) + "elif"
            result += self.visit_if_stmt_case(
                ifstmt.cases[case_num], available_vars, func_params, nesting_level)

        if ifstmt.HasField("else_case"):
            result += get_spaces(nesting_level) + "else:\n"
            result += self.visit_block(ifstmt.else_case,
                                       available_vars, func_params, nesting_level + 1)

        return result

    def visit_for_stmt_range(self, for_stmt_range):
        start = for_stmt_range.start
        stop = for_stmt_range.stop
        if start > stop:
            start, stop = stop, start
        result = f"range({start},{stop}):\n"
        return result

    def visit_for_stmt_var(self, for_stmt_var, available_vars, func_params):
        length = for_stmt_var.length
        if for_stmt_var.HasField("ref_id"):
            # gets bool if no ints :(
            var = self.visit_var_ref(
                for_stmt_var.ref_id, available_vars, func_params)
            result = f"range({var},{var}+{length}):\n"
        else:
            result = f"range({length}):\n"

        return result

    def visit_for_stmt(self, forstmt, available_vars, func_params, nesting_level):
        # local vars
        idx = 0
        
        if Type.INT not in available_vars:
            available_vars[Type.INT] = 1
        else:
            idx = available_vars[Type.INT]
            available_vars[Type.INT] += 1

        loop_var = f"x_INT{idx}"
        result = f"for {loop_var} in "

        if forstmt.HasField("ranged"):
            result += self.visit_for_stmt_range(forstmt.ranged)
        else:
            result += self.visit_for_stmt_var(forstmt.variable,
                                              available_vars, func_params)

        result += self.visit_block(forstmt.body,
                                   available_vars, func_params, nesting_level + 1)

        return result
