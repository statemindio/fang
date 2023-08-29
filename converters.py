from data_types import Type

from utils import get_spaces, get_nearest_multiple
from utils import get_random_token, get_random_element
from utils import checksum_encode, fill_address
from config import MAX_NESTING_LEVEL, MAX_EXPRESSION_LEVEL, MAX_FUNCTION_INPUT, MAX_FUNCTIONS
from config import MAX_FUNCTION_OUTPUT, MAX_STORAGE_VARIABLES, MAX_LOCAL_VARIABLES


from vyperProto_pb2 import Contract, Func, FuncParam, Reentrancy,  Block, Statement
from vyperProto_pb2 import VarDecl, AssignmentStatement, Expression, Int, Bool
from vyperProto_pb2 import VarRef, Literal, BinaryOp, UnaryOp
from vyperProto_pb2 import IfStmtCase, IfStmt, ForStmtRanged, ForStmtVariable, ForStmt


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

        self.current_declared_variable = None

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
                                                     is_global=True)
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

        result = ""
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
    
    def visit_decimal(self):
        result = "decimal"
        return result

    def visit_bytes_m(self, bytesM):
        result = "bytes"

        m = bytesM.m % 32 + 1
        result += str(m)

        return result

    def visit_string(self, string):
        result = "String["

        l = string.max_len
        result += str(l) + "]"

        return result
    
    def visit_type(self, instance):
        vyper_type = ""
        current_type = None

        if instance.HasField("b"):

            vyper_type = self.visit_bool()
            current_type = Type.BOOL
        elif instance.HasField("d"):

            vyper_type = self.visit_decimal()
            current_type = Type.DECIMAL
        elif instance.HasField("bM"):

            vyper_type = self.visit_bytes_m(instance.bM)
            current_type = Type.BytesM
        elif instance.HasField("s"):

            vyper_type = self.visit_string(instance.s)
            current_type = Type.STRING
        elif instance.HasField("adr"):

            vyper_type = self.visit_address()
            current_type = Type.ADDRESS
        elif instance.HasField("barr"):

            vyper_type = self.visit_byte_array(instance.barr.max_len)
            current_type = Type.BYTEARRAY
        else:

            vyper_type = self.visit_int(instance.i)
            current_type = Type.INT
        

        return vyper_type, current_type


    def visit_address(self):
        return "address"

    def visit_byte_array(self, max_len):
        return f"Bytes[{max_len}]"

    def visit_reentrancy(self, ret):
        result = "@nonreentrant(\"" + ret.key + "\")"
        return result

    def visit_var_decl(self, variable, available_vars, is_global=False):
        vyper_type = ""
        idx = 0

        current_type = None

        vyper_type, current_type = self.visit_type(variable)


        if current_type not in available_vars:
            available_vars[current_type] = 1
        else:
            idx = available_vars[current_type]
            available_vars[current_type] += 1

        result = 'x_' + current_type.name + "_" + str(idx) + " : " + vyper_type
        self.current_declared_variable = 'x_' + current_type.name + "_" + str(idx)

        if not is_global:
            result += " = "

            tmp_res, _ = self.visit_expression(variable.expr,
                                               available_vars, [current_type], 1)
            result += tmp_res
        return result

    def visit_expression(self, expr, available_vars, needed_types: [Type], expr_level):

        current_type = None
        result = ''
        if expr.HasField("cons"):

            # make inside literal converter checking for type
            tmp_res, tmp_type = self.visit_literal(expr.cons)

            if tmp_type not in needed_types:

                # RANDOMLY CHOOSE TYPE, BUT WE CAN CHOOSE FIRST ELEMENT or etc
                current_type = get_random_element(needed_types)
                result = str(get_random_token(current_type))
            else:

                current_type = tmp_type
                result = tmp_res

        elif expr_level == MAX_EXPRESSION_LEVEL:

            # RANDOMLY CHOOSE TYPE, BUT WE CAN CHOOSE FIRST ELEMENT or etc
            current_type = get_random_element(needed_types)
            result = str(get_random_token(current_type))

        elif expr.HasField("binop"):

            (tmp_res, tmp_type) = self.visit_bin_op(
                expr.binop, available_vars, expr_level)

            if tmp_type not in needed_types:

                # RANDOMLY CHOOSE TYPE, BUT WE CAN CHOOSE FIRST ELEMENT or etc
                current_type = get_random_element(needed_types)
                result = str(get_random_token(current_type))
            else:
                current_type = tmp_type
                result = tmp_res

        elif expr.HasField("unop"):

            (tmp_res, tmp_type) = self.visit_unary_op(
                expr.unop, available_vars, expr_level)

            if tmp_type not in needed_types:

                # RANDOMLY CHOOSE TYPE, BUT WE CAN CHOOSE FIRST ELEMENT or etc
                current_type = get_random_element(needed_types)
                result = str(get_random_token(current_type))
            else:
                current_type = tmp_type
                result = tmp_res
        else:

            tmp_res, tmp_type = self.visit_var_ref(
                expr.varref, available_vars)

            if tmp_type not in needed_types:  # we should call visit, because type is set during visit()

                # RANDOMLY CHOOSE TYPE, BUT WE CAN CHOOSE FIRST ELEMENT or etc
                current_type = get_random_element(needed_types)
                # think about conversions and vyper_type
                result = str(get_random_token(current_type))
            else:

                current_type = tmp_type
                result = tmp_res
            """
            # should fix if oneof is null
            # if random does not account for type size
            current_type = get_random_element(needed_types)
            result = str(get_random_token(current_type))
            """
        return result, current_type

    def visit_var_ref(self, var_ref, available_vars, func_params=None, is_assign=False, needed_type: Type = None):
        # if var ref is not used as assigned var then func_params not needed
        assert is_assign == (func_params != None)

        current_type = None
        result = ''

        if var_ref.HasField('adr'):
            current_type = Type.ADDRESS
        elif var_ref.HasField('barr'):
            current_type = Type.BYTEARRAY
        elif var_ref.HasField('b'):
            current_type = Type.BOOL
        elif var_ref.HasField('d'):
            current_type = Type.DECIMAL
        elif var_ref.HasField('bM'):
            current_type = Type.BytesM
        elif var_ref.HasField('s'):
            current_type = Type.STRING
        else:
            current_type = Type.INT

        global_vars_type_max_idx = -1
        if current_type in self.global_vars:
            global_vars_type_max_idx = self.global_vars[current_type] - 1

        available_vars_type_max_idx = -1
        if current_type in available_vars:
            available_vars_type_max_idx = available_vars[current_type] - 1

        func_param_type_max_idx = -1
        if func_params:
            if current_type in func_params:
                func_param_type_max_idx = func_params[current_type] - 1

        idx = -1

        if available_vars_type_max_idx >= 0:
            idx = var_ref.varnum % (available_vars_type_max_idx + 1)
        else:
            if is_assign:
                return None, current_type
            else:
                return str(get_random_token(current_type)), current_type

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

        if result == '' or result + current_type.name + "_" + str(idx) == self.current_declared_variable:
            return str(get_random_token(current_type)), current_type
        
        result += current_type.name + "_" + str(idx)

        return result, current_type

    def visit_bin_op(self, binop, available_vars, expr_level):
        symbol = ""
        needed_types = [None]
        op_type = None

        if binop.op == BinaryOp.BOp.ADD:
            needed_types = [Type.INT, Type.DECIMAL]  # ADD can have multiple types
            symbol = "+"

        elif binop.op == BinaryOp.BOp.SUB:
            needed_types = [Type.INT, Type.DECIMAL]
            symbol = "-"

        elif binop.op == BinaryOp.BOp.DIV:
            needed_types = [Type.INT, Type.DECIMAL]
            symbol = "/"

        elif binop.op == BinaryOp.BOp.MOD:
            needed_types = [Type.INT, Type.DECIMAL]
            symbol = "%"

        elif binop.op == BinaryOp.BOp.EXP:
            needed_types = [Type.INT, Type.DECIMAL]
            symbol = "**"

        elif binop.op == BinaryOp.BOp.AND:
            op_type = Type.BOOL

            needed_types = [Type.BOOL]
            symbol = "and"

        elif binop.op == BinaryOp.BOp.OR:
            op_type = Type.BOOL

            needed_types = [Type.BOOL]
            symbol = "or"

        elif binop.op == BinaryOp.BOp.EQ:
            op_type = Type.BOOL

            needed_types = [Type.INT, Type.BOOL, Type.DECIMAL, Type.ADDRESS, Type.BYTEARRAY]
            symbol = "=="

        elif binop.op == BinaryOp.BOp.INEQ:
            op_type = Type.BOOL

            needed_types = [Type.INT, Type.BOOL, Type.DECIMAL, Type.ADDRESS, Type.BYTEARRAY]
            symbol = "!="

        elif binop.op == BinaryOp.BOp.LESS:
            op_type = Type.BOOL

            needed_types = [Type.INT, Type.BOOL, Type.DECIMAL]
            symbol = "<"

        elif binop.op == BinaryOp.BOp.LESSEQ:
            op_type = Type.BOOL

            needed_types = [Type.INT, Type.BOOL, Type.DECIMAL]
            symbol = "<="

        elif binop.op == BinaryOp.BOp.GREATER:
            op_type = Type.BOOL

            needed_types = [Type.INT, Type.BOOL, Type.DECIMAL]
            symbol = ">"

        elif binop.op == BinaryOp.BOp.GREATEREQ:
            op_type = Type.BOOL

            needed_types = [Type.INT, Type.BOOL, Type.DECIMAL]
            symbol = ">="

        elif binop.op == BinaryOp.BOp.BIT_AND:  # CHECK IMPLEMENTATION FOR OTHER TYPES
            needed_types = [Type.INT]
            symbol = "&"

        elif binop.op == BinaryOp.BOp.BIT_OR:  # CHECK IMPLEMENTATION FOR OTHER TYPES
            needed_types = [Type.INT]
            symbol = "|"

        elif binop.op == BinaryOp.BOp.BIT_XOR:  # CHECK IMPLEMENTATION FOR OTHER TYPES
            needed_types = [Type.INT]
            symbol = "^"

        elif binop.op == BinaryOp.BOp.LEFT_SHIFT:  # CHECK IMPLEMENTATION FOR OTHER TYPES
            needed_types = [Type.INT]
            symbol = "<<"

        # elif binop.op == BinaryOp.BOp.RIGHT_SHIFT:  # CHECK IMPLEMENTATION FOR OTHER TYPES
        else:
            needed_types = [Type.INT]
            symbol = ">>"

        left_expr, left_type = self.visit_expression(binop.left, available_vars,
                                                     needed_types, expr_level + 1)
        if op_type == None:
            # EXPRESSION TYPE IS BASED ON LEFT EXPRESSION, WE CAN COMPARE WITH PARENT TYPE OR LEFT IT AS IT IS
            op_type = left_type

        right_expr, right_type = self.visit_expression(binop.right, available_vars,
                                                       needed_types, expr_level + 1)

        result = "( " + left_expr + f" {symbol} "
        if left_type != right_type:  # check here for conversion !
            result += str(get_random_token(left_type))
        else:
            result += right_expr
        result += " )"

        return result, op_type

    def visit_unary_op(self, unop, available_vars, expr_level: int):

        symbol = ''
        needed_types = [None]
        result = ''

        if unop.op == UnaryOp.UOp.NOT:
            needed_types = [Type.BOOL]
            symbol = "not "
        elif unop.op == UnaryOp.UOp.MINUS:
            needed_types = [Type.INT, Type.DECIMAL]
            symbol = "-"
        elif unop.op == UnaryOp.UOp.BALANCE:
            needed_types = [Type.ADDRESS]
            symbol = "balance"
        elif unop.op == UnaryOp.UOp.CODEHASH:
            needed_types = [Type.ADDRESS]
            symbol = "codehash"
        elif unop.op == UnaryOp.UOp.CODESIZE:
            needed_types = [Type.ADDRESS]
            symbol = "codesize"
        elif unop.op == UnaryOp.UOp.IS_CONTRACT:
            needed_types = [Type.ADDRESS]
            symbol = "is_contract"
        elif unop.op == UnaryOp.UOp.CODE:
            needed_types = [Type.ADDRESS]
            symbol = "code"
        elif unop.op == UnaryOp.UOp.BIT_NOT:
        #else:
            needed_types = [Type.INT]
            symbol = "~"

        # generates 0x0...0.symbol which is wrong
        tmp_res, current_type = self.visit_expression(unop.expr, available_vars,
                                                      needed_types, expr_level + 1)

        if current_type == Type.ADDRESS and len(tmp_res) == 42:
            # in outer visit_expression will gen random value due to
            # tmp_type not in needed_types:
            current_type = None

        if Type.ADDRESS in needed_types:
            result = "( " + tmp_res + "." + symbol + " )"
        else:
            result = "( " + symbol + " " + tmp_res + " )"

        return (result, current_type)

    def visit_literal(self, literal):
        result = ''
        cur_type = None
        
        if literal.HasField("addval"):

            adr = str(hex(literal.addval))[:42]
            result = checksum_encode(fill_address(adr))
            cur_type = Type.ADDRESS
        elif literal.HasField("barrval"):
            
            result = f"b\"{hex(literal.barrval)}\""
            cur_type = Type.BYTEARRAY
        elif literal.HasField("boolval"):
            
            # TO-DO check format of str(bool), uppercase
            result = str(literal.boolval)
            cur_type = Type.BOOL
        elif literal.HasField("decimalval"):

            result = str(literal.decimalval / 10**10)
            cur_type = Type.DECIMAL
        elif literal.HasField("bMval"):

            result = "0x" + literal.bMval.hex()[:64]  # get only first 64 characters
            cur_type = Type.BytesM
        elif literal.HasField("strval"):

            result = literal.strval  # CHECK RESTRICTIONS ON STRING LEN
            cur_type = Type.STRING
        else:
            result = str(literal.intval)
            cur_type = Type.INT

        return result, cur_type

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

        vyper_type, current_type = self.visit_type(param)

        if current_type not in available_vars:
            available_vars[current_type] = 1
            # self.func_params[current_type] = 1
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

        vyper_type, current_type = self.visit_type(param)

        return vyper_type

    def visit_block(self, block, available_vars, func_params, nesting_level):

        result = ''
        for statement in block.statements:
            statement_converter = self.visit_statement(
                statement, available_vars, func_params, nesting_level)

            result += get_spaces(nesting_level) + statement_converter + '\n'

        if len(block.statements) == 0:
            result += get_spaces(nesting_level) + "pass\n"

        return result

    def visit_statement(self, statement, available_vars, func_params, nesting_level):

        result = ''
        if statement.HasField('decl'):

            result += self.visit_var_decl(statement.decl,
                                          available_vars, func_params)
            self.current_declared_variable = None
        # can be NoneType
        elif statement.HasField('for_stmt'):

            result += self.visit_for_stmt(statement.for_stmt,
                                          available_vars, func_params, nesting_level)
        elif statement.HasField('if_stmt'):

            result += self.visit_if_stmt(statement.if_stmt,
                                         available_vars, func_params, nesting_level)
        else:

            result += self.visit_assignment_statement(
                statement.assignment, available_vars, func_params)
        return result

    def visit_assignment_statement(self, assign, available_vars, func_params):
        var_ref, var_ref_type = self.visit_var_ref(
            assign.ref_id, available_vars, func_params, is_assign=True)
        
        if var_ref is None :
            return ""  # JUST RETURN EMPTY LINE

        result = var_ref + " = "

        tmp_res, _ = self.visit_expression(assign.expr,
                                           available_vars, [var_ref_type], 1)
        result += tmp_res

        return result

    def visit_if_stmt_case(self, ifstmtcase, available_vars, func_params, nesting_level):

        result, _ = self.visit_expression(
            ifstmtcase.cond, available_vars, [Type.BOOL], 1)
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
                ifstmt.cases[0], available_vars.copy(), func_params, nesting_level)

        for case_num in range(1, branches):
            result += get_spaces(nesting_level) + "elif "
            result += self.visit_if_stmt_case(
                ifstmt.cases[case_num], available_vars.copy(), func_params, nesting_level)

        if ifstmt.HasField("else_case"):
            result += get_spaces(nesting_level) + "else:\n"
            result += self.visit_block(ifstmt.else_case,
                                       available_vars.copy(), func_params, nesting_level + 1)

        return result

    def visit_for_stmt_range(self, for_stmt_range):
        start = for_stmt_range.start
        stop = for_stmt_range.stop
        if start > stop:
            start, stop = stop, start
        result = f"range({start},{stop}):\n"
        return result

    def visit_for_stmt_var(self, for_stmt_var, available_vars):
        length = for_stmt_var.length
        if for_stmt_var.HasField("ref_id"):
            # gets bool if no ints :(
            var, var_typ = self.visit_var_ref(
                for_stmt_var.ref_id, available_vars, needed_type=Type.INT)
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

        loop_var = f"x_INT_{idx}"
        result = f"for {loop_var} in "

        if forstmt.HasField("variable"):
            result += self.visit_for_stmt_var(forstmt.variable,
                                              available_vars)
        else:
            result += self.visit_for_stmt_range(forstmt.ranged)

        result += self.visit_block(forstmt.body,
                                   available_vars, func_params, nesting_level + 1)

        return result
