from types_d import Int, Bool, Decimal, BytesM, String, Address, Bytes

from utils import convert
from utils import get_spaces, get_nearest_multiple
from utils import get_random_element
from utils import checksum_encode, fill_address, check_type_requirements
from config import MAX_NESTING_LEVEL, MAX_EXPRESSION_LEVEL, MAX_FUNCTION_INPUT, MAX_FUNCTIONS
from config import MAX_FUNCTION_OUTPUT, MAX_STORAGE_VARIABLES, MAX_LOCAL_VARIABLES


from vyperProto_pb2 import Contract, Func, FuncParam, Reentrancy,  Block, Statement
# from vyperProto_pb2 import VarDecl, AssignmentStatement, Expression
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

        self.nesting_level = 0  # 

        self.current_declared_variable = None

    def get_func_idx(self):
        return self.func_count

    def visit(self):

        variable_counter = 0
        for variable in self.contract.decls:
            if variable_counter == MAX_STORAGE_VARIABLES:
                break
            variable_counter += 1

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
        n = int.n % 256 + 1
        n = get_nearest_multiple(n, 8)
        int_type = Int(n, int.sign)

        return int_type

    def visit_bool(self):
        b = Bool()
        return b

    def visit_decimal(self):
        d = Decimal()
        return d

    def visit_bytes_m(self, bytesM):
        m = bytesM.m % 32 + 1
        bm = BytesM(m)

        return bm

    def visit_string(self, string):
        l = string.max_len  # TO-DO: max_len is uint64, but len of String can be up to MAX_UINT256
        s = String(l)

        return s

    def visit_type(self, instance):
        if instance.HasField("b"):
            current_type = self.visit_bool()
        elif instance.HasField("d"):
            current_type = self.visit_decimal()
        elif instance.HasField("bM"):
            current_type = self.visit_bytes_m(instance.bM)
        elif instance.HasField("s"):
            current_type = self.visit_string(instance.s)
        elif instance.HasField("adr"):
            current_type = self.visit_address()
        elif instance.HasField("barr"):
            current_type = self.visit_byte_array(instance.barr.max_len)
        else:
            current_type = self.visit_int(instance.i)

        return current_type

    def visit_address(self):
        addr = Address()
        return addr

    def visit_byte_array(self, max_len):
        b_arr = Bytes(max_len)
        return b_arr

    def visit_reentrancy(self, ret):
        result = "@nonreentrant(\"" + ret.key + "\")"
        return result

    def visit_var_decl(self, variable, available_vars, is_global=False):
        current_type = self.visit_type(variable)

        idx = available_vars.get(current_type.name, 0)
        available_vars[current_type.name] = idx + 1

        result = 'x_' + current_type.name + "_" + str(idx) + " : " + current_type.vyper_type
        self.current_declared_variable = 'x_' + \
            current_type.name + "_" + str(idx)

        if not is_global:
            result += " = "

            tmp_res, _, is_literal = self.visit_expression(variable.expr,
                                                           available_vars, [current_type], 1)
            # converted_res = convert(tmp_res, tmp_vyper_type, vyper_type, is_literal)
            result += tmp_res
        return result

    def visit_expression(self, expr, available_vars, needed_types, expr_level, length=None):
        if expr.HasField("cons"):

            # make inside literal converter checking for type
            result, current_type = self.visit_literal(expr.cons)

            result, current_type, is_literal = check_type_requirements(result, current_type, needed_types)

        elif expr_level == MAX_EXPRESSION_LEVEL:
            current_type = get_random_element(needed_types)
            result = current_type.generate()
            result = str(result)

            is_literal = True

        elif expr.HasField("binop"):
            (result, current_type, _) = self.visit_bin_op(
                expr.binop, available_vars, expr_level)

            result, current_type, is_literal = check_type_requirements(result, current_type, needed_types)

        elif expr.HasField("unop"):

            (result, current_type, _) = self.visit_unary_op(
                expr.unop, available_vars, expr_level)

            result, current_type, is_literal = check_type_requirements(result, current_type, needed_types)

        elif expr.HasField("cr_min_proxy"):
            result = self.visit_create_min_proxy(expr.cr_min_proxy, available_vars)
            current_type = Address()

            result, current_type, is_literal = check_type_requirements(result, current_type, needed_types)

        elif expr.HasField('cr_bp'):
            result = self.visit_create_from_blueprint(expr.cr_bp, available_vars)
            current_type = Address()

            result, current_type, is_literal = check_type_requirements(result, current_type, needed_types)

        elif expr.HasField('sha'):
            result = self.visit_sha256(expr.sha, available_vars)
            current_type = BytesM()

            result, current_type, is_literal = check_type_requirements(result, current_type, needed_types)
        else:
            result, current_type, _ = self.visit_var_ref(
                expr.varref, available_vars)

            result, current_type, is_literal = check_type_requirements(result, current_type, needed_types)

            """
            # should fix if oneof is null
            # if random does not account for type size
            current_type = get_random_element(needed_types)
            result = str(get_random_token(current_type))
            """
        return result, current_type, is_literal

    def visit_var_ref(self, var_ref, available_vars, func_params=None, is_assign=False, needed_type = None):
        assert is_assign == (func_params is not None)  # EXPLAINED:  if var ref is not used as assigned var then func_params not needed

        result = ''

        if var_ref.HasField('adr'):
            current_type = Address()
        elif var_ref.HasField('barr'):
            current_type = Bytes(2**256 - 1)
        elif var_ref.HasField('b'):
            current_type = Bool()
        elif var_ref.HasField('d'):
            current_type = Decimal()
        elif var_ref.HasField('bM'):
            current_type = BytesM()
        elif var_ref.HasField('s'):
            current_type = String(2**256 - 1)
        else:
            current_type = Int()

        global_vars_type_max_idx = -1
        if current_type.name in self.global_vars:
            global_vars_type_max_idx = self.global_vars[current_type.name] - 1

        available_vars_type_max_idx = -1
        if current_type.name in available_vars:
            available_vars_type_max_idx = available_vars[current_type.name] - 1

        func_param_type_max_idx = -1
        if func_params:
            if current_type.name in func_params:
                func_param_type_max_idx = func_params[current_type.name] - 1

        idx = -1

        if available_vars_type_max_idx >= 0:
            idx = var_ref.varnum % (available_vars_type_max_idx + 1)
        else:
            if is_assign:
                return None, current_type, current_type.vyper_type
            else:
                result = current_type.generate()
                return str(result), current_type, current_type.vyper_type

        if not is_assign:  # TO-DO: refactor this if - statement
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
            result = current_type.generate()
            return str(result), current_type, current_type.vyper_type

        result += current_type.name + "_" + str(idx)

        return result, current_type, current_type.vyper_type

    def visit_bin_op(self, binop, available_vars, expr_level):
        op_type = None

        if binop.op == BinaryOp.BOp.ADD:
            needed_types = [Int(), Decimal()]
            symbol = "+"

        elif binop.op == BinaryOp.BOp.SUB:
            needed_types = [Int(), Decimal()]
            symbol = "-"

        elif binop.op == BinaryOp.BOp.DIV:
            needed_types = [Int(), Decimal()]
            symbol = "/"

        elif binop.op == BinaryOp.BOp.MOD:
            needed_types = [Int(), Decimal()]
            symbol = "%"

        elif binop.op == BinaryOp.BOp.EXP:
            needed_types = [Int(), Decimal()]
            symbol = "**"

        elif binop.op == BinaryOp.BOp.AND:
            op_type = Bool()

            needed_types = [op_type]
            symbol = "and"

        elif binop.op == BinaryOp.BOp.OR:
            op_type = Bool()

            needed_types = [op_type]
            symbol = "or"

        elif binop.op == BinaryOp.BOp.EQ:
            op_type = Bool()

            needed_types = [Int(), Bool(),
                            Decimal(), Address(), Bytes(100)]
            symbol = "=="

        elif binop.op == BinaryOp.BOp.INEQ:
            op_type = Bool()

            needed_types = [Int(), Bool(),
                            Decimal(), Address(), Bytes(100)]
            symbol = "!="

        elif binop.op == BinaryOp.BOp.LESS:
            op_type = Bool()

            needed_types = [Int(), Bool(), Decimal()]
            symbol = "<"

        elif binop.op == BinaryOp.BOp.LESSEQ:
            op_type = Bool()

            needed_types = [Int(), Bool(), Decimal()]
            symbol = "<="

        elif binop.op == BinaryOp.BOp.GREATER:
            op_type = Bool()

            needed_types = [Int(), Bool(), Decimal()]
            symbol = ">"

        elif binop.op == BinaryOp.BOp.GREATEREQ:
            op_type = Bool()

            needed_types = [Int(), Bool(), Decimal()]
            symbol = ">="

        elif binop.op == BinaryOp.BOp.BIT_AND:
            needed_types = [Int()]
            symbol = "&"

        elif binop.op == BinaryOp.BOp.BIT_OR:
            needed_types = [Int()]
            symbol = "|"

        elif binop.op == BinaryOp.BOp.BIT_XOR:
            needed_types = [Int()]
            symbol = "^"

        elif binop.op == BinaryOp.BOp.LEFT_SHIFT:
            needed_types = [Int()]
            symbol = "<<"

        else:
            needed_types = [Int()]
            symbol = ">>"

        left_expr, left_type, _ = self.visit_expression(binop.left, available_vars,
                                                        needed_types, expr_level + 1)
        if op_type is None:
            op_type = left_type  # EXPLAINED: expression type is based on type of left expression

        right_expr, right_type, right_is_literal = self.visit_expression(binop.right, available_vars,
                                                                         needed_types, expr_level + 1)

        result = "( " + left_expr + f" {symbol} "
        # if left_type != right_type:  # check here for conversion !
        #     result, tmp_vyper_type = get_random_token(left_type)
        #     result += str(result)
        # else:
        #     result += right_expr
        if left_type.vyper_type != right_type.vyper_type:
            converted_right_expr = convert(right_expr, right_type.vyper_type, left_type.vyper_type, right_is_literal)
            if converted_right_expr is not None:
                result += converted_right_expr
        result += " )"

        return result, op_type, op_type.vyper_type

    def visit_unary_op(self, unop, available_vars, expr_level: int):

        symbol = ''
        needed_types = [None]
        op_type = None

        if unop.op == UnaryOp.UOp.NOT:

            needed_types = [Bool()]
            symbol = "not "
        elif unop.op == UnaryOp.UOp.MINUS:

            needed_types = [Int(), Decimal()]
            symbol = "-"
        elif unop.op == UnaryOp.UOp.BALANCE:

            needed_types = [Address()]
            op_type = Int()
            symbol = "balance"
        elif unop.op == UnaryOp.UOp.CODEHASH:

            needed_types = [Address()]
            op_type = BytesM()
            symbol = "codehash"
        elif unop.op == UnaryOp.UOp.CODESIZE:

            needed_types = [Address()]
            op_type = Int()
            symbol = "codesize"
        elif unop.op == UnaryOp.UOp.IS_CONTRACT:

            needed_types = [Address()]
            op_type = Bool()
            symbol = "is_contract"
        elif unop.op == UnaryOp.UOp.CODE:

            needed_types = [Address()]
            op_type = Bytes(2**256 - 1)
            symbol = "code"
        elif unop.op == UnaryOp.UOp.BIT_NOT:

            needed_types = [Int()]
            symbol = "~"

        # generates 0x0...0.symbol which is wrong
        tmp_res, tmp_type, _ = self.visit_expression(unop.expr, available_vars,
                                                     needed_types, expr_level + 1)

        # if current_type == Address() and len(tmp_res) == 42:
        #     # in outer visit_expression will gen random value due to
        #     # tmp_type not in needed_types:
        #     current_type = None

        if op_type is None:  # TO-DO: add assert statement which check op_type == None -> vyper_type == None, op_type != None -> vyper_type != None
            op_type = tmp_type

        if Address() in needed_types:
            result = "( " + tmp_res + "." + symbol + " )"
        else:
            result = "( " + symbol + " " + tmp_res + " )"

        return result, op_type, op_type.vyper_type

    def visit_literal(self, literal):
        if literal.HasField("addval"):

            adr = str(hex(literal.addval))[:42]  # TO-DO: check if first characters are 0x
            result = checksum_encode(fill_address(adr))
            cur_type = Address()
        elif literal.HasField("barrval"):

            hex_val = hex(literal.barrval)
            hex_val = f"{'' if len(hex_val) % 2 == 0 else '0'}{hex_val}"
            result = f"b\"{hex_val}\""
            cur_type = Bytes(len(hex_val) // 2)
        elif literal.HasField("boolval"):

            result = str(literal.boolval)
            cur_type = Bool()
        elif literal.HasField("decimalval"):

            result = str(literal.decimalval / 10**10)
            cur_type = Decimal()
        elif literal.HasField("bMval"):

            hex_val = literal.bMval.hex()[:64]
            hex_val = f"{'' if len(hex_val) % 2 == 0 else '0'}{hex_val}"
            if len(hex_val) == 0:
                hex_val = "00"
            result = "0x" + hex_val
            cur_type = BytesM(len(hex_val) // 2)
        elif literal.HasField("strval"):

            result = literal.strval  # TO-DO: check maximal len of string in proto and vyper
            cur_type = String(len(result))
        else:
            result = str(literal.intval)
            cur_type = Int()

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
        # at least 0.3.9
        if function.HasField("ret") and function.mut != Func.Mutability.PURE:
            result += self.visit_reentrancy(function.ret)

            result += '\n'

        result += "def func_" + str(idx) + "("

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
        current_type = self.visit_type(param)

        idx = available_vars.get(current_type.name, 0)
        available_vars[current_type.name] = idx + 1

        func_params[current_type.name] = available_vars[current_type.name]  # TO-DO check if this holds in every case

        result = 'x_' + current_type.name + "_" + str(idx)
        result += " : " + current_type.vyper_type

        # if self.param.HasField('loc'):
        #     if self.param.loc == FuncParam.MEMORY:
        #         self.result += "memory"
        #     elif self.param.loc == FuncParam.CALLDATA:
        #         self.result += "calldata"

        #     self.result += " "

        return result

    def visit_func_output(self, param):
        current_type = self.visit_type(param)
        return current_type.vyper_type

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
                                          available_vars)
            self.current_declared_variable = None
        # can be NoneType
        elif statement.HasField('for_stmt'):

            result += self.visit_for_stmt(statement.for_stmt,
                                          available_vars, func_params, nesting_level)
        elif statement.HasField('if_stmt'):

            result += self.visit_if_stmt(statement.if_stmt,
                                         available_vars, func_params, nesting_level)
        elif statement.HasField('selfd'):
            result += self.visit_selfdestruct(statement.selfd, available_vars)
        else:

            result += self.visit_assignment_statement(
                statement.assignment, available_vars, func_params)
        return result

    def visit_assignment_statement(self, assign, available_vars, func_params):
        var_ref, var_ref_type, var_ref_vyper_type = self.visit_var_ref(
            assign.ref_id, available_vars, func_params, is_assign=True)

        if var_ref is None :
            return ""  # EXPLAINED: just return empty line if there is no variable to assign to

        result = var_ref + " = "

        tmp_res, _, tmp_is_literal = self.visit_expression(assign.expr,
                                                           available_vars, [var_ref_type], 1)
        # converted_tmp_res = convert(tmp_res, tmp_vyper_type, var_ref_vyper_type, tmp_is_literal)
        result += tmp_res

        return result

    def visit_if_stmt_case(self, ifstmtcase, available_vars, func_params, nesting_level):

        result, _, _ = self.visit_expression(ifstmtcase.cond, available_vars, [Bool()], 1)
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
        result = f"range({start},{stop + 1}):\n"
        return result

    def visit_for_stmt_var(self, for_stmt_var, available_vars):
        length = for_stmt_var.length
        if for_stmt_var.HasField("ref_id"):
            # gets bool if no ints :(
            var, var_typ, var_vyper_type = self.visit_var_ref(
                for_stmt_var.ref_id, available_vars, needed_type=Int())
            result = f"range({var},{var}+{length}):\n"
        else:
            result = f"range({length}):\n"

        return result

    def visit_for_stmt(self, forstmt, available_vars, func_params, nesting_level):
        # local vars
        idx = 0

        range_string = ''
        # cannot have iterator in range()
        if forstmt.HasField("variable"):
            range_string += self.visit_for_stmt_var(forstmt.variable,
                                                    available_vars)
        else:
            range_string += self.visit_for_stmt_range(forstmt.ranged)

        int_type = Int()
        idx = available_vars.get(int_type.name, 0)
        available_vars[int_type.name] = idx + 1

        func_params.setdefault(int_type.name, 0)
        func_params[int_type.name] += 1

        loop_var = f"x_INT_{idx}"
        result = f"for {loop_var} in " + range_string

        result += self.visit_block(forstmt.body,
                                   available_vars, func_params, nesting_level + 1)

        return result

    def visit_create_min_proxy(self, cmp, available_vars):
        result = 'create_minimal_proxy_to('

        target_res, _, _ = self.visit_expression(
            cmp.target, available_vars, [Address()], 1)

        result += target_res

        if cmp.HasField("value"):
            value_res, _, _ = self.visit_expression(
                cmp.value, available_vars, [Int()], 1)
            result += ', value=' + value_res
        if cmp.HasField("salt"):
            salt_res, _, _ = self.visit_expression(
                cmp.salt, available_vars, [BytesM(32)], 1)
            result += ', salt=' + salt_res

        result += ')'

        return result

    def visit_create_from_blueprint(self, cfb, available_vars):
        result = 'create_from_blueprint('

        target_res, _, _ = self.visit_expression(
            cfb.target, available_vars, [Address()], 1)

        result += target_res

        for arg in cfb.args:
            type_list = [Int(), Bool(), Decimal(), BytesM(), String(100), Address(), Bytes(100)]
            arg_r, arg_t, _ = self.visit_expression(
                arg, available_vars, type_list, 1)
            result += ',' + arg_r

        if cfb.HasField("value"):
            value_res, _, _ = self.visit_expression(
                cfb.value, available_vars, [Int()], 1)
            result += ', value=' + value_res
        if cfb.HasField("code_offset"):
            value_res, _, _ = self.visit_expression(
                cfb.value, available_vars, [Int()], 1)
            result += ', code_offset=' + value_res
        if cfb.HasField("salt"):
            salt_res, _, _ = self.visit_expression(
                cfb.salt, available_vars, [BytesM()], 1)
            result += ', salt=' + salt_res

        result += ')'

        return result

    def visit_selfdestruct(self, sd, available_vars):

        result = "selfdestruct("

        to_res, _, _ = self.visit_expression(sd.to, available_vars, [Address()], 1)

        result += to_res + ")"

        return result

    def visit_sha256(self, sha, available_vars):

        result = "sha256("

        # FIXME: a random length of bytes array must be here
        # FIXME: as well as String
        # FIXME: And BytesM :)
        to_res, _, _ = self.visit_expression(sha.value, available_vars, [Bytes(100), String(100), BytesM()], 1)

        result += to_res + ")"

        return result
