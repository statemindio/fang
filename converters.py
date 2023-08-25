from data_types import Type

from utils import get_spaces, get_nearest_multiple
from utils import get_random_token, get_random_element

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

class LiteralConverter(Converter):

    def __init__(self, literal: Literal) -> None:
        super().__init__()

        self.literal = literal
        self.type = None

    def visit(self):
        if self.literal.HasField("intval"):

            self.result = str(self.literal.intval)
            self.type = Type.INT

        elif self.literal.HasField("boolval"):

            self.result = str(self.literal.boolval)  # TO-DO check format of str(bool), uppercase 
            self.type = Type.BOOL

        return self.result

class BinOpConverter(Converter):

    def __init__(self, binop: BinaryOp, global_vars, available_vars, base_expr_level) -> None:
        super().__init__()

        self.binop = binop

        self.global_vars = global_vars
        self.available_vars = available_vars

        self.type = None
        self.base_expr_level = base_expr_level

    def visit(self):
        symbol = ""

        if self.binop.op == BinaryOp.BOp.ADD :
            needed_types = [Type.INT]  # ADD can have multiple types
            symbol = "+"
        
        elif self.binop.op == BinaryOp.BOp.SUB :
            needed_types = [Type.INT]  
            symbol = "-"

        elif self.binop.op == BinaryOp.BOp.DIV :
            needed_types = [Type.INT]  
            symbol = "/"

        elif self.binop.op == BinaryOp.BOp.MOD :
            needed_types = [Type.INT]  
            symbol = "%"

        elif self.binop.op == BinaryOp.BOp.EXP :
            needed_types = [Type.INT]  # ADD can have multiple types
            symbol = "**"
        
        elif self.binop.op == BinaryOp.BOp.AND :
            self.type = Type.BOOL

            needed_types = [Type.BOOL]  # ADD can have multiple types
            symbol = "and"
        
        elif self.binop.op == BinaryOp.BOp.OR :
            self.type = Type.BOOL

            needed_types = [Type.BOOL]  # ADD can have multiple types
            symbol = "or"
        
        elif self.binop.op == BinaryOp.BOp.EQ:
            self.type = Type.BOOL

            needed_types = [Type.INT, Type.BOOL]
            symbol = "=="

        elif self.binop.op == BinaryOp.BOp.INEQ:
            self.type = Type.BOOL

            needed_types = [Type.INT, Type.BOOL]
            symbol = "!="
        
        elif self.binop.op == BinaryOp.BOp.LESS:
            self.type = Type.BOOL

            needed_types = [Type.INT, Type.BOOL]
            symbol = "<"

        elif self.binop.op == BinaryOp.BOp.LESSEQ:
            self.type = Type.BOOL

            needed_types = [Type.INT, Type.BOOL]
            symbol = "<="
        
        elif self.binop.op == BinaryOp.BOp.GREATER:
            self.type = Type.BOOL

            needed_types = [Type.INT, Type.BOOL]
            symbol = ">"
        
        elif self.binop.op == BinaryOp.BOp.GREATEREQ:
            self.type = Type.BOOL

            needed_types = [Type.INT, Type.BOOL]
            symbol = ">="
        
        elif self.binop.op == BinaryOp.BOp.BIT_AND: # CHECK IMPLEMENTATION FOR OTHER TYPES
            needed_types = [Type.INT]  
            symbol = "&"
        
        elif self.binop.op == BinaryOp.BOp.BIT_OR: # CHECK IMPLEMENTATION FOR OTHER TYPES
            needed_types = [Type.INT]  
            symbol = "|"
        
        elif self.binop.op == BinaryOp.BOp.BIT_XOR: # CHECK IMPLEMENTATION FOR OTHER TYPES
            needed_types = [Type.INT]  
            symbol = "^"
        
        elif self.binop.op == BinaryOp.BOp.LEFT_SHIFT: # CHECK IMPLEMENTATION FOR OTHER TYPES
            needed_types = [Type.INT]  
            symbol = "<<"
        
        elif self.binop.op == BinaryOp.BOp.RIGHT_SHIFT: # CHECK IMPLEMENTATION FOR OTHER TYPES
            needed_types = [Type.INT]  
            symbol = ">>"

        left_expr = ExpressionConverter(self.binop.op.left, needed_types, self.global_vars, self.available_vars, self.base_expr_level + 1)
        if self.type == None:
            self.type = left_expr.type  # EXPRESSION TYPE IS BASED ON LEFT EXPRESSION, WE CAN COMPARE WITH PARENT TYPE OR LEFT IT AS IT IS 

        right_expr = ExpressionConverter(self.binop.op.right, needed_types, self.global_vars, self.available_vars, self.base_expr_level + 1)

        self.result = "( " + left_expr.visit() + f" {symbol} "
        if left_expr.type != right_expr.type:  # check here for conversion !
            self.result += "dictionaryToken()"  # CHANGE dictionary token to random value
        else:
            self.result += right_expr.visit()
        self.result += " )"

        return self.result


class UnaryOpConverter(Converter):

    def __init__(self, unop: UnaryOp, global_vars, available_vars, base_expr_level) -> None:
        super().__init__()

        self.unop = unop

        self.global_vars = global_vars
        self.available_vars = available_vars.copy() # CHECK IF SHOULD COPY, BECAUSE IT SHOULD BE READ-ONLY

        self.type = None
        self.base_expr_level = base_expr_level

    def visit(self):
        if self.unop.op == UnaryOp.UOp.NOT:
            needed_types = [Type.BOOL]
            symbol = "not"  # CHECK MAYBE ADD BRACKETS

        elif self.unop.op == UnaryOp.UOp.Minus:
            needed_types = [Type.INT]
            symbol = "-"

        elif self.unop.op == UnaryOp.Uop.BIT_NOT:
            needed_types = [Type.INT]
            symbol = "~"
        
        expr = ExpressionConverter(self.unop.op, needed_types, self.global_vars, self.available_vars, self.base_expr_level + 1)
        if self.type == None:
            self.type = expr.type

        self.result = "( " + symbol + " " + expr.visit() + " )"

        return self.result
        

class BoolConverter(Converter):

    def __init__(self):
        super().__init__()

    def visit(self):
        self.result = "bool"

        return self.result


class IntConverter(Converter):

    def __init__(self, int: Int):
        super().__init__()

        self.int = int

    def visit(self):
        if self.int.sign:
            self.result = "int"
        else:
            self.result = "uint"

        n = self.int.n % 256 + 1
        n = get_nearest_multiple(n, 8)

        self.result += str(n)

        return self.result


class ExpressionConverter(Converter):

    def __init__(self, expr: Expression, needed_types: [Type], global_vars, available_vars, expr_level) -> None:
        super().__init__()

        self.expr = expr
        self.needed_types = needed_types
        self.type = None

        self.global_vars = global_vars
        self.available_vars = available_vars.copy()  # CHECK IF SHOULD COPY, BECAUSE IT SHOULD BE READ-ONLY

        self.expr_level = expr_level

    def visit(self):
        if self.expr.HasField("varref"):

            var_c = VarRefConverter(self.expr.varref, self.global_vars, self.available_vars)
            tmp_res = var_c.visit()

            if var_c.type not in self.needed_types:  # we should call visit, because type is set during visit()

                self.type = get_random_element(self.needed_types)  # RANDOMLY CHOOSE TYPE, BUT WE CAN CHOOSE FIRST ELEMENT or etc
                return str(get_random_token(self.type))  #  think about conversions and vyper_type
            else:

                self.type = var_c.type
                self.result = tmp_res

                return self.result

        elif self.expr.HasField("cons"):

            literal_c = LiteralConverter(self.expr.cons)  # make inside literal converter checking for type
            tmp_res = literal_c.visit()

            if literal_c.type not in self.needed_types:
                
                self.type = get_random_element(self.needed_types)  # RANDOMLY CHOOSE TYPE, BUT WE CAN CHOOSE FIRST ELEMENT or etc
                return str(get_random_token(self.type))
            else:

                self.type = literal_c.type
                self.result = tmp_res
                return self.result
            
        elif self.expr_level == MAX_EXPRESSION_LEVEL:

            self.type = get_random_element(self.needed_types)  # RANDOMLY CHOOSE TYPE, BUT WE CAN CHOOSE FIRST ELEMENT or etc
            return str(get_random_token(self.type))
        
        elif self.expr.HasField("binop"):
            
            binop_c = BinOpConverter(self.expr.binop, self.global_vars, self.available_vars, self.expr_level)
            tmp_res = binop_c.visit()

            if binop_c.type not in self.needed_types:

                self.type = get_random_element(self.needed_types)  # RANDOMLY CHOOSE TYPE, BUT WE CAN CHOOSE FIRST ELEMENT or etc
                return str(get_random_token(self.type))
            else:
                self.type = binop_c.type
                self.result = tmp_res
            
                return self.result
        
        elif self.expr.HasField("unop"):

            unop_c = UnaryOpConverter(self.expr.unop, self.global_vars, self.available_vars, self.expr_level)
            tmp_res = unop_c.visit()

            if unop_c.type not in self.needed_types:

                self.type = get_random_element(self.needed_types)  # RANDOMLY CHOOSE TYPE, BUT WE CAN CHOOSE FIRST ELEMENT or etc
                return get_random_token(self.type)
            else:
                self.type = unop_c.type
                self.result = tmp_res

                return self.result

        return self.result


class ReentrancyConverter(Converter):

    def __init__(self, ret: Reentrancy) -> None:
        super().__init__()

        self.ret = ret

    def visit(self):
        self.result = "@nonreentrant(\"" + self.ret.key + "\")"

        return self.result
    
class FuncParamConverter(Converter):

    def __init__(self, param: FuncParam, available_vars=None, func_params=None) -> None:
        super().__init__()

        self.param = param

        self.available_vars = available_vars  # if available_vars is None, then it is output param 
        self.func_params = func_params  # if available_vars == None, then func_params should be None
    
    def visit(self):
        if self.available_vars:
            return self.visit_input()
        else:
            return self.visit_output()

    def visit_input(self):  # refactor to avoid code duplication with VarDecl
        vyper_type = ""
        idx = 0

        if self.param.HasField("i"):

            int = IntConverter(self.param.i)

            vyper_type += int.visit()
            self.type = Type.INT

        elif self.param.HasField("b"):

            bool = BoolConverter()

            vyper_type += bool.visit()
            self.type = Type.BOOL

        if self.type not in self.available_vars:
            self.available_vars[self.type] = 1
            # self.func_params[self.type] = 1
        else: 
            idx = self.available_vars[self.type]
            self.available_vars[self.type] += 1

        self.func_params[self.type] = self.available_vars[self.type]  # CHECK IF THIS HOLDS IN EVERY CASE

        self.result = 'x_' + self.type.name + "_" + str(idx)
        self.result += " : " + vyper_type

        # if self.param.HasField('loc'):
        #     if self.param.loc == FuncParam.MEMORY:
        #         self.result += "memory"
        #     elif self.param.loc == FuncParam.CALLDATA:
        #         self.result += "calldata"
            
        #     self.result += " "

        return self.result

    def visit_output(self):
        vyper_type = ""

        if self.param.HasField("i"):

            int = IntConverter(self.param.i)

            vyper_type += int.visit()
            self.type = Type.INT

        elif self.param.HasField("b"):

            bool = BoolConverter()

            vyper_type += bool.visit()
            self.type = Type.BOOL
        
        self.result = vyper_type

        return self.result


class VarRefConverter(Converter):

    def __init__(self, var_ref: VarRef, global_vars, available_vars, func_params=None, is_assign=False) -> None:
        assert is_assign == (func_params != None)  # if var ref is not used as assigned var then func_params not needed

        super().__init__()

        self.var_ref = var_ref
        self.type = None

        self.global_vars = global_vars
        self.available_vars = available_vars
        self.func_params = func_params

        self.is_assign = is_assign

    def visit(self):
        if self.var_ref.HasField('i'):
            self.type = Type.INT
        elif self.var_ref.HasField('b'):
            self.type = Type.BOOL

        global_vars_type_max_idx = -1
        if self.type in self.global_vars:
            global_vars_type_max_idx = self.global_vars[self.type] - 1
        
        available_vars_type_max_idx = -1
        if self.type in self.available_vars:
            available_vars_type_max_idx = self.available_vars[self.type] - 1

        func_param_type_max_idx = -1
        if self.func_params:
            if self.type in self.func_params:
                func_param_type_max_idx = self.func_params[self.type] - 1

        idx = -1

        if available_vars_type_max_idx >= 0:
            idx = self.var_ref.varnum % (available_vars_type_max_idx + 1)
        else:
            # IF IT IS NOT ASSIGNEMENT VAR REF THEN RETURN LITERAL - CONSTANT, ELSE RETURN NONE AND ADD PROCESSING FOR THIS CASE
            if self.type == Type.INT:
                self.result = "1"
            else:
                self.result = "True"

            return self.result

        if not self.is_assign:  # REFACTOR THIS IF STATEMENT AND CHECK WHAT TO DO IF WE DON'T HAVE ANY FREE VARIABLES
            if idx <= global_vars_type_max_idx:
                self.result = "self.x_"
            else:
                self.result = "x_"
        else:
            if idx <= global_vars_type_max_idx:
                self.result = "self.x_"
            elif idx <= func_param_type_max_idx:

                if available_vars_type_max_idx > func_param_type_max_idx:
                    idx = func_param_type_max_idx + 1
                    self.result = "x_"
            else:
                self.result = "x_"
        
        self.result += self.type.name + "_" + str(idx)

        return self.result


class AssignmentStatementConverter(Converter):

    def __init__(self, assign: AssignmentStatement, global_vars, available_vars, func_params):
        super().__init__()

        self.assign = assign

        self.global_vars = global_vars
        self.available_vars = available_vars  # There is no need to copy because no new variable will created
        self.func_params = func_params

    def visit(self):
        var_ref_converter = VarRefConverter(self.assign.ref_id, self.func_params, is_assign=True)

        self.result = var_ref_converter.visit() + " = "

        needed_types = [var_ref_converter.type]
        expr = ExpressionConverter(self.assign.expr, needed_types, self.global_vars, self.available_vars, 1)
        self.result += expr.visit()

        return self.result

class StatementConverter(Converter):

    def __init__(self, statement: Statement, global_vars, available_vars, func_params, nesting_level) -> None:
        super().__init__()

        self.statement = statement

        self.global_vars = global_vars
        self.available_vars = available_vars.copy()
        self.func_params = func_params

        self.nesting_level = nesting_level  # FOR WHAT NESTING LEVEL ?

    def visit(self):
        if self.statement.HasField('decl'):
            var_decl_converter = VarDeclConverter(self.statement.decl, self.available_vars)

            self.result += var_decl_converter.visit()

        elif self.statement.HasField('assignment'):
            assignment_converter = AssignmentStatementConverter(self.statement.assignment, self.global_vars, self.available_vars, self.func_params)

            self.result += assignment_converter.visit()

        return self.result

class BlockConverter(Converter):     

    def __init__(self, block: Block, global_vars, available_vars, func_params, nesting_level):
        super().__init__()

        self.block = block

        self.global_vars = global_vars
        self.available_vars = available_vars.copy()
        self.func_params = func_params

        self.nesting_level = nesting_level

    
    def visit(self):
        for statement in self.block.statements:
            statement_converter = StatementConverter(statement, self.global_vars, self.available_vars, self.func_params, self.nesting_level)
            
            self.result += get_spaces(self.nesting_level) + statement_converter.visit()

        return self.result



class FuncConverter(Converter):

    def __init__(self, contract: Contract, function: Func, nesting_level):  # we add nesting level in function to add inner functions further 
        super().__init__()

        self.function = function

        self.nesting_level = nesting_level
        self.idx = contract.get_func_idx()

        self.global_vars = contract.global_vars  # DON'T CHANGE THIS VARIABLE, IT IS READ-ONLY. TO WRITE SOMETHING USE self.available_vars
        self.available_vars = contract.global_vars.copy()
        self.func_params = {}


    def visit(self):
        self.result = "@"

        if self.function.vis == Func.Visibility.EXTERNAL:
            self.result += "external"
        elif self.function.vis == Func.Visibility.INTERNAL:
            self.result += "internal"
        
        self.result += "\n"

        if self.function.mut != Func.Mutability.NONPAYABLE:
            self.result += "@"

            if self.function.mut == Func.Mutability.PURE:
                self.result += "pure" 
            elif self.function.mut == Func.Mutability.VIEW:
                self.result += "view"
            elif self.function.mut == Func.Mutability.PAYABLE:
                self.result += "payable"
        
            self.result += "\n"

        if self.function.HasField("ret"):
            ret = ReentrancyConverter(self.function.ret)
            self.result += ret.visit()

            self.result += '\n'

        self.result += "def func_" + str(self.idx) + "("

        # here can be set input length
        # does not add to local vars
        input_counter = 0
        for input_param in self.function.input_params:
            if input_counter == MAX_FUNCTION_INPUT:
                break
            input_counter += 1

            param_converter = FuncParamConverter(input_param, self.available_vars)

            self.result += param_converter.visit() + ", "
        
        if input_counter != 0:
            self.result = self.result[:-2] + ")"

        if len(self.function.output_params) != 0:
            
            self.result += " -> ("

            # can move to utility to not replicate code
            output_counter = 0
            for output_param in self.function.output_params:
                if output_counter == MAX_FUNCTION_OUTPUT:
                    break
                output_counter += 1

                param_converter = FuncParamConverter(output_param)

                self.result += param_converter.visit() + ", "
            
            self.result = self.result[:-2] + ")"
        
        self.result += ":" + "\n"

        block_converter = BlockConverter(self.function.block, self.global_vars, self.available_vars, self.func_params, self.nesting_level)
        self.result += block_converter.visit()

        return self.result

class VarDeclConverter(Converter):

    def __init__(self, variable: VarDecl, global_vars, available_vars, is_global=False):
        super().__init__()

        self.variable = variable

        self.global_vars = global_vars
        self.available_vars = available_vars

        self.type = None
        self.is_global = is_global

    def visit(self):
        vyper_type = ""
        idx = 0

        if self.variable.HasField("i"):

            int = IntConverter(self.variable.i)

            vyper_type += int.visit()
            self.type = Type.INT

        elif self.variable.HasField("b"):

            bool = BoolConverter()

            vyper_type += bool.visit()
            self.type = Type.BOOL
    
        if self.type not in self.available_vars:
            self.available_vars[self.type] = 1
        else: 
            idx = self.available_vars[self.type]
            self.available_vars[self.type] += 1
        
        self.result = 'x_' + self.type.name + "_" +str(idx) + " : " + vyper_type

        if not self.is_global:
            self.result += " = "

            needed_types = [self.type]
            expr = ExpressionConverter(self.variable.expr, needed_types, self.global_vars, self.available_vars, 1)
            self.result += expr.visit()

        return self.result

class ContractConverter(Converter):

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

            variable_converter = VarDeclConverter(variable, self.global_vars, is_global=True)
            
            res = variable_converter.visit()
            self.result += res + '\n'

        function_counter = 0
        for function in self.contract.functions:
            if function_counter == MAX_FUNCTIONS:
                break
            function_counter += 1

            function_converter = FuncConverter(self, function, self.nesting_level + 1)
            self.result += function_converter.visit() + '\n'

            self.func_count += 1


class IfStmtCaseConverter(Converter):

    def __init__(self, ifstmtcase: IfStmtCase, global_vars, available_vars, nesting_level):
        super().__init__()

        self.ifstmtcase = ifstmtcase
        self.nesting_level = nesting_level
        self.global_vars = global_vars
        self.available_vars = available_vars.copy()

    def visit(self):
        needed_types = [Type.BOOL]
        expr = ExpressionConverter(self.variable.expr, needed_types, self.global_vars, self.available_vars, 1)
        self.result += expr.visit()
        self.result += ":\n"
        block = BlockConverter(self.variable.b, self.global_vars, self.available_vars, self.nesting_level + 1)
        self.result += block.visit()
    
        return self.result
    

class IfStmtConverter(Converter):

    def __init__(self, ifstmt: IfStmt, global_vars, available_vars, nesting_level):

        super().__init__()
        self.ifstmt = ifstmt
        self.nesting_level = nesting_level
        self.global_vars = global_vars
        self.available_vars = available_vars.copy()

    def visit(self):

        self.result = get_spaces(self.nesting_level) + "if "
        branches = len(self.ifstmt.cases)
        # add tabbing
        if branches == 0:
            self.result += "False:\n"
            self.result += get_spaces(self.nesting_level) + "    pass\n"
        else:
            ifbody = IfStmtCaseConverter(self.ifstmt.cases[0], self.global_vars, self.available_vars, self.nesting_level)
            self.result += ifbody.visit()
            
        for case_num in range(1, branches):
            self.result += get_spaces(self.nesting_level) + "elif"
            ifbody = IfStmtCaseConverter(self.ifstmt.cases[case_num], self.global_vars, self.available_vars, self.nesting_level)
            self.result += ifbody.visit()
        
        if self.ifstmt.HasField("else_case"):
            self.result += get_spaces(self.nesting_level) + "else:\n"
            block = BlockConverter(self.ifstmt.else_case, contract.global_vars, contract.available_vars, self.nesting_level + 1)
            self.result += block.visit()

        return self.result
    

class ForStmtRangedConverter(Converter):

    def __init__(self, forstmt_range: ForStmtRanged):
        super().__init__()

        self.forstmt_range = forstmt_range
    
    def visit(self):
        start = self.forstmt_range.start
        stop = self.forstmt_range.stop
        if start > stop:
            start, stop = stop, start
        self.result = f"range({start},{stop}):\n"
        return self.result
    

class ForStmtVariableConverter(Converter):

    def __init__(self, forstmt_var: ForStmtVariable, global_vars, available_vars):
        super().__init__()

        self.forstmt_var = forstmt_var
        self.global_vars = global_vars
        self.available_vars = available_vars.copy()

    def visit(self):
        length = self.forstmt_var.length
        if self.forstmt_var.HasField("ref_id"):
            var_c = VarRefConverter(self.forstmt_var.ref_id, self.global_vars, self.available_vars)
            var = var_c.visit()
            self.result = f"range({var},{var}+{length}):\n"
        else:
            self.result = f"range({length}):\n"

        return self.result
    

class ForStmtConverter(Converter):

    def __init__(self, forstmt: ForStmt, available_vars, global_vars, nesting_level):
        super().__init__()

        self.forstmt = forstmt
        self.nesting_level = nesting_level
        self.available_vars = available_vars.copy()
        self.global_vars = global_vars

    def visit(self):
        # local vars 
        if Type.INT not in self.available_vars:
            self.available_vars[Type.INT] = 1
        else: 
            idx = self.available_vars[Type.INT]
            self.available_vars[Type.INT] += 1

        loop_var = f"x_INT_{idx}"
        self.result += get_spaces(self.nesting_level) + f"for {loop_var} in "

        if self.forstmt.HasField("ranged"):
            ranged = ForStmtRangedConverter(self.forstmt.ranged)
            self.result += ranged.visit()
        else:
            variable = ForStmtVariableConverter(self.forstmt.variable, self.global_vars, self.available_vars)
            self.result += variable.visit()

        block = BlockConverter(self.forstmt.body, self.global_vars, self.available_vars, self.nesting_level + 1)
        self.result += block.visit()

        return self.result