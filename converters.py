from enum import Enum

from utils import get_spaces, get_nearest_multiple

from vyperProto_pb2 import Contract, Func, FuncParam, Reentrancy,  Block, Statement
from vyperProto_pb2 import VarDecl, AssignmentStatement, Expression, Int, Bool
from vyperProto_pb2 import VarRef, Literal, BinaryOp, UnaryOp


class Type(Enum):
    INT = 0
    BOOL = 1

class Converter:

    def __init__(self) -> None:
        self.result = ""

    def visit(self):
        pass

class LiteralConverter(Converter):

    def __init__(self, literal: Literal) -> None:
        super().__init__()

        self.literal = literal

    def visit(self):  # check here type of variable, or maybe check this during assinging
        if self.literal.HasField("intval"):
            self.result = str(self.literal.intval)
        elif self.literal.HasField("strval"):
            self.result = self.literal.strval
        elif self.literal.HasField("boolval"):
            self.result = str(self.literal.boolval)  # TO-DO check format of str(bool), uppercase 

        return self.result

class BinOpConverter(Converter):

    def __init__(self, binop: BinaryOp) -> None:
        super().__init__()

        self.binop = binop

    def visit():
        return ""

class UnaryOpConverter(Converter):

    def __init__(self, unop: UnaryOp) -> None:
        super().__init__()

        self.unop = unop

    def visit(self):
        if self.unop.op == UnaryOp.UOp.NOT:
            self.result = "not "
        elif self.unop.op == UnaryOp.UOp.Minus:
            self.result = "-"
        elif self.unop.op == UnaryOp.Uop.BIT_NOT:
            self.result = "~"
        
        expr = ExpressionConverter(self.unop.expr)
        self.result += expr.visit()

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


class ExpressionConverter(Converter):  # TO-DO maybe store here type of variable ?

    def __init__(self, expr: Expression) -> None:
        super().__init__()

        self.expr = expr

    def visit(self):
        if self.expr.HasField("varref"):
            pass 
        elif self.expr.HasField("cons"):

            literal = LiteralConverter(self.expr.cons)
            self.result = literal.visit()

        elif self.expr.HasField("binop"):

            binop = BinOpConverter(self.expr.binop)
            self.result = binop.visit()

        elif self.expr.HasField("unop"):

            uniop = UnaryOpConverter(self.expr.unop)
            self.result = uniop.visit()
        
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

        if self.variable.HasField("i"):

            int = IntConverter(self.variable.i)

            vyper_type += int.visit()
            self.type = Type.INT

        elif self.variable.HasField("b"):

            bool = BoolConverter(self.variable.b)

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

        if self.variable.HasField("i"):

            int = IntConverter(self.variable.i)

            vyper_type += int.visit()
            self.type = Type.INT

        elif self.variable.HasField("b"):

            bool = BoolConverter(self.variable.b)

            vyper_type += bool.visit()
            self.type = Type.BOOL
        
        self.result = vyper_type

        return self.result


class VarRefConverter(Converter):

    def __init__(self, var_ref: VarRef, global_vars, available_vars, func_params, is_assign=False) -> None:
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
        if self.type in self.func_params:
            func_param_type_max_idx = self.func_params[self.type] - 1

        idx = self.var_ref.varnum % (available_vars_type_max_idx + 1)

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

        expr = ExpressionConverter(self.assign.expr)
        self.result += expr.visit()

        return self.result

class StatementConverter(Converter):

    def __init__(self, statement: Statement, global_vars, available_vars, func_params) -> None:
        super().__init__()

        self.statement = statement

        self.global_vars = global_vars
        self.available_vars = available_vars.copy()
        self.func_params = func_params

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
            statement_converter = StatementConverter(statement, self.global_vars, self.available_vars, self.func_params)
            
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

        for input_param in self.function.input_params:
            param_converter = FuncParamConverter(input_param, self.available_vars)

            self.result += param_converter.visit() + ", "
        
        self.result = self.result[:-2] + ")"

        if len(self.function.output_params) != 0:
            
            self.result += " -> ("

            for output_param in self.function.output_params:
                param_converter = FuncParamConverter(output_param)

                self.result += param_converter.visit() + ", "
            
            self.result = self.result[:-2] + ")"
        
        self.result += ":" + "\n"

        block_converter = BlockConverter(self.function.block, self.global_vars, self.available_vars, self.func_params, self.nesting_level)
        self.result += block_converter.visit()

        return self.result

class VarDeclConverter(Converter):

    def __init__(self, variable: VarDecl, available_vars, is_global=False):
        super().__init__()

        self.variable = variable
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

            bool = BoolConverter(self.variable.b)

            vyper_type += bool.visit()
            self.type = Type.BOOL
    
        if self.type not in self.available_vars:
            self.available_vars[self.type] = 1
        else: 
            idx = self.available_vars[self.type]
            self.available_vars += 1
        
        self.result = 'x_' + self.type.name + "_" +str(idx) + " : " + vyper_type

        if not self.is_global:
            self.result += " = "

            expr = ExpressionConverter(self.variable.expr)
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
        for variable in self.contract.decls:

            variable_converter = VarDeclConverter(variable, self.global_vars, is_global=True)
            
            res = variable_converter.visit()
            self.result += res + '\n'

        for function in self.contract.functions:

            function_converter = FuncConverter(self, function, self.nesting_level + 1)
            self.result += function_converter.visit() + '\n'

            self.func_count += 1