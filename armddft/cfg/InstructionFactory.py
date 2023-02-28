from armddft.cfg.instructions.InstructionPush import InstructionPush
from armddft.cfg.instructions.InstructionPop import InstructionPop
from armddft.cfg.instructions.InstructionStr import InstructionStr
from armddft.cfg.instructions.InstructionLdr import InstructionLdr
from armddft.cfg.instructions.InstructionCmp import InstructionCmp
from armddft.cfg.instructions.InstructionMov import InstructionMov
from armddft.cfg.instructions.InstructionAdd import InstructionAdd
from armddft.cfg.instructions.InstructionLsl import InstructionLsl
from armddft.cfg.instructions.InstructionSub import InstructionSub
from armddft.cfg.instructions.InstructionB import InstructionB
from armddft.cfg.instructions.InstructionBl import InstructionBl




class InstructionFactory:
    instructions = {
        
        'push': InstructionPush,
        'pop' : InstructionPop,
        'sub' : InstructionSub,
        'mov' : InstructionMov,
        'add' : InstructionAdd,
        'cmp' : InstructionCmp,
        'str' : InstructionStr,
        'ldr' : InstructionLdr,
        'b'   : InstructionB,
        'lsl' : InstructionLsl,
        'bl': InstructionBl
    }

    @staticmethod
    def get_instruction(func_name, function):
        if func_name in InstructionFactory.instructions:
            func = InstructionFactory.instructions[func_name](function)
            return func
        else:
            raise NotImplementedError('Instruction "%s" is not implemented.' % func_name)

    @staticmethod
    def copy_instruction(instr, function=None):
        instr_copy = InstructionFactory.get_instruction(instr.name, function if function is not None else instr.function)
        instr_copy.address = instr.address
        instr_copy.length = instr.length
        instr_copy.clock = instr.clock
        instr_copy.operand_num = instr.operand_num
        instr_copy.src_op =  instr.src_op
        instr_copy.dst_op =  instr.dst_op
        instr_copy.condition = instr.condition
        instr_copy.setflag = instr.setflag
        instr_copy.disp = instr.disp
        instr_copy.base_reg = instr.base_reg
        instr_copy.index_reg = instr.index_reg
        instr_copy.file = instr.file
        
        return instr_copy