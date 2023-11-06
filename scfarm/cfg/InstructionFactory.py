from scfarm.cfg.instructions.InstructionPush import InstructionPush
from scfarm.cfg.instructions.InstructionPop import InstructionPop
from scfarm.cfg.instructions.InstructionStr import InstructionStr
from scfarm.cfg.instructions.InstructionLdr import InstructionLdr
from scfarm.cfg.instructions.InstructionCmp import InstructionCmp
from scfarm.cfg.instructions.InstructionMov import InstructionMov
from scfarm.cfg.instructions.InstructionAdd import InstructionAdd
from scfarm.cfg.instructions.InstructionLsl import InstructionLsl
from scfarm.cfg.instructions.InstructionSub import InstructionSub
from scfarm.cfg.instructions.InstructionB import InstructionB
from scfarm.cfg.instructions.InstructionBl import InstructionBl
from scfarm.cfg.instructions.InstructionMul import InstructionMul
from scfarm.cfg.instructions.InstructionAnd import InstructionAnd
from scfarm.cfg.instructions.InstructionNop import InstructionNop


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
        'bl'  : InstructionBl,
        'and' : InstructionAnd,
        'mul' : InstructionMul,
        'nop' : InstructionNop
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
        instr_copy.file = instr.file
        
        return instr_copy