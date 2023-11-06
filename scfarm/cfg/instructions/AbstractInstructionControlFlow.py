from scfarm.cfg.AbstractInstruction import AbstractInstruction
from scfarm.cfg.ExecutionPoint import ExecutionPoint


class AbstractInstructionControlFlow(AbstractInstruction):
    def __init__(self, function):
        super(AbstractInstructionControlFlow, self).__init__(function)

    def get_branch_target(self):
        target_addr = self.dst_op[0]
        target = ExecutionPoint(self.function.name, target_addr, self.function.caller)
        
        return target
