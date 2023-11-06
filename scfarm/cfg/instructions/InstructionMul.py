from scfarm.cfg.AbstractInstruction import AbstractInstruction

class InstructionMul(AbstractInstruction):
    name = 'mul'

    def get_execution_time(self):
        return self.clock