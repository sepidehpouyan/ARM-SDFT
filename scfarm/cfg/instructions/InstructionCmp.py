from scfarm.cfg.AbstractInstruction import AbstractInstruction

class InstructionCmp(AbstractInstruction):
    name = 'cmp'

    def get_execution_time(self):
        return self.clock