from scfarm.cfg.AbstractInstruction import AbstractInstruction

class InstructionAnd(AbstractInstruction):
    name = 'and'

    def get_execution_time(self):
        return self.clock