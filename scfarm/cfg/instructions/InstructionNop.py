from scfarm.cfg.AbstractInstruction import AbstractInstruction

class InstructionNop(AbstractInstruction):
    name = 'nop'

    def get_execution_time(self):
        return self.clock