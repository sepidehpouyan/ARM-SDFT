from scfarm.cfg.AbstractInstruction import AbstractInstruction

class InstructionLsl(AbstractInstruction):
    name = 'lsl'

    def get_execution_time(self):
        return self.clock