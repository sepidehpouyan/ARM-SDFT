from scfarm.cfg.AbstractInstruction import AbstractInstruction

class InstructionSub(AbstractInstruction):
    name = 'sub'

    def get_execution_time(self):
        return self.clock