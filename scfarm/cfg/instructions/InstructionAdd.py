from scfarm.cfg.AbstractInstruction import AbstractInstruction

class InstructionAdd(AbstractInstruction):
    name = 'add'

    def get_execution_time(self):
        return self.clock