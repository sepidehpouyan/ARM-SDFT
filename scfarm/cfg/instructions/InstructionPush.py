from scfarm.cfg.AbstractInstruction import AbstractInstruction


class InstructionPush(AbstractInstruction):
    name = 'push'

    def get_execution_time(self):
        return self.clock
