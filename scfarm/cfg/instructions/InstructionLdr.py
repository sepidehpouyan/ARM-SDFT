from scfarm.cfg.AbstractInstruction import AbstractInstruction


class InstructionLdr(AbstractInstruction):
    name = 'ldr'

    def get_execution_time(self):
        return self.clock