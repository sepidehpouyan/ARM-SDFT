from scfarm.cfg.AbstractInstruction import AbstractInstruction

class InstructionMov(AbstractInstruction):
    name = 'mov'
    
    def get_execution_time(self):
        return self.clock
