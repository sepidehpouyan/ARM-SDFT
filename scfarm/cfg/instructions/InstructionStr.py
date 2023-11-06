from scfarm.cfg.AbstractInstruction import AbstractInstruction


class InstructionStr(AbstractInstruction):
    name = 'str'

    def get_execution_time(self):
        return self.clock


        
        

