from armsdft.cfg.StatusRegister import StatusRegister
from armsdft.cfg.instructions.AbstractInstructionBranching import AbstractInstructionBranching


class InstructionB(AbstractInstructionBranching):
    name = 'b'

    def get_successors(self):
        if self.condition == '':
            return [self.get_branch_target()]
            
        else:
            ret = super(InstructionB, self).get_successors()
            return ret
    
    def get_execution_time(self):
        return self.clock

    def execute_judgment(self, ac):
        if self.condition == '':
            pass
        else:
            super(InstructionB, self).execute_judgment(ac)

    def get_branching_condition_domain(self, ac): 
        if(self.condition == 'eq' or self.condition == 'ne'):
            return ac.sra.get(StatusRegister.ZERO)
        if(self.condition == 'ge' or self.condition == 'lt'):
            return ac.sra.get(StatusRegister.Negative) & ac.sra.get(StatusRegister.Overflow)
        if(self.condition == 'le' or self.condition == 'gt'):
            return ac.sra.get(StatusRegister.Negative) & ac.sra.get(StatusRegister.Overflow) & \
                ac.sra.get(StatusRegister.ZERO)
        