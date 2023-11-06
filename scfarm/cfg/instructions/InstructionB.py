from scfarm.cfg.instructions.AbstractInstructionBranching import AbstractInstructionBranching


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
        