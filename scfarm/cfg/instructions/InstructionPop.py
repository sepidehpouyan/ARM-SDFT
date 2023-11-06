from scfarm.cfg.AbstractInstruction import AbstractInstruction


class InstructionPop(AbstractInstruction):
    name = 'pop'

    def get_successors(self):
        #print(self.dst_op)
        if 'pc' in self.dst_op:
            if self.get_execution_point().has_caller():
                return [self.get_execution_point().caller]
            else:
                return []
        else:
            return [self.get_execution_point().forward(self.length)]
    
    def get_execution_time(self):
        return self.clock