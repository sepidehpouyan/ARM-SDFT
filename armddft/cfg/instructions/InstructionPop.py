from armddft.cfg.StackPointer import StackPointer
from armddft.cfg.AbstractInstruction import AbstractInstruction


class InstructionPop(AbstractInstruction):
    name = 'pop'

    def get_successors(self):
        print(self.dst_op)
        if 'pc' in self.dst_op:
            if self.get_execution_point().has_caller():
                return [self.get_execution_point().caller]
            else:
                return []
        else:
            return [self.get_execution_point().forward(self.length)]
    
    def get_execution_time(self):
        return self.clock

    def execute_judgment(self, ac):
        for i in range(self.operand_num):
            val = self.program.mem_map.get(self.program.sp, None)
            if((val is not None) and isinstance(val, int)):
                self.program.reg_map.update({self.dst_op[(self.operand_num - 1) - i]: val,})
            else:
                self.program.reg_map.update({self.dst_op[(self.operand_num - 1) - i]: 'unclear',})  

            sec_level = ac.mem.get(self.program.sp) & ac.secenv.get(self.get_execution_point()) 
            ac.ra.set(self.dst_op[(self.operand_num - 1) - i], sec_level)

            self.program.sp = self.program.sp + 4

        sp_domain = ac.ra.get(StackPointer.SP)& ac.secenv.get(self.get_execution_point())
        ac.ra.set(StackPointer.SP, sp_domain)

        print("o0o0o0o0o0lo0o0o: ", self.program.reg_map)