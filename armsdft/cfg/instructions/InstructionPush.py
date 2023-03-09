from armsdft.cfg.StackPointer import StackPointer
from armsdft.cfg.AbstractInstruction import AbstractInstruction


class InstructionPush(AbstractInstruction):
    name = 'push'

    def get_execution_time(self):
        return self.clock

    def execute_judgment(self, ac): # only regisgter get pushed in arm cortex m23
        for i in range(self.operand_num):
            self.program.sp = self.program.sp - 4
            val = self.program.reg_map.get(self.src_op[i], None)
            if((val is not None) and isinstance(val, int)):
                self.program.mem_map.update({self.program.sp: val,})
            else:
                self.program.mem_map.update({self.program.sp: 'unclear',})  

            sec_level = ac.ra.get(self.src_op[i]) & ac.secenv.get(self.get_execution_point()) 
            ac.mem.set(self.program.sp, sec_level)

        sp_domain = ac.ra.get(StackPointer.SP)& ac.secenv.get(self.get_execution_point())
        ac.ra.set(StackPointer.SP, sp_domain)
