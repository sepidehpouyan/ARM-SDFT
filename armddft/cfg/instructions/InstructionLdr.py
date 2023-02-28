from armddft.cfg.StackPointer import StackPointer
from armddft.cfg.AbstractInstruction import AbstractInstruction


class InstructionLdr(AbstractInstruction):
    name = 'ldr'

    def get_execution_time(self):
        return self.clock

    def execute_judgment(self, ac):
        print("base reg: ", self.base_reg, "disp: ", self.disp, type(self.disp))
        base_addr = self.program.reg_map.get(self.base_reg, None)
        if base_addr is not None:
            target_addr = base_addr + self.disp
            print("target_addr:", target_addr)

        val = self.program.mem_map.get(target_addr, None)
        if(val is not None and isinstance(val, int)):
            self.program.reg_map.update({self.dst_op[0]: val,}) 
        else:
            self.program.reg_map.update({self.dst_op[0]: 'unclear',}) 
        print(self.program.reg_map)

        sec_level = ac.mem.get(target_addr) & ac.secenv.get(self.get_execution_point()) 
        ac.ra.set(self.dst_op[0], sec_level)