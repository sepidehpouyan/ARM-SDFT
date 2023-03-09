from armsdft.verifier.SecurityLevel import SecurityLevel
from armsdft.verifier.AssignmentCollection import AssignmentCollection
from armsdft.cfg.AbstractInstruction import AbstractInstruction


class InstructionStr(AbstractInstruction):
    name = 'str'

    def get_execution_time(self):
        return self.clock

    def execute_judgment(self, ac):
        print("base reg: ", self.base_reg, "disp: ", self.disp, type(self.disp))
        base_addr = self.program.reg_map.get(self.base_reg, None)
        if base_addr is not None:
            target_addr = base_addr + self.disp
            print("target_addr:", target_addr)

        val = self.program.reg_map.get(self.src_op[0], None)
        if(val is not None and isinstance(val, int)):
            self.program.mem_map.update({target_addr: val,}) 
        else:
            self.program.mem_map.update({target_addr: 'unclear',}) 
        print(self.program.mem_map)
        sec_level = ac.ra.get(self.src_op[0]) & ac.secenv.get(self.get_execution_point()) 
        ac.mem.set(target_addr, sec_level)
        print("sec str: ", ac.mem.get(target_addr))


        
        

