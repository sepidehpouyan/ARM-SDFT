from armddft.cfg.instructions.AbstractInstructionTwoRegisters import AbstractInstructionTwoRegisters
from armddft.cfg.StatusRegister import StatusRegister


class InstructionMov(AbstractInstructionTwoRegisters):
    name = 'mov'
    
    def get_execution_time(self):
        return self.clock

    def execute_judgment(self, ac):
        if(isinstance(self.src_op[0], int)): # immediate operand
            self.program.reg_map.update({self.dst_op[0]: self.src_op[0],})
            domain = ac.secenv.get(self.get_execution_point())
            ac.ra.set(self.dst_op[0], domain)
            if(self.setflag == 1):
                ac.sra.set(StatusRegister.CARRY, domain)
                ac.sra.set(StatusRegister.ZERO, domain)
                ac.sra.set(StatusRegister.Negative, domain)
                ac.sra.set(StatusRegister.Overflow, domain)

        else: #register operand
            domain = ac.ra.get(self.src_op[0]) & ac.secenv.get(self.get_execution_point())
            ac.ra.set(self.dst_op[0], domain)
            if(self.setflag == 1):
                ac.sra.set(StatusRegister.CARRY, domain)
                ac.sra.set(StatusRegister.ZERO, domain)
                ac.sra.set(StatusRegister.Negative, domain)
                ac.sra.set(StatusRegister.Overflow, domain)
        
            val = self.program.reg_map.get(self.src_op[0], None)
            if(val is not None and isinstance(val, int)):
                if(self.dst_op[0] == 'sp'):
                    self.program.sp =  val
                else:    
                    self.program.reg_map.update({self.dst_op[0]: val,})
            else:
                self.program.reg_map.update({self.dst_op[0]: 'unclear',})           
                    
        print("reg_map: ", self.program.reg_map)
    
        

        