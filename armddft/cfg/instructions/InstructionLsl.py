from armddft.cfg.instructions.AbstractInstructionTwoRegisters import AbstractInstructionTwoRegisters


class InstructionLsl(AbstractInstructionTwoRegisters):
    name = 'lsl'

    def get_execution_time(self):
        return self.clock

    def execute_judgment(self, ac):
        op1 = self.src_op[0]
        op2 = self.src_op[1]
        val1 = self.program.reg_map.get(self.src_op[0], None)
        val2 = self.program.reg_map.get(self.src_op[1], None)
        
        if(isinstance(val1, int) and isinstance(val2, int)):
            self.program.reg_map.update({self.dst_op[0]: val1 << val2,})
        elif(isinstance(val1, int) and isinstance(op2, int)):
            self.program.reg_map.update({self.dst_op[0]: val1 << op2,})
        else:
            self.program.reg_map.update({self.dst_op[0]: 'unclear',})

        print("reg_map: ", self.program.reg_map)

        super(InstructionLsl, self).execute_judgment(ac)
        if(self.setflag == 1):
            self._execute_judgment_carry(ac)
            self._execute_judgment_zero(ac)
            self._execute_judgment_negative(ac)
            self._execute_judgment_overflow(ac)
