from armsdft.cfg.AbstractInstruction import AbstractInstruction
from armsdft.cfg.StatusRegister import StatusRegister


class AbstractInstructionTwoRegisters(AbstractInstruction):       
    
    def execute_judgment(self, ac):
        # Usually, the first register is the Rd (destination) register
        # and the second register contains additional arguments.
        # That means, that the destination register is the least
        # upper bound of both registers
        rd = self.dst_op[0]
        domain = self._get_register_domain(ac)
        ac.ra.set(rd, domain)

    def _get_register_domain(self, ac):
        op1 = self.src_op[0] # first operand
        op2 = self.src_op[1] # second operand

        if(isinstance(op2, int)):
            return ac.ra.get(op1) & ac.secenv.get(self.get_execution_point())
        else:
            return ac.ra.get(op1) & ac.ra.get(op2) & ac.secenv.get(self.get_execution_point())          

    def _execute_judgment_carry(self, ac):
        domain = self._get_register_domain(ac)
        ac.sra.set(StatusRegister.CARRY, domain)

    def _execute_judgment_zero(self, ac):
        domain = self._get_register_domain(ac)
        ac.sra.set(StatusRegister.ZERO, domain)

    def _execute_judgment_negative(self, ac):
        domain = self._get_register_domain(ac)
        ac.sra.set(StatusRegister.Negative, domain)

    def _execute_judgment_overflow(self, ac):
        domain = self._get_register_domain(ac)
        ac.sra.set(StatusRegister.Overflow, domain)