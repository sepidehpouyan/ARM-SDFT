from armddft.cfg.AbstractInstruction import AbstractInstruction
from armddft.cfg.ExecutionPoint import ExecutionPoint
from armddft.cfg.instructions.RecursionException import RecursionException
from elftools.elf.elffile import ELFFile

class InstructionBl(AbstractInstruction):
    name = 'bl'

    def get_execution_time(self):
        return self.clock

    def execute_judgment(self, ac):
        pass

    def get_successors(self):
        call_target = self.dst_op[0]
        call_target_for_elftools = self.dst_op[0] + 1

        elf = ELFFile(open(self.file, 'rb'))
        callee_function_name = self.find_symbol_by_addr(elf, call_target_for_elftools)

        # Check for recursion 
        callers = {self.function.name}
        caller = self.get_execution_point().caller
        while caller is not None:
            if callee_function_name in callers:
                raise RecursionException('Recursive successor requested, but recursion is not supported!')
            callers.add(caller.function)
            caller = caller.caller

        # caller type: ExecutionPoint()
        target = ExecutionPoint(callee_function_name, call_target, self.get_execution_point().forward(self.length))
        return [target,]

    def find_symbol_by_addr(self, elf, addr):
        name = ''
        for section in elf.iter_sections():
            if section.header['sh_type'] == 'SHT_SYMTAB':
                for sym in section.iter_symbols():
                    if sym['st_value'] == addr:
                        secname = elf.get_section(sym['st_shndx'])
                        if sym['st_name'] == 0:
                            name = secname.name
                        else:
                            name =  sym.name
                        return name
        return None