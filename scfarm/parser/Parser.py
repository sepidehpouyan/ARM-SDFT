from scfarm.cfg.InstructionFactory import InstructionFactory
from scfarm.cfg.AbstractInstruction import AbstractInstruction
from scfarm.cfg.Function import Function
from scfarm.cfg.Program import Program
from elftools.elf.elffile import ELFFile
from capstone.arm import *

class Parser:
    @staticmethod
    def parse_file(file, starting_function):
        elf = ELFFile(open(file, 'rb'))
        sym_table, section_name = Parser.find_symbol_by_name(elf, starting_function)
        starting_function_size = sym_table['st_size']
        starting_function_address = sym_table['st_value'] - 1
        program = Program()
        return Parser.parse_elf(file, elf, starting_function, starting_function_address, 
         starting_function_size, section_name, program, caller= None, call_dic={})

    @staticmethod
    def parse_elf(file, elf, starting_function, starting_function_address, size, section_name,
                     program, caller, call_dic):
        insoff =  0
        current_func = Function(starting_function, program, file, caller)
        program.add_function(current_func)
        section = elf.get_section_by_name(section_name)
       
        sh_addr = section['sh_addr'] # the address of section ".text"
        sh_size = section['sh_size'] # the size of section ".text"
    
        if(size == 0): # sometime the size is 0
            size = sh_size

        offset = starting_function_address - sh_addr
        stop_offset = offset + size
        code = section.data()[offset:stop_offset]
        base_address =  starting_function_address
        callers = set()
        caller = list()

        while (insoff < len(code)):
            abs_ins = AbstractInstruction(current_func)
            mnemonic, length, address, op_num, src_op, dst_op, \
            clock, condition = abs_ins.disasm(code[insoff : insoff + 4], base_address + insoff)

            instr = InstructionFactory.get_instruction(mnemonic, function=current_func)
            instr.get_info(length, address, op_num, src_op, dst_op,clock, condition, file)
            current_func.add_instruction(instr)

            #---------------------------------------------------------------------------------------------------------------

            if(mnemonic == 'bl'):
                call_target = dst_op[0]
                call_target_for_elftools = dst_op[0] + 1
                elf = ELFFile(open(file, 'rb'))
                sym_table_name, sym_table_size, section_name = Parser.find_symbol_by_addr(elf, call_target_for_elftools)
                callee_function_name = sym_table_name
                callee_function_size = sym_table_size

                # Check for recursionn -------------------------
                callers.clear()
                if caller is not None:
                    caller.clear()

                if(call_target ==  starting_function_address):
                    return program   
                else:
                    count = 0
                    call_dic.setdefault(call_target, []).append(starting_function_address)
                    callers = {starting_function_address}
                    tmp = call_dic.get(starting_function_address)
                    if tmp is not None:
                        caller.extend(tmp)
                    while len(caller) > 0:
                        first_caller =  caller.pop(0)
                        if(len(callers) == count):
                            return program
                        if (call_target in callers):
                            return program
                        count = len(callers)
                        callers.add(first_caller)
                        temp = call_dic.get(first_caller)
                        if temp is not None:
                            caller.extend(temp)
              
                Parser.parse_elf(file, elf, callee_function_name, call_target,\
                                     callee_function_size, section_name, program, current_func, call_dic)

            #----------------------------------------------------------------------------------------------------------------

            insoff += length

        return program
    
    @staticmethod
    def find_symbol_by_addr(elf, addr):
        name = ''
        size = 0
        for section in elf.iter_sections():
            if section.header['sh_type'] == 'SHT_SYMTAB':
                for sym in section.iter_symbols():
                    #print("------: ", sym.name, hex(sym['st_value']))
                    if sym['st_value'] == addr:
                        secname = elf.get_section(sym['st_shndx'])
                        if sym['st_name'] == 0:
                            name = secname.name
                        else:
                            name =  sym.name
                        size = sym['st_size']
                        return name, size, secname.name
        return None

    @staticmethod
    def find_symbol_by_name(elf, name):
        for section in elf.iter_sections():
            if section.header['sh_type'] == 'SHT_SYMTAB':
                for sym in section.iter_symbols():
                    if sym.name == name:
                        secname = elf.get_section(sym['st_shndx'])
                        return sym, secname.name
        return None
