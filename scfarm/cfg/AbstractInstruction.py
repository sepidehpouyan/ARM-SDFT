from scfarm.cfg.ExecutionPoint import ExecutionPoint
import capstone
from capstone.arm import *
import re


class AbstractInstruction:
    name = ''
    length = 2

    def __init__(self, function):
        self.md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
        self.md.detail = True

        self.length = 0
        self.mnemonic = ''
        self.address = 0
        self.clock = 0
        self.src_op = ()
        self.dst_op = ()
        self.operand_num = 0
        self.setflag = 0
        self.condition = ''

        self.file = ''
        self.program = function.program
        self.function = function
        self.arguments = ()

        self.immediate_dominator = None
        self.immediate_post_dominator = None
        self.predecessors = None

        self.__successors_checked_cache = None
        self.__execution_point = None

    def __unicode__(self):
        return '"%s: %s %s"' % (hex(self.address), self.name, self.arguments)


    def __repr__(self):
        return self.__unicode__()

    def disasm(self, bytes, base):
        pattern = "(eq|ne|gt|lt|ge|le|cs|hs|cc|lo|mi|pl|al|nv|vs|vc|hi|ls)"
        src_op = ()
        dst_op = ()
        condition = ''

        try:
            insts = self.md.disasm(bytes, base)
            ins = insts.__next__()
            
            length = len(ins.bytes)
            address = ins.address
            operand_num = len(ins.operands)

            if(ins.mnemonic.startswith("push")):
                mnemonic = 'push'
                clock = 1 + operand_num

                #print("mnemonic: ", ins.mnemonic, "length: ", length, "address:", hex(address), 
                #"operand_num: ", operand_num, "operand: ", ins.op_str)

                if len(ins.operands) > 0:
                    for i in ins.operands:
                        if i.type == ARM_OP_REG:
                            src_op = src_op + (ins.reg_name(i.value.reg),)

                #print(src_op)

            elif(ins.mnemonic.startswith("pop")):
                mnemonic = 'pop'
                clock = 1 + operand_num

                #print("mnemonic: ", ins.mnemonic, "length: ", length, "address:", hex(address), 
                #"operand_num: ", operand_num, "operand: ", ins.op_str)

                if len(ins.operands) > 0:
                    for i in ins.operands:
                        if i.type == ARM_OP_REG:
                            dst_op = dst_op + (ins.reg_name(i.value.reg),)
                
                if 'pc' in dst_op:
                    clock = 3 + operand_num

                #print(dst_op)

            elif(ins.mnemonic.startswith("sub")):
                if(ins.mnemonic.startswith("subs")):
                    setflag = 1
                mnemonic = 'sub'
                x = re.search(pattern, ins.mnemonic)
                if x is not None:
                    condition = x.group(1)
                clock = 1
                
                #print("mnemonic: ", ins.mnemonic, "length: ", length, "address:", hex(address), 
                #"operand_num: ", operand_num, "operand: ", ins.op_str)

                if operand_num == 2:
                    c = 0
                    for i in ins.operands:
                        if (c == 0):
                            src_op = src_op + (ins.reg_name(i.value.reg),)
                            dst_op = dst_op + (ins.reg_name(i.value.reg),)
                        else:
                            if i.type == ARM_OP_REG:
                                src_op = src_op + (ins.reg_name(i.value.reg),)
                            if i.type == ARM_OP_IMM:
                                src_op = src_op + (i.value.imm,)
                        c = c + 1 
                if operand_num == 3:
                    c = 0
                    for i in ins.operands:
                        if (c == 0):
                            dst_op = dst_op + (ins.reg_name(i.value.reg),)
                        else:
                            if i.type == ARM_OP_REG:
                                src_op = src_op + (ins.reg_name(i.value.reg),)
                            if i.type == ARM_OP_IMM:
                                src_op = src_op + (i.value.imm,)
                        c = c + 1  

                #print(src_op, dst_op) 

            elif(ins.mnemonic.startswith("add")):
                mnemonic = 'add'
                x = re.search(pattern, ins.mnemonic)
                if x is not None:
                    condition = x.group(1)
                clock = 1

                #print("mnemonic: ", ins.mnemonic, "length: ", length, "address:", hex(address), 
                #"operand_num: ", operand_num, "operand: ", ins.op_str)

                if operand_num == 2:
                    c = 0
                    for i in ins.operands:
                        if (c == 0):
                            #print("operand: ", ins.op_str)
                            src_op = src_op + (ins.reg_name(i.value.reg),)
                            dst_op = dst_op + (ins.reg_name(i.value.reg),)
                        else:
                            if i.type == ARM_OP_REG:
                                #print("operand: ", ins.op_str)
                                src_op = src_op + (ins.reg_name(i.value.reg),)
                            if i.type == ARM_OP_IMM:
                                #print("operand: ", ins.op_str)
                                src_op = src_op + (i.value.imm,)
                        c = c + 1 
                    if "pc" in dst_op:
                        clock = 2
                
                if operand_num == 3:
                    c = 0
                    for i in ins.operands:
                        if (c == 0):
                            dst_op = dst_op + (ins.reg_name(i.value.reg),)
                        else:
                            if i.type == ARM_OP_REG:
                                src_op = src_op + (ins.reg_name(i.value.reg),)
                            if i.type == ARM_OP_IMM:
                                src_op = src_op + (i.value.imm,)
                        c = c + 1
                    if "pc" in dst_op:
                        clock = 2  

                #print(src_op, dst_op)    

            elif(ins.mnemonic.startswith("str")):
                mnemonic = 'str'
                clock = 2
                #print("mnemonic: ", ins.mnemonic, "length: ", length, "address:", hex(address), 
                #"operand_num: ", operand_num, "operand: ", ins.op_str)
                for i in ins.operands:
                    if i.type == ARM_OP_REG:
                        src_op = src_op + (ins.reg_name(i.value.reg),)
                    if i.type == ARM_OP_MEM:
                        if i.value.mem.base != 0:
                            base_reg = ins.reg_name(i.value.mem.base)
                        if i.value.mem.index != 0:
                            index_reg = ins.reg_name(i.value.mem.index)
                        if i.value.mem.disp != 0:
                            disp = i.value.mem.disp
                        if i.value.mem.disp == 0:
                            disp = 0
                
                #print(src_op, base_reg, disp)

            elif(ins.mnemonic.startswith("mov")):
                mnemonic = 'mov'
                clock = 1
                if(ins.mnemonic.startswith('movt') or ins.mnemonic.startswith('movw')):
                    clock = 3

                #print("mnemonic: ", ins.mnemonic, "length: ", length, "address:", hex(address), 
                #"operand_num: ", operand_num)
                c = 0
                for i in ins.operands:
                    if (c == 0):
                        #print("operand: ", ins.op_str)
                        dst_op = dst_op + (ins.reg_name(i.value.reg),)
                    else:
                        if i.type == ARM_OP_REG:
                            #print("operand: ", ins.op_str)
                            src_op = src_op + (ins.reg_name(i.value.reg),)
                        if i.type == ARM_OP_IMM:
                            #print("operand: ", ins.op_str)
                            src_op = src_op + (i.value.imm,)
                    c = c + 1
                if "pc" in dst_op:
                        clock = 2  
                
                #print(src_op, dst_op)
            
            elif(ins.mnemonic.startswith("ldr")):
                mnemonic = 'ldr'
                clock = 2

                #print("mnemonic: ", ins.mnemonic, "length: ", length, "address:", hex(address), 
                #"operand_num: ", operand_num)

                for i in ins.operands:
                    #print("operand: ", ins.op_str)
                    if i.type == ARM_OP_REG:
                        dst_op = dst_op + (ins.reg_name(i.value.reg),)
                    if i.type == ARM_OP_MEM:
                        if i.value.mem.base != 0:
                            base_reg = ins.reg_name(i.value.mem.base)
                        if i.value.mem.index != 0:
                            index_reg = ins.reg_name(i.value.mem.index)
                        if i.value.mem.disp != 0:
                            disp = i.value.mem.disp
                        if i.value.mem.disp == 0:
                            disp = 0
                
                #print(dst_op, base_reg, disp)

            elif(ins.mnemonic.startswith("cmp")):
                mnemonic = 'cmp'
                clock = 1

                #print("mnemonic: ", ins.mnemonic, "length: ", length, "address:", hex(address), 
                #"operand_num: ", operand_num)

                for i in ins.operands:
                    #print("operand: ", ins.op_str)
                    if i.type == ARM_OP_REG:
                        src_op = src_op + (ins.reg_name(i.value.reg),)
                    if i.type == ARM_OP_IMM:
                        src_op = src_op + (i.value.imm,)
                
                #print(src_op)

            elif(ins.mnemonic.startswith("bl") and not ins.mnemonic.startswith("ble") and
                not ins.mnemonic.startswith("blt")):

                mnemonic = 'bl'
                clock = 3
                x = re.search(pattern, ins.mnemonic)
                if x is not None:
                    condition = x.group(1)
                    clock = 1

                #print("mnemonic: ", ins.mnemonic, "length: ", length, "address:", hex(address), type(address), address,
                #"operand_num: ", operand_num, "operand: ", ins.op_str, "condition: ", condition)

                for i in ins.operands:
                    dst_op = dst_op + (i.value.imm,)

            elif(ins.mnemonic.startswith("b")):
                mnemonic = 'b'
                clock = 2
                if '.w' in ins.mnemonic:
                    clock = 3
                x = re.search(pattern, ins.mnemonic)
                if x is not None:
                    condition = x.group(1)
                    clock = 1

                #print("mnemonic: ", ins.mnemonic, "length: ", length, "address:", hex(address), type(address), address,
                #"operand_num: ", operand_num, "operand: ", ins.op_str, "condition: ", condition)

                for i in ins.operands:
                    dst_op = dst_op + (i.value.imm,)
                
                #print(type(i.value.imm), i.value.imm)
                #print(type(dst_op[0]), dst_op[0])

            elif(ins.mnemonic.startswith("lsl")):
                if(ins.mnemonic.startswith("lsls")):
                    setflag = 1
                mnemonic = 'lsl'
                x = re.search(pattern, ins.mnemonic)
                if x is not None:
                    condition = x.group(1)
                clock = 1

                #print("mnemonic: ", ins.mnemonic, "length: ", length, "address:", hex(address), 
                #"operand_num: ", operand_num, "operand: ", ins.op_str)

                if operand_num == 2:
                    c = 0
                    for i in ins.operands:
                        if (c == 0):
                            src_op = src_op + (ins.reg_name(i.value.reg),)
                            dst_op = dst_op + (ins.reg_name(i.value.reg),)
                        else:
                            if i.type == ARM_OP_REG:
                                src_op = src_op + (ins.reg_name(i.value.reg),)
                            if i.type == ARM_OP_IMM:
                                src_op = src_op + (i.value.imm,)
                        c = c + 1 
                
                if operand_num == 3:
                    c = 0
                    for i in ins.operands:
                        if (c == 0):
                            dst_op = dst_op + (ins.reg_name(i.value.reg),)
                        else:
                            if i.type == ARM_OP_REG:
                                src_op = src_op + (ins.reg_name(i.value.reg),)
                            if i.type == ARM_OP_IMM:
                                src_op = src_op + (i.value.imm,)
                        c = c + 1  

                #print(src_op, dst_op)    

            elif(ins.mnemonic.startswith("and")):
                mnemonic = 'and'
                clock = 1

            elif(ins.mnemonic.startswith("mul")):
                mnemonic = 'mul'
                clock = 1

            elif(ins.mnemonic.startswith("nop")):
                mnemonic = 'nop'
                clock = 1
                
            return mnemonic, length, address, operand_num, src_op, dst_op, clock, condition

        except StopIteration:
                print("An exception occurred")

    def get_info(self, length, address, op_num, src_op, dst_op, clock, condition, file):

        self.length = length
        self.address = address
        self.operand_num = op_num
        self.clock = clock
        self.src_op = src_op
        self.dst_op = dst_op
        self.condition = condition
        self.file =  file

    def get_execution_point(self):
        if self.__execution_point is None:
            self.__execution_point = ExecutionPoint(self.function.name, self.address, self.function.caller)
        return self.__execution_point

    def get_successors(self):        
        return [self.get_execution_point().forward(self.length)]

    def get_successors_checked(self):
        if self.__successors_checked_cache is not None:
            return self.__successors_checked_cache
        successors = self.get_successors()
        ret = []
        for succ in successors:
            try:
                self.program.get_instruction_at_execution_point(succ)
                ret.append(succ)
            except:
                pass
        self.__successors_checked_cache = ret
        return ret

    def get_execution_time(self):
        pass

    def get_branching_time(self):
        """
        Clock cycles that are required to take a branch. Has to be added
        to get_execution_time when comparing the execution time of two branches.

        Defaults to one, because this is correct for most branching instructions.
        :return: Numeric clock cycles it takes extra to take a branch.
        """
        return 1

    def get_region_then(self):
        return []

    def get_region_else(self):
        return []

    def _get_branchtime(self, region):
        ret = 0
        for ep in region:
            instr = self.program.get_instruction_at_execution_point(ep)
            ret += instr.get_execution_time()
            # Avoid infinite looping, when accidentally called on loops
            if not (ep == self.get_execution_point()):
                # Use else, because there is no extra time involved when not taking the branch
                ret -= instr.get_branchtime_then()     
        return ret

    def get_branchtime_then(self):
        return self._get_branchtime(self.get_region_then())

    def get_branchtime_else(self):
        return self._get_branchtime(self.get_region_else())

    def get_junction(self):
        return []

    def execute_judgment(self, ac):
        raise NotImplementedError('Instruction "%s" is lacking an execute_judgment implementation! At %s' %
                                  (self.name, self.get_execution_point()))

