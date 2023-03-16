import angr
import json
import sys
import logging
import capstone

cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)

conditional_branch = ['beq', 'bne', 'bgt', 'blt', 'bge', 'ble']
junction_dict = {'0x8159': '0x8161'}
secret_branch = []
nested_branch_list = []

def print_state_backtrace_formatted(state):
    """
    Returns the block backtrace for a given state, formatted as a list of strings that can be printed immediately.
    """
    bbt = []
    for a in state.history.bbl_addrs:
        sym = state.project.loader.find_symbol(a, fuzzy=True)
        rel = a - state.project.loader.min_addr
        bbt.append(f'{a:#x} {sym.name:<35} ({rel:#x} relative to obj base)')
    print("\n".join(bbt))

def track_writes(state):

    reg_offset = state.inspect.reg_write_offset
    reg_name = state.arch.register_names[state.solver.eval(reg_offset)]

    #print('Write', state.inspect.reg_write_expr, 'to', reg_name, "state.ip: ", hex(state.scratch.ins_addr))
    #print(f'State has information_leakage: {str(state.globals["secret_branching"])}')
    
    expr = state.inspect.reg_write_expr
    if 'secret' not in str(expr):
        if state.globals["secret_branching"]:
            expr.name = 'secret'
            reg = state.solver.BVS("{}_secret".format(str(expr)), expr.size())
            setattr(state.regs, reg_name, reg)

def track_mem_writes(state):

    #print('------- Write', state.inspect.mem_write_expr, 'to', state.inspect.mem_write_address)
    #print(f'State has information_leakage: {str(state.globals["secret_branching"])}')

    expr = state.inspect.mem_write_expr
    mem_addr = state.solver.eval(state.inspect.mem_write_address)
    if 'secret' not in str(expr):
        if state.globals["secret_branching"]:
            reg = state.solver.BVS("{}_secret".format(str(expr)), expr.size())
            state.mem[mem_addr] = reg
    

def stop_information_leakage(state):
    if state.globals['secret_branching']:
        state.globals['branch_number'] -= 1
    if state.globals['branch_number'] == 0:
        print('stop_information_leakage')
        state.globals['secret_branching'] = False

def track_instruction(state):
    #print('___________****___________', state.inspect.instruction)
    if state.inspect.instruction is not None:
        block = state.project.factory.block(state.inspect.instruction)
        insn = cs.disasm(block.bytes, state.inspect.instruction)
        ins = insn.__next__()

        #print(f"Current instruction: {ins.mnemonic} -- {ins.op_str}")

    if ins.mnemonic in conditional_branch:
        print('^^^^^branch^^^^^^')
        if state.globals['state_reg_tainted']:
            state.globals['secret_branching'] = True
            print(ins.mnemonic, hex(state.inspect.instruction))
            secret_branch.append(hex(state.inspect.instruction))
            state.globals['branch_number'] += 1 

    elif ins.mnemonic in ['cmp'] and not state.globals['secret_branching']:
        parts = ins.op_str.split(', ')
        is_tainted = False
        for p in parts:
            reg = getattr(state.regs, p)
            if 'secret' in str(reg):
                is_tainted = True
        
        state.globals['state_reg_tainted'] = is_tainted

#----------------------------------------------------------------------------------  

def main():
    logging.disable(logging.WARNING)
    input_reg = []
    args = sys.argv
    if args is None or len(args) < 2:
        print('Run using a path to a json file')
        return 0
    string = ''
    with open(args[1]) as f:
        for line in f:
            string += line
    data = json.loads(string)
    r = 0
    for param in data['parameters']:
        if param['confidential']:
            input_reg.append('r' + str(r))
        r += 1
#----------------------------------------------------------------------------------    
    proj = angr.Project('fork', load_options={'auto_load_libs': False})
    
    main_size = proj.loader.main_object.get_symbol("main").size
    main_addr = proj.loader.main_object.get_symbol("main").rebased_addr
    state = proj.factory.entry_state(addr=main_addr)
    state.globals['state_reg_tainted'] =  False
    state.globals['secret_branching'] =  False
    state.globals['branch_number'] = 0 #----******
#----------------------------------Initial register tagging --------------------------------- 
    for reg_name in input_reg:
        reg = getattr(state.regs, reg_name)
        reg = state.solver.BVS("{}_secret".format(reg_name), reg.size())
        setattr(state.regs, reg_name, reg)
#------------------------------------Set Breakpoint ------------------------------------------ 
    state.inspect.b('reg_write', when=angr.BP_AFTER, action=track_writes)
    state.inspect.b('mem_write', when=angr.BP_AFTER, action=track_mem_writes)
    state.inspect.b('instruction', when=angr.BP_BEFORE, action=track_instruction)

    for junction in junction_dict:
        state.project.hook(int(junction_dict[junction], 16), stop_information_leakage)
#--------------------------------------Symbolic Executing ------------------------------------  
    simgr = proj.factory.simulation_manager(state)

    while len(simgr.active) > 0:
        simgr.step()

    
    #print('secret_branch_list: ', secret_branch)
    print(f'number of deadended states: {str(simgr.stashes)}')
    for s in simgr.unconstrained:
        #print_state_backtrace_formatted(s)
        print('-----------------------------------------------\n')
        for reg_name in proj.arch.register_names.values():
            reg = getattr(s.regs, reg_name)
            if 'secret' in str(reg):
                print(reg_name, reg)
    
        changed_bytes_list = s.memory.changed_bytes(state.memory)
        for addr in changed_bytes_list:
            value = s.memory.load(addr, 1)
            if 'secret' in str(value):
                print(hex(addr), value)

#----------------------------------------------------------------------------------  

if __name__ == '__main__':
    sys.exit(main())