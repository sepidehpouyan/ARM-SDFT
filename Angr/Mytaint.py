import angr
import json
import sys
import logging
import capstone


sensetive_branch_region = []
non_sensetive_branch_region = []

secret_regs = {}
secret_addr = {}

conditional_branch = ['beq', 'bne', 'bgt', 'blt', 'bge', 'ble']

def track_writes(state):

    reg_offset = state.inspect.reg_write_offset
    reg_name = state.arch.register_names[state.solver.eval(reg_offset)]

    #print('Write', state.inspect.reg_write_expr, 'to', reg_name, "state.ip: ", hex(state.scratch.ins_addr))
    #print(f'State has information_leakage: {str(state.globals["information_leakage"])}')


    expr = str(state.inspect.reg_write_expr)
    if 'secret' in expr:
        secret_regs.update({reg_name: hex(state.solver.eval(state.scratch.ins_addr))}) 

    if reg_name in secret_regs:
        if 'secret' not in expr: 
            if secret_regs.get(reg_name) not in non_sensetive_branch_region:
                secret_regs.pop(reg_name)

    if hex(state.solver.eval(state.ip)) in sensetive_branch_region:
        secret_regs.update({reg_name: hex(state.solver.eval(state.ip))})  

def track_mem_writes(state):

    #print('****************** Write', state.inspect.mem_write_expr, 'to', state.inspect.mem_write_address)
    #print(f'State has information_leakage: {str(state.globals["information_leakage"])}')

    expr = str(state.inspect.mem_write_expr)
    mem_addr = hex(state.solver.eval(state.inspect.mem_write_address))
    if 'secret' in expr:
        secret_addr.update({mem_addr: hex(state.solver.eval(state.ip))}) 

    if(mem_addr in secret_addr):
        if 'secret' not in expr: 
            if secret_addr.get(mem_addr) not in non_sensetive_branch_region:
                secret_regs.pop(mem_addr)

    if hex(state.solver.eval(state.ip)) in sensetive_branch_region:
        secret_regs.update({mem_addr: hex(state.solver.eval(state.ip))}) 

def track_forks(state):
    print('####### forked')
    # get_forked_state
    state.globals['information_leakage'] = True

def stop_information_leakage(state):
    state.globals['information_leakage'] = False


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

def track_instruction(state):
    print('___________****___________', hex(state.inspect.instruction))
    # Get the executed instruction address
    ip = state.recent_block.addr
    # Get the bytes representing the instruction
    instr_bytes = state.solver.eval(state.memory.load(ip, state.project.arch.instruction_length))
    # Disassemble the instruction bytes
    md = capstone.Cs(state.project.arch.capstone_type, state.project.arch.capstone_mode)
    instr = next(md.disasm(instr_bytes, ip))
    # Extract the instruction mnemonic and operands
    mnemonic = instr.mnemonic
    operands = instr.op_str
    print(f"Executed instruction: {mnemonic} {operands}")

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
    state.globals['information_leakage'] = False
#---------------------------------------------------------------------------------- 
    for reg_name in input_reg:
        reg = getattr(state.regs, reg_name)
        reg = state.solver.BVS("{}_secret".format(reg_name), reg.size())
        setattr(state.regs, reg_name, reg)
#---------------------------------------------------------------------------------- 
    state.inspect.b('reg_write', when=angr.BP_AFTER, action=track_writes)
    state.inspect.b('mem_write', when=angr.BP_AFTER, action=track_mem_writes)
    state.inspect.b('instruction', when=angr.BP_AFTER, action=track_instruction)
    state.inspect.b('fork', when=angr.BP_BEFORE, action=track_forks)

    junction_list = []

    for junction in junction_list:
        state.inspect.hook(junction, stop_information_leakage)
#----------------------------------------------------------------------------------  
    simgr = proj.factory.simulation_manager(state)

    while len(simgr.active) > 0:
        simgr.step()

    
    print(secret_addr)
    #print(f'number of deadended states: {str(simgr.stashes)}')
    for s in simgr.unconstrained:
        #print_state_backtrace_formatted(s)
        print('--------------\n')
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