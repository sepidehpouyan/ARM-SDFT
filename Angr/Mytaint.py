import angr
import json
import sys

sensetive_branch_region = []
non_sensetive_branch_region = []

secret_regs = {}
secret_addr = {}

def track_writes(state):

    reg_offset = state.inspect.reg_write_offset
    reg_name = state.arch.register_names[state.solver.eval(reg_offset)]

    print('Write', state.inspect.reg_write_expr, 'to', reg_name, state.ip)

    expr = str(state.inspect.reg_write_expr)
    if 'secret' in expr:
        secret_regs.update({reg_name: hex(state.solver.eval(state.ip))}) 

    if reg_name in secret_regs:
        if 'secret' not in expr: 
            if secret_regs.get(reg_name) not in non_sensetive_branch_region:
                secret_regs.pop(reg_name)

    if hex(state.solver.eval(state.ip)) in sensetive_branch_region:
        secret_regs.update({reg_name: hex(state.solver.eval(state.ip))})  

def track_mem_writes(state):

    print('****************** Write', state.inspect.mem_write_expr, 'to', state.inspect.mem_write_address)

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

def main():
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
#---------------------------------------------------------------------------------- 
    for reg_name in input_reg:
        reg = getattr(state.regs, reg_name)
        reg = state.solver.BVS("{}_secret".format(reg_name), reg.size())
        setattr(state.regs, reg_name, reg)
#---------------------------------------------------------------------------------- 
    state.inspect.b('reg_write', when=angr.BP_AFTER, action=track_writes)
    #state.inspect.b('mem_write', when=angr.BP_AFTER, action=track_mem_writes)
#----------------------------------------------------------------------------------  
    simgr = proj.factory.simulation_manager(state)

    while len(simgr.active) > 0:
        simgr.step()


    print(secret_regs)
    print(secret_addr)


if __name__ == '__main__':
    sys.exit(main())