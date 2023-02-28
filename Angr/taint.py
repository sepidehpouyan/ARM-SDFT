import angr
import json
import sys

input_reg = []

sensetive_branch_region = []
non_sensetive_branch_region = []

secret_regs = {}
secret_addr = {}

#main_addr = -1
#main_size =  0

proj = angr.Project('fork', load_options={'auto_load_libs': False})
    
main_size = proj.loader.main_object.get_symbol("main").size
main_addr = proj.loader.main_object.get_symbol("main").rebased_addr
    #main_end_addr = main_addr + main_size - 2
    #print(f'End of main @ {main_end_addr:#x}')

class ExitState(angr.SimProcedure):
    """
    Simple Procedure that just aborts the exploration of this state.
    """
    def run(self, return_values=None):
        self.exit(0)

class MainState(angr.SimProcedure):
   
    def run(self, return_values=None):
        print(f'Tainting registers as secret now: {input_reg}')
        for reg_name in input_reg:
            reg = getattr(self.state.regs, reg_name)
            reg = self.state.solver.BVS("{}_secret".format(reg_name), reg.size())
            setattr(self.state.regs, reg_name, reg)
        #for reg_name in self.state.project.arch.register_names.values():
            #print(f'{reg_name} : {getattr(self.state.regs, reg_name)}')

        #ret_addr = self.state.solver.eval(self.state.regs.lr)
        #print(f'Hooking lr @ {ret_addr:#x}')  
        #self.project.hook(ret_addr, MainExitState())

class MainExitState(angr.SimProcedure):
    """
    Simple Procedure that just aborts the exploration of this state.
    """
    def run(self, return_values=None):
        print(f'Check registers')
        for reg_name in self.state.project.arch.register_names.values():
            reg_value = getattr(self.state.regs, reg_name)
            print(f'on exit: {reg_name} : {reg_value}')
            if 'secret' in str(reg_value):
                secret_regs[reg_name] = self.state.ip
        self.exit(0)

def track_writes(state):

    reg_offset = state.inspect.reg_write_offset
    reg_name = state.arch.register_names[state.solver.eval(reg_offset)]

    print('Write', state.inspect.reg_write_expr, 'to', reg_name)
    print(hex(state.solver.eval(state.ip)))

    expr = str(state.inspect.reg_write_expr)
    if 'secret' in expr:
        if (main_addr <= state.solver.eval(state.ip) < (main_addr+main_size)):
            print('helooooo')
            secret_regs[reg_name] = hex(state.solver.eval(state.ip))
'''
    if reg_name in secret_regs:
        if 'secret' not in expr: 
            if secret_regs.get(reg_name) not in non_sensetive_branch_region:
                secret_regs.pop(reg_name)

    if state.ip in sensetive_branch_region:
        secret_regs.update({reg_name: state.ip})  
'''
def track_mem_writes(state):

    print('****************** Write', state.inspect.mem_write_expr, 'to', state.inspect.mem_write_address)
     
    expr = str(state.inspect.mem_write_expr)
    if 'secret' in expr:
        secret_addr.update({hex(state.solver.eval(state.inspect.mem_write_address)): state.ip}) 

def main():

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
    state = proj.factory.entry_state()
#---------------------------------------------------------------------------------- 
    proj.hook_symbol('main', MainState())
    proj.hook(main_addr+main_size, ExitState())
    #proj.hook_symbol('_exit', ExitState())
#----------------------------------------------------------------------------------  
    state.inspect.b('reg_write', when=angr.BP_AFTER, action=track_writes)
    #state.inspect.b('mem_write', when=angr.BP_AFTER, action=track_mem_writes)
#----------------------------------------------------------------------------------  
    simgr = proj.factory.simulation_manager(state)
  

    while len(simgr.active) > 0:
        #print(f'----------------------------------------------------------------------------------')
        #print(f'Making a step. Have {len(simgr.active)} active and {simgr.deadended} deadended states.')
        #print(f'----------------------------------------------------------------------------------')
        simgr.step()


    print(secret_regs)
    print(secret_addr)


if __name__ == '__main__':
    sys.exit(main())