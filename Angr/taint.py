import angr
import claripy
import json
import sys
import logging
import capstone
from angr.storage import MemoryMixin

from angr.storage.memory_mixins import PagedMemoryMixin, SymbolicMergerMixin, DefaultFillerMixin, UltraPagesMixin, \
    PrivilegedPagingMixin, DictBackerMixin, ClemoryBackerMixin, ConcreteBackerMixin, StackAllocationMixin, \
    DirtyAddrsMixin, ConvenientMappingsMixin, ConditionalMixin, ActionsMixinLow, AddressConcretizationMixin, \
    SizeNormalizationMixin, SizeConcretizationMixin, UnderconstrainedMixin, ActionsMixinHigh, InspectMixinHigh, \
    DataNormalizationMixin, NameResolutionMixin, UnwrapperMixin, SmartFindMixin, SimplificationMixin


cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)

register_list = ['r11', 'ip', 'sp', 'pc', 'lr', "cc_op", 'cc_dep1', "cc_dep2",  
                "cc_ndep", "qflag32", "geflag0", "geflag1", "geflag2", "geflag3", 
                "emnote", "cmstart", "cmlen", "nraddr", "ip_at_syscall",
                "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "d10",
                "d11", "d12", "d13", "d14", "d15", "d16", "d17", "d18", "d19", "d20", 
                "d21", "d22", "d23", "d24", "d25", "d26", "d27", "d28", "d29", "d30", "d31", "fpscr", "tpidruro", "itstate"]

conditional_branch = ['beq', 'bne', 'bgt', 'blt', 'bge', 'ble']
junction_dict = {'0x8169': '0x8179'}
#array {'0x8159': '0x817d'} #diamond {'0x8159': '0x8173', '0x8178': '0x8181'} # fork {'0x8159': '0x8161'}
secret_branch = []


class TrustzoneAwareMixin(MemoryMixin):

    def store(self, addr, data, **kwargs):
        reg_name =  ''
        print('before if', data, 'to', addr)
        print(self.category)
        if (self.category == 'reg'):
            reg_name = self.state.arch.register_names[self.state.solver.eval(addr)]
            print(reg_name)
        if is_tainted(data):
            print('yessssssssssssssssssss it is tainted')


        new_data = data

        if 'secret_branching' in self.state.globals and self.state.globals["secret_branching"]:
            print('Write', data, 'to', addr, "state.ip: ", hex(self.state.scratch.ins_addr))
            if not is_tainted(data) and reg_name not in register_list:
                print('data is not tainted and [r0 - r10]/mem  ^^^^^^^^^^((((((((^ | ^))))))))')
                new_data = data.append_annotation(TaintedAnnotation())

        r = super().store(addr, new_data, **kwargs)

        # do something else

        return r

#---------------------------------------------------------------------------------------------------------
# Trustzone aware memory
#---------------------------------------------------------------------------------------------------------

class TrustzoneAwareMemory(
    # HexDumperMixin, # adds the hex_dump function which is quite slow
    SmartFindMixin,
    UnwrapperMixin, # description: processes SimActionObjects by passing on their .ast field.
    NameResolutionMixin, # description: allows you to provide register names as load addresses, and will automatically translate this to an offset and size.
    DataNormalizationMixin, # description: Normalizes the data field for a store and the fallback field for a load to be BVs.
    SimplificationMixin, # hooks stores and first calls state.solver.simplify(data) if options.SIMPLIFY_[MEMORY/REGISTER]_WRITES is set
    InspectMixinHigh, # The logic to inspect memory/register reads/writes --> calls ._inspect before/after.
    ActionsMixinHigh,
    UnderconstrainedMixin,
    SizeConcretizationMixin,
    SizeNormalizationMixin,
    TrustzoneAwareMixin,     # Trustzone mixin that does the secret tainting
    AddressConcretizationMixin,
    #InspectMixinLow,
    ActionsMixinLow,
    ConditionalMixin,
    ConvenientMappingsMixin,
    DirtyAddrsMixin,
    # -----
    StackAllocationMixin,
    ConcreteBackerMixin,
    ClemoryBackerMixin,
    DictBackerMixin,
    PrivilegedPagingMixin,
    UltraPagesMixin,
    DefaultFillerMixin,
    SymbolicMergerMixin,

    # Paged memory that dispatches to individual pages.
    # Needs size and addr of both store and load to be concretized (int)
    # PagedMemoryMixin does not return a context and is the last mixin to execute
    PagedMemoryMixin,

):
    pass

#---------------------------------------------------------------------------------------------------------

class TaintedAnnotation(claripy.Annotation):
    """
    Annotation for doing taint-tracking in angr.
    """
    
    @property
    def eliminatable(self):
        return False

    @property
    def relocatable(self):
        return True

    def relocate(self, src, dst):
        srcAnnotations = list(src.annotations)
        if len(srcAnnotations) == 0: return None
        elif len(srcAnnotations) == 1: return srcAnnotations[0]
        else: raise ValueError("more than one annotation: {}".format(srcAnnotations))

def taintedUnconstrainedBits(state, name, bits):
    """
    name: a name for the BVS
    bits: how many bits long
    """
    return state.solver.Unconstrained(name, bits, key=("tainted_"+name,), eternal=False, annotations=(TaintedAnnotation(),))

def is_tainted(ast):
    return _is_immediately_tainted(ast) or any(_is_immediately_tainted(v) for v in ast.leaf_asts())

def _is_immediately_tainted(ast):
    return any(isinstance(a, TaintedAnnotation) for a in ast.annotations)

#---------------------------------------------------------------------------------------------------------

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
    if not is_tainted(expr):
        if state.globals["secret_branching"]:
            if reg_name in register_list:
                print('Write', state.inspect.reg_write_expr, 'to', reg_name, "state.ip: ", hex(state.scratch.ins_addr))
                state.inspect.reg_write_expr = expr.append_annotation(TaintedAnnotation())
   
def track_mem_writes(state):

    #print('------- Write', state.inspect.mem_write_expr, 'to', state.inspect.mem_write_address)
    #print(f'State has information_leakage: {str(state.globals["secret_branching"])}')

    expr = state.inspect.mem_write_expr
    mem_addr = state.solver.eval(state.inspect.mem_write_address)
    if not is_tainted(expr):
        if state.globals["secret_branching"]:
            print('------- Write', state.inspect.mem_write_expr, 'to', state.inspect.mem_write_address)
            state.inspect.mem_write_expr = expr.append_annotation(TaintedAnnotation())


def stop_information_leakage(state):
    if state.globals['secret_branching']:
        #print("^^^^^^^^^^^^please do it correctly: ", state.globals['branch_number'], "state.ip: ", hex(state.scratch.ins_addr))
        #state.globals['branch_number'] -= 1
    #if state.globals['branch_number'] == 0:
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
            #state.globals['branch_number'] += 1 

    elif ins.mnemonic in ['cmp'] and not state.globals['secret_branching']:
        print("&&&&&&&&&&&&&&&&& inside the cmp &&&&&&&&&&&&&&&&&")
        parts = ins.op_str.split(', ')
        print(parts)
        reg_is_tainted = False
        for p in parts:
            if 'r' in p:
                reg = getattr(state.regs, p)
                if is_tainted(reg):
                    reg_is_tainted = True
        
        state.globals['state_reg_tainted'] = reg_is_tainted

#-----------------------------------Main-----------------------------------------------  

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

#----------------------------------------------------------------------------------   
    from angr.sim_state import SimState
    SimState.register_default('sym_memory', TrustzoneAwareMemory)
    proj = angr.Project('testcase/call', load_options={'auto_load_libs': False})
    
    main_size = proj.loader.main_object.get_symbol("main").size
    main_addr = proj.loader.main_object.get_symbol("main").rebased_addr
    state = proj.factory.entry_state(addr=main_addr)
    state.globals['state_reg_tainted'] =  False
    state.globals['secret_branching'] =  False
#----------------------------------Initial register tagging --------------------------------- 
    for reg_name in input_reg:
        reg = getattr(state.regs, reg_name)
        new_reg = reg.append_annotation(TaintedAnnotation())
        setattr(state.regs, reg_name, new_reg)
#------------------------------------Set Breakpoint ------------------------------------------ 
    #state.inspect.b('reg_write', when=angr.BP_AFTER, action=track_writes)
    #state.inspect.b('mem_write', when=angr.BP_AFTER, action=track_mem_writes)
    state.inspect.b('instruction', when=angr.BP_BEFORE, action=track_instruction)

    for junction in junction_dict:        
        state.project.hook(int(junction_dict[junction], 16), stop_information_leakage)
#--------------------------------------Symbolic Executing ------------------------------------  
    simgr = proj.factory.simulation_manager(state)

    tech = angr.exploration_techniques.DFS()
    simgr.use_technique(tech)

    while len(simgr.active) > 0:
        print("^^^^^^^^^^^^^^^^^^^^^^^^^^: ", simgr.active)
        simgr.step()
        # move all but one state from simgr.active to simgr.later
        # if len(simgr.active) == 0 but len(simgr.later) > 0:
        # move one from simgr.later to simgr.active
        # simgr.move(from_stash='active', to_stash='incorrect', filter_func=lambda x: x in wrong_jumps)

    
    #print('secret_branch_list: ', secret_branch)
    print(f'number of deadended states: {str(simgr.stashes)}')
    for s in simgr.unconstrained:
        #print_state_backtrace_formatted(s)
        print('-----------------------------------------------\n')
        for reg_name in proj.arch.register_names.values():
            reg = getattr(s.regs, reg_name)
            if is_tainted(reg):
                print(reg_name, reg)
    
        changed_bytes_list = s.memory.changed_bytes(state.memory)
        for addr in changed_bytes_list:
            value = s.memory.load(addr, 1)
            if is_tainted(value):
                print(hex(addr), value)

#----------------------------------------------------------------------------------  

if __name__ == '__main__':
    sys.exit(main())