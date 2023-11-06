import angr
import claripy
import logging
import capstone
from angr.storage import MemoryMixin
from angr.sim_state import SimState

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

#-------------------------------------------------------------------------

def taintedUnconstrainedBits(state, name, bits):
        """
        name: a name for the BVS
        bits: how many bits long
        """
        return state.solver.Unconstrained(name, bits, key=("tainted_"+name,), eternal=False, annotations=(TaintedAnnotation(),))

def _is_immediately_tainted(ast):
        return any(isinstance(a, TaintedAnnotation) for a in ast.annotations)
    
def is_tainted(ast):
        return _is_immediately_tainted(ast) or any(_is_immediately_tainted(v) for v in ast.leaf_asts())

#-------------------------------------------------------------------------

class TrustzoneAwareMixin(MemoryMixin):

    def store(self, addr, data, **kwargs):
        reg_name =  ''
        #print('before if', data, 'to', addr)
        #print(self.category)
        if (self.category == 'reg'):
            reg_name = self.state.arch.register_names[self.state.solver.eval(addr)]
            #print(reg_name)
        #if is_tainted(data):
            #print('yessssssssssssssssssss it is tainted')

        new_data = data

        if 'secret_branching' in self.state.globals and self.state.globals["secret_branching"]:
            #print('Write', data, 'to', addr, "state.ip: ", hex(self.state.scratch.ins_addr))
            if not is_tainted(data) and reg_name not in register_list:
                #print('data is not tainted and [r0 - r10]/mem  ^^^^^^^^^^^^^^^^^^^^^^^^')
                new_data = data.append_annotation(TaintedAnnotation())

        r = super().store(addr, new_data, **kwargs)

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

#----------------------------------------------------------------------------------------------

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
        elif len(srcAnnotations) > 1: return srcAnnotations[0]
        #else: raise ValueError("more than one annotation: {}".format(srcAnnotations))

#-----------------------------------------------------------------------------------------------

class Angr:
    def __init__(self, file, starting_function):
        logging.disable(logging.WARNING)

        self.secret_branch = set()

        SimState.register_default('sym_memory', TrustzoneAwareMemory)
        self.proj = angr.Project(file, load_options={'auto_load_libs': False})
        
        main_addr = self.proj.loader.main_object.get_symbol(starting_function).rebased_addr
        self.state = self.proj.factory.entry_state(addr=main_addr)
        self.state.globals['state_reg_tainted'] =  False
        self.state.globals['secret_branching'] =  False
        
    #-----------------------------------------------------------------------
    def stop_information_leakage(self, state):
        if state.globals['secret_branching']:
            print('stop_information_leakage')
            state.globals['secret_branching'] = False

    def track_instruction(self, state):
        #print('___________****___________', state.inspect.instruction)
        if state.inspect.instruction is not None:
            block = state.project.factory.block(state.inspect.instruction)
            insn = cs.disasm(block.bytes, state.inspect.instruction)
            ins = insn.__next__()

            #print(f"Current instruction: {ins.mnemonic} -- {ins.op_str}")

        if ins.mnemonic in conditional_branch:
            #print('^^^^^branch^^^^^^')
            if state.globals['state_reg_tainted']:
                state.globals['secret_branching'] = True
                #print(ins.mnemonic, hex(state.inspect.instruction))
                self.secret_branch.add(hex((state.inspect.instruction) -1))
            #print("secret branch in track ins: ", self.secret_branch)

        elif ins.mnemonic in ['cmp'] and not state.globals['secret_branching']:
            parts = ins.op_str.split(', ')
            reg_is_tainted = False
            for p in parts:
                if 'r' in p:
                    reg = getattr(state.regs, p)
                    if is_tainted(reg):
                        reg_is_tainted = True
            
            state.globals['state_reg_tainted'] = reg_is_tainted

    #---------------------------------------------------------------------------
    def check_info_flow(self, input_list, input_dict):
        #Initial register tagging
        for reg_name in input_list:
            reg = getattr(self.state.regs, reg_name)
            new_reg = reg.append_annotation(TaintedAnnotation())
            setattr(self.state.regs, reg_name, new_reg)
       
        self.state.inspect.b('instruction', when=angr.BP_BEFORE, action = self.track_instruction)
    
        for junction in input_dict:   
            self.state.project.hook(int(input_dict[junction], 16), self.stop_information_leakage)
        
        #Symbolic Executing
        simgr = self.proj.factory.simulation_manager(self.state)

        tech = angr.exploration_techniques.DFS()
        simgr.use_technique(tech)

        while len(simgr.active) > 0:
            simgr.step()
        
        #if simgr.stashes['active'] and len(simgr.stashes['active']) % 100 == 0:
            #print(f"Reached {len(simgr.stashes['active'])} steps")
        #print('secret_branch_list: ', self.secret_branch)
        print(f'number of deadended states: {str(simgr.stashes)}')
        for s in simgr.unconstrained:
            #print_state_backtrace_formatted(s)
            print('-----------------------------------------------\n')
            for reg_name in self.proj.arch.register_names.values():
                reg = getattr(s.regs, reg_name)
                if is_tainted(reg):
                    print(reg_name, reg)
        
            changed_bytes_list = s.memory.changed_bytes(self.state.memory)
            for addr in changed_bytes_list:
                value = s.memory.load(addr, 1)
                if is_tainted(value):
                    print(hex(addr), value)

        return self.secret_branch