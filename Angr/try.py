import angr
import capstone

def print_state_backtrace_formatted(state):
    """
    Returns the block backtrace for a given state, formatted as a list of strings that can be printed immediately.
    """
    bbt = []
    for a in state.history.bbl_addrs:
        sym = state.project.loader.find_symbol(a, fuzzy=True)
        rel = a - state.project.loader.min_addr
        #print("min_addr: ", hex(state.project.loader.min_addr), "rel_addr: ", hex(rel))
        bbt.append(f'{a:#x} {sym.name:<35} ({rel:#x} relative to obj base)')
    print("\n".join(bbt))


def do_step():

    """
    Helper to make a single step in the program and direclty print our existing program traces.
    """

    # Set up Capstone to disassemble ARM instructions
    cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)

    print("Step: ", sm.step())
    #print("Length of sm.active: ", len(sm.active), type(sm.active))
    print("sm.active: ", sm.active)
    for s in sm.active:
        print("State:")
        print_state_backtrace_formatted(s)
        #print("Current basic block:")

        rip = s.solver.eval(s.regs.ip)
        current_block = s.project.factory.block(rip)

        #disasm = s.project.analyses.Disassembly(ranges=[(current_block.addr, current_block.addr + current_block.size)])
        #print(disasm)
        insn = cs.disasm(current_block.bytes, current_block.addr)
        ins = insn.__next__()
        #print("insssssssssssss: ", ins)
        #pretty_print = disasm.render()
        #pretty_print_str = "".join([f'\t{line}\n' for line in pretty_print.split('\n')])

        #sym = s.project.loader.find_symbol(rip, fuzzy=True)
        #print(f'=== ASM START ===')
        #print(f'{sym.name}:')
        #print(pretty_print_str)
        #print(f'=== ASM END   ===')


class ExitState(angr.SimProcedure):
    """
    Simple Procedure that just aborts the exploration of this state.
    """
    def run(self, return_values=None):
        self.exit(0)


# load binary
p = angr.Project('fork', main_opts={'backend': 'elf', 'arch': 'ARMEL'}) # ARMCortexM


# Hook the _exit symbol as that is an infinite loop that we want to abort on
p.hook_symbol('_exit', ExitState())

# Get the simulation manager from angr
sm = p.factory.simgr()

# Perform a loop that calls our do_step function while there are still 'active' states
while len(sm.active) > 0:
    do_step()

