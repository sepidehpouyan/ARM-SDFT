from armsdft.verifier.SecurityLevel import SecurityLevel
from armsdft.verifier.exceptions.BranchtimeDiffersException import BranchtimeDiffersException
from armsdft.verifier.exceptions.LoopOnHighConditionException import LoopOnHighConditionException
from armsdft.verifier.exceptions.NemisisOnHighConditionException import NemisisOnHighConditionException

from armsdft.cfg.RegionComputation import RegionComputation
from armsdft.cfg.instructions.AbstractInstructionControlFlow import AbstractInstructionControlFlow


class AbstractInstructionBranching(AbstractInstructionControlFlow):
    def __init__(self, function):
        super(AbstractInstructionBranching, self).__init__(function)
        self.regions_computed = False
        self.region_then = set()#[]
        self.region_else = set()#[]
        self.nemesis_region_then = []
        self.nemesis_region_else = []
        self.junction = None
        self.then_number = 0
        self.else_number = 0

    def get_successors(self):
        ret = super(AbstractInstructionBranching, self).get_successors()
        ret.append(self.get_branch_target())
        return ret

    def compute_regions(self):
        computation = RegionComputation(self.program, self.region_then, self.region_else, \
            self.nemesis_region_then, self.nemesis_region_else)
        self.region_then, self.nemesis_region_then, self.region_else, self.nemesis_region_else, self.junction = computation.start_computation(self)


    def get_region_then(self):
        if self.condition != '':
            if not self.regions_computed:
                self.compute_regions()
                self.regions_computed = True
            #print("Branching then: ", self.region_then)
        return self.region_then

    def get_region_else(self):
        if self.condition != '':
            if not self.regions_computed:
                self.compute_regions()
                self.regions_computed = True
        #print("Branching else: ", self.region_else)
        return self.region_else

    def get_junction(self):
        if not self.regions_computed:
            self.compute_regions()
            self.regions_computed = True

        return self.junction

    def compare_region(self):
        for ep_then , ep_else in zip(self.nemesis_region_then, self.nemesis_region_else):
            instr_then = self.program.get_instruction_at_execution_point(ep_then)
            instr_else = self.program.get_instruction_at_execution_point(ep_else)
            if(instr_then.get_execution_time() != instr_else.get_execution_time()):
                return True
        return False

    def have_nemesis(self):
        nemesis = True
        if(len(self.nemesis_region_then) == len(self.nemesis_region_else)):
            nemesis = self.compare_region()
        return nemesis

    def is_loop(self):
        """
        Predicate that checks whether this branch is a loop
        or a condition. Returns True when this is a loop.
        :return:
        """
        return self.immediate_dominator in self.get_region_else() or self.immediate_dominator in self.get_region_then()

    def get_branching_condition_domain(self, ac):
        """
        Returns the security domain this branch depends on.
        This is specific to the concrete command, hence can't
        be implemented here directly.
        :return:
        """
        pass

    def execute_judgment(self, ac):
        # Exit early if this branch depends on LOW data
        if (self.get_branching_condition_domain(ac) & ac.secenv.get(self.get_execution_point())) == SecurityLevel.LOW:
            return

        # From here on, this branch depends on HIGH data

        for ep in self.get_region_then():
            ac.secenv.set(ep, SecurityLevel.HIGH)
        for ep in self.get_region_else():
            ac.secenv.set(ep, SecurityLevel.HIGH)

        if self.is_loop():
            raise LoopOnHighConditionException()
        
        #if self.have_nemesis():
            #raise NemisisOnHighConditionException()

        if not self.is_loop():
            print(self.get_branchtime_then() + self.get_branching_time())
            print(self.get_branchtime_else())
            #if not (self.get_branchtime_then() + self.get_branching_time() == self.get_branchtime_else()):
                #raise BranchtimeDiffersException()

 