from scfarm.cfg.RegionComputation import RegionComputation
from scfarm.cfg.instructions.AbstractInstructionControlFlow import AbstractInstructionControlFlow
from scfarm.flowanalysis.exceptions.BranchtimeDiffersException import BranchtimeDiffersException
from scfarm.flowanalysis.exceptions.LoopOnHighConditionException import LoopOnHighConditionException
from scfarm.flowanalysis.exceptions.NemisisOnHighConditionException import NemisisOnHighConditionException
from scfarm.flowanalysis.exceptions.BUStedOnHighConditionException import BUStedOnHighConditionException


class AbstractInstructionBranching(AbstractInstructionControlFlow):
    def __init__(self, function):
        super(AbstractInstructionBranching, self).__init__(function)
        self.regions_computed = False
        self.region_then = set()#[]
        self.region_else = set()#[]
        self.junction = set()
        self.nemesis_region_then = []
        self.nemesis_region_else = []
        self.then_number = 0
        self.else_number = 0

    def get_successors(self):
        ret = super(AbstractInstructionBranching, self).get_successors()
        ret.append(self.get_branch_target())
        return ret

    def compute_regions(self):
        computation = RegionComputation(self.program, self.region_then, self.region_else, \
            self.nemesis_region_then, self.nemesis_region_else, self.junction)
        self.region_then, self.nemesis_region_then, self.region_else, \
            self.nemesis_region_else, self.junction = computation.start_computation(self)


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
        if self.condition != '':
            if not self.regions_computed:
                self.compute_regions()
                self.regions_computed = True

        return self.junction

    def vulnerable_to_BUSted(self):
        then_busted_list = []
        else_busted_list = []
        t_then = 1
        t_else = 0
        busted = False
        #print("then: ", self.nemesis_region_then)
        #print("else: ", self.nemesis_region_else)
        for ep_then in self.nemesis_region_then:
            instr_then = self.program.get_instruction_at_execution_point(ep_then)
            if(instr_then.name == 'str' or instr_then.name == 'ldr'):
                then_busted_list.append(t_then)
            t_then += instr_then.get_execution_time()
            
        for ep_else in self.nemesis_region_else:
            instr_else = self.program.get_instruction_at_execution_point(ep_else)
            if(instr_else.name == 'str' or instr_else.name == 'ldr'):
                else_busted_list.append(t_else)
            t_else += instr_else.get_execution_time()
        
        #print("****************", then_busted_list, else_busted_list)

        if(len(then_busted_list) != len(else_busted_list)):
            busted = True
        
        for t1, t2 in zip(then_busted_list, else_busted_list):
            if(t1 != t2):
                busted = True

        return busted
  
    def compare_region(self):
        for ep_then , ep_else in zip(self.nemesis_region_then, self.nemesis_region_else):
            instr_then = self.program.get_instruction_at_execution_point(ep_then)
            instr_else = self.program.get_instruction_at_execution_point(ep_else)
            if(instr_then.get_execution_time() != instr_else.get_execution_time()):
                return True
        return False

    def vulnerable_to_nemesis(self):
        nemesis = True
        #if(len(self.nemesis_region_then) == len(self.nemesis_region_else)):
            #nemesis = self.compare_region()
        return nemesis

    def is_loop(self):
        """
        Predicate that checks whether this branch is a loop
        or a condition. Returns True when this is a loop.
        :return:
        """
        return self.immediate_dominator in self.get_region_else() or self.immediate_dominator in self.get_region_then()

    def execute_judgment(self):
        
        if self.is_loop():
            raise LoopOnHighConditionException()
        
        #if self.vulnerable_to_nemesis():
            #raise NemisisOnHighConditionException()

        #if self.vulnerable_to_BUSted():
            #raise BUStedOnHighConditionException()

        if not self.is_loop():
            #print(self.get_branchtime_then(), self.get_branchtime_else()) 
            if not (self.get_branchtime_then() + self.get_branching_time() == self.get_branchtime_else()):
                raise BranchtimeDiffersException()

 