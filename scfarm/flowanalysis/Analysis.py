from collections import namedtuple

from scfarm.flowanalysis.AnalysisResult import AnalysisResult
from scfarm.flowanalysis.exceptions.BranchtimeDiffersException import BranchtimeDiffersException
from scfarm.flowanalysis.exceptions.LoopOnHighConditionException import LoopOnHighConditionException
from scfarm.flowanalysis.exceptions.NemisisOnHighConditionException import NemisisOnHighConditionException
from scfarm.flowanalysis.exceptions.BUStedOnHighConditionException import BUStedOnHighConditionException

class Analysis:

    result = namedtuple('result', ['result', 'ep'])
    def __init__(self, program):
        self.program = program

    def analyze(self, starting_ep, secret_branch):
        pending_ep = [starting_ep]
        while len(pending_ep) > 0:
            
            current_ep = pending_ep.pop(0)
            current_instr = self.program.get_instruction_at_execution_point(current_ep)
            #print("address: ", hex(current_ep.address))
            if (hex(current_ep.address) in secret_branch):
                try:
                    current_instr.execute_judgment()
                except BranchtimeDiffersException:
                    return Analysis.result(AnalysisResult.TIMING_LEAK, current_ep)
                except NemisisOnHighConditionException:
                    return Analysis.result(AnalysisResult.NEMISIS_VULNERABILITY, current_ep)
                except LoopOnHighConditionException:
                    return Analysis.result(AnalysisResult.LOOP_ON_SECRET_DATA, current_ep)
                except BUStedOnHighConditionException:
                    return Analysis.result(AnalysisResult.BUSted_VULNERABILITY, current_ep)
            
            pending_ep.extend(current_instr.get_successors_checked())
        
        return Analysis.result(AnalysisResult.SUCCESS, None)