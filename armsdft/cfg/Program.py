import networkx as nx
from armsdft.cfg.NetworkXConvert import NetworkXConvert


class Program:
    def __init__(self):
        self.functions = {}
        self.functions_with_callers = {}
        self.entry_point = None
        self.possible_exit_points = []
        self.exit_point = None

        self.graph = None

        self.sp = 0
        self.reg_map = {}
        self.mem_map = {}


    def add_function(self, function):
        self.functions.update({
            function.name: function
        })

    def set_entry_point(self, ep):
        if self.entry_point == ep:
            return
        self.entry_point = ep

        print("***** Starting CFG *******")
        
        conv = NetworkXConvert(self)
        self.graph = conv.create_graph_from(ep)

    def get_exit_point(self):
        return self.exit_point

    def get_instruction_at_execution_point(self, ep):
        if ep.has_caller():
            key = ep.caller
            if key not in self.functions_with_callers.keys():
                self.functions_with_callers[key] = self.functions[ep.function].get_for_caller(ep.caller)
            return self.functions_with_callers[key].instructions[ep]
        else:
            return self.functions[ep.function].instructions[ep]