import json

import math

from armsdft.verifier.AssignmentCollection import AssignmentCollection
from armsdft.verifier.SecurityLevel import SecurityLevel

class ConfigParser:
    def __init__(self):
        self.data = {}

    def parse_file(self, file):
        string = ''
        with open(file) as f:
            for line in f:
                string += line

        self.parse_string(string)

    def parse_string(self, string):
        self.data = json.loads(string)

    def get_file_path(self):
        return self.data['file']

    def set_parameters(self, ac, parameters, to):
        r = 0
        for param in parameters:
            if param['confidential']:
                ac.ra.set('r' + str(r), to)
            r += 1

    def get_starting_ac(self):
        ac = AssignmentCollection.bottom()
        self.set_parameters(ac, self.data['parameters'], SecurityLevel.HIGH)
        return ac

    def get_finishing_ac(self):
        ac = AssignmentCollection.top()
        self.set_parameters(ac, [self.data['result']], SecurityLevel.LOW)
        return ac

    def get_starting_function(self):
        return self.data['starting_function']

    def get_include_functions(self):
        return self.data.get('include_functions', None)

    def get_timing_sensitive(self):
        return self.data.get('timing_sensitive', True)
