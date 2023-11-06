import json

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

    def get_security_level(self):
        input_reg = []
        r = 0
        for param in self.data['parameters']:
            if param['confidential']:
                input_reg.append('r' + str(r))
            r += 1
        return input_reg


    def get_starting_function(self):
        return self.data['starting_function']

    def get_include_functions(self):
        return self.data.get('include_functions', None)

    def get_timing_sensitive(self):
        return self.data.get('timing_sensitive', True)
