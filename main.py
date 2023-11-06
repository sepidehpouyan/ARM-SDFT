
import json
import sys

from scfarm.parser.ConfigParser import ConfigParser
from scfarm.parser.Parser import Parser
from scfarm.flowanalysis.Angr import Angr 
from scfarm.flowanalysis.Analysis import Analysis


def main():
    args = sys.argv
    if args is None or len(args) < 2:
        print('Run using a path to a json file')
        return 0

    config_parser = ConfigParser()
    config_parser.parse_file(args[1])
    config_parser.get_security_level()
    program = Parser.parse_file(config_parser.get_file_path(), config_parser.get_starting_function())
    
    starting_ep = program.functions[config_parser.get_starting_function()].\
        first_instruction.get_execution_point()
    junction = program.set_entry_point(starting_ep)

    angr = Angr(config_parser.get_file_path(), config_parser.get_starting_function())
    secret_branch = angr.check_info_flow(config_parser.get_security_level(), junction)

    analysis = Analysis(program)
    result = analysis.analyze(starting_ep, secret_branch)

    output = {
        'result': result.result.name,
        'result_code': result.result.value,
        'execution_point': None if result.ep is None else {
            'function': result.ep.function,
            'address': hex(result.ep.address)
        }
    }
    print(json.dumps(output))

    return 0

if __name__ == '__main__':
    sys.exit(main())
