
import json
import sys

from armddft.verifier.Analysis import Analysis
from armddft.parser.ConfigParser import ConfigParser
from armddft.parser.Parser import Parser

def main():
    args = sys.argv
    if args is None or len(args) < 2:
        print('Run using a path to a json file')
        return 0

    config_parser = ConfigParser()
    config_parser.parse_file(args[1])
    program = Parser.parse_file(config_parser.get_file_path(), config_parser.get_starting_function())

    analysis = Analysis(program)
    starting_ep = program.functions[config_parser.get_starting_function()].\
        first_instruction.get_execution_point()
    starting_ac = config_parser.get_starting_ac()
    finishing_ac = config_parser.get_finishing_ac()
    timing_sensitive = config_parser.get_timing_sensitive()
    result = analysis.analyze(starting_ep, starting_ac, finishing_ac, timing_sensitive)

    output = {
        'result': result.result.name,
        'result_code': result.result.value,
        'execution_point': None if result.ep is None else {
            'function': result.ep.function,
            'address': hex(result.ep.address)
        },
        'unique_ret': str(result.unique_ret)
    }
    print(json.dumps(output))

    return 0

if __name__ == '__main__':
    sys.exit(main())



    #print(cap_ins)# <>
            #print(cap_ins.mnemonic) # addseq
            #print("length: ", len(cap_ins.bytes))
            #print("operand: ", cap_ins.op_str) #<r1, r7>
            #print("id: ", cap_ins.id , "address: ", hex(cap_ins.address))
            #for r in cap_ins.regs_read:
                #print("reg_read: %s " %cap_ins.reg_name(r))
            #for r in cap_ins.regs_write:
                #print("reg_write: %s " %cap_ins.reg_name(r))
   # insnlist = list(ins_mnemonic)
        #for csinsn in insnlist:
            #print(csinsn)



# for mov

"""

def get_successors(self):
        oplist = self.oplist.split()
        if(oplist[0][0] == '3' and oplist[0][1] == '0' and oplist[0][2] == '4' and oplist[0][3] == '1'): # ret
            if self.get_execution_point().has_caller():
                return [self.get_execution_point().caller]
            else:
                return []

        elif(oplist[0][0] == '3' and oplist[0][1] == '0' and oplist[0][2] == '4' and oplist[0][3] == '0'): # br
            hex_addr =  oplist[0][6] + oplist[0][7] + oplist[0][4] + oplist[0][5]
            br_target = int(hex_addr, 16)
            target = ExecutionPoint(self.function.name, br_target, self.function.caller)
            return [target,]
            
        else:
            return [self.get_execution_point().forward(self.length*2)]


"""
