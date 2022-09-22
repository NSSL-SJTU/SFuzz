# coding:utf-8
# find trans

try:
    # For https://github.com/VDOO-Connected-Trust/ghidra-pyi-generator
    from ghidra.ghidra_builtins import *
    from functools import reduce
except:
    pass
import os
import json
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.symbol import FlowType
from ghidra.program.model.pcode import PcodeOp,PcodeOpAST
from ghidra.program.model.address import GenericAddress
from ghidra.program.model.symbol import SourceType
from ghidra.util.exception import DuplicateNameException
from ghidra.app.plugin.core.analysis import DefaultDataTypeManagerService
from ghidra.app.util.parser import FunctionSignatureParser
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd

output_dir_name = currentProgram.getExecutablePath().split('/')[-1] + '_result'

hfunc_cache = {}

def get_hfunction(func):
    func_entry_offset = func.getEntryPoint().getOffset()
    if func_entry_offset in hfunc_cache:
        return hfunc_cache.get(func_entry_offset)
    decomplib = DecompInterface()
    decomplib.openProgram(currentProgram)
    timeout = 10
    dRes = decomplib.decompileFunction(func, timeout, getMonitor())
    hfunction = dRes.getHighFunction()
    hfunc_cache[func_entry_offset] = hfunction
    return hfunction

class FlowNode:

    def __init__(self, vn):
        self.vn = vn

    def get_value(self):
        if not self.vn:
            return None
        if self.vn.isAddress():
            vn_data = getDataAt(self.vn.getAddress())
            if not vn_data:
                return None
            return vn_data.getValue()
        elif self.vn.isConstant():
            return self.vn.getAddress()
        elif self.vn.isUnique():
            return self.calc_pcode(self.vn.getDef())
        elif self.vn.isRegister():
            return self.calc_pcode(self.vn.getDef())
        elif self.vn.isAddrTied():
            return self.calc_pcode(self.vn.getDef())

    def calc_pcode(self, pcode):
        if isinstance(pcode, PcodeOpAST):
            opcode = pcode.getOpcode()
            if opcode == PcodeOp.PTRSUB:
                var_node_1 = FlowNode(pcode.getInput(0))
                var_node_2 = FlowNode(pcode.getInput(1))
                value_1 = var_node_1.get_value()
                value_2 = var_node_2.get_value()
                if isinstance(value_1, GenericAddress) and isinstance(value_2, GenericAddress):
                    return toAddr(value_1.offset + value_2.offset)
                else:
                    return None
            elif opcode == PcodeOp.PTRADD:
                var_node_0 = FlowNode(pcode.getInput(0))
                var_node_1 = FlowNode(pcode.getInput(1))
                var_node_2 = FlowNode(pcode.getInput(2))
                try:
                    value_0 = var_node_0.get_value()
                    if not isinstance(value_0, GenericAddress):
                        return
                    value_1 = var_node_1.get_value()
                    if not isinstance(value_1, GenericAddress):
                        return
                    if pcode.getNumInputs() == 3:
                        value_2 = var_node_2.get_value()
                        if not isinstance(value_2, GenericAddress):
                            return
                        return toAddr(value_0.offset + value_1.offset * value_2.offset)
                    elif pcode.getNumInputs() == 2:
                        return toAddr(value_0.offset + value_1.offset)
                except Exception as err:
                    return None
                except:
                    return None
            elif opcode == PcodeOp.COPY or opcode == PcodeOp.INDIRECT or opcode == PcodeOp.CAST:
                var_node_1 = FlowNode(pcode.getInput(0))
                value_1 = var_node_1.get_value()
                if isinstance(value_1, GenericAddress):
                    return value_1
                else:
                    return None
        else:
            return None


TERMINATOR = '\00'

def custom_get_str(addr, length):
    ret = ""
    for i in range(length):
        b = currentProgram.getMemory().getByte(addr)
        if b >= 0x20 and b <= 0x7f:
            ret += chr(b)
        addr = addr.addNoWrap(1)
    return ret


def get_str_from_vn(vn):
    val = FlowNode(vn).get_value()
    if val and (isinstance(val, GenericAddress)) and currentProgram.getMaxAddress() >= val >= currentProgram.getMinAddress():
        data = getDataAt(val)
        if data and data.hasStringValue():
            return data.getValue().strip('"')
        if not data:
            end_addr = find(val, TERMINATOR)
            if not end_addr:
                return None
            length = end_addr.getOffset() - val.getOffset()
            if length > 1:
                str_data = custom_get_str(val, length)
                return str_data.strip('"')
    return None


def may_trans_func(func,refers):
    if len(refers) < 10:
        return False,0,0
    call_refers = [x for x in refers if x.getReferenceType() == FlowType.UNCONDITIONAL_CALL]
    if len(call_refers) < 10:
        return False,0,0
    for call_ref in call_refers[:5]:
        caller = getFunctionContaining(call_ref.getFromAddress())
        if not caller:
            continue
        high_caller = get_hfunction(caller)
        if not high_caller:
            continue
        for item in high_caller.getPcodeOps(call_ref.getFromAddress()):
            if item.getOpcode() == PcodeOp.CALL and item.getInput(0).getAddress() == func.getEntryPoint():
                param_num = item.getNumInputs()
                if param_num < 3:
                    break
                str_count = 0
                current = 0
                for i in range(1, param_num):
                    str_key = get_str_from_vn(item.getInput(i))
                    if str_key:
                        str_count += 1
                        current = i
                if str_count == 1:
                    return True,current,param_num
    return False,0,0


def main():
    referManger = currentProgram.getReferenceManager()
    map_res = {}
    all_count = currentProgram.getFunctionManager().getFunctionCount()
    count = 0
    for func in currentProgram.getFunctionManager().getFunctions(True):
        count += 1
        print("{}/{}".format(count,all_count))
        # if not func.getName().startswith('model'):
        #     continue
        func_entry_offset = func.getEntryPoint().getOffset()
        refersIter = referManger.getReferencesTo(func.getEntryPoint())
        refers = []
        while refersIter.hasNext():
            refers.append(refersIter.next())
        may_trans,str_pos,param_len = may_trans_func(func,refers)
        if not may_trans:
            continue
        if func_entry_offset not in map_res:
            map_res[func_entry_offset] = {
                'param_sign': (str_pos,param_len),
                'keys': set()
            }
        call_refers = [x for x in refers if x.getReferenceType() == FlowType.UNCONDITIONAL_CALL]
        for call_ref in call_refers:
            caller = getFunctionContaining(call_ref.getFromAddress())
            if not caller:
                continue
            high_caller = get_hfunction(caller)
            if not high_caller:
                continue
            for item in high_caller.getPcodeOps(call_ref.getFromAddress()):
                if item.getOpcode() == PcodeOp.CALL and item.getInput(0).getAddress() == func.getEntryPoint():
                    str_key = get_str_from_vn(item.getInput(str_pos))
                    map_res[func_entry_offset]['keys'].add(str_key)
                    break
    hash_set = set()
    if not os.path.exists('%s/findtrace_output/%s' % (os.getcwd(),output_dir_name)):
        os.makedirs('%s/findtrace_output/%s' % (os.getcwd(),output_dir_name))
    with open('%s/findtrace_output/%s/convey.txt' % (os.getcwd(),output_dir_name), 'w') as f:
        for key1 in map_res:
            for key2 in map_res:
                if key1 != key2 and is_param_sign_equal(map_res[key1]['param_sign'],map_res[key2]['param_sign']):
                    if (key1,key2) in hash_set:
                        continue
                    hash_set.add((key1,key2))
                    hash_set.add((key2, key1))
                    if len(map_res[key1]['keys'] & map_res[key2]['keys']) > (len(map_res[key1]['keys']) + len(map_res[key2]['keys']))/4.0\
                            and abs(len(map_res[key1]['keys']) - len(map_res[key2]['keys'])) < min(len(map_res[key1]['keys']),len(map_res[key2]['keys'])):
                        f.write("{}:{}\n".format(getFunctionAt(toAddr(key1)).getName(),getFunctionAt(toAddr(key2)).getName()))

def is_param_sign_equal(item1, item2):
    if item1[1] == item2[1]:
        if item1[0] == item2[0]:
            return True
    if abs(item1[1] - item2[1]) == 1:
        return True

def change_func_sign(sign, func):
    try:
        parser = FunctionSignatureParser(currentProgram.getDataTypeManager(), DefaultDataTypeManagerService())
        # print("sign: %r"%sign)
        fddt = parser.parse(func.getSignature(), sign)
        cmd = ApplyFunctionSignatureCmd(func.getEntryPoint(), fddt, SourceType.USER_DEFINED, True, True)
        cmd.applyTo(currentProgram, getMonitor())
    except Exception as e:
        print("chang func sign failed for {} -> {}".format(func.getName(), sign))


if __name__ == '__main__':
    # apply simresult to current program
    if os.path.exists(currentProgram.getExecutablePath() + '.simresult'):
        print("Reading simresult from %s" % (currentProgram.getExecutablePath() + '.simresult'))
        with open(currentProgram.getExecutablePath() + '.simresult', 'r') as f:
            simresults = json.load(f)
    else:
        print("No simresult found")
        simresults = None
    if simresults:
        for simresult in simresults:
            offset = int(simresult['offset'], 16)
            funcName = simresult['funcName']
            function = getFunctionAt(toAddr(offset))
            if function:
                try:
                    function.setName(funcName, SourceType.DEFAULT)
                except DuplicateNameException as e:
                    print("DuplicateNameException:", e)
            elif not createFunction(toAddr(offset), funcName):
                print("Failed to create function %s @ 0x%08x" % (funcName, offset))
            funcSign = simresult.get('funcSign')
            function = getFunctionAt(toAddr(offset))
            if funcSign and function:
                change_func_sign(funcSign, function)
    main()