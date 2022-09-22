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
from ghidra.app.decompiler.component import DecompilerUtils

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

all_convey = {
    'modelWrite': 1,
    'modelRead': 1,
    'nvram_set': 1,
    'nvram_get': 1,
    'FUN_8002b64c': 1,
    'FUN_8002ae6c': 1,
    'setenv': 1,
    'getenv': 1,
    'set_local_var': 1,
    'get_local_var': 1
}

def init_func_map():
    func_map = {}
    funcs = currentProgram.getFunctionManager().getFunctions(True)
    for item in funcs:
        func_name = item.getName()
        if func_name not in func_map:
            func_map[func_name] = []
        func_map[func_name].append(item)
    return func_map


def custom_get_function(func_name):
    global GLOBAL_FUNC_MAP
    if func_name in GLOBAL_FUNC_MAP:
        return GLOBAL_FUNC_MAP[func_name][0]
    return None

def get_funcname_at_call(item):
    var_addr = item.getInput(0).getAddress()
    if not var_addr:
        return None
    func = getFunctionAt(var_addr)
    if not func:
        return None
    return func.getName()


def get_possible_str(var):
    varnodes = DecompilerUtils.getBackwardSlice(var)
    all_pocode = set()
    for item in varnodes:
        pcodes = DecompilerUtils.getForwardSliceToPCodeOps(item)
        for item in pcodes:
            all_pocode.add(item)
    ret = set()
    for item in all_pocode:
        for varnode in item.getInputs():
            one_str =  get_str_from_vn(varnode)
            if one_str:
                ret.add(one_str)
    return list(ret)


def get_all_not_const(refs_list,idx,target_name):
    ret_list = []
    for item in refs_list:
        fromAddr = item.getFromAddress()
        callingFunc = getFunctionContaining(fromAddr)
        if not callingFunc:
            continue
        # if callingFunc.getName() != 'dhcpv6cParamsUpdate':
        #     continue
        high_func = get_hfunction(callingFunc)
        if not high_func:
            continue
        pcodes = high_func.getPcodeOps(fromAddr)
        for pcode in pcodes:
            if pcode.getOpcode() == PcodeOp.CALL:
                called_name = get_funcname_at_call(pcode)
                if called_name and called_name == target_name:
                    target_var = pcode.getInput(idx)
                    if not target_var:
                        break
                    val = FlowNode(target_var).get_value()
                    if not val:
                        possible_strs = get_possible_str(target_var)
                        ret_list.append((str(fromAddr),possible_strs))
                    break
    return ret_list

def main():
    referManger = currentProgram.getReferenceManager()
    map_res = {}
    for key in all_convey:
        idx = all_convey[key]
        targert_func = custom_get_function(key)
        if not targert_func:
            continue
        target_res = {}
        refs_list = []
        for item in referManger.getReferencesTo(targert_func.getEntryPoint()):
            refs_list.append(item)
        target_res['xref_count'] = len(refs_list)
        may_dynamic = get_all_not_const(refs_list,idx,key)
        target_res['may_dynamic_count'] = len(may_dynamic)
        target_res['may_dynamic'] = may_dynamic
        map_res[key] = target_res

    if not os.path.exists('%s/findtrace_output/%s' % (os.getcwd(),output_dir_name)):
        os.makedirs('%s/findtrace_output/%s' % (os.getcwd(),output_dir_name))
    print('%s/findtrace_output/%s/dynamic.txt' % (os.getcwd(),output_dir_name))
    with open('%s/findtrace_output/%s/dynamic.txt' % (os.getcwd(),output_dir_name), 'w') as f:
        f.write(json.dumps(map_res,indent=4,ensure_ascii=False))

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
    if os.access(currentProgram.getExecutablePath() + '.simresult', os.F_OK):
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
    GLOBAL_FUNC_MAP = init_func_map()
    main()