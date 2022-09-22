# coding:utf-8
# find trace
# 25min version

# NOTICE: OUTPUT FORMAT DEFINITION

# call patch output:
# <addr> nop <0 or 1>
#   0 or 1: stand for whether the subfuction contains subsubfunctions or not, angr will not patch the call instr if it equals 1, but fuzzer will still patch no matter 0 or 1

# jmp patch output:
# <addr> jmp <target addr> [avoid excution/exit emulation addr]
#   if target addr == 0, it means this condition jump is input-data-related, so angr and fuzzer will not patch this condition jmp, however the 4th args here stands for the branch that cannot reach target function, so fuzzer will interpret this addr and when it reaches this addr it will straightly end current simulation(so that AFL will consider current input as 'uninterested'), also angr will interpret this arg and abort any state that reach this addr
#   if target addr != 0, it means this condition jump is not input-data-related, so fuzzer will patch this condition jump(while angr will not), and angr will interpret the 4th arg so that it saves much time on simulating multiple states(while fuzzer will not)
#   the 4th args here is not requisite, which means if both branch are reachable to target function, obviously we should not do anything to program

import string
import re
import os
import json
import sys

from ghidra.app.plugin.core.analysis import DefaultDataTypeManagerService
from ghidra.app.util.parser import FunctionSignatureParser

try:
    import queue as Queue
except:
    import Queue
from ghidra.program.model.util import CodeUnitInsertionException
from ghidra.program.model.address import Address
from ghidra.app.decompiler import DecompInterface, DecompileOptions, DecompileResults
from ghidra.program.model.pcode import HighFunction
from ghidra.program.model.pcode import PcodeBlockBasic
from ghidra.program.model.listing import Function
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.block import CodeBlock
from ghidra.program.model.pcode import PcodeOp, Varnode, PcodeOpAST, HighSymbol
from ghidra.program.model.address import GenericAddress
import ghidra.program.model.address.GenericAddress
from ghidra.program.model.listing import Data
from ghidra.program.model.symbol import RefType
from ghidra.program.model.block import PartitionCodeSubModel
from ghidra.app.decompiler.component import DecompilerUtils
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.util.exception import DuplicateNameException
from ghidra.app.emulator import EmulatorHelper
from ghidra.program.model.pcode import HighParam,HighLocal
from ghidra.program.model.scalar import Scalar
import time
import json

try:
    # For https://github.com/VDOO-Connected-Trust/ghidra-pyi-generator
    from ghidra.ghidra_builtins import *
    from functools import reduce
except:
    pass


class FlowNode:

    def __init__(self, vn):
        self.vn = vn

    def get_value(self):
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

source_funcs = []
sink_funcs = []

maybe_source_funcs = {
    'Packt_WebGetsVar':"[0]",
    'recvfrom':"[0, 2]", 
    'recv':"[0, 2]",
    'jsonObjectGetString':"[0]",
    'jsonGetObjectString':'[0]',
    'json_object_get_decode':'[0]',
    'recv_http_response':'[2]',
    'os_file_get':'[1]',
    'os_get_file':'[1]',
    'getenv': '[1]',
    'j_getenv': '[1]',
    'webgetvar': '[0]',
    'bb_get_bt_context_ptr': '[0]'
}
maybe_sink_funcs = {
    'memcpy': "[3]",  # [2, 3]
    'memncpy': "[3]",
    'memmove': "[3]",  # [2, 3]
    'snprintf': "[2, 3]",  # [4, 2, 3, 5, 6, 7, 8]",
    'sprintf': "[3, 2, 4, 5, 6, 7, 8]",
    'sscanf': "[1, 2]",
    'strcat': "[2]",
    'strcpy': "[2]",
    'strncat': "[3]",  # [2, 3]",
    'strncpy': "[3]",  # [2, 3]",
    'spliter': "[1,2]",
    'bcopy': "[3]",
    'vsnprintf':"[2, 3]",
    'vsprintf':"[3, 2, 4, 5, 6, 7, 8]",
    'strscat':"[2, 3]",
}

maybe_sink_funcs_overflow_info = {
    'memcpy': [1],
    'memncpy': [1],
    'memmove': [1],  # [2, 3]
    'snprintf': [1],  # [4, 2, 3, 5, 6, 7, 8]",
    'sprintf': [1],
    'sscanf': [3,4,5,6],
    'strcat': [1],
    'strcpy': [1],
    'strncat': [1],  # [2, 3]",
    'strncpy': [1],  # [2, 3]",
    'spliter': [3],
    'bcopy': [2],
    'vsnprintf': [1],
    'vsprintf': [1],
    'strscat':[1],
}

maybe_sink_funcs_source_info = {
    'memcpy': [2],
    'memncpy': [2],
    'memmove': [2],  # [2, 3]
    'snprintf': [4,5,6,7,8],  # [4, 2, 3, 5, 6, 7, 8]",
    'sprintf': [3,4,5,6,7],
    'sscanf': [1],
    'strcat': [2],
    'strcpy': [2],
    'strncat': [2],  # [2, 3]",
    'strncpy': [2],  # [2, 3]",
    'spliter': [1],
    'bcopy': [1],
    'vsnprintf': [4,5,6,7,8],
    'vsprintf': [3,4,5,6,7],
    'strscat':[2],
}

buffer_pos_info = {
    'memcpy': [1,2],
    'memncpy': [1,2],
    'memmove': [1,2],  # [2, 3]
    'snprintf': [1,4,5,6,7,8],  # [4, 2, 3, 5, 6, 7, 8]",
    'sprintf': [1,3,4,5,6,7],
    'sscanf': [1,3,4,5,6],
    'strcat': [1,2],
    'strcpy': [1,2],
    'strncat': [1,2],  # [2, 3]",
    'strncpy': [1,2],  # [2, 3]",
    'spliter': [1,3],
    'bcopy': [1,2],
    'vsnprintf': [1,4,5,6,7,8],
    'vsprintf': [1,3,4,5,6,7],
    'strscat': [1,2],
    'recvfrom': [2],
    'recv': [2],
    'getenv': [1]
}


is_binary_mips = 'MIPS' in currentProgram.getLanguage().toString()


def change_func_sign(sign, func):
    try:
        parser = FunctionSignatureParser(currentProgram.getDataTypeManager(), DefaultDataTypeManagerService())
        # print("sign: %r"%sign)
        fddt = parser.parse(func.getSignature(), sign)
        cmd = ApplyFunctionSignatureCmd(func.getEntryPoint(), fddt, SourceType.USER_DEFINED, True, True)
        cmd.applyTo(currentProgram, getMonitor())
    except Exception as e:
        print("chang func sign failed for {} -> {}".format(func.getName(), sign))


output_dir_name = currentProgram.getExecutablePath().split('/')[-1] + '_result'

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
                print("DuplicateNameException:",e)
        elif not createFunction(toAddr(offset), funcName):
            print("Failed to create function %s @ 0x%08x" % (funcName, offset))
        funcSign = simresult.get('funcSign')
        function = getFunctionAt(toAddr(offset))
        if funcSign and function:
            change_func_sign(funcSign, function)
        for maybe_source_func in maybe_source_funcs:
            if funcName.startswith(maybe_source_func) and funcName not in source_funcs:
                source_funcs.append(funcName)
                break
        for maybe_sink_func in maybe_sink_funcs:
            if funcName.startswith(maybe_sink_func) and funcName not in sink_funcs:
                sink_funcs.append(funcName)
                break


else:
    for func in currentProgram.getFunctionManager().getFunctions(True):
        for maybe_sink_func in maybe_sink_funcs:
            if func.getName().startswith(maybe_sink_func) and func.getName() not in sink_funcs:
                sink_funcs.append(func.getName())
        for maybe_source_func in maybe_source_funcs:
            if func.getName().startswith(maybe_source_func) and func.getName() not in source_funcs:
                source_funcs.append(func.getName())

# predefined source function spec
source_func_spec = {
    'recv':{'critical_idx': 2, 'limit_len':True, 'limit_idx':3}, 
    'recvfrom':{'critical_idx': 2, 'limit_len':True, 'limit_idx':3}, 
    'Packt_WebGetsVar':{'critical_idx': 0, 'limit_len':False},
    'webgetvar':{'critical_idx': 0, 'limit_len':False},
    'bb_get_bt_context_ptr':{'critical_idx': 0, 'limit_len':False},
    'j_getenv':{'critical_idx': 1, 'limit_len':False},
    'getenv':{'critical_idx': 1, 'limit_len':False},
    'jsonObjectGetString':{'critical_idx': 0, 'limit_len':False},
    'jsonGetObjectString':{'critical_idx': 0, 'limit_len':False},
    'json_object_get_decode':{'critical_idx': 0, 'limit_len':False},
    'recv_http_response':{'critical_idx': 2, 'limit_len':False},
    'os_get_file':{'critical_idx': 1, 'limit_len':False},
    'os_file_get':{'critical_idx': 1, 'limit_len':False},
}
trans_func_list = [
    {
        'in': {'name': 'nvram_set', 'idx': [2], 'name_idx': [1]},
        'out': {'name': 'nvram_get', 'idx': [-1], 'name_idx': [1]},
    },
    {
        'in': {'name': 'setenv', 'idx': [2], 'name_idx': [1]},
        'out': {'name': 'getenv', 'idx': [-1], 'name_idx': [1]},
    },
    # {
    #     'in': {'name': 'set_local_var', 'idx':[2], 'name_idx': [1]},
    #     'out': {'name': 'get_local_var', 'idx':[2], 'name_idx': [1]},
    # }
]
summary = []
trace_cnt = 0


def time_calc(t):
    fl = "%f" % t
    mi = int(t / 60)
    st = "%dm %fs" % (mi, t - mi * 60)
    return "%s(%s)" % (fl, st)


def create_more_funcs():
    """
    Try to create more functions by identifying the beginning and end of the function
    """
    instIter = currentProgram.getListing().getInstructions(True)
    while instIter.hasNext():
        instruction = instIter.next()
        if instruction.getFlowType() == RefType.TERMINATOR:
            try:
                funcAddr = instruction.getMaxAddress().next()
                func = currentProgram.getFunctionManager().getFunctionContaining(funcAddr)
                if func == None:
                    funcBeginInstr = currentProgram.getListing().getInstructionAt(funcAddr)
                    if funcBeginInstr == None:
                        # If it is not followed by exactly one instruction, the next instruction position should be found to start the creation
                        funcBeginInstr = currentProgram.getListing().getInstructionAfter(funcAddr)
                        if funcBeginInstr != None:
                            funcAddr = funcBeginInstr.getAddress()
                            if currentProgram.getFunctionManager().getFunctionContaining(funcAddr) != None:
                                continue
                    if funcBeginInstr != None:
                        # createFunctionNear
                        partitionBlockModel = PartitionCodeSubModel(currentProgram)
                        blocks = partitionBlockModel.getCodeBlocksContaining(funcAddr, getMonitor())
                        if len(blocks) != 1:
                            continue
                        address = blocks[0].getFirstStartAddress()
                        createFunction(address, None)
            except Exception:
                pass


# Cache hfunc, otherwise it will take longer to decompile each time
hfunc_cache = {}


def get_hfunction(func):
    """
    Get the high-level representation of a function
    """
    func_entry_offset = func.getEntryPoint().getOffset()
    if func_entry_offset in hfunc_cache:
        return hfunc_cache.get(func_entry_offset)
    decomplib = DecompInterface()
    decomplib.openProgram(currentProgram)
    timeout = 60
    dRes = decomplib.decompileFunction(func, timeout, getMonitor())
    hfunction = dRes.getHighFunction()
    hfunc_cache[func_entry_offset] = hfunction
    return hfunction


def get_func_pcodes(func):
    """
    Get all call and cbranch pcode for a function
    """
    ret = []
    hfunc = get_hfunction(func)
    if not hfunc:
        return ret
    for basic_block in hfunc.getBasicBlocks():
        iter = basic_block.getIterator()
        while iter.hasNext():
            item = iter.next()
            if item.getOpcode() == PcodeOp.CALL or item.getOpcode() == PcodeOp.CBRANCH or item.getOpcode() == PcodeOp.BRANCH:
                ret.append(item)
    return ret


def filter_pcodes_called_with(func_pcodes,func_name):
    """
    Filter out the list of pcodes that call a specific function from many pcodes
    """
    ret = []
    for item in func_pcodes:
        if item.getOpcode() == PcodeOp.CALL:
            this_func = getFunctionAt(item.getInput(0).getAddress())
            if this_func and this_func.getName() == func_name:
                ret.append(item)
    return ret


def get_vns_same_space(vn):
    """
    Return the set of varnodes that point to the same memory area as vn
    """
    ret = set()
    vn_def = vn.getDef()
    if vn_def:
        # If it is calculated by PRTSUB, that means it points to some memory area on the stack, look for a varnode that points to the same memory area
        if vn_def.getOpcode() == PcodeOp.PTRSUB:
            vn_addr = HighFunctionDBUtil.getSpacebaseReferenceAddress(currentProgram, vn_def)
            hvn = vn.getHigh()
            if hvn:
                hfunc = hvn.getHighFunction()
                if hfunc:
                    iter = hfunc.getPcodeOps()
                    while iter.hasNext():
                        item = iter.next()
                        if item.getOpcode() == PcodeOp.PTRSUB:
                            this_addr = HighFunctionDBUtil.getSpacebaseReferenceAddress(currentProgram, item)
                            if this_addr == vn_addr and item.getOutput():
                                ret.add(item.getOutput())
    if vn_def == None:
        # If the memory area pointed to by vn is out of firmware range, it will be recognized as a const type value
        if vn.isConstant() and vn.getOffset() > currentProgram.getMinAddress().getOffset():
            const_val = vn.getOffset()
            hvn = vn.getHigh()
            if hvn:
                hfunc = hvn.getHighFunction()
                iter = hfunc.getPcodeOps()
                while iter.hasNext():
                    item = iter.next()
                    for i in item.getInputs():
                        if i.isConstant() and i.getOffset() == const_val:
                            ret.add(i)
    ret.add(vn)
    return ret


def get_all_forward_slice(seed,skip_item=None):
    """
    Get all subsequent varnodes affected by seed
    """
    varnodes = set()

    worklist = Queue.Queue()
    worklist.put(seed)
    while not worklist.empty():
        curvn = worklist.get()
        if curvn in varnodes:
            continue
        else:
            varnodes.add(curvn)
        # iter Get all pcode lists with curvn as input
        iter = curvn.getDescendants()
        while iter.hasNext():
            op = iter.next()
            if not op:
                continue
            # if op.getOpcode() == PcodeOp.CALL:
            #     first_vn = op.getInput(0)
            #     if first_vn:
            #         called_func = getFunctionAt(first_vn.getAddress())
            #         if called_func and should_func_patch(called_func):
            #             continue
            curvn = op.getOutput()
            if not curvn:
                continue
            if skip_item and skip_item == curvn:
                continue
            worklist.put(curvn)

    return varnodes


def get_global_offset(vn):
    """
    If a vn points to a global variable, return its corresponding offset address
    """
    if vn.isAddress():
        has_func = getFunctionContaining(vn.getAddress())
        if has_func:
            return None
        data = getDataAt(vn.getAddress())
        if data and data.isPointer():
            return None
        if not data or not data.hasStringValue():
            return vn.getAddress().getOffset()
    return None


def get_all_vns_influenced(source_vn_set,current_func,global_offset_set,remove_output=None):
    all_taint_set = set()
    all_taint_set |= set(source_vn_set)
    for sv in source_vn_set:
        bs = DecompilerUtils.getBackwardSlice(sv)
        all_taint_set |= set(bs)
        fs = get_all_forward_slice(sv, remove_output)
        all_taint_set |= set(fs)
    high_func = get_hfunction(current_func)
    if high_func:
        iter = high_func.getPcodeOps()
        while iter.hasNext():
            item = iter.next()
            for vn in item.getInputs():
                goff = get_global_offset(vn)
                if goff:
                    # If vn is pointing to a global variable then do the following
                    if vn in all_taint_set:
                        # If vn is affected and points to a global variable, set the global variable offset to taint
                        global_offset_set.add(goff)
                    elif goff in global_offset_set:
                        # If vn is unaffected, but the global variable pointed to by vn is affected
                        new_bs = DecompilerUtils.getBackwardSlice(vn)
                        all_taint_set |= set(new_bs)
    return all_taint_set


def get_patch_info(call_trace,begin_func_name,end_func_name,begin_idxs,end_idxs,out_name_idx=(1,), param_names=()):
    """
    For each source point, a patch set is returned
    """
    # Store the pcodes on the entire call_trace
    call_trace_pcodes = []
    for func in call_trace[:-1]:
        func_pcodes = get_func_pcodes(func)
        call_trace_pcodes.append(func_pcodes)
    # The pcode of the first function
    first_func_pcodes = call_trace_pcodes[0]
    # All source pcode
    source_pcodes = filter_pcodes_called_with(first_func_pcodes, begin_func_name)
    # For each source point, a set of patches is returned
    for source_pcode in source_pcodes:
        global_offset_set = set() # Affected set
        if param_names:
            name_vn = source_pcode.getInput(out_name_idx[0])
            if name_vn:
                param_key = get_key_from_vn(name_vn,source_pcode,out_name_idx[0])
                # If the parameter name here is not controllable at the time of set, skip
                if param_key and param_key not in param_names:
                    continue
        # Input data set
        source_vn_set = set()
        remove_output = source_pcode.getOutput()
        for bi in begin_idxs:
            if bi <= 0:
                vn = source_pcode.getOutput()
                remove_output = None
            else:
                vn = source_pcode.getInput(bi)
            if not vn:
                continue
            source_vn_set |= get_vns_same_space(vn)
        # The set of all varnodes affected by the input data
        all_taint_set = set()
        all_taint_set |= source_vn_set
        all_taint_set |= get_all_vns_influenced(source_vn_set,call_trace[0],global_offset_set,remove_output)
        # All pcode of the second function called in the first function
        second_called_pcodes = filter_pcodes_called_with(first_func_pcodes,call_trace[1].getName())
        # The set of parameters that may be affected by the second called function
        current_func_taint_idx = set()
        for scp in second_called_pcodes:
            printf_vuln_idx = get_printf_idxs(scp, call_trace[1].getName())
            for i, vn in enumerate(scp.getInputs()):
                if printf_vuln_idx != None:
                    if i in printf_vuln_idx and vn in all_taint_set:
                        current_func_taint_idx.add(i)
                else:
                    if vn in all_taint_set:
                        current_func_taint_idx.add(i)
        # If no parameters are affected, process the next source point
        if len(current_func_taint_idx) == 0:
            continue
        # Process the following functions one by one
        for i,func in enumerate(call_trace[1:]):
            # If the current function is the target function and is affected, a result is returned
            if func.getName() == end_func_name:
                if len(set(end_idxs) & current_func_taint_idx):
                    yield all_taint_set,call_trace_pcodes,source_pcode
                else:
                    break
            # If there is no more next function, break
            if i + 1 + 1 >= len(call_trace):
                break
            hfunc = get_hfunction(func)
            # Failed to get hfunc
            if not hfunc:
                break
            new_tainted = set()
            for param_idx in current_func_taint_idx:
                if param_idx - 1 >= hfunc.getLocalSymbolMap().getNumParams():
                    continue
                tainted_parm = hfunc.getLocalSymbolMap().getParam(param_idx - 1)
                if not tainted_parm:
                    continue
                tainted_vn = tainted_parm.getRepresentative()
                if tainted_vn:
                    new_tainted.add(tainted_vn)
            all_taint_set |= new_tainted
            all_taint_set |= get_all_vns_influenced(new_tainted,call_trace[i + 1],global_offset_set)
            # Next function
            called_func = call_trace[i + 1 + 1]
            # The pcode of all call pcode to the next function in the current function
            called_pcodes = filter_pcodes_called_with(call_trace_pcodes[i+1], called_func.getName())
            # Update current_func_taint_idx to the affected state of the next function
            current_func_taint_idx = set()
            for cp in called_pcodes:
                printf_vuln_idx = get_printf_idxs(cp,called_func.getName())
                for i, vn in enumerate(cp.getInputs()):
                    if printf_vuln_idx != None:
                        if i in printf_vuln_idx and vn in all_taint_set:
                            current_func_taint_idx.add(i)
                    else:
                        if vn in all_taint_set:
                            current_func_taint_idx.add(i)

    return


def init_func_map():
    """
    To handle the case that the thunk function can't found by getFunction
    """
    func_map = {}
    funcs = currentProgram.getFunctionManager().getFunctions(True)
    for item in funcs:
        func_name = item.getName()
        if func_name not in func_map:
            func_map[func_name] = []
        func_map[func_name].append(item)
    return func_map


GLOBAL_FUNC_MAP = init_func_map()
ignore_func = ['strdup', 'printf'] + list(maybe_source_funcs.keys()) + list(maybe_sink_funcs.keys())


def custom_get_function(func_name):
    global GLOBAL_FUNC_MAP
    if func_name in GLOBAL_FUNC_MAP:
        return GLOBAL_FUNC_MAP[func_name][0]
    return None


def judge(call_trace, begin_func_name, detect_data_convey):
    """
    Remove some meaningless traces in advance
    """
    if not detect_data_convey:
        for func in call_trace:
            if 'nvram_get' in func.getName() or 'getenv' in func.getName() or 'nvram_set' in func.getName() or 'setenv' in func.getName():
                # print("False case 1 %r"%func.getName())
                return False
    if detect_data_convey and ('nvram_get' in begin_func_name or 'getenv' in begin_func_name):
        for func in call_trace:
            if 'nvram_set' in func.getName() or 'setenv' in func.getName():
                # print("False case 2 %r"%func.getName())
                return False
    if detect_data_convey and ('nvram_set' in begin_func_name or 'setenv' in begin_func_name):
        for func in call_trace:
            if 'nvram_get' in func.getName() or 'getenv' in func.getName():
                # print("False case 3 %r"%func.getName())
                return False
    for func in call_trace[:-1]:
        for ign_f in ignore_func:
            if func.getName().startswith(ign_f):
                # print("False case 4 %r %r"%(ign_f,func.getName()))
                return False
    return True


def get_calling_funcs(target_func):
    """
    Get all functions that call targetFunc
    """
    ret = set()
    # Get the cross-reference of all calls to the target function
    source_refs = currentProgram.getReferenceManager().getReferencesTo(target_func.getEntryPoint())
    for cref in source_refs:
        # Get the address where all cross-references occur
        fromAddr = cref.getFromAddress()
        callingFunc = getFunctionContaining(fromAddr)
        if not callingFunc:
            continue
        ret.add(callingFunc)
    return ret


def get_call_relation(func):
    """
    Get the call relationship of the target function
    """
    ret = {}
    queue = Queue.Queue()
    queue.put(func)
    while not queue.empty():
        current = queue.get()
        func_entry_offset = current.getEntryPoint().getOffset()
        if func_entry_offset not in ret:
            ret[func_entry_offset] = current.getCalledFunctions(getMonitor())
            for item in ret[func_entry_offset]:
                queue.put(item)
    return ret


def get_call_traces(call_map, calling_func, sink_func):
    """
    Returns all possible call traces
    """
    ret = []
    queue = Queue.Queue()
    queue.put(([calling_func], calling_func.getEntryPoint().getOffset()))
    while not queue.empty():
        current = queue.get()
        if len(current[0]) > 7:
            # print("abort current call trace %r due to too long trace length"%current[0])
            continue
        for item in call_map[current[1]]:
            if item.getEntryPoint().getOffset() == sink_func.getEntryPoint().getOffset():
                # Some call traces will be very deep, currently only the first 7 layers are taken here
                ret.append(current[0][:] + [item])
            # If the function already appears in the call trace, skip
            elif item.getEntryPoint().getOffset() in [x.getEntryPoint().getOffset() for x in current[0]]:
                continue
            else:
                queue.put((current[0][:] + [item], item.getEntryPoint().getOffset()))
    return ret


def get_call_trace_between_func(begin_func_name, end_func_name, detect_data_convey):
    """
    Get the call_trace from begin_func_name to end_func_name
    """
    ret = []
    begin_func = custom_get_function(begin_func_name)
    # Get the sink function
    end_func = custom_get_function(end_func_name)
    # print("begin_func %r end_func %r"%(begin_func, end_func))
    if not begin_func or not end_func:
        return ret
    # if end_func_name != 'strcpy' and end_func_name != 'nvram_set':
    #     return ret
    calling_begin_funcs = get_calling_funcs(begin_func)
    # print("calling_begin_funcs %r"%calling_begin_funcs)
    for item in calling_begin_funcs:
        # if item.getName() != 'FUN_800d50a4' and item.getName() != 'FUN_800d5204':
        #     continue
        call_map = get_call_relation(item)
        if end_func.getEntryPoint().getOffset() in call_map:
            call_traces = get_call_traces(call_map, item, end_func)
            # print("call_trace before filtered %r"%call_traces)
            call_traces = [call_trace for call_trace in call_traces if
                           judge(call_trace, begin_func_name, detect_data_convey)]
            # print("call_trace after filtered %r"%call_traces)
            ret += call_traces
    return ret


def getoneFuncOffset(target_func, offset):
    listing = currentProgram.getListing()
    codeUnits = listing.getCodeUnits(target_func.getBody(), True)
    if u"MIPS" in currentProgram.getLanguage().toString():
        loadra = addsp = None
        for codeUnit in codeUnits:
            # print("codeUnit.toString(): "+str(codeUnit.toString()))
            if re.match("^_*lw ra,0x[0-9a-f]+\(sp\)$", codeUnit.toString()):
                #         print("Found ra load instr at 0x{} : {:16} {}".format(codeUnit.getAddress(), hexlify(codeUnit.getBytes()), codeUnit.toString()))
                loadra = codeUnit.toString()
                if addsp:
                    break
            elif re.match("^_*addiu sp,sp,0x[0-9a-f]+$", codeUnit.toString()):
                addsp = codeUnit.toString()
                if loadra:
                    break
        if not loadra:
            print("Currently not supported func structure")
            return offset, offset
        pcoffset = int(loadra.strip('_')[6:-4], 0) + offset
        offset = int(addsp.strip('_')[12:], 0) + offset
        return offset, pcoffset

    elif u"ARM" in currentProgram.getLanguage().toString():
        pushinstr = spinstr = None
        for codeUnit in codeUnits:
            if re.match("^stmdb sp!,\{.*\}$", codeUnit.toString()):
                pushinstr = codeUnit.toString()
                if spinstr:
                    break
            elif re.match("^sub sp,sp,#0x[0-9a-f]+$", codeUnit.toString()):
                spinstr = codeUnit.toString()
                if pushinstr:
                    break
        if not pushinstr or 'lr' not in pushinstr:
            print("Currently not supported func structure")
            return offset, offset
        pushinstr = pushinstr[pushinstr.find('{') + 1: pushinstr.find('}')].split(' ')
        if spinstr:
            spinstr = spinstr[spinstr.find('#') + 1:]
            pcoffset = offset + int(spinstr, 0) + pushinstr.index('lr') * 4
            offset = offset + len(pushinstr) * 4 + int(spinstr, 0)
            return offset, pcoffset
        else:
            pcoffset = offset + pushinstr.index('lr') * 4
            offset = offset + len(pushinstr) * 4
            return offset, pcoffset
    else:
        print("Currently not supported %r" % currentProgram.getLanguage())
        return 0, 0


def get_str_from_vn(vn):
    val = FlowNode(vn).get_value()
    if val and (
    isinstance(val, GenericAddress)) and currentProgram.getMaxAddress() >= val >= currentProgram.getMinAddress():
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


def parse_format_str(format_str):
    """
    '%savbbss%2d' -> ('%s', '%2d')
    """
    line = format_str

    # lines = '''\
    # Worker name is %s and id is %d
    # That is %i%%
    # %c
    # Decimal: %d  Justified: %.6d
    # %10c%5hc%5C%5lc
    # The temp is %.*f
    # %ss%lii
    # %*.*s | %.3d | %lC | %s%%%02d'''

    cfmt = '''\
    (                                  # start of capture group 1
    %                                  # literal "%"
    (?:                                # first option
    (?:[-+0 #]{0,5})                   # optional flags
    (?:\d+|\*)?                        # width
    (?:\.(?:\d+|\*))?                  # precision
    (?:h|l|ll|w|I|I32|I64)?            # size
    [cCdiouxXeEfgGaAnpsSZ]             # type
    ) |                                # OR
    %%)                                # literal "%%"
    '''
    return tuple(m.group(1) for m in re.finditer(cfmt, line, flags=re.X))


def format_func_vul_idxs(call_pcode, format_idx):
    """
    call_pcode with formatted string function; formatted string at parameter position; first parameter position is 1
    If the range is none, it means not found, otherwise it returns a list of idx
    """
    input_num = call_pcode.getNumInputs()
    if format_idx > input_num - 1:
        return None
    vn = call_pcode.getInput(format_idx)
    data = get_str_from_vn(vn)
    if data:
        format_params = parse_format_str(data)
        if len(format_params) == 0:
            return None
        else:
            ret = []
            for i in range(len(format_params)):
                if format_params[i].endswith('s'):
                    ret.append(i + 1 + format_idx)
            return ret
    return None


printf_func_spec = {
    'sprintf': 2,
    'snprintf': 3,
    'vsprintf': 2,
    'vsnprintf': 3
}


def get_printf_idxs(call_pcode, target_func_name):
    for printf_func in printf_func_spec:
        if target_func_name.startswith(printf_func):
            printf_target_idxs = format_func_vul_idxs(call_pcode, printf_func_spec[printf_func])
            if printf_target_idxs != None:
                return printf_target_idxs
            else:
                return None
    return None


def outputConnect(addr1, addr2, trace_cnt):
    listing = currentProgram.getListing()
    instr1 = next(listing.getInstructions(addr1, True))
    instr2 = next(listing.getInstructions(addr2, True))
    func1 = getFunctionAt(instr1.getPcode()[len(instr1.getPcode()) - 1].getInput(0).getAddress())
    func2 = getFunctionAt(instr2.getPcode()[len(instr2.getPcode()) - 1].getInput(0).getAddress())
    contents = []
    file_path = "findtrace_output/%s/connect_%d" % (output_dir_name, trace_cnt)
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            contents = f.read().split('\n')
    f = open(file_path, 'a')
    if func1.getName().startswith('nvram_set'):
        this_content = "0x%08x 0x%08x 2 0\n" % (addr1.getOffset(), addr2.getOffset())
        if this_content.strip('\n') not in contents:
            f.write(this_content)
    elif func1.getName().startswith('setenv'):
        this_content = "0x%08x 0x%08x 2 0\n" % (addr1.getOffset(), addr2.getOffset())
        if this_content.strip('\n') not in contents:
            f.write(this_content)
    else:
        print("Unsupported function %r and %r" % (func1, func2))
    f.close()


def getmultiFuncOffset(call_trace, trace_cnt):
    assert len(
        call_trace) > 1, "Call trace should at least include one caller and one callee(sink func), however we get %s" % str(
        call_trace)
    f = open("findtrace_output/%s/stack_retaddr_%d" % (output_dir_name, trace_cnt), 'a')
    offset = 0
    pcoffsets = []
    for func in call_trace[:-1][::-1]:
        # the 1st func in call_trace must be a function, some get/set func pair may insert the instr address in call_trace
        if type(func) != type(call_trace[0]):
            # this means we meet a get/set func, and we will not extrace pcoffset after it
            offset, pcoffset = getoneFuncOffset(getFunctionContaining(func), offset)
            pcoffsets.append(pcoffset)
            break
        offset, pcoffset = getoneFuncOffset(func, offset)
        pcoffsets.append(pcoffset)
    print("pcoffsets: " + str(pcoffsets))
    f.write(' '.join([str(pcoffset) for pcoffset in pcoffsets]) + '\n')
    f.close()
    print(
        "results has been saved in %s/findtrace_output/%s/stack_retaddr_%d" % (os.getcwd(), output_dir_name, trace_cnt))


def custom_get_str(addr, length):
    ret = ""
    for i in range(length):
        b = currentProgram.getMemory().getByte(addr)
        if b >= 0x20 and b <= 0x7f:
            ret += chr(b)
        addr = addr.addNoWrap(1)
    return ret


def print_trace_str(func_opcodes_map, f_dict):
    '''
    For the current trace, extract all possible strings referenced on the trace 
    (used to add to the AFL dictionary to help quickly fuzz out some checks like strcmp, strstr, etc.)
    '''
    ret = set()
    for key,opcodes in func_opcodes_map.items():
        for item in opcodes:
            for vn in item.getInputs():
                val = FlowNode(vn).get_value()
                if val and isinstance(val,
                                      GenericAddress) and currentProgram.getMaxAddress() >= val >= currentProgram.getMinAddress():
                    data = getDataAt(val)
                    if data and data.hasStringValue():
                        ret.add(data.getValue())
                    if not data:
                        end_addr = find(val, TERMINATOR)
                        if not end_addr:
                            continue
                        length = end_addr.getOffset() - val.getOffset()
                        if length <= 1:
                            # If the length of the string is less than or equal to 1, it is currently not output
                            continue
                        str_data = custom_get_str(val, length)
                        ret.add(str_data)
    print("dict content:")
    for st in ret:
        print('"%s"' % st.replace('"', '\\"'))
        f_dict.write('%s\n' % st.replace('"', '\\"').replace("\n",""))


def find_all_branch_vn(traces):
    """
    Find the varnode where all the branches of the judgment condition are located
    """
    ret = set()
    for pcode_item in traces:
        if pcode_item.getOpcode() == PcodeOp.CBRANCH:
            # The first parameter is a judgment condition
            ret.add(pcode_item.getInput(1))
    return ret


def is_param_taint(call_pcode, varnodes):
    """
    Determine if the parameters have received input influence
    """
    for i in range(1, call_pcode.getNumInputs()):
        if call_pcode.getInput(i) in varnodes:
            return True
    return False


def check_func_hascall(vn):
    """
    Check if there are function calls in the function corresponding to the address pointed to by vn
    """
    func = getFunctionAt(vn.getAddress())
    count = 0
    for called_func in func.getCalledFunctions(monitor):
        # If the function called in this function is not itself, count + 1
        if called_func.getEntryPoint().getOffset() != func.getEntryPoint().getOffset():
            count += 1
    return count == 0


def should_func_patch(func):
    """
    Determine if a function is a complex function, and if so, it needs to be patched
    """
    csum_like = ['checksum', 'csum']
    for csum_l in csum_like:
        if func.getName().lower().startswith(csum_l):
            return True
    this_func_offset = func.getEntryPoint().getOffset()
    for subfunc in func.getCalledFunctions(getMonitor()):
        # Recursive call itself, no patch
        if subfunc.getEntryPoint().getOffset() == this_func_offset:
            continue
        if len(subfunc.getCalledFunctions(getMonitor())) != 0:
            return True
    return False


def is_checksum_like_func(vn):
    """
    Determine if the current address of vn is a checksum-like function
    """
    csum_like = ['checksum', 'csum']
    func = getFunctionAt(vn.getAddress())
    for csum_l in csum_like:
        if func.getName().lower().startswith(csum_l):
            return True
    return False


def get_funcname_at_call(item):
    """
    Get the function called at call pcode
    """
    return getFunctionAt(item.getInput(0).getAddress()).getName()


def is_target_call_pcode(pcode_item, target_func_names):
    """
    For the demo to determine whether it is sink pcode, the extension needs to determine the formatting parameters and support other types of functions
    """
    if pcode_item.getOpcode() == PcodeOp.CALL and get_funcname_at_call(pcode_item) in target_func_names:
        return True
    return False


def get_reachable_bbs(pcodes, target_func_names,taint_set, sink_func_info):
    # Return the set of basic blocks in the function that can reach target_func
    reachable_bbs = set()
    sink_bbs = set()
    sink_pcodes = set()
    for item in pcodes:
        if is_target_call_pcode(item, target_func_names):
            affected = False
            this_called_name = get_funcname_at_call(item)
            if this_called_name and this_called_name in sink_func_info:
                printf_vuln_idx = get_printf_idxs(item,this_called_name)
                for i,vn in enumerate(item.getInputs()):
                    if printf_vuln_idx != None:
                        if i in printf_vuln_idx and vn in taint_set and i in sink_func_info[this_called_name]:
                            sink_pcodes.add(item)
                            affected = True
                            break
                    else:
                        if vn in taint_set and i in sink_func_info[this_called_name]:
                            sink_pcodes.add(item)
                            affected = True
                            break
            else:
                for vn in item.getInputs():
                    if vn in taint_set:
                        affected = True
                        break
            if affected:
                sink_bbs.add(item.getParent())

    to_visit = Queue.Queue()
    # The distance from each sink basic block to sink basic block is 0
    for i in sink_bbs:
        to_visit.put(i)

    while not to_visit.empty():
        current_bb = to_visit.get()
        if current_bb in reachable_bbs:
            continue
        else:
            reachable_bbs.add(current_bb)
            for i in range(current_bb.getInSize()):
                dest = current_bb.getIn(i)
                to_visit.put(dest)

    return reachable_bbs,sink_pcodes


def find_start(bb, addr):
    """
    Find the first address after addr in the basic block
    """
    if bb.getStart().getOffset() > addr.getOffset():
        return bb.getStart()
    iter = bb.getIterator()
    while iter.hasNext():
        item = iter.next()
        if item.getSeqnum().getTarget().getOffset() > addr.getOffset():
            return item.getSeqnum().getTarget()
    return bb.getStart()


def get_avoid_address(pcode_item, reachable_bbs):
    # Get the first address of all the basic blocks of the current pcode_item that do not reach the sink subsequently
    ret = set()
    next_addrs = set()
    this_bb = pcode_item.getParent()
    this_bb_stop = this_bb.getStop()
    # Because the instructions at each address may be converted into multiple pcode statements, it has been found that some addresses may span the PcodeBasicBlock
    # So here we return the next PcodeBasicBlock that does not span the subsequent address
    for i in range(this_bb.getOutSize()):
        dest = this_bb.getOut(i)
        start_addr_set = find_start(dest, this_bb_stop)
        # start_addr_set = dest.getStart()
        next_addrs.add(start_addr_set)
        if dest not in reachable_bbs:
            ret.add(start_addr_set)
    return ret,next_addrs

def get_convery_func_info(func_name):
    for item in trans_func_list:
        for key,val in item.items():
            if val['name'] == func_name:
                return val, item['out']
    return None,None


def get_get_pocdes(param_key,begin_func_name):
    ret = []
    for key,val in get_map_res.items():
        # Each key is in fact the same param_key
        if val[0]['param_key'] == param_key and get_funcname_at_call(key) == begin_func_name:
            ret.append(key)
    return ret

def is_vn_local(vn, all_vn=None):
    if all_vn is None:
        all_vn = set()
    if vn in all_vn:
        return False
    all_vn.add(vn)
    high_vn = vn.getHigh()
    if high_vn:
        if isinstance(high_vn,HighParam):
            return False
        # if isinstance(high_vn,HighLocal):
        #     return True
    def_pcode = vn.getDef()
    if not def_pcode:
        return False
    def_op = def_pcode.getOpcode()
    if def_op == PcodeOp.CALL or def_op == PcodeOp.CALLIND:
        return False
    if def_op == PcodeOp.PTRSUB:
        vn_addr = HighFunctionDBUtil.getSpacebaseReferenceAddress(currentProgram, def_pcode)
        if not vn_addr:
            return False
        high_func = high_vn.getHighFunction()
        high_sys = high_func.getLocalSymbolMap().findLocal(vn_addr,None)
        if not high_sys:
            return False
        if high_sys.getName():
            return True
    else:
        for item in def_pcode.getInputs():
            if is_vn_local(item,all_vn):
                return True
    return False


def get_cbranch_unpatch_addr(pcode_item,patched_call_set):
    """
    Return the return address of the function in the basic block where cbranch is located that has not been patched, 
    or the starting address of the basic block if it is not found
    """
    this_bb = pcode_item.getParent()
    pcodes = []
    iter = this_bb.getIterator()
    while iter.hasNext():
        pcodes.append(iter.next())
    pcodes = pcodes[::-1]
    for item in pcodes:
        if item.getOpcode() == PcodeOp.CALL and item not in patched_call_set:
            unpatch_call_addr = item.getSeqnum().getTarget()
            if is_binary_mips:
                return toAddr(unpatch_call_addr.getOffset() + 2 * currentProgram.getDefaultPointerSize())
            else:
                return toAddr(unpatch_call_addr.getOffset() + currentProgram.getDefaultPointerSize())
    return this_bb.getStart()


def record_tree_res(tree_res,f_patch, f_exec, f_cbranch_info,f_call_checksum,should_patch_pcodes=()):
    # The set of all varnodes affected by souce
    tainted_vns = tree_res['taint_set']
    func_opcodes_map = tree_res['func_opcodes_map']
    call_map = tree_res['call_map']
    sink_func_info = tree_res['sink_func_info']
    source_pcode = tree_res['source_pcode']

    end_pcodes = set()
    for key, val in func_opcodes_map.items():
        call_tree_funcs_map[global_current_source_pcode].add(key)
        branch_csum_related_varnodes = set()
        condition_vn_set = find_all_branch_vn(val)
        call_tree_cbranch_vn_map[global_current_source_pcode] |= tainted_vns & condition_vn_set
        next_funcs_names = [x.getName() for x in call_map.get(key, [])]
        reachable_bbs, sink_pcodes = get_reachable_bbs(val, next_funcs_names, tainted_vns, sink_func_info)
        end_pcodes |= sink_pcodes
        call_addr_set = set()
        patched_call_set = set()
        branch_map = {}
        for pcode_item in val:
            if pcode_item.getOpcode() == PcodeOp.CALL:
                call_tree_all_call_map[global_current_source_pcode].add(pcode_item)
                if pcode_item == source_pcode:
                    continue
                is_pcode_affected = is_param_taint(pcode_item, tainted_vns)
                if is_pcode_affected:
                    call_tree_affect_call_map[global_current_source_pcode].add(pcode_item)
                call_addr_set.add(pcode_item.getSeqnum().getTarget().getOffset())
                current_called_func = getFunctionAt(pcode_item.getInput(0).getAddress())
                # If it is a function on trace, then follow up
                this_called_name = current_called_func.getName()
                should_patch = True
                if this_called_name in next_funcs_names:
                    if pcode_item in should_patch_pcodes:
                        should_patch = True
                    elif this_called_name in sink_func_info:
                        printf_vuln_idx = get_printf_idxs(pcode_item, this_called_name)
                        for i, vn in enumerate(pcode_item.getInputs()):
                            if printf_vuln_idx != None:
                                if i in printf_vuln_idx and vn in tainted_vns and i in sink_func_info[this_called_name]:
                                    should_patch = False
                                    break
                            else:
                                if vn in tainted_vns and i in sink_func_info[this_called_name]:
                                    should_patch = False
                                    break
                    else:
                        for vn in pcode_item.getInputs():
                            if vn in tainted_vns:
                                should_patch = False
                                break
                if not should_patch:
                    continue
                if not is_pcode_affected:
                    # independent of the input, then patch is nop
                    content = '0x{} {} {} {}'.format(pcode_item.getSeqnum().getTarget(), 'nop',
                                                  check_func_hascall(pcode_item.getInput(0)),pcode_item.getNumInputs() - 1)
                    call_tree_patched_call_map[global_current_source_pcode].add(pcode_item)
                    patched_call_set.add(pcode_item)
                    f_patch.write(content + '\n')
                    print(content)
                else:
                    # Input data related
                    if should_func_patch(current_called_func):
                        # If need to patch
                        patched_call_set.add(pcode_item)
                        call_tree_patched_call_map[global_current_source_pcode].add(pcode_item)
                        if is_checksum_like_func(pcode_item.getInput(0)):
                            branch_csum_related_varnodes = branch_csum_related_varnodes | (
                                    get_all_forward_slice(pcode_item.getOutput()) & condition_vn_set)
                            content = '0x{} {} {} {}'.format(pcode_item.getSeqnum().getTarget(), 'nop', 1,pcode_item.getNumInputs() - 1)
                            f_patch.write(content + '\n')
                            print(content)
                        else:
                            content = '0x{} {} {} {}'.format(pcode_item.getSeqnum().getTarget(), 'nop',
                                                          check_func_hascall(pcode_item.getInput(0)),pcode_item.getNumInputs() - 1)
                            f_patch.write(content + '\n')
                            print(content)

            if pcode_item.getOpcode() == PcodeOp.BRANCH:
                pcode_offset = pcode_item.getSeqnum().getTarget().getOffset()
                if pcode_item.getInput(0) and pcode_item.getInput(0).getAddress():
                    branch_map[pcode_offset] = pcode_item.getInput(0).getAddress()

        for pcode_item in val:
            if pcode_item.getOpcode() == PcodeOp.CBRANCH:
                call_tree_all_cbranch_map[global_current_source_pcode].add(pcode_item)
                if pcode_item.getSeqnum().getTarget().getOffset() in call_addr_set:
                    continue
                pcode_addr = pcode_item.getSeqnum().getTarget()
                avoid_address, jmp_addrs = get_avoid_address(pcode_item, reachable_bbs)
                jmp_addrs = list(jmp_addrs)
                avoid_address = list(avoid_address)
                branch_addr = None
                if pcode_addr.getOffset() in branch_map:
                    branch_addr = branch_map[pcode_addr.getOffset()]
                if branch_addr:
                    for i in range(len(jmp_addrs)):
                        if jmp_addrs[i].getOffset() == pcode_addr.getOffset():
                            jmp_addrs[i] = branch_addr
                    for i in range(len(avoid_address)):
                        if avoid_address[i].getOffset() == pcode_addr.getOffset():
                            avoid_address[i] = branch_addr
                if is_binary_mips and ('movn' not in currentProgram.getListing().getCodeUnitAt(
                        pcode_addr).toString() and 'movz' not in currentProgram.getListing().getCodeUnitAt(
                        pcode_addr).toString()):
                    # we only need to correct b instr in MIPS arch
                    one_bb_start_offset = pcode_addr.getOffset() + 2 * currentProgram.getDefaultPointerSize()
                    wrong_offset = one_bb_start_offset + currentProgram.getDefaultPointerSize()
                    tmp_jmp_addrs = jmp_addrs[:]
                    tmp_avoid_addrs = avoid_address[:]
                    for ij, jmp_addr in enumerate(tmp_jmp_addrs):
                        if jmp_addr.getOffset() == wrong_offset:
                            jmp_addrs[ij] = toAddr(one_bb_start_offset)

                    for ij, avoid_addr in enumerate(tmp_avoid_addrs):
                        if avoid_addr.getOffset() == wrong_offset:
                            avoid_address[ij] = toAddr(one_bb_start_offset)

                if len(avoid_address) != 2:
                    call_tree_patched_cbranch_map[global_current_source_pcode].add(pcode_item)
                    # Get the varnode where the condition is located
                    condation_vn = pcode_item.getInput(1)
                    known_jmp_addr = False
                    # If both branches of a conditional judgment are backward unreachable, \
                    # then the basic block where the conditional jump itself is located should be on one of the original backward unreachable branches, 
                    # so this patch does not need to be output, which also improves our patch utilization
                    new_avoid_address = ','.join(['0x' + str(x) for x in avoid_address])
                    # If there is only one jump direction and the condition is not affected by the input data; or csum function return value related to cbranch
                    if len(avoid_address) == 1:
                        if (condation_vn not in tainted_vns or condation_vn in branch_csum_related_varnodes):
                            new_jmp_addrs = ['0x' + str(x) for x in jmp_addrs if x not in avoid_address]
                            if len(new_jmp_addrs) == 1:
                                content = '0x{} jmp {} {}'.format(pcode_item.getSeqnum().getTarget(), new_jmp_addrs[0], new_avoid_address)
                                known_jmp_addr = True
                                if condation_vn in branch_csum_related_varnodes:
                                    f_call_checksum.write('{}\n'.format(new_jmp_addrs[0]))
                        else:
                            # Affected by input data, only output avoid_adress and do not output information in cbranch
                            known_jmp_addr = True
                            content = '0x{} jmp 0x0 {}'.format(pcode_item.getSeqnum().getTarget(), new_avoid_address)
                    else:
                        # If there are two directions you can go to jump and are affected by the input data
                        # only output avoid_address and do not output the information in the cbranch
                        if condation_vn in tainted_vns:
                            known_jmp_addr = True
                        content = '0x{} jmp 0x0 {}'.format(pcode_item.getSeqnum().getTarget(), new_avoid_address)
                    f_patch.write(content + '\n')
                    print(content)


                    # If it is not affected by the input data, add the information related to the cbranch jump
                    if not known_jmp_addr:
                        bb_addr = get_cbranch_unpatch_addr(pcode_item,patched_call_set)
                        jmp_addrs = ' '.join(['0x' + str(x) for x in jmp_addrs])
                        content = '{} {} {}'.format(pcode_addr,bb_addr,jmp_addrs)
                        f_cbranch_info.write('%s\n'%content)
                        print(content)

    return end_pcodes


global_var_cache_list = []
global_var_cache_list_inited = False

def get_global_size(goffset):
    global global_var_cache_list_inited
    global global_var_cache_list
    if not global_var_cache_list_inited:
        global_var_cache_list_inited = True
        offsets = set()
        ref_manager = currentProgram.getReferenceManager()
        for key in buffer_pos_info:
            key_func = custom_get_function(key)
            if not key_func:
                continue
            for item in ref_manager.getReferencesTo(key_func.getEntryPoint()):
                from_addr = item.getFromAddress()
                calling_func = getFunctionContaining(from_addr)
                if calling_func:
                    high_calling = get_hfunction(calling_func)
                    if not high_calling:
                        continue
                    for item in high_calling.getPcodeOps(from_addr):
                        if item.getOpcode() == PcodeOp.CALL and get_funcname_at_call(item) == key:
                            for idx in buffer_pos_info[key]:
                                idx_vn = item.getInput(idx)
                                if idx_vn:
                                    vn_val = FlowNode(idx_vn).get_value()
                                    if vn_val:
                                        if isinstance(vn_val,GenericAddress):
                                            offsets.add(vn_val.getOffset())
                                        if isinstance(vn_val,Scalar):
                                            offsets.add(vn_val.getValue())
            global_var_cache_list = list(offsets)
            global_var_cache_list.sort()
    if goffset in global_var_cache_list:
        g_idx = global_var_cache_list.index(goffset)
        if g_idx < len(global_var_cache_list) - 1:
            return global_var_cache_list[g_idx+1] - goffset
    return -1


def get_possible_size(vn,all_vn=None):
    if all_vn is None:
        all_vn = set()
    if vn in all_vn:
        return -1
    all_vn.add(vn)
    high_vn = vn.getHigh()
    if high_vn:
        if isinstance(high_vn, HighParam):
            return -1
    def_pcode = vn.getDef()
    if not def_pcode:
        return -1
    def_op = def_pcode.getOpcode()
    if def_op == PcodeOp.CALL:
        if def_pcode.getInput(0):
            item_func_name = getFunctionAt(def_pcode.getInput(0).getAddress()).getName()
            if item_func_name.startswith('malloc') or item_func_name.startswith('realloc'):
                param_vn = def_pcode.getInput(1)
                if param_vn:
                    val = FlowNode(param_vn).get_value()
                    if val:
                        return val.getOffset()

    for item in def_pcode.getInputs():
        may_size = get_possible_size(item,all_vn)
        if may_size != -1:
            return may_size
    return -1

def get_local_possible_size(vn,all_vn=None):
    if all_vn is None:
        all_vn = set()
    if vn in all_vn:
        return -1
    all_vn.add(vn)
    def_pcode = vn.getDef()
    if not def_pcode:
        return -1
    def_op = def_pcode.getOpcode()
    if def_op == PcodeOp.CALL:
        return -1
    if def_op == PcodeOp.PTRSUB:
        vn_addr = HighFunctionDBUtil.getSpacebaseReferenceAddress(currentProgram, def_pcode)
        if not vn_addr:
            return -1
        high_vn = vn.getHigh()
        if not high_vn:
            return -1
        high_func = high_vn.getHighFunction()
        high_sys = high_func.getLocalSymbolMap().findLocal(vn_addr, None)
        if not high_sys:
            return -1
        return high_sys.getSize()
    else:
        for item in def_pcode.getInputs():
            may_size = get_local_possible_size(item,all_vn)
            if may_size != -1:
                return may_size
    return -1

call_tree_funcs_map = {}
call_tree_cbranch_vn_map = {}
call_tree_affect_call_map = {}
call_tree_patched_call_map = {}
call_tree_patched_cbranch_map = {}
call_tree_all_call_map = {}
call_tree_all_cbranch_map = {}
global_current_source_pcode = None

def handle_trace(tree_res, f_patch, f_exec, f_cbranch_info,f_dict,f_calltrace,f_call_checksum,f_xalloc,f_sink_buf,plink=None,should_patch_pcodes=()):
    """
    Handling instructions on trace (subfunction call instructions, conditional jump instructions)
    """
    source_pcode = tree_res['source_pcode']
    global global_current_source_pcode
    global_current_source_pcode = source_pcode
    if source_pcode not in call_tree_funcs_map:
        call_tree_funcs_map[global_current_source_pcode] = set()
    if source_pcode not in call_tree_cbranch_vn_map:
        call_tree_cbranch_vn_map[global_current_source_pcode] = set()
    if source_pcode not in call_tree_affect_call_map:
        call_tree_affect_call_map[global_current_source_pcode] = set()
    if source_pcode not in call_tree_patched_call_map:
        call_tree_patched_call_map[global_current_source_pcode] = set()
    if source_pcode not in call_tree_patched_cbranch_map:
        call_tree_patched_cbranch_map[global_current_source_pcode] = set()
    if source_pcode not in call_tree_all_call_map:
        call_tree_all_call_map[global_current_source_pcode] = set()
    if source_pcode not in call_tree_all_cbranch_map:
        call_tree_all_cbranch_map[global_current_source_pcode] = set()
    call_traces = tree_res['call_traces']
    for ct in call_traces:
        f_calltrace.write(str(source_pcode.getSeqnum().getTarget()) + ":" + '->'.join([x.getName() for x in ct]) + '\n')
    end_pcodes = record_tree_res(tree_res, f_patch, f_exec, f_cbranch_info,f_call_checksum,should_patch_pcodes)
    all_get_pcodes = []
    if plink:
        end_pcodes = set()
        for item in plink:
            set_pcode = item[0]
            get_pcode = item[1]
            if get_pcode != None:
                all_get_pcodes.append(get_pcode)
                this_tree_res = convert_list(get_map_res[get_pcode] ,get_pcode)
                for ct in this_tree_res['call_traces']:
                    f_calltrace.write(str(get_pcode.getSeqnum().getTarget()) + ":" +'->'.join([x.getName() for x in ct]) + '\n')
                    # Splice the new part of the call trace: caller function of set + set's address + get's address + call trace
                    call_traces.append([getFunctionContaining(set_pcode.getSeqnum().getTarget()),set_pcode.getSeqnum().getTarget(),get_pcode.getSeqnum().getTarget()] + ct[1:])
                    outputConnect(set_pcode.getSeqnum().getTarget(), get_pcode.getSeqnum().getTarget(), trace_cnt)
                print_trace_str(this_tree_res['func_opcodes_map'], f_dict)
                end_pcodes |= record_tree_res(this_tree_res, f_patch, f_exec, f_cbranch_info,f_call_checksum)
            else:
                # get_pcode is empty, which means the location of set_pcode is directly sink_pcode
                end_pcodes.add(set_pcode)

    if 'MIPS' not in currentProgram.getLanguage().toString() and 'ARM' not in currentProgram.getLanguage().toString() and '32' not in currentProgram.getLanguage().toString():
        print("Currently not support %s" % currentProgram.getLanguage().toString())
        return

    # Output the call address of malloc/realloc
    for func_entry_offset in call_tree_funcs_map[source_pcode]:
        this_func = getFunctionAt(toAddr(func_entry_offset))
        if not this_func:
            continue
        high_this_func = get_hfunction(this_func)
        if not high_this_func:
            continue
        for item in high_this_func.getPcodeOps():
            if item.getOpcode() == PcodeOp.CALL:
                if item.getInput(0):
                    item_func_name = getFunctionAt(item.getInput(0).getAddress()).getName()
                    if item_func_name.startswith('malloc') or item_func_name.startswith('realloc'):
                        item_called_addr = hex(item.getSeqnum().getTarget().getOffset()).strip('L')
                        f_xalloc.write(item_called_addr + '\n')


    print("exec content:")
    start_pcode = source_pcode  # should be a PcodeOp.CALL pcode

    for end_pcode in end_pcodes:
        sink_func_name = get_funcname_at_call(end_pcode)
        calling_func_name = getFunctionContaining(end_pcode.getSeqnum().getTarget()).getName()
        for trace in call_traces:
            if trace[-1].getName() == sink_func_name:
                if isinstance(trace[-2],Function):
                    if trace[-2].getName() == calling_func_name:
                        getmultiFuncOffset(trace, trace_cnt)
                        # break
                else:
                    # For set/get, the trace[-2] may not be a function, but a call address
                    if getFunctionContaining(trace[-2]).getName() == calling_func_name:
                        getmultiFuncOffset(trace, trace_cnt)
                        # break
    #
    #1st line: program load base
    address = currentProgram.getAddressMap().getImageBase().getOffset()
    print(hex(address).strip('L'))
    f_exec.write(hex(address).strip('L') + '\n')
    # 2nd line: program arch
    arch = "mips" if "MIPS" in currentProgram.getLanguage().toString() else "arm"
    arch += 'el' if "little" in currentProgram.getLanguage().toString() else "eb"
    print(arch)
    f_exec.write(arch + '\n')
    # 3rd line: simulation start address(fuzzer and angr, should be the block address of input, and we should patch every call instr before our injection call instr)
    block = start_pcode.getParent()
    address = block.getStart().getOffset()
    listing = currentProgram.getListing()
    opiter = listing.getInstructions(block.getStart(), True)
    while opiter.hasNext():
        op = opiter.next()
        pcodes = op.getPcode()
        if len(pcodes) <= 0:
            print("???" + str(pcodes))
        if len(pcodes) > 0 and pcodes[0].getSeqnum().getTarget() == start_pcode.getSeqnum().getTarget():
            break
        for pcode in pcodes:
            if pcode.getMnemonic() == u'CALL':
                content = '0x{} {} {}'.format(pcode.getSeqnum().getTarget(), 'nop', 0)
                print("add one more patch: %s" % content)
                f_patch.write(content + '\n')
    print(hex(address).strip('L'))
    f_exec.write(hex(address).strip('L') + '\n')
    # 4th line: address that we nop and hook to inject our input data(shoule be a call instr)
    address = start_pcode.getSeqnum().getTarget().getOffset()
    print(hex(address).strip('L'))
    summ_startaddr = address
    f_exec.write(hex(address).strip('L') + '\n')
    # 5th line: the args index that we should inject our fuzzing data(should be a int >=0 and <=6)
    source_func_name = get_funcname_at_call(source_pcode)
    for key in source_func_spec:
        if key in source_func_name:
            source_func_spec_name = key
            break
    input_idx = source_func_spec[source_func_spec_name]['critical_idx']
    print(input_idx)
    f_exec.write(str(input_idx) + '\n')
    # 6th line: the longest data input length(-1 means apply our default maxlength)
    if source_func_spec[source_func_spec_name]['limit_len']:
        max_len = start_pcode.getInput(source_func_spec[source_func_spec_name]['limit_idx']).offset
        print(max_len)
        f_exec.write(str(max_len) + '\n')
    else:
        print(-1)
        f_exec.write('-1\n')
    # cat. a pcodes, which sink buffer is all local
    a_pcodes = []
    # else cat. b
    b_pcodes = []
    for ep in end_pcodes:
        all_local = True
        ep_func_name = getFunctionAt(ep.getInput(0).getAddress()).getName()
        for key in maybe_sink_funcs_overflow_info:
            if ep_func_name.startswith(key):
                for idx in maybe_sink_funcs_overflow_info[key]:
                    this_vn = ep.getInput(idx)
                    if not this_vn:
                        continue
                    if not is_vn_local(this_vn):
                        all_local = False
                        this_vn_val = FlowNode(this_vn).get_value()
                        if this_vn_val:
                            if isinstance(this_vn_val, GenericAddress):
                                psize = get_global_size(this_vn_val.getOffset())
                            if isinstance(this_vn_val, Scalar):
                                psize = get_global_size(this_vn_val.getValue())
                        else:
                            psize = get_possible_size(this_vn)
                    else:
                        psize = get_local_possible_size(this_vn)
                    f_sink_buf.write(
                        "{} {} {} {}\n".format(hex(ep.getSeqnum().getTarget().getOffset()).strip('L'), idx, psize,
                                               ','.join([str(x) for x in maybe_sink_funcs_source_info[key]])))
                break
        if all_local:
            a_pcodes.append(ep)
        else:
            b_pcodes.append(ep)
    # 7th line: address to stop our symbolic soving(should be the block address of vuln call, here we simply apply the call instr addr)
    # address = end_pcode.getParent().getStart().getOffset()
    address = [ep.getSeqnum().getTarget().getOffset() for ep in a_pcodes]
    print(' '.join([hex(i).strip('L') for i in address]))
    f_exec.write(' '.join([hex(i).strip('L') for i in address]) + '\n')
    # 8th line: address to stop our fuzzer(should be the one last instr after vuln call)
    address = [ep.getSeqnum().getTarget().getOffset() for ep in a_pcodes]
    summary[-1] = (summary[-1], hex(summ_startaddr))
    offset = 4 if 'arm' in arch else 8
    address = [i+offset for i in address]
    print(' '.join([hex(i).strip('L') for i in address]))
    f_exec.write(' '.join([hex(i).strip('L') for i in address]) + '\n')

    address = [ep.getSeqnum().getTarget().getOffset() for ep in b_pcodes]
    print(' '.join([hex(i).strip('L') for i in address]))
    f_exec.write(' '.join([hex(i).strip('L') for i in address]) + '\n')
    address = [ep.getSeqnum().getTarget().getOffset() for ep in b_pcodes]
    summary[-1] = (summary[-1], hex(summ_startaddr))
    offset = 4 if 'arm' in arch else 8
    address = [i + offset for i in address]
    print(' '.join([hex(i).strip('L') for i in address]))
    f_exec.write(' '.join([hex(i).strip('L') for i in address]) + '\n')

    # linux or rtos? sometimes rtos image will be a ELF format too
    if (currentProgram.getExecutableFormat() == 'Raw Binary') or len(currentProgram.getExternalManager().getExternalLibraryNames())==0:
        print('rtos')
        f_exec.write('rtos\n')
    else:
        print("linux")
        f_exec.write('linux\n')
    all_get_pcodes = [start_pcode] + all_get_pcodes
    caller_end_list = []
    for this_pcode in all_get_pcodes:
        caller = getFunctionContaining(this_pcode.getSeqnum().getTarget())
        if caller:
            high_caller = get_hfunction(caller)
            for item in high_caller.getBasicBlocks():
                # 出度为0
                if item.getOutSize() == 0:
                    caller_end_list.append(hex(item.getStop().getOffset()).strip('L'))
    f_exec.write(','.join(caller_end_list) +'\n')

def inner_get_key_from_vn(vn):
    if not vn:
        return None
    ret = get_str_from_vn(vn)
    if ret:
        return ret
    if vn.isAddress():
        vn_data = getDataAt(vn.getAddress())
        if not vn_data:
            return
        val = vn_data.getValue()
    else:
        val = FlowNode(vn).get_value()
    if val:
        return val.getOffset()
    return None

def getAddress(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)


def do_emu(target_func,callee,called_offset,name_idx):
    # Uncontrollable return address
    CONTROLLED_RETURN_OFFSET = 0

    arg_reg_name = None
    if is_binary_mips:
        if name_idx <= 4:
            arg_reg_name = 'a{}'.format(name_idx - 1)
    # current mips/arm
    else:
        if name_idx <= 4:
            arg_reg_name = 'r{}'.format(name_idx - 1)

    if not arg_reg_name:
        return None
    # Establish emulation helper, please check out the API docs
    # for `EmulatorHelper` - there's a lot of helpful things
    # to help make architecture agnostic emulator tools.
    emuHelper = EmulatorHelper(currentProgram)
    callee_entry_offset = callee.getEntryPoint().getOffset()
    try:
        # Set controlled return location so we can identify return from emulated function
        controlledReturnAddr = getAddress(CONTROLLED_RETURN_OFFSET)

        # Set initial RIP
        targetFunctionEntryLong = int("0x{}".format(target_func.getEntryPoint()), 16)
        emuHelper.writeRegister(emuHelper.getPCRegister(), targetFunctionEntryLong)

        # Set the stack address
        emuHelper.writeRegister(emuHelper.getStackPointerRegister(), 0x2FFF0000)
        # If no parameter is set, the default is 0
        count = 0
        maxCount = 3000
        after_offset = False
        while monitor.isCancelled() is False:
            count += 1
            # Preventing a dead-end cycle
            if count > maxCount:
                break
            executionAddress = emuHelper.getExecutionAddress()
            if (executionAddress == controlledReturnAddr):
                print("Emulation complete.")
                return
            if (executionAddress.getOffset() == called_offset):
                after_offset = True
            if after_offset and executionAddress.getOffset() == callee_entry_offset:
                arg_val = emuHelper.readRegister(arg_reg_name)
                strArg1 = emuHelper.readNullTerminatedString(toAddr(arg_val), 100)
                return strArg1
            success = emuHelper.step(monitor)
            if (success == False):
                # lastError = emuHelper.getLastError()
                # printerr("Emulation Error: '{}'".format(lastError))
                return
    except Exception:
        pass
    finally:
        emuHelper.dispose()

key_cache = {}

def get_key_from_vn(vn, call_pcode,name_idx):
    if vn in key_cache:
        return key_cache[vn]
    ret = inner_get_key_from_vn(vn)
    if ret:
        key_cache[vn] = ret
        return ret
    # If the value is not obtained, emulation
    calling_func = getFunctionContaining(call_pcode.getSeqnum().getTarget())
    if not calling_func:
        return None
    callee_vn = call_pcode.getInput(0)
    if not callee_vn:
        return None
    callee = getFunctionAt(callee_vn.getAddress())
    if not callee:
        return None

    ret = do_emu(calling_func,callee,call_pcode.getSeqnum().getTarget().getOffset(),name_idx)
    key_cache[vn] = ret
    # if ret:
    #     with open('findtrace_output/%s/emu.txt' % output_dir_name, 'a') as f:
    #         str_addr = find(ret)
    #         xref_list = []
    #         if str_addr:
    #             for item in getReferencesTo(str_addr):
    #                 xref_list.append(item.getFromAddress())
    #         f.write("{} {} {} {}\n".format(callee.getName(),call_pcode.getSeqnum().getTarget(),ret, xref_list))
    # else:
    #     with open('findtrace_output/%s/emu_fail.txt' % output_dir_name, 'a') as f:
    #         f.write("{} {}\n".format(callee.getName(),call_pcode.getSeqnum().getTarget()))
    return ret


def convert_list(val_list,source_pcode):
    taint_set = set()
    func_opcodes_map = {}
    call_map = {}
    sink_func_info = {}
    call_traces = []
    for item in val_list:
        item_taint_set = item['taint_set']
        taint_set |= item_taint_set
        item_call_trace = item['call_trace']
        call_traces.append(item_call_trace)
        item_opcodes = item['opcode_trace']
        sink_func_name = item['sink_func_name']
        sink_func_idx = item['sink_func_idx']
        if sink_func_name not in sink_func_info:
            sink_func_info[sink_func_name] = sink_func_idx
        for i,func in enumerate(item_call_trace[:-1]):
            func_entry_offset = func.getEntryPoint().getOffset()
            if func_entry_offset not in func_opcodes_map:
                func_opcodes_map[func_entry_offset] = item_opcodes[i]
            if func_entry_offset not in call_map:
                call_map[func_entry_offset] = set()
            if i + 1 < len(item_call_trace):
                call_map[func_entry_offset].add(item_call_trace[i+1])

    return {
        'taint_set':taint_set,
        'func_opcodes_map': func_opcodes_map,
        'call_map': call_map,
        'source_pcode': source_pcode,
        'sink_func_info': sink_func_info,
        'call_traces': call_traces
    }

# Store the results of all source->sink to be merged with the same source point
map_res = {}
# Store the results of all get->set
get_map_res = {}


# source->set only needs to be processed once, so add a cache here
source_trans_call_traces_cached = {}
source_trans_pcode_traces_cached = {}

tree_deep_map = {}
set_deep_map = {}

source_sink_trace_num = 0
source_convey_trace_num = 0
convey_sink_trace_num = 0

def handle_call_trace(source_func_name,sink_func_name,source_func_idx,sink_func_idx):
    global source_sink_trace_num
    global source_convey_trace_num
    global convey_sink_trace_num
    # Analyze the result of the path from source->sink function
    print("1st phase: Analysis single mission data flow")
    source_sink_call_traces = get_call_trace_between_func(source_func_name, sink_func_name, False)
    source_sink_trace_num += len(source_sink_call_traces)
    for ss_trace in source_sink_call_traces:
        for res in get_patch_info(ss_trace, source_func_name, sink_func_name, source_func_idx, sink_func_idx):
            taint_set, pcodes,source_pcode = res
            if source_pcode not in map_res:
                map_res[source_pcode] = []
            map_res[source_pcode].append({
                'opcode_trace': pcodes,
                'taint_set': taint_set,
                'call_trace': ss_trace,
                'source_pcode': source_pcode,
                'sink_func_name':sink_func_name,
                'sink_func_idx': sink_func_idx
            })
            if source_pcode not in tree_deep_map:
                tree_deep_map[source_pcode] = len(ss_trace)
            else:
                tree_deep_map[source_pcode] = max(tree_deep_map[source_pcode], len(ss_trace))

    # Analyze the results of the path from source->transfer function and from transfer function->sink
    print("2nd phase: Analysis multi mission data flow")
    source_trans_call_traces_dict = {}
    if source_func_name in source_trans_call_traces_cached:
        source_trans_call_traces_dict = source_trans_call_traces_cached[source_func_name]
    else:
        for item in trans_func_list:
            set_func_name = item['in']['name']
            source_trans_call_traces_dict[set_func_name] = get_call_trace_between_func(source_func_name, set_func_name,
                                                                                       True)
            source_convey_trace_num += len(source_trans_call_traces_dict[set_func_name])
        source_trans_call_traces_cached[source_func_name] = source_trans_call_traces_dict

    trans_sink_call_traces_dict = {}
    if len(source_trans_call_traces_dict) > 0:
        for item in trans_func_list:
            get_func_name = item['out']['name']
            trans_sink_call_traces_dict[get_func_name] = get_call_trace_between_func(get_func_name, sink_func_name,
                                                                                     True)
            convey_sink_trace_num += len(trans_sink_call_traces_dict[get_func_name])
    print("-----------begin set func pcode trace--------------")
    for item in trans_func_list:
        set_func_name = item['in']['name']
        get_func_name = item['out']['name']
        if source_trans_call_traces_dict[set_func_name] and trans_sink_call_traces_dict[get_func_name]:
            this_cache_key = source_func_name + ',' + set_func_name
            if this_cache_key not in source_trans_pcode_traces_cached:
                source_trans_pcode_traces = []
                for source_trans_trace in source_trans_call_traces_dict[set_func_name]:
                    for res in get_patch_info(source_trans_trace, source_func_name, set_func_name,
                                                                 source_func_idx, item['in']['idx']):
                        taint_set, pcodes, source_pcode = res
                        source_trans_pcode_traces.append({
                            'opcode_trace': pcodes,
                            'taint_set': taint_set,
                            'call_trace': source_trans_trace,
                            'source_pcode': source_pcode
                        })
                print("-----------begin get func pcode trace--------------")
                all_param_keys = set()
                new_source_trans_pcode_traces = []
                for stp_trace in source_trans_pcode_traces:
                    param_keys_set = set()
                    opcode_trace = stp_trace['opcode_trace']
                    set_func_call_pcodes = filter_pcodes_called_with(opcode_trace[-1],set_func_name)
                    for idx in item['in']['name_idx']:
                        for sfcp in set_func_call_pcodes:
                            if not is_param_taint(sfcp,stp_trace['taint_set']):
                                continue
                            name_vn = sfcp.getInput(idx)
                            param_key = get_key_from_vn(name_vn,sfcp,idx)
                            if param_key:
                                param_keys_set.add(param_key)
                                if param_key not in set_deep_map:
                                    set_deep_map[param_key] = {}
                                if stp_trace['source_pcode'] not in set_deep_map[param_key]:
                                    set_deep_map[param_key][stp_trace['source_pcode']] = len(stp_trace['call_trace'])
                                else:
                                    set_deep_map[param_key][stp_trace['source_pcode']] = max(set_deep_map[param_key][stp_trace['source_pcode']],len(stp_trace['call_trace']))
                    all_param_keys |= param_keys_set
                    new_source_trans_pcode_traces.append({
                        'opcode_trace': opcode_trace,
                        'taint_set': stp_trace['taint_set'],
                        'call_trace': stp_trace['call_trace'],
                        'source_pcode': stp_trace['source_pcode'],
                        'param_keys': param_keys_set,
                        'trans_func_info': item
                    })
                for nitem in new_source_trans_pcode_traces:
                    if nitem['source_pcode'] not in map_res:
                        map_res[nitem['source_pcode']] = []
                    map_res[nitem['source_pcode']].append({
                        'opcode_trace': nitem['opcode_trace'],
                        'taint_set': nitem['taint_set'],
                        'call_trace': nitem['call_trace'],
                        'source_pcode': nitem['source_pcode'],
                        'sink_func_name': set_func_name,
                        'sink_func_idx': item['in']['idx']
                    })
                source_trans_pcode_traces_cached[this_cache_key] = (source_trans_pcode_traces,all_param_keys)
            else:
                source_trans_pcode_traces,all_param_keys = source_trans_pcode_traces_cached[this_cache_key]
            # print(len(new_source_trans_pcode_traces))
            trans_sink_pcode_traces = []
            if len(source_trans_pcode_traces) > 0:
                for trans_sink_trace in trans_sink_call_traces_dict[get_func_name]:
                    for res in get_patch_info(trans_sink_trace, get_func_name, sink_func_name,
                                              source_func_idx, sink_func_idx,item['out']['name_idx'], all_param_keys):
                        taint_set, pcodes, source_pcode = res
                        trans_sink_pcode_traces.append({
                            'opcode_trace': pcodes,
                            'taint_set': taint_set,
                            'call_trace': trans_sink_trace,
                            'source_pcode': source_pcode
                        })
            new_trans_sink_pcode_traces = []
            for tsp_trace in trans_sink_pcode_traces:
                opcode_trace = tsp_trace['opcode_trace']
                get_func_call_pcode = tsp_trace['source_pcode']
                for idx in item['out']['name_idx']:
                    name_vn = get_func_call_pcode.getInput(idx)
                    param_key = get_key_from_vn(name_vn,get_func_call_pcode,idx)
                    if param_key:
                        new_trans_sink_pcode_traces.append({
                            'opcode_trace': opcode_trace,
                            'taint_set': tsp_trace['taint_set'],
                            'call_trace': tsp_trace['call_trace'],
                            'source_pcode': tsp_trace['source_pcode'],
                            'param_key': param_key,
                            'trans_func_info': item
                        })
                        if param_key in set_deep_map:
                            for key,val in set_deep_map[param_key].items():
                                if key not in tree_deep_map:
                                    tree_deep_map[key] = val + len(tsp_trace['call_trace']) -1
                                else:
                                    tree_deep_map[key] = max(tree_deep_map[key], val + len(tsp_trace['call_trace']) -1)

            for item in new_trans_sink_pcode_traces:
                if item['source_pcode'] not in get_map_res:
                    get_map_res[item['source_pcode']] = []
                get_map_res[item['source_pcode']].append({
                    'opcode_trace': item['opcode_trace'],
                    'taint_set': item['taint_set'],
                    'call_trace': item['call_trace'],
                    'source_pcode': item['source_pcode'],
                    'trans_func_info': item['trans_func_info'],
                    'param_key': item['param_key'],
                    'sink_func_name': sink_func_name,
                    'sink_func_idx': sink_func_idx
                })


def dump_one_link_res(tree_res,plink,should_patch_pcodes):
    global trace_cnt, summary
    print("Find a possible call tree result, try to dump it")
    print("begin @{}".format(tree_res['source_pcode'].getSeqnum().getTarget()))
    summary.append(tree_res['source_pcode'].getSeqnum().getTarget())

    f_patch = open('findtrace_output/%s/patch_%d' % (output_dir_name, trace_cnt), 'w')
    f_exec = open('findtrace_output/%s/exec_%d' % (output_dir_name, trace_cnt), 'w')
    f_dict = open('findtrace_output/%s/dict_%d' % (output_dir_name, trace_cnt), 'w')
    f_calltrace = open('findtrace_output/%s/calltrace_%d' % (output_dir_name, trace_cnt), 'w')
    f_cbranch_info = open('findtrace_output/%s/cbranch_info_%d' % (output_dir_name, trace_cnt), 'w')
    f_call_checksum = open('findtrace_output/%s/call_checksum_%d' % (output_dir_name, trace_cnt), 'w')
    f_xalloc = open('findtrace_output/%s/xalloc_%d' % (output_dir_name, trace_cnt), 'w')
    f_sink_buf = open('findtrace_output/%s/sink_buf_%d' % (output_dir_name, trace_cnt), 'w')

    handle_trace(tree_res, f_patch, f_exec, f_cbranch_info,f_dict,f_calltrace,f_call_checksum,f_xalloc,f_sink_buf,plink,should_patch_pcodes)
    # Print all strings in the trace for the AFL dictionary
    print_trace_str(tree_res['func_opcodes_map'], f_dict)

    f_patch.close()
    f_exec.close()
    f_dict.close()
    f_calltrace.close()
    f_cbranch_info.close()
    f_call_checksum.close()
    f_xalloc.close()
    f_sink_buf.close()
    print("patch file has been saved in %s/findtrace_output/%s/patch_%d" % (os.getcwd(), output_dir_name, trace_cnt))
    print("exec file has been saved in %s/findtrace_output/%s/exec_%d" % (os.getcwd(), output_dir_name, trace_cnt))
    print("dict file has been saved in %s/findtrace_output/%s/dict_%d" % (os.getcwd(), output_dir_name, trace_cnt))
    trace_cnt += 1


def get_possible_links(link_res):
    """
    Added multiple links to the output
    """
    all_possible_path = []
    one_res = []
    for item in link_res:
        set_pcode = item[0]
        get_pcodes = item[1]
        if not get_pcodes:
            one_res.append((set_pcode, None))
        elif len(get_pcodes) > 0:
            for gpcode in get_pcodes:
                one_res.append((set_pcode,gpcode))
    all_possible_path.append(one_res)
    return all_possible_path


def dump_all():
    for key, val in map_res.items():
        tree_res = convert_list(val, key)
        tainted_vns = tree_res['taint_set']
        func_opcodes_map = tree_res['func_opcodes_map']
        call_map = tree_res['call_map']
        sink_func_info = tree_res['sink_func_info']

        end_pcodes = set()
        for key2, val2 in func_opcodes_map.items():
            next_funcs_names = [x.getName() for x in call_map.get(key2, [])]
            _, sink_pcodes = get_reachable_bbs(val2, next_funcs_names, tainted_vns, sink_func_info)
            end_pcodes |= sink_pcodes

        link_res = []
        should_patch_pcodes = []
        for end_pcode in end_pcodes:
            set_func_name = get_funcname_at_call(end_pcode)
            set_func_info,get_func_info = get_convery_func_info(set_func_name)
            if set_func_info and get_func_info:
                this_key = get_key_from_vn(end_pcode.getInput(set_func_info['name_idx'][0]),end_pcode,set_func_info['name_idx'][0])
                get_pcodes = get_get_pocdes(this_key, get_func_info['name'])
                if len(get_pcodes) > 0:
                    link_res.append((end_pcode,get_pcodes))
                else:
                    should_patch_pcodes.append(end_pcode)
            else:
                # If end_pcode is a direct sink function, there is no need to link
                link_res.append((end_pcode,None))
        if len(link_res) == 0:
            continue
        all_possible_links = get_possible_links(link_res)
        for plink in all_possible_links:
            dump_one_link_res(tree_res,plink,should_patch_pcodes)


def main():
    sys.stdout.write("\033[0;42mfindtrace start %r\033[0m\n" % currentProgram)
    start_time = time.time()

    os.system('mkdir -p %s/findtrace_output/%s' % (os.getcwd(), output_dir_name))
    # source
    print("source_funcs: %r" % source_funcs)
    print("sink_funcs: %r" % sink_funcs)
    # Try to create more functions
    create_more_funcs()
    for source_func_name in source_funcs:
        for sink_func_name in sink_funcs:
            # source_func_name = 'recvfrom'
            # sink_func_name = 'memcpy'
            print("Digging from function %r to function %r" % (source_func_name, sink_func_name))
            if simresults:
                # The location of the source function stores the user input, 
                # -1 is considered the return value, 0 represents the function itself
                # The idx of param1 is considered to be 1
                for simresult in simresults:
                    if source_func_name == simresult['funcName']:
                        source_func_idx = eval(simresult['criticalIndex'])
                        for i in range(len(source_func_idx)):
                            if source_func_idx[i] <= 0:
                                source_func_idx[i] = -1
                        break
                # If this position of the sink function is affected, it is considered that a vulnerability may occur
                for simresult in simresults:
                    if sink_func_name == simresult['funcName']:
                        sink_func_idx = eval(simresult['criticalIndex'])
                        for i in range(len(sink_func_idx)):
                            if sink_func_idx[i] <= 0:
                                sink_func_idx[i] = -1
                        break
            else:
                foundsource = False
                this_maybe_source_func = None
                for maybe_source_func in maybe_source_funcs:
                    if source_func_name.startswith(maybe_source_func):
                        this_maybe_source_func = source_func_name
                        foundsource = True
                        break
                if not foundsource:
                    continue
                foundsink = False
                this_maybe_sink_func = None
                for maybe_sink_func in maybe_sink_funcs:
                    if sink_func_name.startswith(maybe_sink_func):
                        this_maybe_sink_func = sink_func_name
                        foundsink = True
                        continue
                if not foundsink:
                    continue
                if this_maybe_sink_func not in maybe_sink_funcs:
                    continue
                if this_maybe_source_func not in maybe_source_funcs:
                    continue
                source_func_idx = eval(maybe_source_funcs[source_func_name])
                for i in range(len(source_func_idx)):
                    if source_func_idx[i] <= 0:
                        source_func_idx[i] = -1
                sink_func_idx = eval(maybe_sink_funcs[sink_func_name])
                for i in range(len(sink_func_idx)):
                    if sink_func_idx[i] <= 0:
                        sink_func_idx[i] = -1
            print("source_func_idx %r\t\tsink_func_idx %r" % (source_func_idx, sink_func_idx))
            handle_call_trace(source_func_name,sink_func_name,source_func_idx,sink_func_idx)
        #     break
        # break
    dump_all()

    end_time = time.time()
    print("All done, time: %s" % time_calc(end_time - start_time))

    source_xrefs_count = 0
    sink_xrefs_count = 0
    referManger = currentProgram.getReferenceManager()
    for source_func_name in source_funcs:
        func = custom_get_function(source_func_name)
        if not func:
            continue
        source_xrefs_count += referManger.getReferenceCountTo(func.getEntryPoint())
    for sink_func_name in sink_funcs:
        func = custom_get_function(sink_func_name)
        if not func:
            continue
        sink_xrefs_count += referManger.getReferenceCountTo(func.getEntryPoint())
    with open('findtrace_output/%s/summary' % output_dir_name, 'w') as f:
        print("Summary: find %d call_traces" % len(summary))
        f.write("Summary: find %d call_traces\n" % len(summary))
        for call_trace in summary:
            print(str(call_trace))
            f.write(str(call_trace) + '\n')
        f.write("Analysis time: %s\n" % time_calc(end_time - start_time))
        print("summary file has been saved in %s/findtrace_output/%s/summary" % (os.getcwd(), output_dir_name))
    with open('findtrace_output/%s/summary.json' % output_dir_name, 'w') as f:
        # Some statistical information
        # How many input points are there
        # Merge into how many call trees
        # depth of the call tree, number of functions included, analysis time, number of branches affected by the input, sub-functions
        # Count the average number of subfunction calls we delete for each model trace, and the number of branches we delete
        call_tree_info_list = []
        for k,v in tree_deep_map.items():
            ins_count = 0
            for func_entry in call_tree_funcs_map[k]:
                this_func = getFunctionAt(toAddr(func_entry))
                insIter = currentProgram.getListing().getInstructions(this_func.getBody(),True)
                while insIter.hasNext():
                    ins = insIter.next()
                    ins_count += 1
            call_tree_info_list.append({
                'deep':v,
                'funcs': [getFunctionAt(x.getInput(0).getAddress()).getName() for x in call_tree_all_call_map[k]],
                'affect_call': len(call_tree_affect_call_map[k]),
                'affect_cbranch': len(call_tree_cbranch_vn_map[k]),
                'patched_call': len(call_tree_patched_call_map[k]),
                'patched_cbranch': len(call_tree_patched_cbranch_map[k]),
                'all_call': len(call_tree_all_call_map[k]),
                'all_cbranch': len(call_tree_all_cbranch_map[k]),
                'ins_count': ins_count
            })
        result_json = {
            'source_pcode_num_1st': len(map_res),
            'source_pcode_trace_num_1st': reduce(lambda x, y: x+y,[0] + [len(val) for key,val in map_res.items()]),
            'source_pcode_num_2st_convey_sink': len(get_map_res),
            # [0] is to prevent the list after it from being empty
            'source_pcode_trace_num_2st_convey_sink': reduce(lambda x, y: x+y,[0] + [len(val) for key,val in get_map_res.items()]),
            'all_source_num': len(map_res),
            'call_tree_num': len(summary),
            'cost_time': end_time - start_time,
            'call_tree_info': call_tree_info_list,
            'all_func_num': currentProgram.getFunctionManager().getFunctionCount(),
            'source_xrefs_count': source_xrefs_count,
            'sink_xrefs_count': sink_xrefs_count,
            'source_sink_trace_num': source_sink_trace_num,
            'source_convey_trace_num': source_convey_trace_num,
            'convey_sink_trace_num':convey_sink_trace_num,
            'all_trace_sum_num': source_sink_trace_num + source_convey_trace_num + convey_sink_trace_num
        }
        f.write(json.dumps(result_json,ensure_ascii=False,indent=4))
    sys.stdout.write("\033[0;44mfindtrace end %r\033[0m\n" % currentProgram)


if __name__ == '__main__':
    main()