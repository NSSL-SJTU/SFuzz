#!/usr/bin/env python3
import angr, sys, claripy
import time, random, signal
from threading import Timer
import code
import copy
from copy import deepcopy

import os, subprocess

import binascii
from utils import conv_regs, UF_Logging, Patch
import time
import random, shutil

start_time = time.time()
one_time = None
end_time = None

l = UF_Logging(__name__)
l.setlevel(l.INFO)

with open("workdir/exec", 'r') as f:
    exec_info=f.read().strip('\n').split('\n')
ARCH=exec_info[1][:-2]
ENDIAN='little' if 'le' in exec_info[1][-2:] or 'el' in exec_info[1][-2:] else 'big'
TARGET=os.environ['UF_TARGET']
BASE_ADDR=int(exec_info[0], 0)
'''
ROM:800C83EC 158 1C 06 C6 24 la      $a2, aWifissid   # "wifiSSID"             
ROM:800C83F0 158 21 28 40 02 move    $a1, $s2
ROM:800C83F4 158 69 1D 03 0C jal     Packt_websGetVar  # Jump And Link
ROM:800C83F8 158 21 20 20 02 move    $a0, $s1
ROM:800C83FC 158 2F 80 18 3C lui     $t8, 0x802F      # Load Upper Immediate                <---  START_ADDR
...
ROM:800C8568 158                 jal     memset           # Jump And Link
ROM:800C856C 158                 addiu   $a0, $sp, 0x130+var_120  # Add Immediate Unsigned
ROM:800C8570 158                 lui     $a1, 0x802E      # Load Upper Immediate            <---  TARGET_END_ADDR
ROM:800C8574 158                 addiu   $a0, $sp, 0x130+var_120  # Add Immediate Unsigned
ROM:800C8578 158                 la      $a1, aS5g        # "%s_5G"
ROM:800C857C 158                 jal     sprintf_1        # Jump And Link
ROM:800C8580 158                 move    $a2, $s0
ROM:800C8584 158                 lui     $a0, 0x802D      # Load Upper Immediate
'''
START_ADDR = int(exec_info[2], 0)
INJECT_ADDR = int(exec_info[3], 0)
INJECT_IDX = int(exec_info[4], 0)
INJECT_MAXLEN = int(exec_info[5], 0)
TARGET_END_ADDR = [int(i, 0) for i in exec_info[6].split(' ')] if len(exec_info[6])>0 else []
FUZZ_END_ADDR = [int(i, 0) for i in exec_info[7].split(' ')] if len(exec_info[7])>0 else []
TARGET_END_ADDR += [int(i, 0) for i in exec_info[8].split(' ')] if len(exec_info[8])>0 else []
FUZZ_END_ADDR += [int(i, 0) for i in exec_info[9].split(' ')] if len(exec_info[9])>0 else []
CLASSB_TARGET_END_ADDR = [int(i, 0) for i in exec_info[8].split(' ')] if len(exec_info[8])>0 else []
OS = exec_info[10]
if len(exec_info)>11:
    EXEC_END_ADDR = [int(i, 0) for i in exec_info[11].split(',')] if len(exec_info[11])>0 else []
else:
    EXEC_END_ADDR = []

# SYMBOLIZE_INPUT = True
SYMBOLIZE_INPUT = os.access("workdir/call_checksum",os.F_OK) and len(open("workdir/call_checksum",'r').read().strip('\n'))>0
FOUND_LIMITSOLVE = True
FOUND_MORESTEPS = 5
DEBUG = True

MAIN_REEXEC_TIME = 32
REEXEC_TIME = 64
SHRINK_THRESHOLD = 50
l.setlevel(l.INFO)
if DEBUG:
    l.setlevel(l.DEBUG)
    MAIN_REEXEC_TIME = 1

if ARCH == 'mips':
    NOP = b'\0\0\0\0'
elif ARCH == 'arm':
    if ENDIAN == 'little':
        NOP = b'\x00\xf0 \xe3'
    elif ENDIAN == 'big':
        NOP = b'\xe3 \xf0\x00'

CLASSB_UNKNOWNSIZE_SINK_BUFS = {}
with open('workdir/sink_buf','r') as f:
    content = f.read().strip('\n').split('\n')
    for c in content:
        c = c.split(' ')
        addr = int(c[0], 0)
        if addr not in CLASSB_TARGET_END_ADDR:
            continue
        info = []
        for i in c[1:]:
            if ',' in i:
                info.append([int(_, 0) for _ in i.split(',')])
            else:
                info.append(int(i, 0))
        if info[1] == -1:
            # we only want classB with unknown size 
            CLASSB_UNKNOWNSIZE_SINK_BUFS[addr] = info

def output_symresult():
    def output_constrains_statistic(append_str):
        global simgr
        active_state_cnt = len(simgr.active)
        constraints_sum = 0
        crashinput_constraints_sum = 0
        for s in simgr.active:
            print(s.solver.constraints)
            constraints_sum += len(s.solver.constraints)
            for c in s.solver.constraints:
                if 'crash_input_sim' in str(c):
                    crashinput_constraints_sum += 1
        with open('workdir/sfuzz_concolic_stat/symsolve_constraints_statistic_%s' % append_str, 'w') as f:
            f.write(sys.argv[1] + '\n')
            f.write(str(active_state_cnt) + '\n')
            f.write(str(constraints_sum) + '\n')
            f.write(str(crashinput_constraints_sum))


    def output_subfunc_statistic(append_str):
        global simgr
        cnt = 0
        for s in simgr.active:
            if 'subfunc_flag' in s.globals and s.globals['subfunc_flag'] == True:
                cnt += 1

        with open('workdir/sfuzz_concolic_stat/symsolve_subfunc_statistic_%s' % append_str, 'w') as f:
            f.write(sys.argv[1] + '\n')
            f.write(str(cnt)+'\n')
            f.write(str(len(simgr.active)))

    if not os.access("workdir/sfuzz_concolic_stat", os.F_OK):
        os.mkdir("workdir/sfuzz_concolic_stat")
    append_str = ''.join([random.choice('123456789abcdefghijklmn') for i in range(8)])
    output_subfunc_statistic(append_str)
    output_constrains_statistic(append_str)

def judge_in_range(state, addr_or_addrlist):
    block = state.block()
    if type(addr_or_addrlist)==set or type(addr_or_addrlist)==list:
        for addr in addr_or_addrlist:
            if addr in range(block.addr, block.addr+block.size):
                l.debug("addr {} in range({}, {})".format(addr, block.addr, block.addr + block.size))
                return True
    else:
        if addr_or_addrlist in range(block.addr, block.addr+block.size):
            l.debug("addr {} in range({}, {})".format(addr_or_addrlist, block.addr, block.addr + block.size))
            return True
    # print("block.addr=0x%08x, size=0x%08x, addr_or_addrlist %s, return False"%(block.addr, block.size, addr_or_addrlist))
    return False
def judge_on_trace(state, pctrace):
    res = (state.block().addr in pctrace) or (state.block().addr-4 in pctrace) or (state.block().addr-8 in pctrace) or (state.block().addr+4 in pctrace) or (state.block().addr+8 in pctrace)
    l.debug("judge_on_trace judging %r, pctrace len:%d, return %r"%(state, len(pctrace), res))
    return res
def hasundrop(state, pctrace, proj):
    if 'undrop' not in state.globals:
        return False
    # print("state at %r has undrop attr %r"%(state, state.globals['undrop']))
    if state.globals['undrop']:
        if state.addr in pctrace and not proj.is_hooked(state.addr):
            state.globals['undrop'] = False
            # print("change state at %r back to drop, orig set addr 0x%08x"%(state, state.globals['undrop_setaddr']))
            return True
        else:
            return state.globals['undrop']
    return False
    
'''
FUZZ_END_ADDR: Ghidra output
TRACE_END_ADDR: Hybrid Fuzzing output
SYMSOLVE_END_ADDR: Poc Analysis output
'''
TRACE_END_ADDR = {}
SYMSOLVE_END_ADDR = {}
for fuzz_endaddr in FUZZ_END_ADDR:
    TRACE_END_ADDR[fuzz_endaddr] = False
    SYMSOLVE_END_ADDR[fuzz_endaddr] = False
if not os.getenv("UF_POC_SAVETIME") or os.getenv("UF_POC_SAVETIME").lower()!='no':
    if os.access("workdir/poc_trace_end_addr", os.F_OK):
        with open("workdir/poc_trace_end_addr",'r') as f:
            content = f.read().strip('\n').split('\n')
            content = [int(i,0) for i in content]
            for c in content:
                TRACE_END_ADDR[c] = True
    if os.access("workdir/poc_symsolve_end_addr", os.F_OK):
        with open("workdir/poc_symsolve_end_addr",'r') as f:
            content = f.read().strip('\n').split('\n')
            content = [int(i,0) for i in content]
            for c in content:
                SYMSOLVE_END_ADDR[c] = True
        
CURR_TARGET_END_ADDR = None


def output_others(other_constrains, curr_sink_addr):
    with open("workdir/relied_functions",'a') as f:
        f.write('other constrains:\n')
        f.write(str(other_constrains))
        f.write('\n')
def output_relied(relied_functions, curr_sink_addr):
    if os.access("workdir/call_checksum", os.F_OK):
        with open("workdir/call_checksum", 'r') as f:
            relied_functions += ["Function called at 0x%08x is required as checksum" % int(i, 0) for i in f.read().strip('\n').split('\n') if len(i)>3]
            # relied_functions = relied_functions.union(["Function called at 0x%08x is required as checksum" % int(i, 0) for i in f.read().strip('\n').split('\n') if len(i)>3])
    with open("workdir/relied_functions",'a') as f:
        f.write('crash input "'+sys.argv[1]+'" may required to reach sink addr 0x%08x:\n'%curr_sink_addr)
        f.write('\n'.join(relied_function for relied_function in relied_functions))
        # f.write('\n'.join(hex(relied_function) for relied_function in relied_functions))
        f.write('\n')
def output_unsolve_constraints(curr_sink_addr):
    with open("workdir/relied_functions",'a') as f:
        f.write('crash input "'+sys.argv[1]+'" is unable to find solvable path to sink addr 0x%08x (maybe due to timeout or unsolvable path), this crash input may not trigger crash in reality, source addr: 0x%08x, sink addr: [%s]\n'%(curr_sink_addr if curr_sink_addr else 0x0, START_ADDR, ', '.join([hex(i) for i  in FUZZ_END_ADDR])))

stored = False
apply_tmin_to_crashinput = False

found = False


step_cnt = 0
reach_target = False
relied_functions = []
other_constrains = []
explore_steps = 0
crash_input_calc_cnt = 0
crash_input_sim = None
crash_input = None
simgr = None
proj = None
CURR_TARGET_END_ADDR = None
avoid_addrs = None
checksum_judgeaddr = None
patches = None

def add_invert_rerun_simgr(pre_constrain, active_state_ori, other_supplement_memaddr = None, other_constrains = None, max_step_cnt = None, max_active_state_cnt = None):
    global stored, avoid_addrs, checksum_judgeaddr, TARGET_END_ADDR
    stored = False

    s = proj.factory.blank_state(addr = START_ADDR)

    if other_supplement_memaddr:
        l.debug("read from original active_state 0x%08x to new_blank_state"%other_supplement_memaddr)
        s.memory.store(other_supplement_memaddr, active_state_ori.memory.load(other_supplement_memaddr, 0x1000))

    if type(pre_constrain) == list:
        for pc in pre_constrain:
            s.solver.add(pc.__invert__())    
    else:
        s.solver.add(pre_constrain.__invert__())

    if type(other_constrains) == list:
        for oc in other_constrains:
            s.solver.add(oc)
    elif other_constrains != None:
        s.solver.add(other_constrains)
    # print(s.solver.constraints)
    if DEBUG:
        simgr_invertrun = proj.factory.simgr(s, save_unsat=True, save_unconstrained=True)
    else:
        simgr_invertrun = proj.factory.simgr(s, save_unsat=True, save_unconstrained=False)
    step_cnt = 0
    reach_target = False
    explore_steps = 0
    while len(simgr_invertrun.active)>0:
        print('\n=========================\nadd_invert_rerun_simgr step_cnt %d max_step_cnt %r max_active_state_cnt %r target sink addr %s'%(step_cnt, max_step_cnt, max_active_state_cnt, str([hex(i) for i in TARGET_END_ADDR])))
        step_cnt += 1
        if (max_step_cnt and step_cnt>max_step_cnt):
            break
        if max_active_state_cnt and len(simgr_invertrun.active)>max_active_state_cnt:
            pending_states = []
            for state in simgr_invertrun.active:
                if state.addr not in [state.addr for state in pending_states]:
                    pending_states.append(state)
            pending_states = pending_states[:max_active_state_cnt]
            l.debug("Shrinking from %r to %r"%(simgr_invertrun.active, pending_states))
            if DEBUG:
                simgr_invertrun = proj.factory.simgr(pending_states, save_unsat=True, save_unconstrained=True)
            else:
                simgr_invertrun = proj.factory.simgr(pending_states, save_unsat=True, save_unconstrained=False)
        l.debug("Current stashes: %s"%str(simgr_invertrun.stashes))
        def try_satisifiable(unsat_s):
            if SYMBOLIZE_INPUT:
                l.debug("unsat_s.addr: {}\tchecksum_judgeaddr: {}".format(hex(unsat_s.addr), ", ".join(hex(i) for i in checksum_judgeaddr)))
                if unsat_s.addr in checksum_judgeaddr:
                    unsat_s.preconstrainer.remove_preconstraints()
                    l.debug("try_satisifiable: %r"%unsat_s.solver.satisfiable())
                    return unsat_s.solver.satisfiable()
                else:
                    l.debug("try_satisifiable: %r"%False)
                    return False
            else:
                l.debug("try_satisifiable: %r"%False)
                return False
        simgr_invertrun.move(from_stash='unsat', to_stash='active', filter_func = try_satisifiable)
        for active_state in simgr_invertrun.active:
            # l.debug("active_state %r constrain: %r"%(active_state, active_state.solver.constraints))
            if judge_in_range(active_state, TARGET_END_ADDR):
                # if we successfully reach the target block with given input, try to solve all symbol we added to each subfunction call
                l.success("Successfully reach the target block 0x%08x with given crash input and inverted constrain!"%(active_state.addr))
                l.debug("pre_constrain: %r"%(pre_constrain.__invert__() if type(pre_constrain)!=list else [c.__invert__() for c in pre_constrain]))
                l.debug("other_constrains: %r"%other_constrains)
                l.debug("success state constrains: %r"%active_state.solver.constraints)
                return False
        

        simgr_invertrun.drop(stash='unsat')
        simgr_invertrun.drop(stash='active', filter_func=lambda s:s.addr in avoid_addrs)

        simgr_invertrun.step(stash='active')

    l.info("No more active states, or failed to reach endaddr with limited steps, current simgr.stashes %r" % simgr_invertrun.stashes)
    return True

def sink_hook(active_state):
    global step_cnt, reach_target, relied_functions, other_constrains, explore_steps, crash_input_calc_cnt, one_time, found, crash_input_sim, simgr, proj, CURR_TARGET_END_ADDR, avoid_addrs, checksum_judgeaddr, CLASSB_UNKNOWNSIZE_SINK_BUFS, crash_input

    active_state_addr = active_state.addr
    if ARCH == 'mips':
        active_state_addr -= 4

    # if we successfully reach the target block with given input, try to solve all symbol we added to each subfunction call
    l.success("Successfully reach the target block 0x%08x with given crash input! "%active_state_addr)
    reach_target = True

    if active_state_addr in CLASSB_UNKNOWNSIZE_SINK_BUFS:
        sinkbuf_idx = CLASSB_UNKNOWNSIZE_SINK_BUFS[active_state_addr][0]
        sinkbuf = proj.factory.cc().get_args(active_state, is_fp=sinkbuf_idx)[-1]
        try:
            if (sinkbuf > active_state.regs.sp-0x4000).is_true() and (sinkbuf <= 0x7fff0800).is_true():
                with open('workdir/poc_can_analyze_target_mem_size','a') as f:
                    f.write(hex(active_state_addr)+'\n')
        except:
            pass 
    else:
        with open('workdir/poc_can_analyze_target_mem_size','a') as f:
            f.write(hex(active_state_addr)+'\n')

    if SYMBOLIZE_INPUT:
        crash_input = active_state.solver.eval(crash_input_sim, cast_to=bytes)
        print("Crash input has been re-evaled, result: %r"%crash_input)
        with open("workdir/poc_reeval_crashinput_%s_%d"%(sys.argv[1].split('/')[-1].split(',')[0], crash_input_calc_cnt), 'wb') as f:
            f.write(crash_input)
            crash_input_calc_cnt += 1
    else:
        print("Crash input: %r"%crash_input)
        with open("workdir/poc_reeval_crashinput_%s_%d"%(sys.argv[1].split('/')[-1].split(',')[0], crash_input_calc_cnt), 'wb') as f:
            f.write(crash_input)
            crash_input_calc_cnt += 1
    state_relied_functions = []
    found = False
    l.debug("active_state.solver.constraints: %r"%active_state.solver.constraints)

    # Update: For all constrains, filter constraints that involved with subfunc_retval, invert each of them and re-run the simgr from start, to judge whether these constrains are required.
    subfunc_retval_constrains = [c for c in active_state.solver.constraints if "subfunc_retval_sim_" in str(c)]
    print("all constrains related to subfunc_retval: %r(len:%d)" % (subfunc_retval_constrains, len(subfunc_retval_constrains)))
    call_addr_may_relied = []
    # state_other_constraints = claripy.BoolV(True)
    state_other_constraints = [c for c in active_state.solver.constraints if "subfunc_retval_sim_" not in str(c)]

    for constrain in active_state.solver.constraints:
        if "subfunc_retval_sim_" in str(constrain):
            l.debug("constrain: %r is add as inverted for testing"%constrain)
            symname = [s for s in str(constrain).split(' ') if "subfunc_retval_sim_" in s][0].split('subfunc_retval_sim_')[1] # like: subfunc_retval_sim_0x800c84a4_6_6_32
            addr = int(symname.split('_')[0],0)
            sym_idx = int(symname.split('_')[1],0)
            if addr not in call_addr_may_relied:
                found_corr_patch = False
                for patch in patches:
                    if hex(patch.addr) in str(constrain):
                        patch.add_subfunc_call_hook_in_reexec(proj, constrain)
                        found_corr_patch = True
                        break
                if not found_corr_patch:
                    l.error("Failed to find corresponding patch info for constrain %r" % constrain)
                    raise ValueError
                j = False
                for arg in constrain.args:
                    if "subfunc_retval_sim_" in str(arg):
                        val1 = active_state.solver.eval(arg, cast_to=int)
                        print('val1: ', hex(val1))
                        if val1 > 0x10000:
                            # if it is a pointer, dont change pointer value, but change the content pointed
                            all_constrain_related = []
                            for c in active_state.solver.constraints:
                                if '%08x'%val1 in str(c):
                                    if str(c)!=str(constrain):
                                        i=0
                                        while i<len(state_other_constraints):
                                            if str(state_other_constraints[i]) == str(c):
                                                state_other_constraints=state_other_constraints[:i]+state_other_constraints[i+1:]
                                            else:
                                                i+=1
                                        all_constrain_related.append(c)
                                    else:
                                        all_constrain_related.append(c.__invert__())
                            j = add_invert_rerun_simgr(all_constrain_related, active_state, other_supplement_memaddr=val1, other_constrains=state_other_constraints, max_step_cnt = round(10*step_cnt), max_active_state_cnt = round(1.5*len(simgr.active)))
                        else:
                            # if it is not a pointer, change the value
                            j = add_invert_rerun_simgr(constrain, active_state, other_constrains=state_other_constraints, max_step_cnt = round(10*step_cnt), max_active_state_cnt = round(1.5*len(simgr.active)))
                        break
                if j:
                    l.debug("constrain: %r is required"%constrain)
                    call_addr_may_relied.append(addr)
                    for arg in constrain.args:
                        if "subfunc_retval_sim_" in str(arg):
                            val1 = active_state.solver.eval(arg, cast_to=int)
                            if val1 > 0x10000:
                                # consider val1 as a pointer
                                val2 = active_state.solver.eval(active_state.memory.load(val1, 32), cast_to=bytes).split(b'\0')[0]
                                print("Function called at 0x%08x should return: 0x%08x pointing to %s\nrelated constraints:%r" % (addr, val1, str(val2), [c for c in active_state.solver.constraints if 'subfunc_retval_sim_0x%08x'%addr in str(c)]))
                                state_relied_functions.append("Function called at 0x%08x should return: 0x%08x pointing to %s\nrelated constraints:%r" % (addr, val1, str(val2), [c for c in active_state.solver.constraints if 'subfunc_retval_sim_0x%08x'%addr in str(c)]))
                            else:
                                # consider val1 as a const number
                                print("Function called at 0x%08x should return: 0x%08x\nrelated constraints:%r" % (addr, val1, [c for c in active_state.solver.constraints if 'subfunc_retval_sim_0x%08x'%addr in str(c)]))
                                state_relied_functions.append("Function called at 0x%08x should return: 0x%08x\nrelated constraints:%r" % (addr, val1, [c for c in active_state.solver.constraints if 'subfunc_retval_sim_0x%08x'%addr in str(c)]))
                            found = True
                            SYMSOLVE_END_ADDR[CURR_TARGET_END_ADDR] = True
                            if not os.getenv("UF_POC_SAVETIME") or os.getenv("UF_POC_SAVETIME").lower()!='no':
                                with open("workdir/poc_symsolve_end_addr",'a') as f:
                                    f.write(hex(CURR_TARGET_END_ADDR)+'\n')
                            break
                else:
                    l.debug("constrain: %r is not required"%constrain)
                for patch in patches:
                    if hex(patch.addr) in str(constrain):
                        patch.add_subfunc_call_hook(proj)
                        break

    # other_constrains = claripy.Or(state_other_constraints)
    other_constrains += (state_other_constraints)

    relied_functions += state_relied_functions

    
    if not found:
        # l.info("No symbol of subfunction found or solver is unable to solve")
        l.info("No symbol of subfunction found or solver is unable to solve, here's all constrains: %s"%str(active_state.solver.constraints))
    if one_time==None:
        one_time = time.time()    

def main(rep1, repall):
    global step_cnt, reach_target, relied_functions, other_constrains, explore_steps, crash_input_calc_cnt, one_time, found, crash_input_sim, simgr, proj, CURR_TARGET_END_ADDR, avoid_addrs, checksum_judgeaddr, TARGET_END_ADDR, patches, crash_input
    if ARCH=='mips' and ENDIAN=='little':
        angr_arch = 'mipsel'
    elif ARCH=='mips':
        angr_arch = 'mipseb'
    elif ARCH=='arm' and ENDIAN=='little':
        angr_arch = 'armel'
    elif ARCH=='mips':
        angr_arch = 'armeb'

    if OS=='linux':
        proj = angr.Project(TARGET, support_selfmodifying_code=True)
    else:
        proj = angr.Project(TARGET, main_opts = {'backend': 'blob', 'arch': angr_arch, 'base_addr': BASE_ADDR}, support_selfmodifying_code=True)
    
    if apply_tmin_to_crashinput:
        os.system("UF_TARGET=%s UF_TRACE=no afl-tmin -U -i %s -o %s_tmin ./uf" % (TARGET, sys.argv[1], sys.argv[1]))
        with open(sys.argv[1]+'_tmin','rb') as f:
            crash_input = f.read()
    else:
        with open(sys.argv[1],'rb') as f:
            crash_input = f.read()

    if SYMBOLIZE_INPUT:
        crash_input_sim = claripy.BVS("crash_input_sim", len(crash_input)*8)

    def store_inject_data(s, data, addr=0x12340000):
        global stored
        # assert not stored, "store_inject_data get multi-called"
        stored = True
        s.memory.store(addr, b'\0'*0x20000)
        s.memory.store(addr, data)
        print('testing...')
        print(s.memory.load(addr, 4))
        print(s.solver.eval(s.memory.load(addr, 4)))
        return addr
    def findAndChangeReg(s, regval, dataAddr=0x12340000):
        if ARCH=='mips':
            if str(s.regs.s0) == str(regval):
                l.debug("changing reg s0 to dataAddr(0x%08x)"%dataAddr)
                s.regs.s0 = dataAddr
            if str(s.regs.s1) == str(regval):
                l.debug("changing reg s1 to dataAddr(0x%08x)"%dataAddr)
                s.regs.s1 = dataAddr
            if str(s.regs.s2) == str(regval):
                l.debug("changing reg s2 to dataAddr(0x%08x)"%dataAddr)
                s.regs.s2 = dataAddr
            if str(s.regs.s3) == str(regval):
                l.debug("changing reg s3 to dataAddr(0x%08x)"%dataAddr)
                s.regs.s3 = dataAddr
            if str(s.regs.s4) == str(regval):
                l.debug("changing reg s4 to dataAddr(0x%08x)"%dataAddr)
                s.regs.s4 = dataAddr
            if str(s.regs.s5) == str(regval):
                l.debug("changing reg s5 to dataAddr(0x%08x)"%dataAddr)
                s.regs.s5 = dataAddr
            if str(s.regs.s6) == str(regval):
                l.debug("changing reg s6 to dataAddr(0x%08x)"%dataAddr)
                s.regs.s6 = dataAddr
            if str(s.regs.s7) == str(regval):
                l.debug("changing reg s7 to dataAddr(0x%08x)"%dataAddr)
                s.regs.s7 = dataAddr
            if str(s.regs.fp) == str(regval):
                l.debug("changing reg fp to dataAddr(0x%08x)"%dataAddr)
                s.regs.fp = dataAddr
        elif ARCH=='arm':
            if str(s.regs.r4) == str(regval):
                l.debug("changing reg r4 to dataAddr(0x%08x)"%dataAddr)
                s.regs.r4 = dataAddr
            if str(s.regs.r5) == str(regval):
                l.debug("changing reg r5 to dataAddr(0x%08x)"%dataAddr)
                s.regs.r5 = dataAddr
            if str(s.regs.r6) == str(regval):
                l.debug("changing reg r6 to dataAddr(0x%08x)"%dataAddr)
                s.regs.r6 = dataAddr
            if str(s.regs.r7) == str(regval):
                l.debug("changing reg r7 to dataAddr(0x%08x)"%dataAddr)
                s.regs.r7 = dataAddr
            if str(s.regs.r8) == str(regval):
                l.debug("changing reg r8 to dataAddr(0x%08x)"%dataAddr)
                s.regs.r8 = dataAddr
            if str(s.regs.r9) == str(regval):
                l.debug("changing reg r9 to dataAddr(0x%08x)"%dataAddr)
                s.regs.r9 = dataAddr
            if str(s.regs.r10) == str(regval):
                l.debug("changing reg r10 to dataAddr(0x%08x)"%dataAddr)
                s.regs.r10 = dataAddr
            if str(s.regs.r11) == str(regval):
                l.debug("changing reg r11 to dataAddr(0x%08x)"%dataAddr)
                s.regs.r11 = dataAddr
        else:
            l.error("Unsupported arch %s"%ARCH)
    def inject_data(s):
        l.debug("inject data @ %r"%s.regs.pc)
        import codecs
        l.debug("inject data content: %r"%codecs.encode(crash_input, 'hex'))
        if INJECT_IDX == 0:
            l.debug("Data inject to return value")
            if SYMBOLIZE_INPUT:
                s.preconstrainer.preconstrain(crash_input, crash_input_sim)
                setattr(s.regs, conv_regs[ARCH]['rv'], store_inject_data(s, crash_input_sim))
            else:
                setattr(s.regs, conv_regs[ARCH]['rv'], store_inject_data(s, crash_input))
        else:
            if INJECT_IDX == 1:
                regval = getattr(s.regs, conv_regs[ARCH]['a0'])
                l.debug("Data inject to arg0 @ %r" % regval)
            if INJECT_IDX == 2:
                regval = getattr(s.regs, conv_regs[ARCH]['a1'])
                l.debug("Data inject to arg1 @ %r" % regval)
            if INJECT_IDX == 3:
                regval = getattr(s.regs, conv_regs[ARCH]['a2'])
                l.debug("Data inject to arg2 @ %r" % regval)
            if INJECT_IDX == 4:
                regval = getattr(s.regs, conv_regs[ARCH]['a3'])
                l.debug("Data inject to arg3 @ %r" % regval)
            if regval.symbolic and str(getattr(s.regs, conv_regs[ARCH]['bp'])) not in str(regval):
                l.debug("detect symbolic input address %r, find and change all possible reg value to dataAddr..."%regval)
                findAndChangeReg(s, regval)
                if SYMBOLIZE_INPUT:
                    s.preconstrainer.preconstrain(crash_input, crash_input_sim)
                    store_inject_data(s, crash_input_sim)
                    l.info("Data injection complete, symbolized data: %r"%crash_input_sim)
                else:
                    store_inject_data(s, crash_input)
                    l.info("Data injection complete, data: %r"%crash_input)
            else:
                if SYMBOLIZE_INPUT:
                    s.preconstrainer.preconstrain(crash_input, crash_input_sim)
                    store_inject_data(s, crash_input_sim, regval)
                    l.info("Data injection complete, symbolized data: %r"%crash_input_sim)
                else:
                    store_inject_data(s, crash_input, regval)
                    l.info("Data injection complete, data: %r"%crash_input)
            
            setattr(s.regs, conv_regs[ARCH]['rv'], claripy.BVS('inject_retval', 32))
            
    if ARCH=='mips':
        delay_slot_instr = proj.loader.memory.load(INJECT_ADDR+4, 4)
        proj.loader.memory.store(INJECT_ADDR, delay_slot_instr)
        proj.hook(INJECT_ADDR+4, inject_data, length=4, replace=True)
    else:
        proj.hook(INJECT_ADDR, inject_data, length=4, replace=True)

    reexec = 0
    p0 = subprocess.Popen("python3 scripts/tmp_branch_patch.py", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    p0.wait()
    p0.terminate()

    while True:
        trace_output=b''
        if DEBUG:
            p = subprocess.Popen("./run.sh TRACE ~ 0 %s %s" % (TARGET, sys.argv[1]), shell=True, stderr = subprocess.PIPE)
        else:
            p = subprocess.Popen("./run.sh TRACE ~ 0 %s %s" % (TARGET, sys.argv[1]), shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        
        reexec += 1
        # timeout check
        t_beginning = time.time()
        while p.poll() is None:
            trace_output += p.stderr.read() # prevent deadlock
            time.sleep(0.1)
            if time.time() - t_beginning > 3:
                p.terminate()
                break

        
        # exception check
        if p.poll() is not None:
            if p.wait()!=0:
                if DEBUG:
                    print("p.returncode: ",p.returncode)
                break
            if DEBUG:
                print("p.returncode: ",p.returncode)
        print("trace exec times: {}".format(reexec))
        if reexec>REEXEC_TIME:
            l.error("Failed to trigger the vuln in limited time, exit")
            exit(-1)
    

    trace_output += p.stderr.read()
    if DEBUG:
        print(trace_output)
        pass
    if b'on stack at ' in trace_output:
        # classA
        CURR_TARGET_END_ADDR = int(trace_output.split(b'on stack at ')[1].split(b'\n')[0],0)
    elif b'detect buffer overflow at ' in trace_output:
        # classB
        CURR_TARGET_END_ADDR = int(trace_output.split(b'detect buffer overflow at ')[1].split(b'\n')[0],0)
    else:
        # trace_output = CURR_TARGET_END_ADDR = None
        l.error("Failed to get CURR_TARGET_END_ADDR")
        p.terminate()
        return
    
    l.info("CURR_TARGET_END_ADDR: 0x%08x, find for new sink addr for %d/%d times"%(CURR_TARGET_END_ADDR, rep1, repall))
    p.terminate()

    if TRACE_END_ADDR[CURR_TARGET_END_ADDR]:
        l.info("CURR_TARGET_END_ADDR 0x%08x has been analyzed, pass."%CURR_TARGET_END_ADDR)
        return
    TRACE_END_ADDR[CURR_TARGET_END_ADDR] = True
    if not os.getenv("UF_POC_SAVETIME") or os.getenv("UF_POC_SAVETIME").lower()!='no':
        with open("workdir/poc_trace_end_addr",'a') as f:
            f.write(hex(CURR_TARGET_END_ADDR)+'\n')

    
    with open("workdir/pcLogger.txt",'r') as f:
        pctrace=[int(i,16) for i in f.read()[:-1].split('\n') if len(i)>3]
    pctrace = set([START_ADDR] + pctrace)
            
    def hook_connect(p):
        if not os.access("workdir/connect",os.F_OK):
            return
        with open("workdir/connect",'r') as f:
            connect_info = [i.split(' ') for i in f.read().strip('\n').split('\n') if len(i)>3]   
        connect_cnt = len(connect_info) 
        setaddr = []
        getaddr = []
        setargidx = []
        getargidx = []
        for i in range(connect_cnt):
            connect_i = connect_info[i]
            print("connect_i: %r"%connect_i)
            setaddr.append(int(connect_i[0], 16))
            getaddr.append(int(connect_i[1], 16))
            setargidx.append(int(connect_i[2]))
            getargidx.append(int(connect_i[3]))
        def connect(s):
            l.debug("connect(%r) get called"%s)
            if (s.regs.pc+4).args[0] in pctrace:
                l.info("connect @ %r found nopped in pctrace"%s.regs.pc)
            else:
                l.info("connect @ %r found called in pctrace"%s.regs.pc)
                i=0
                while i<connect_cnt:
                # for i in range(connect_cnt):
                    print('setaddr[%d]: 0x%08x & getaddr[%d]: 0x%08x'%(i, setaddr[i], i, getaddr[i]))
                    if setaddr[i] == s.regs.pc.args[0]:
                        if ARCH=='mips' and getaddr[i]+8 in pctrace:
                            break
                        elif ARCH=='arm' and getaddr[i]+4 in pctrace:
                            break
                    i+=1
                if i == connect_cnt:
                    l.error("Unable to locate connect info")
                    return
                if ARCH == 'mips':
                    l.debug('state %r jump to 0x%08x'%(s, getaddr[i]+8))
                    setattr(s.regs ,conv_regs[ARCH]['pc'], getaddr[i]+8)
                else:
                    l.debug('state %r jump to 0x%08x'%(s, getaddr[i]+4))
                    setattr(s.regs ,conv_regs[ARCH]['pc'], getaddr[i]+4)
                regval = None
                if setargidx[i] == 1:
                    regval = getattr(s.regs, conv_regs[ARCH]['a0'])
                elif setargidx[i] == 2:
                    regval = getattr(s.regs, conv_regs[ARCH]['a1'])
                elif setargidx[i] == 3:
                    regval = getattr(s.regs, conv_regs[ARCH]['a2'])
                elif setargidx[i] == 4:
                    regval = getattr(s.regs, conv_regs[ARCH]['a3'])
                else:
                    l.error("set arg index out of range: %d"%setargidx[i])
                if getargidx[i] == 0:
                    setattr(s.regs, conv_regs[ARCH]['rv'], regval)
                elif getargidx[i] == 1:
                    setattr(s.regs, conv_regs[ARCH]['a0'], regval)
                elif getargidx[i] == 2:
                    setattr(s.regs, conv_regs[ARCH]['a1'], regval)
                elif getargidx[i] == 3:
                    setattr(s.regs, conv_regs[ARCH]['a2'], regval)
                elif getargidx[i] == 4:
                    setattr(s.regs, conv_regs[ARCH]['a3'], regval)
                else:
                    l.error("get arg index out of range: %d"%getargidx[i])
        if DEBUG:
            print("setaddr: %r"%[hex(i) for i in setaddr])
            print("getaddr: %r"%[hex(i) for i in getaddr])
            print("setargidx: %r"%[hex(i) for i in setargidx])
            print("getargidx: %r"%[hex(i) for i in getargidx])

        for i in range(connect_cnt):
            l.debug("Hook connect at 0x%08x"%setaddr[i])
            if ARCH == 'mips':
                c1 = p.loader.memory.load(setaddr[i]+4,4)
                p.loader.memory.store(setaddr[i],c1)
                setaddr[i] += 4
                p.hook(setaddr[i], connect)
            elif ARCH == 'arm':
                p.hook(setaddr[i], connect)
            else:
                l.error("Currently not support arch %r"%ARCH)
    hook_connect(proj)

    with open("workdir/patch",'r') as f:
        patch_file = [i.split(' ') for i in f.read().strip('\n').split('\n') if len(i)>3]
        patches = []
        for patch_info in patch_file:
            if len(patch_info)<4:
                l.error("patch format error, check your syntax")
            else:
                if int(patch_info[0],0) not in [patch.addr for patch in patches]:
                    if len(patch_info)>4:
                        patch = Patch(int(patch_info[0],0), int(patch_info[1],0), patch_info[2], int(patch_info[3],0), int(patch_info[4],0), proj, NOP)
                    else:
                        patch = Patch(int(patch_info[0],0), int(patch_info[1],0), patch_info[2], int(patch_info[3],0), None, proj, NOP)
                    if patch.type == patch.TYPE_CALL:
                        patch.add_subfunc_call_hook(proj)
                    patches.append(patch)
    
    for patch in patches:
        if patch.len != len(patch.content):
            l.error("Patch %s has non-correspond patch len and content"%patch)
        # if not (patch.type==patch.TYPE_CALL and patch.bypass_in_poc == 1):
        # if patch.type==patch.TYPE_CALL and patch.bypass_in_poc == 0:
        #     if patch.len > 0:
        #         l.info("Writing %s to 0x%08x"%(str(patch.content), patch.addr))
        #         proj.loader.memory.store(patch.addr, patch.content)

    
    avoid_addrs = set([patch.avoid_addr for patch in patches if patch.type==patch.TYPE_JMP and patch.avoid_addr != 0])
    avoid_addrs.update(EXEC_END_ADDR)

    l.info("avoid_addrs: %s"%', '.join(hex(addr) for addr in avoid_addrs))


    # trace.remove(INJECT_ADDR + 4 if ARCH == "ARM" else INJECT_ADDR + 8)
    # t = angr.exploration_techniques.Tracer(trace=trace, crash_addr=None, copy_states=True, fast_forward_to_entry=False, aslr=False, follow_unsat=True)
    # simgr.use_technique(t)
    if os.access("workdir/call_checksum", os.F_OK):
        with open("workdir/call_checksum",'r') as f:
            checksum_judgeaddr = [int(i,0) for i in f.read().strip('\n').split('\n') if len(i)>3]


    s = proj.factory.blank_state(addr = START_ADDR)
    s.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
    s.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)

    # preconstraining: adding constraints which you would like to remove later.
    # input_sim = claripy.BVS("input_sim", 8*len(crash_input))
    # s.preconstrainer.preconstrain(crash_input, input_sim)

    if DEBUG:
        simgr = proj.factory.simgr(s, save_unsat=True, save_unconstrained=True)
    else:
        simgr = proj.factory.simgr(s, save_unsat=True, save_unconstrained=False)

    for tea in TARGET_END_ADDR:
        if ARCH == 'mips':
            target_sink_delay_slot = proj.loader.memory.load(tea+4, 4)
            proj.loader.memory.store(tea, target_sink_delay_slot)
            proj.hook(tea+4, sink_hook, length=4, replace=True)
        else:
            proj.hook(tea, sink_hook, length=4, replace=True)

    if DEBUG:
        print("simgr.stashes: %r"%simgr.stashes)

    while len(simgr.active)>0:
        print('\n=========================\nstep_cnt %d length of active states list: %d target sink addr: 0x%08x'%(step_cnt, len(simgr.active), CURR_TARGET_END_ADDR))
        step_cnt += 1
        l.debug("Current stashes: %s"%str(simgr.stashes))
        
        if len(simgr.active)>SHRINK_THRESHOLD:
            l.debug("shrinking simgr active states from %d to %d"%(len(simgr.active), SHRINK_THRESHOLD))

            pending_states = []
            for state in simgr.active:
                if state.addr not in [state.addr for state in pending_states]:
                    pending_states.append(state)
            pending_states = pending_states[:SHRINK_THRESHOLD]
            l.debug("Shrinking from %r to %r"%(simgr.active, pending_states))
            if DEBUG:
                simgr = proj.factory.simgr(pending_states, save_unsat=True, save_unconstrained=True)
            else:
                simgr = proj.factory.simgr(pending_states, save_unsat=True, save_unconstrained=False)

        def try_satisifiable(unsat_s):
            if SYMBOLIZE_INPUT:
                l.debug("unsat_s.addr: {}\tchecksum_judgeaddr: {}".format(hex(unsat_s.addr), ", ".join(hex(i) for i in checksum_judgeaddr)))
                # print(hex(unsat_s.history.addr))
                if unsat_s.addr in checksum_judgeaddr:
                    # _exit(0)
                    unsat_s.preconstrainer.remove_preconstraints()
                    l.debug("try_satisifiable: %r"%unsat_s.solver.satisfiable())
                    return unsat_s.solver.satisfiable()
                else:
                    l.debug("try_satisifiable: %r"%False)
                    return False
            else:
                l.debug("try_satisifiable: %r"%False)
                return False
        simgr.move(from_stash='unsat', to_stash='active', filter_func = try_satisifiable)

        if reach_target:
            l.info("Successfully reach sink address enables, return.")
            output_relied(relied_functions, CURR_TARGET_END_ADDR)
            output_others(other_constrains, CURR_TARGET_END_ADDR)
            output_symresult()
            return 
        # if reach_target and FOUND_LIMITSOLVE:
        #     explore_steps += 1
        #     l.debug("FOUND_LIMITSOLVE enables, current explore_steps:%d"%explore_steps)
        # if reach_target and FOUND_LIMITSOLVE and explore_steps > FOUND_MORESTEPS:
        #     l.info("FOUND_LIMITSOLVE enables, return.")
        #     output_relied(relied_functions, CURR_TARGET_END_ADDR)
        #     return 
        if reach_target:
            simgr.drop(filter_func=lambda s: judge_in_range(s, TARGET_END_ADDR))
        
        simgr.drop(filter_func=lambda s: not hasundrop(s, pctrace, proj) and not judge_on_trace(s, pctrace))
        simgr.drop(stash='unsat')
        simgr.drop(stash='active', filter_func=lambda s:s.addr in avoid_addrs)
        simgr.step(stash='active')

    l.info("No more active states, current simgr.stashes %r" % simgr.stashes)


    if not reach_target:
        output_unsolve_constraints(CURR_TARGET_END_ADDR)    
        l.info("Unable to find solvable path to target function, this crash input may not trigger crash in reality")
    else:
        l.info("Successfully reach sink address enables, return.")
        output_relied(relied_functions, CURR_TARGET_END_ADDR)
        output_others(other_constrains, CURR_TARGET_END_ADDR)
    output_symresult()

def time_calc(t):
    fl = "%f"%t
    mi = int(t/60)
    st = "%dm %fs"%(mi, t-mi*60)
    return "%s(%s)"%(fl,st)

def sigint_handler(signum, frame):
    global found
    if not found:
        output_unsolve_constraints(CURR_TARGET_END_ADDR)
        l.info("Unable to find solvable path to target function before SIGINT sent, this crash input may not trigger crash in reality")
    else:
        l.info("Time limit reached, we have some findings, stop symbolic solving")
    output_symresult()
    os._exit(0)
def shutdown(secs):
    global found
    if not found:
        output_unsolve_constraints(CURR_TARGET_END_ADDR)
        l.info("Unable to find solvable path to target function in given time(%r secs), this crash input may not trigger crash in reality"%secs)
    else:
        l.info("Time limit reached, we have some findings, stop symbolic solving")
    output_symresult()
    os._exit(0)

if __name__=='__main__':
    signal.signal(signal.SIGINT, sigint_handler)
    timer = Timer(2*60*60, shutdown, args=(2*60*60,))
    timer.start()
    # we run whole process for at most 64 times, first trace and find whether it reaches one specific sink
    for i in range(MAIN_REEXEC_TIME):
        main(i, MAIN_REEXEC_TIME)
        # if reach_target:
        #     break
        # for end_addr in TRACE_END_ADDR:
        #     if not TRACE_END_ADDR[end_addr]:
        #         continue
        #     break
    end_time = time.time()
    
    if one_time != None:
        l.success("All done, time:\nsolve one possible state: %s\tsolve all possible state: %s"%(time_calc(one_time-start_time), time_calc(end_time-start_time)))
    else:
        l.success("All done, but we failed to find any solvable state, run time: %s"%time_calc(end_time-start_time))
    
    timer.cancel()
