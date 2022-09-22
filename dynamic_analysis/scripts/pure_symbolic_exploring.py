#!/usr/bin/env python3
import angr, sys, claripy
import time, random, signal
from threading import Timer
import code
import copy
from copy import deepcopy

import traceback
import os, subprocess, shutil

import binascii
from utils import conv_regs, UF_Logging, Patch
import time

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

SYMBOLIZE_INPUT = True
CRASH_INPUT_SYMLEN = 1024
FOUND_LIMITSOLVE = True
CONTINUE_SYMEXPLORE = True

HOOK_CONNECT = True
DEBUG = False
TIMEOUT = 6*60*60 if len(sys.argv)<=1 else int(sys.argv[1])
PATCH_CALL_JMP = False if len(sys.argv)<=2 or sys.argv[2]=='False' else True


MAIN_REEXEC_TIME = 32
REEXEC_TIME = 64
SHRINK_THRESHOLD = 12000
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

TRACE_END_ADDR = {}
SYMSOLVE_END_ADDR = {}
for fuzz_endaddr in FUZZ_END_ADDR:
    TRACE_END_ADDR[fuzz_endaddr] = False
    SYMSOLVE_END_ADDR[fuzz_endaddr] = False
        

stored = False
apply_tmin_to_crashinput = False

found = False


step_cnt = 0
reach_target = False
relied_functions = []
other_constrains = []
explore_steps = 0
crash_input_calc_cnt = 0
syminput_cnt = 0
crash_input = None
crash_input_sim = None
simgr = None
proj = None
avoid_addrs = None
checksum_judgeaddr = None
patches = None

# 拿AC11和WDR7660做对比：
# 
# 记录首次找到漏洞的时间
# 去掉pure symbolic中的nop-patch记录经过nop patch的state数量占比
# 最终两种方法所能发现的漏洞数量对比

result_dir = "workdir/pure_symsolve_%r" % PATCH_CALL_JMP

def check_puresymsolve_dir():
    if not os.access(result_dir, os.F_OK):
        os.mkdir(result_dir)
    else:
        shutil.rmtree(result_dir)
        os.mkdir(result_dir)

def write_syminput(crash_input):
    # write syminput for every state that simgr have
    global syminput_cnt
    find_crashinput_time = int(time.time() - start_time) # in second
    with open('%s/symsolve_input_%d_%d'%(result_dir, syminput_cnt, find_crashinput_time), 'wb') as f:
        f.write(crash_input)
        syminput_cnt += 1

def write_sink_syminput(crash_input, active_state_addr):
    # write syminput that can reach sinks
    global crash_input_calc_cnt
    find_sink_time = int(time.time() - start_time) # in second
    with open("%s/symsolve_sink_crashinput_%d_%d_0x%08x"%(result_dir, crash_input_calc_cnt, find_sink_time, active_state_addr), 'wb') as f:
        f.write(crash_input)
        crash_input_calc_cnt += 1

def output_symresult():
    output_simgr_active_syminput()
    output_subfunc_statistic()
    output_constrains_statistic()

def output_constrains_statistic():
    global simgr
    active_state_cnt = len(simgr.active)
    constraints_sum = 0
    crashinput_constraints_sum = 0
    for s in simgr.active:
        constraints_sum += len(s.solver.constraints)
        for c in s.solver.constraints:
            if 'crash_input_sim' in str(c):
                crashinput_constraints_sum += 1
    with open('%s/symsolve_constraints_statistic' % result_dir, 'w') as f:
        f.write(str(active_state_cnt)+'\n')
        f.write(str(constraints_sum)+'\n')
        f.write(str(crashinput_constraints_sum))


def output_subfunc_statistic():
    global simgr
    cnt = 0
    for s in simgr.active:
        if 'subfunc_flag' in s.globals and s.globals['subfunc_flag'] == True:
            cnt += 1

    with open('%s/symsolve_subfunc_statistic' % result_dir, 'w') as f:
        f.write(str(cnt)+'\n')
        f.write(str(len(simgr.active)))
    
    with open('%s/symsolve_subfunc_step_statistic' % result_dir, 'w') as f:
        for s in simgr.active:
            if 'step_cnt' in s.globals and 'patched_subfunc_steps_cnt' in s.globals:
                f.write(str(s.globals['patched_subfunc_steps_cnt']))
                f.write(' ')
                f.write(str(s.globals['step_cnt']))
                f.write('\n')

def output_simgr_active_syminput():
    global simgr
    l.info('simgr.active: %r' % simgr.active)
    for state in simgr.active:
        crash_input = state.solver.eval(crash_input_sim, cast_to=bytes)
        write_syminput(crash_input)

def sink_hook(active_state):
    global reach_target, one_time, crash_input_sim, crash_input

    active_state_addr = active_state.addr
    if ARCH == 'mips':
        active_state_addr -= 4

    # if we successfully reach the target block with given input, try to solve all symbol we added to each subfunction call
    l.success("Successfully reach the target block 0x%08x with given crash input! "%active_state_addr)
    reach_target = True

    crash_input = active_state.solver.eval(crash_input_sim, cast_to=bytes)
    write_syminput(crash_input)
    write_sink_syminput(crash_input, active_state_addr)
    

    if one_time==None:
        one_time = time.time()    

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

def main():
    global step_cnt, reach_target, relied_functions, other_constrains, explore_steps, crash_input_calc_cnt, one_time, found, crash_input_sim, simgr, proj, avoid_addrs, checksum_judgeaddr, TARGET_END_ADDR, patches, crash_input, CONTINUE_SYMEXPLORE
    if ARCH=='mips' and ENDIAN=='little':
        angr_arch = 'mipsel'
    elif ARCH=='mips':
        angr_arch = 'mipseb'
    elif ARCH=='arm' and ENDIAN=='little':
        angr_arch = 'armel'
    elif ARCH=='mips':
        angr_arch = 'armeb'

    proj = angr.Project(TARGET, main_opts = {'backend': 'blob', 'arch': angr_arch, 'base_addr': BASE_ADDR}, support_selfmodifying_code=True)
    
    crash_input_sim = claripy.BVS("crash_input_sim", CRASH_INPUT_SYMLEN*8)

    def store_inject_data(s, data, addr=0x12340000):
        global stored
        if not stored:
        # assert not stored, "store_inject_data get multi-called"
            stored = True
            s.memory.store(addr, b'\0'*0x20000)
            s.memory.store(addr, data)
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
        if INJECT_IDX == 0:
            setattr(s.regs, conv_regs[ARCH]['rv'], store_inject_data(s, crash_input_sim))
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
                store_inject_data(s, crash_input_sim)
            else:
                store_inject_data(s, crash_input_sim, regval)
            
            setattr(s.regs, conv_regs[ARCH]['rv'], claripy.BVS('inject_retval', 32))

    def subfunc_flag_add(s):
        l.debug("add subfunc flag to state %r"%s)
        s.globals['subfunc_flag'] = True
        s.globals['in_patched_subfunc_flag'] = True
    def subfunc_flag_remove(s):
        l.debug("remove subfunc flag to state %r"%s)
        print('kkkkkk')
        s.globals['in_patched_subfunc_flag'] = False
    def add_step_cnt(s):
        # print(s)
        if 'step_cnt' not in s.globals:
            s.globals['step_cnt'] = 0
        if 'patched_subfunc_steps_cnt' not in s.globals:
            s.globals['patched_subfunc_steps_cnt'] = 0
        s.globals['step_cnt'] += 1
        if 'in_patched_subfunc_flag' in s.globals and s.globals['in_patched_subfunc_flag'] == True:
            s.globals['patched_subfunc_steps_cnt'] += 1
        # print(s.globals['step_cnt'], s.globals['patched_subfunc_steps_cnt'])

    if ARCH=='mips':
        delay_slot_instr = proj.loader.memory.load(INJECT_ADDR+4, 4)
        proj.loader.memory.store(INJECT_ADDR, delay_slot_instr)
        proj.hook(INJECT_ADDR+4, inject_data, length=4, replace=True)
    else:
        proj.hook(INJECT_ADDR, inject_data, length=4, replace=True)
            
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
            global simgr
            l.debug("connect(%r) get called"%s)
            i=0
            while i<connect_cnt:
                if setaddr[i] == s.regs.pc.args[0]:
                    if ARCH=='mips':
                        ss = s.copy()
                        l.debug('state %r jump to 0x%08x'%(ss, getaddr[i]+8))
                        setattr(ss.regs ,conv_regs[ARCH]['pc'], getaddr[i]+8)
                    elif ARCH=='arm':
                        ss = s.copy()
                        l.debug('state %r jump to 0x%08x'%(ss, getaddr[i]+4))
                        setattr(ss.regs ,conv_regs[ARCH]['pc'], getaddr[i]+4)
                    regval = None
                    if setargidx[i] == 1:
                        regval = getattr(ss.regs, conv_regs[ARCH]['a0'])
                    elif setargidx[i] == 2:
                        regval = getattr(ss.regs, conv_regs[ARCH]['a1'])
                    elif setargidx[i] == 3:
                        regval = getattr(ss.regs, conv_regs[ARCH]['a2'])
                    elif setargidx[i] == 4:
                        regval = getattr(ss.regs, conv_regs[ARCH]['a3'])
                    else:
                        l.error("set arg index out of range: %d"%setargidx[i])
                    if getargidx[i] == 0:
                        setattr(ss.regs, conv_regs[ARCH]['rv'], regval)
                    elif getargidx[i] == 1:
                        setattr(ss.regs, conv_regs[ARCH]['a0'], regval)
                    elif getargidx[i] == 2:
                        setattr(ss.regs, conv_regs[ARCH]['a1'], regval)
                    elif getargidx[i] == 3:
                        setattr(ss.regs, conv_regs[ARCH]['a2'], regval)
                    elif getargidx[i] == 4:
                        setattr(ss.regs, conv_regs[ARCH]['a3'], regval)
                    else:
                        l.error("get arg index out of range: %d"%getargidx[i])
                    simgr.active.append(ss)
                i+=1

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

    if HOOK_CONNECT:
        hook_connect(proj)

    if PATCH_CALL_JMP:
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
    else:
        # add angr hook, add flag for every symstate that get into the subfunc that should have been patched NOP
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
                            proj.hook(patch.addr, subfunc_flag_add, replace=True)
                            if ARCH == 'mips':
                                proj.hook(patch.addr + 8, subfunc_flag_remove, replace=True)
                            else:
                                proj.hook(patch.addr + 4, subfunc_flag_remove, replace=True)
                        patches.append(patch) 
    if PATCH_CALL_JMP:
        avoid_addrs = set([patch.avoid_addr for patch in patches if patch.type==patch.TYPE_JMP and patch.avoid_addr != 0])
    else:
        avoid_addrs = set()

    s = proj.factory.blank_state(addr = START_ADDR)
    s.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
    s.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)

    simgr = proj.factory.simgr(s, save_unsat=False, save_unconstrained=False)

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
        print('\n=========================\nstep_cnt %d length of active states list: %d'%(step_cnt, len(simgr.active)))
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
            
            simgr = proj.factory.simgr(pending_states, save_unsat=False, save_unconstrained=False)

        if DEBUG:
            cnt = 0
            for s in simgr.active:
                if 'subfunc_flag' in s.globals and s.globals['subfunc_flag'] == True:
                    cnt += 1

        if reach_target:
            l.info("Successfully reach sink address enables, return.")
            output_symresult()
            return 
        simgr.drop(stash='active', filter_func=lambda s:s.addr in avoid_addrs)
        # simgr.drop(stash='active', filter_func=lambda s:judge_in_range(s, avoid_addrs))
        simgr.apply(stash='active', state_func = add_step_cnt)
        simgr.step(stash='active')

    l.info("No more active states")
    output_symresult()


def time_calc(t):
    fl = "%f"%t
    mi = int(t/60)
    st = "%dm %fs"%(mi, t-mi*60)
    return "%s(%s)"%(fl,st)

def sigint_handler(signum, frame):
    print("sigint triggered")
    output_symresult()
    os._exit(0)
def shutdown(secs):
    print("timeout triggered")
    output_symresult()
    os._exit(0)

if __name__=='__main__':
    signal.signal(signal.SIGINT, sigint_handler)
    check_puresymsolve_dir()
    timer = Timer(TIMEOUT, shutdown, args=(TIMEOUT,))
    timer.start()
    main()
    end_time = time.time()
    
    if one_time != None:
        l.success("All done, time:\nsolve one possible state: %s\tsolve all possible state: %s"%(time_calc(one_time-start_time), time_calc(end_time-start_time)))
    else:
        l.success("All done, but we failed to find any solvable state reaching sink functions, run time: %s"%time_calc(end_time-start_time))
    
    timer.cancel()
