import angr, claripy, binascii
from utils import conv_regs, Patch, Free_Memory_Manager
import subprocess, os, time, logging, random
from itertools import islice
l=logging.getLogger(__name__)
# l.setLevel(logging.INFO)
l.setLevel(logging.DEBUG)

def output_symresult(simgr):
    active_state_cnt = len(simgr.active)
    constraints_sum = 0
    crashinput_constraints_sum = 0
    for s in simgr.active:
        constraints_sum += len(s.solver.constraints)
        for c in s.solver.constraints:
            if 'crash_input_sim' in str(c):
                crashinput_constraints_sum += 1
    randstr = ''.join([random.choice('1234567890abcdefghijklmn') for i in range(8)])
    with open('workdir/driller_constraints_statistic_%s' % randstr, 'w') as f:
        f.write(str(active_state_cnt)+'\n')
        f.write(str(constraints_sum)+'\n')
        f.write(str(crashinput_constraints_sum))

class Driller(object):
    """
    Driller object, symbolically follows an input looking for new state transitions.
    """
    def __init__(self, binary, start_addr, inject_addr, end_addr, inject_idx, os_str, exec_end_addr, arch, angr_arch, fuzz_input, fuzz_bitmap, NOP, **kwargs):
        """
        :param binary     : The binary to be traced.
        :param start_addr : address begin simulation 
        :param inject_addr: address we inject our fuzzing input
        :param end_addr   : address end simulation
        :param inject_idx : arg index to inject our fuzzing input
        :param fuzz_input  : mutated data for fuzzing
        :param fuzz_bitmap: AFL's bitmap of state transitions (defaults to empty).
        """
        self.binary        = binary
        self.identifier    = os.path.basename(binary)
        self.start_addr    = start_addr
        self.inject_addr   = inject_addr
        self.end_addr      = end_addr
        self.inject_idx    = inject_idx
        self.os            = os_str
        self.arch          = arch
        self.angr_arch     = angr_arch
        self.fuzz_input    = fuzz_input
        self.fuzz_inputc   = open(fuzz_input,'rb').read() + b'\0'*0x20
        self.fuzz_bitmap   = fuzz_bitmap
        self.NOP           = NOP
        self.exec_end_addr = exec_end_addr
        self.setaddr = []
        self.getaddr = []
        self.setargidx = []
        self.getargidx = []
        self.simgr = None
        
        
        
        if os_str == 'linux':
            self.libpath   = kwargs['libpath']
        elif os_str == 'rtos':
            self.base_addr = kwargs['base_addr']

        # The driller core, which is now an exploration technique in angr.
        self._core       = None
        # Start time, set by drill method.
        self.start_time = time.time()
        # Set of all the generated inputs.
        self._generated = set()

        l.debug("[%s] drilling started on %s.", self.identifier, time.ctime(self.start_time))
    
    def drill(self):
        """
        Perform the drilling, finding more code coverage based off our existing input base.
        """
        drill_output = list(set(self._drill_input()))
        if self.simgr!=None:
            output_symresult(self.simgr)
        return drill_output
    def preset(self, p): 
        def store_inject_data(s, data, addr=0x12340000):
            # assert not stored, "store_inject_data get multi-called @ %r"%s
            s.memory.store(addr,b'\0'*0x20000)
            s.memory.store(addr, data)
            return addr
        def findAndChangeReg(s, regval, dataAddr=0x12340000):
            if self.arch=='mips':
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
            elif self.arch=='arm':
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
                l.error("Unsupported arch %s"%self.arch)
            
        def hook_injection(p):
            input_sim = claripy.BVS("input_sim", 8*len(self.fuzz_inputc))
            def inject_data(s):
                if self.inject_idx == 0:
                    l.debug("Data inject to return value")
                    setattr(s.regs, conv_regs[self.arch]['rv'], store_inject_data(s, input_sim))
                else:
                    if self.inject_idx == 1:
                        regval = getattr(s.regs, conv_regs[self.arch]['a0'])
                        l.debug("Data inject to arg0 @ %r" % regval)
                    elif self.inject_idx == 2:
                        regval = getattr(s.regs, conv_regs[self.arch]['a1'])
                        l.debug("Data inject to arg1 @ %r" % regval)
                    elif self.inject_idx == 3:
                        regval = getattr(s.regs, conv_regs[self.arch]['a2'])
                        l.debug("Data inject to arg2 @ %r" % regval)
                    elif self.inject_idx == 4:
                        regval = getattr(s.regs, conv_regs[self.arch]['a3'])
                        l.debug("Data inject to arg3 @ %r" % regval)

                    if regval.symbolic and str(getattr(s.regs, conv_regs[self.arch]['bp'])) not in str(regval):
                        l.debug("detect symbolic input address %r, find and change all possible reg value to dataAddr..."%regval)
                        findAndChangeReg(s, regval)
                        store_inject_data(s, input_sim)
                    else:
                        store_inject_data(s, input_sim, regval)
                
                l.info("Data injection complete")
            p.hook(self.inject_addr, inject_data, length=4 if self.arch=='arm' else 8)
            return input_sim
        def hook_connect(p):
            if not os.access("workdir/connect",os.F_OK):
                return
            with open("workdir/connect",'r') as f:
                connect_info = [i.split(' ') for i in f.read().strip('\n').split('\n') if len(i)>3]
            self.connect_cnt = len(connect_info) 
            for i in range(self.connect_cnt):
                connect_i = connect_info[i]
                self.setaddr.append(int(connect_i[0], 16))
                self.getaddr.append(int(connect_i[1], 16))
                self.setargidx.append(int(connect_i[2]))
                self.getargidx.append(int(connect_i[3]))
            def connect(s):
                if (s.regs.pc+4).args[0] in self.trace:
                    l.info("connect @ 0x%08x found nopped in trace"%s.regs.pc)
                else:
                    l.info("connect @ 0x%08x found called in trace"%s.regs.pc)
                    for i in range(self.connect_cnt):
                        if self.setaddr[i] == s.regs.pc.args[0] and self.getaddr[i] in self.trace:
                            break
                        if i == self.connect_cnt:
                            l.error("Unable to locate connect info")
                            return
                    if self.arch == 'mips':
                        self.getaddr[i] += 4
                    self.getaddr[i] += 4
                    setattr(s.regs ,conv_regs[self.arch]['pc'], self.getaddr[i])
                    regval = None
                    if self.setargidx[i] == 1:
                        regval = getattr(s.regs, conv_regs[self.arch]['a0'])
                    elif self.setargidx[i] == 2:
                        regval = getattr(s.regs, conv_regs[self.arch]['a1'])
                    elif self.setargidx[i] == 3:
                        regval = getattr(s.regs, conv_regs[self.arch]['a2'])
                    elif self.setargidx[i] == 4:
                        regval = getattr(s.regs, conv_regs[self.arch]['a3'])
                    else:
                        l.error("set arg index out of range: %d"%self.setargidx[i])
                    if self.getargidx[i] == 0:
                        setattr(s.regs, conv_regs[self.arch]['rv'], regval)
                    elif self.getargidx[i] == 1:
                        setattr(s.regs, conv_regs[self.arch]['a0'], regval)
                    elif self.getargidx[i] == 2:
                        setattr(s.regs, conv_regs[self.arch]['a1'], regval)
                    elif self.getargidx[i] == 3:
                        setattr(s.regs, conv_regs[self.arch]['a2'], regval)
                    elif self.getargidx[i] == 4:
                        setattr(s.regs, conv_regs[self.arch]['a3'], regval)
                    else:
                        l.error("get arg index out of range: %d"%self.getargidx[i])
                    
            for i in range(self.connect_cnt):
                if self.arch == 'mips':
                    c1 = p.loader.memory.load(self.setaddr[i]+4,4)
                    p.loader.memory.store(self.setaddr[i],c1)
                    self.setaddr[i] += 4
                    p.hook(self.setaddr[i], connect, replace=True)
                elif self.arch == 'arm':
                    p.hook(self.setaddr[i], connect, replace=True)
                else:
                    l.error("Currently not support arch %r"%self.arch)
            
        def apply_patch(p):
            with open("workdir/patch",'r') as f:
                patch_file = [i.split(' ') for i in f.read().strip('\n').split('\n') if len(i)>3]
            patches = []
            for patch in patch_file:
                if int(patch[0],0) not in [patch.addr for patch in patches]:
                    if len(patch)==3:
                        patches.append(Patch(int(patch[0],0), int(patch[1],0),       '', int(patch[3], 0),             None, p, self.NOP))
                    elif len(patch)==4:
                        patches.append(Patch(int(patch[0],0), int(patch[1],0), patch[2], int(patch[3], 0),             None, p, self.NOP))
                    elif len(patch)==5:
                        patches.append(Patch(int(patch[0],0), int(patch[1],0), patch[2], int(patch[3], 0), int(patch[4], 0), p, self.NOP))

            self.avoid_addrs = set()
            for patch in patches:
                if hasattr(patch, 'avoid_addr'):
                    self.avoid_addrs.add(patch.avoid_addr)
                if patch.len != len(patch.content):
                    l.error("Patch %s has non-correspond patch len and content"%patch)
                if patch.type==patch.TYPE_CALL and patch.len > 0:
                    # patch.add_subfunc_call_hook(p)
                    l.info("Writing %s to 0x%08x"%(str(patch.content), patch.addr))
                    p.loader.memory.store(patch.addr, patch.content)
            s = p.factory.blank_state(addr = self.start_addr)
            # s.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
            # s.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
            return s

        input_sim = hook_injection(p)
        hook_connect(p)
        s = apply_patch(p)
        return (input_sim, s)

    def judge_in_range(self, state, addr_or_addrlist):
        block = state.block()
        l.debug("Checking block 0x%08x-0x%08x"%(block.addr, block.addr + block.size))
        if type(addr_or_addrlist)==set:
            for addr in addr_or_addrlist:
                if addr >= block.addr and addr < block.addr + block.size:
                # if addr in range(block.addr, block.addr+block.size):
                    l.debug("block return: in-range")
                    return True
        else:
            if addr_or_addrlist >= block.addr and addr_or_addrlist < block.addr + block.size:
            # if addr_or_addrlist in range(block.addr, block.addr+block.size):
                l.debug("block return: in-range")
                return True
        l.debug("block return: not in-range")
        return False

    def _drill_input(self):
        
        # p = subprocess.Popen(['python3','./wrapper-test.py', self.binary, self.libpath, self.inputfile],)
        # if p:
        #     p.wait()
        os.system("./run.sh TRACE %s %s %s %s 1>&2 2>/dev/null"%(os.environ["GHIDRA_DIR"], os.environ["TRACE_IDX"], self.binary, self.fuzz_input))

        with open("workdir/traceLog.txt",'r') as f:
            # since we exec one instr and restore the unicorn engine, this will introduce one redundant trace log
            self.trace=[int(i,16) for i in f.read()[:-1].split('\n')][1:]
        with open("workdir/pcLogger.txt",'r') as f:
            # since we exec one instr and restore the unicorn engine, this will introduce one redundant trace log
            self.pctrace=[int(i,16) for i in f.read()[:-1].split('\n')][1:]

        if self.os == 'linux':
            with open("workdir/libLog.txt",'r') as f:
                libbase = f.read()[:-1].split('\n')
                lib_opt = {}
                for i in libbase:
                    i=i.split(' ')
                    libname = os.path.basename(i[0])
                    libbase = int(i[1],16)
                    assert libname not in lib_opt, "FATAL: one lib get multi baseaddr???"
                    lib_opt[libname]={"base_addr":libbase}
            # FIXME: The address here may not to be corresponding to UF emulator... Could this bring any problem?
            # tiny fix here: add lib_opt to set base addr of objects, NOT all memory segments
            p = angr.Project(self.binary, force_load_libs=['./demo-libcpreload.so'], lib_opts=lib_opt, use_system_libs=False, ld_path=self.libpath, support_selfmodifying_code=True)
            l.info("p.loader.all_objects: %s"%str(p.loader.all_objects))

        elif self.os == 'rtos':
            main_opts = {'backend':'blob', 'arch':self.angr_arch, 'base_addr':self.base_addr}
            p = angr.Project(self.binary, main_opts = main_opts, support_selfmodifying_code=True)
            l.info("p.loader.all_objects: %s"%str(p.loader.all_objects))
        else:
            l.error("Unsupported os %s"%self.os)
        
        (input_sim, s) = self.preset(p)

        # preconstraining: adding constraints which you would like to remove later.
        s.preconstrainer.preconstrain(self.fuzz_inputc, input_sim)
        
        simgr = p.factory.simulation_manager(s, save_unsat=True, hierarchy=False)#, save_unconstrained=r.crash_mode) 
        self.simgr = simgr
        t = angr.exploration_techniques.Tracer(trace=self.trace, crash_addr=None, copy_states=True, fast_forward_to_entry=False, aslr=False, follow_unsat=True)
        self._core = angr.exploration_techniques.DrillerCore(trace=self.trace, fuzz_bitmap=self.fuzz_bitmap)

        simgr.use_technique(t)
        simgr.use_technique(angr.exploration_techniques.Oppologist())
        simgr.use_technique(self._core)

        self._set_concretizations(simgr.one_active)

        l.debug("Drilling into %r.", self.fuzz_input)
        l.debug("Input is %r.", self.fuzz_inputc)
        l.debug("Start from state: %r", s)
        l.debug("avoiding address: %s"%str([hex(i) for i in self.avoid_addrs]))
        # l.debug("simgr.stashes:")
        # print(simgr.stashes)
        # if len(simgr.active)>0:
        #     simgr.one_active.block().pp()

        simgr_avoid_addrs = self.avoid_addrs.copy()
        simgr_avoid_addrs.update(self.end_addr)
        simgr_avoid_addrs.update(self.exec_end_addr)

        while simgr.active and simgr.one_active.globals['trace_idx'] < len(self.trace) - 1:
            print(simgr.stashes)
            # print('\n\n')
            try:
                simgr.step()
            except Exception as e:
                print("simgr step failed with ",e,", exit driller analysis")
                return
            debug = True
            debug = False
            if debug:            
                l.debug("simgr.stashes:")
                print(simgr.stashes)
                if len(simgr.active)>0:
                    simgr.one_active.block().pp()

            # IMPORTANT: Since we only fuzz one function, the return addr of this caller shoule be the deadend of the simgr
            # simgr.move(from_stash='active', to_stash='deadended', filter_func=lambda s: self.judge_in_range(s, self.end_addr))
            simgr.drop(filter_func=lambda s: self.judge_in_range(s, simgr_avoid_addrs))

            if 'diverted' not in simgr.stashes:
                # not found any new path that AFL not found, continue exploring
                continue

            simgr.drop(stash='diverted', filter_func=lambda s: self.judge_in_range(s, simgr_avoid_addrs))

            

            while simgr.diverted:
                state = simgr.diverted.pop(0)
                l.debug("Found a diverted state, exploring to some extent.")
                # l.debug("state.solver.constraints:")
                # print(state.solver.constraints)
                w = self._writeout(state.history.bbl_addrs[-1], state, input_sim)
                if w is not None:
                    # l.debug("self._writeout generate something...")
                    yield w
                for i in self._symbolic_explorer_stub(state, input_sim):
                    # l.debug("self._symbolic_explorer_stub generate something...")
                    yield i
    
    # Utils 

    @staticmethod
    def _set_concretizations(state):
        # Let's put conservative thresholds for now.
        state.unicorn.concretization_threshold_memory = 50000
        state.unicorn.concretization_threshold_registers = 50000

    def _writeout(self, prev_addr, state, input_sim):
        if prev_addr == 0x4030984c:
            print("state.solver.constraints: %r" % state.solver.constraints)
        generated = state.solver.eval(input_sim, cast_to=bytes).strip(b'\0')

        key = (len(generated), prev_addr, state.addr)

        # Checks here to see if the generation is worth writing to disk.
        # Currently PENDING this check
        # If we generate too many inputs which are not really different we'll seriously slow down AFL.
        #if self._in_catalogue(*key):
        #    self._core.encounters.remove((prev_addr, state.addr))
        #    return None
        #else:
        #    self._add_to_catalogue(*key)

        l.info("[%s] dumping input for %#x -> %#x.", self.identifier, prev_addr, state.addr)

        self._generated.add((key, generated))

        l.info("Generated: %s", binascii.hexlify(generated))

        return (key, generated)

    def _symbolic_explorer_stub(self, state, input_sim):
        # Create a new simulation manager and step it forward up to 1024
        # accumulated active states or steps.
        steps = 0
        accumulated = 1

        p = state.project
        state = state.copy()
        try:
            state.options.remove(angr.options.LAZY_SOLVES)
        except KeyError:
            pass
        simgr = p.factory.simulation_manager(state, hierarchy=False)

        l.debug("[%s] started symbolic exploration at %s.", self.identifier, time.ctime())

        while len(simgr.active) and accumulated < 1024:
            simgr.step()
            steps += 1

            # Dump all inputs.
            accumulated = steps * (len(simgr.active) + len(simgr.deadended))

        l.debug("[%s] stopped symbolic exploration at %s.", self.identifier, time.ctime())

        # DO NOT think this is the same as using only the deadended stashes. this merges deadended and active
        simgr.stash(from_stash='deadended', to_stash='active')
        for dumpable in simgr.active:
            try:
                if dumpable.satisfiable():
                    w = self._writeout(dumpable.history.bbl_addrs[-1], dumpable, input_sim)
                    if w is not None:
                        yield w

            # If the state we're trying to dump wasn't actually satisfiable.
            except IndexError:
                pass
